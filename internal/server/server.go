// Package server runs Magpie's local web UI: drop an .ipa on the page and get
// the report in the browser. It is meant to listen on localhost only.
package server

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Kumar-ranjan12345/magpie/internal/checks"
	"github.com/Kumar-ranjan12345/magpie/internal/engine"
	"github.com/Kumar-ranjan12345/magpie/internal/report"
)

//go:embed upload.html
var uploadHTML string

var uploadPage = template.Must(template.New("upload").Parse(uploadHTML))

// MaxUpload caps the size of an uploaded app (large games can be several GB).
const MaxUpload = 4 << 30

type Server struct {
	Version string
	Logger  *log.Logger

	once sync.Once
	jobs *jobStore
}

func (s *Server) Handler() http.Handler {
	s.once.Do(func() { s.jobs = newJobStore() })
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.index)
	mux.HandleFunc("GET /favicon.svg", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Cache-Control", "max-age=86400")
		w.Write(report.IconSVG())
	})
	mux.HandleFunc("POST /scan", s.scan)
	mux.HandleFunc("GET /jobs/{id}", s.jobStatus)
	mux.HandleFunc("GET /jobs/{id}/report", s.jobReport)
	return securityHeaders(mux)
}

func (s *Server) index(w http.ResponseWriter, _ *http.Request) {
	var buf bytes.Buffer
	err := uploadPage.Execute(&buf, struct {
		Icon    template.HTML
		Version string
		Rules   int
	}{report.Icon(), s.Version, len(checks.Rules())})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(buf.Bytes())
}

func (s *Server) scan(w http.ResponseWriter, r *http.Request) {
	// Another website open in the browser must not be able to post files here.
	if !sameOrigin(r) {
		http.Error(w, "cross-origin request refused", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxUpload)
	mr, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "expected a multipart file upload", http.StatusBadRequest)
		return
	}

	var tmpPath, name string
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			uploadError(w, err)
			return
		}
		if part.FormName() != "file" {
			continue
		}
		name = filepath.Base(part.FileName())
		if tmpPath, err = saveUpload(part, name); err != nil {
			uploadError(w, err)
			return
		}
		break
	}
	if tmpPath == "" {
		http.Error(w, "no file uploaded", http.StatusBadRequest)
		return
	}

	// The upload is done; scan in the background and let the page poll for progress.
	id, j := s.jobs.add(name)
	go s.run(j, tmpPath)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"id": id})
}

func (s *Server) run(j *job, tmpPath string) {
	defer os.RemoveAll(filepath.Dir(tmpPath))
	setStage := func(st engine.Stage) {
		j.mu.Lock()
		j.stage = st
		j.mu.Unlock()
	}

	rep, err := engine.ScanWithProgress(tmpPath, s.Version, setStage)
	var buf bytes.Buffer
	if err == nil {
		err = report.InteractiveHTML(&buf, rep)
	}

	j.mu.Lock()
	defer j.mu.Unlock()
	j.done = true
	if err != nil {
		j.err = "Could not scan " + j.name + ": " + err.Error()
		s.logf("failed %s: %v", j.name, err)
		return
	}
	j.report = buf.Bytes()
	s.logf("scanned %s (%s) in %s: grade %s, %d findings", j.name, rep.App.BundleID,
		time.Since(j.started).Round(time.Millisecond), rep.Grade, len(rep.Findings))
}

func (s *Server) jobStatus(w http.ResponseWriter, r *http.Request) {
	j := s.jobs.get(r.PathValue("id"))
	if j == nil {
		http.Error(w, "scan not found or expired", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(j.status())
}

func (s *Server) jobReport(w http.ResponseWriter, r *http.Request) {
	j := s.jobs.get(r.PathValue("id"))
	if j == nil {
		http.Error(w, "This report has expired. Scan the app again.", http.StatusNotFound)
		return
	}
	j.mu.Lock()
	page, done, msg := j.report, j.done, j.err
	j.mu.Unlock()
	switch {
	case !done:
		http.Error(w, "scan still running", http.StatusConflict)
	case msg != "":
		http.Error(w, msg, http.StatusUnprocessableEntity)
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(page)
	}
}

func saveUpload(src io.Reader, name string) (string, error) {
	ext := strings.ToLower(filepath.Ext(name))
	if ext != ".ipa" && ext != ".zip" {
		return "", fmt.Errorf("%q is not an .ipa or .zip file", name)
	}
	dir, err := os.MkdirTemp("", "magpie-upload-*")
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "upload"+ext)
	f, err := os.Create(path)
	if err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	_, err = io.Copy(f, src)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	return path, nil
}

func uploadError(w http.ResponseWriter, err error) {
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) {
		http.Error(w, fmt.Sprintf("file is larger than %d GB", MaxUpload>>30), http.StatusRequestEntityTooLarge)
		return
	}
	http.Error(w, err.Error(), http.StatusBadRequest)
}

func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true // non-browser clients such as curl
	}
	u, err := url.Parse(origin)
	return err == nil && u.Host == r.Host
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) logf(format string, args ...any) {
	if s.Logger != nil {
		s.Logger.Printf(format, args...)
	}
}
