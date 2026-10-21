package server

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixtureIPA(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	src := "../../testdata/VulnerableApp.app"
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		w, err := zw.Create("Payload/VulnerableApp.app/" + filepath.ToSlash(rel))
		if err != nil {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		_, err = w.Write(data)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	zw.Close()
	return buf.Bytes()
}

func post(t *testing.T, name string, data []byte, origin string) *httptest.ResponseRecorder {
	t.Helper()
	return postTo(t, (&Server{Version: "test"}).Handler(), name, data, origin)
}

func postTo(t *testing.T, h http.Handler, name string, data []byte, origin string) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("file", name)
	fw.Write(data)
	mw.Close()

	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8077/scan", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestUploadPage(t *testing.T) {
	rec := httptest.NewRecorder()
	(&Server{}).Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Drop an .ipa here") {
		t.Fatalf("GET / = %d", rec.Code)
	}
	if rec.Header().Get("Content-Security-Policy") == "" {
		t.Error("missing Content-Security-Policy header")
	}
}

func TestScanUpload(t *testing.T) {
	srv := &Server{Version: "test"}
	h := srv.Handler()
	rec := postTo(t, h, "VulnerableApp.ipa", fixtureIPA(t), "http://127.0.0.1:8077")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var started struct{ ID string }
	if err := json.Unmarshal(rec.Body.Bytes(), &started); err != nil || started.ID == "" {
		t.Fatalf("bad response %q", rec.Body.String())
	}

	// Poll the job like the page does.
	var st jobStatus
	for deadline := time.Now().Add(10 * time.Second); ; {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/jobs/"+started.ID, nil))
		json.Unmarshal(rec.Body.Bytes(), &st)
		if st.Done || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !st.Done || st.Error != "" {
		t.Fatalf("job did not finish cleanly: %+v", st)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/jobs/"+started.ID+"/report", nil))
	body := rec.Body.String()
	for _, want := range []string{"VulnerableApp", "MP-ENT-001", "Scan another app", "<b>F</b>"} {
		if !strings.Contains(body, want) {
			t.Errorf("report missing %q", want)
		}
	}
}

func TestUnknownJob(t *testing.T) {
	rec := httptest.NewRecorder()
	(&Server{}).Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/jobs/nope", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404", rec.Code)
	}
}

func TestRejectsWrongType(t *testing.T) {
	if rec := post(t, "notes.txt", []byte("hello"), ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", rec.Code)
	}
}

func TestRejectsCorruptIPA(t *testing.T) {
	h := (&Server{}).Handler()
	rec := postTo(t, h, "broken.ipa", []byte("not a zip"), "")
	var started struct{ ID string }
	json.Unmarshal(rec.Body.Bytes(), &started)
	var st jobStatus
	for i := 0; i < 200 && !st.Done; i++ {
		r := httptest.NewRecorder()
		h.ServeHTTP(r, httptest.NewRequest(http.MethodGet, "/jobs/"+started.ID, nil))
		json.Unmarshal(r.Body.Bytes(), &st)
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(st.Error, "broken.ipa") {
		t.Errorf("error should name the file, got %+v", st)
	}
}

func TestRejectsCrossOrigin(t *testing.T) {
	if rec := post(t, "VulnerableApp.ipa", fixtureIPA(t), "https://evil.example"); rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", rec.Code)
	}
}
