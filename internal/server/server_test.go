package server

import (
	"archive/zip"
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	(&Server{Version: "test"}).Handler().ServeHTTP(rec, req)
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
	rec := post(t, "VulnerableApp.ipa", fixtureIPA(t), "http://127.0.0.1:8077")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"VulnerableApp", "MP-ENT-001", "Scan another app", `class="grade F"`} {
		if !strings.Contains(body, want) {
			t.Errorf("report missing %q", want)
		}
	}
}

func TestRejectsWrongType(t *testing.T) {
	if rec := post(t, "notes.txt", []byte("hello"), ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", rec.Code)
	}
}

func TestRejectsCorruptIPA(t *testing.T) {
	rec := post(t, "broken.ipa", []byte("not a zip"), "")
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status %d, want 422", rec.Code)
	}
	if b, _ := io.ReadAll(rec.Body); !strings.Contains(string(b), "broken.ipa") {
		t.Errorf("error should name the file, got %q", b)
	}
}

func TestRejectsCrossOrigin(t *testing.T) {
	if rec := post(t, "VulnerableApp.ipa", fixtureIPA(t), "https://evil.example"); rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", rec.Code)
	}
}
