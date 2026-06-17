package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeEnvelope writes the standard MiniCA success envelope with the given data.
func writeEnvelope(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"data":    data,
		"error":   null{},
	})
}

type null struct{}

func (null) MarshalJSON() ([]byte, error) { return []byte("null"), nil }

func TestFindCertIDByCNFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/cas/ca1/certs_by_cn" && r.URL.Query().Get("cn") == "web.example.com" {
			writeEnvelope(w, map[string]any{"id": "abc123"})
			return
		}
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newClient("admin", "pass", false)
	id, found, err := c.findCertIDByCN(srv.URL, "ca1", "web.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !found {
		t.Fatalf("expected found=true")
	}
	if id != "abc123" {
		t.Fatalf("expected id abc123, got %q", id)
	}
}

func TestFindCertIDByCNNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": false,
			"data":    nil,
			"error":   map[string]any{"code": "not_found", "message": "nope", "status": 404},
		})
	}))
	defer srv.Close()

	c := newClient("admin", "pass", false)
	id, found, err := c.findCertIDByCN(srv.URL, "ca1", "missing.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Fatalf("expected found=false")
	}
	if id != "" {
		t.Fatalf("expected empty id, got %q", id)
	}
}

func TestFindCertIDByCNServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newClient("admin", "pass", false)
	if _, _, err := c.findCertIDByCN(srv.URL, "ca1", "web.example.com"); err == nil {
		t.Fatalf("expected error on 500")
	}
}

// reuseServer serves the lookup as a hit plus all download endpoints, and
// records whether a create PUT was ever received.
func reuseServer(t *testing.T, sawCreate *bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/cas/ca1/certs_by_cn":
			writeEnvelope(w, map[string]any{"id": "abc123"})
		case r.Method == http.MethodPut && r.URL.Path == "/api/cas/ca1/certs":
			*sawCreate = true
			writeEnvelope(w, map[string]any{"id": "should-not-happen"})
		case r.URL.Path == "/download/cert/ca1/abc123/cert":
			fmt.Fprint(w, "CERT-PEM")
		case r.URL.Path == "/download/cert/ca1/abc123/key":
			fmt.Fprint(w, "KEY-PEM")
		case r.URL.Path == "/download/cert/ca1/abc123/pkcs12":
			fmt.Fprint(w, "P12-BYTES")
		case r.URL.Path == "/download/cert/ca1/abc123/password":
			fmt.Fprint(w, "P12-PASSWORD")
		case r.URL.Path == "/download/ca/ca1/cert":
			fmt.Fprint(w, "CA-PEM")
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusInternalServerError)
		}
	}))
}

func TestRunCertReusesExistingCert(t *testing.T) {
	sawCreate := false
	srv := reuseServer(t, &sawCreate)
	defer srv.Close()

	outDir := t.TempDir()
	// Isolate from any real ~/.minica.
	t.Setenv("MINICA_CONFIG", filepath.Join(t.TempDir(), "no-such-file"))
	t.Setenv("MINICA_URL", srv.URL)
	t.Setenv("MINICA_USER", "admin")
	t.Setenv("MINICA_PASSWORD", "pass")
	t.Setenv("MINICA_CA_ID", "ca1")
	t.Setenv("MINICA_OUT_DIR", outDir)

	err := runCert([]string{"-y", "--cn", "web.example.com", "--name", "reused"})
	if err != nil {
		t.Fatalf("runCert returned error: %v", err)
	}
	if sawCreate {
		t.Fatalf("create PUT must not be called when the cert already exists")
	}

	want := map[string]string{
		"reused.pem":          "CERT-PEM",
		"reused.key":          "KEY-PEM",
		"reused.p12":          "P12-BYTES",
		"reused.p12.password": "P12-PASSWORD",
		"CA.pem":              "CA-PEM",
	}
	for name, content := range want {
		got, err := os.ReadFile(filepath.Join(outDir, name))
		if err != nil {
			t.Fatalf("expected file %s: %v", name, err)
		}
		if strings.TrimSpace(string(got)) != content {
			t.Fatalf("file %s: expected %q, got %q", name, content, string(got))
		}
	}
}

func TestRunCertCreatesWhenAbsent(t *testing.T) {
	sawCreate := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/cas/ca1/certs_by_cn":
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": false, "data": nil,
				"error": map[string]any{"code": "not_found", "message": "nope", "status": 404},
			})
		case r.Method == http.MethodPut && r.URL.Path == "/api/cas/ca1/certs":
			sawCreate = true
			writeEnvelope(w, map[string]any{"id": "new123", "cert_pem": "NEW-CERT", "key_pem": "NEW-KEY"})
		case r.URL.Path == "/download/cert/ca1/new123/pkcs12":
			fmt.Fprint(w, "P12-BYTES")
		case r.URL.Path == "/download/cert/ca1/new123/password":
			fmt.Fprint(w, "P12-PASSWORD")
		case r.URL.Path == "/download/ca/ca1/cert":
			fmt.Fprint(w, "CA-PEM")
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	outDir := t.TempDir()
	t.Setenv("MINICA_CONFIG", filepath.Join(t.TempDir(), "no-such-file"))
	t.Setenv("MINICA_URL", srv.URL)
	t.Setenv("MINICA_USER", "admin")
	t.Setenv("MINICA_PASSWORD", "pass")
	t.Setenv("MINICA_CA_ID", "ca1")
	t.Setenv("MINICA_OUT_DIR", outDir)

	err := runCert([]string{"-y", "--cn", "new.example.com", "--name", "fresh"})
	if err != nil {
		t.Fatalf("runCert returned error: %v", err)
	}
	if !sawCreate {
		t.Fatalf("create PUT must be called when the cert does not exist")
	}
	got, err := os.ReadFile(filepath.Join(outDir, "fresh.pem"))
	if err != nil || strings.TrimSpace(string(got)) != "NEW-CERT" {
		t.Fatalf("expected fresh.pem with NEW-CERT, got %q err=%v", string(got), err)
	}
}
