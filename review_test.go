package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/v0rtal/nfc-sdm-backend-go/sdm"
)

func TestExplicitMasterRequired(t *testing.T) {
	t.Setenv("MASTER_KEY", "")
	if _, err := configuration(); err == nil {
		t.Fatal("Missing master accepted")
	}
	t.Setenv("MASTER_KEY", strings.Repeat("0", 32))
	t.Setenv("ALLOW_FACTORY_KEYS", "0")
	if _, err := configuration(); err == nil {
		t.Fatal("Implicit factory key accepted")
	}
	t.Setenv("ALLOW_FACTORY_KEYS", "1")
	if _, err := configuration(); err != nil {
		t.Fatal(err)
	}
}

func TestStandaloneAPKPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "writer.apk")
	payload := []byte("PK\x03\x04test-public-artifact")
	if err := os.WriteFile(path, payload, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("APK_PATH", path)
	h := handler(sdm.Verifier{Master: make([]byte, 16), DeriveMode: "legacy", MACParam: "cmac"})
	for _, method := range []string{"GET", "HEAD", "POST"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(method, "/downloads/NFC-Tag-Writer-debug.apk", nil))
		want := http.StatusOK
		if method == "POST" {
			want = 405
		}
		if w.Code != want {
			t.Fatal(method, w.Code)
		}
		if method == "GET" && string(w.Body.Bytes()) != string(payload) {
			t.Fatal("Wrong APK file")
		}
	}
}
