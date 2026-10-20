package main

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/v0rtal/nfc-sdm-backend-go/sdm"
)

func TestHTTP(t *testing.T) {
	h := handler(sdm.Verifier{Master: make([]byte, 16), DeriveMode: "legacy", MACParam: "cmac"})
	for _, c := range []struct {
		path   string
		status int
	}{
		{"/api/tag?picc_data=EF963FF7828658A599F3041510671E88&cmac=94EED9EE65337086", 200},
		{"/api/tag?e=EF963FF7828658A599F3041510671E8894EED9EE65337086", 200},
		{"/api/tagpt?uid=041E3C8A2D6B80&ctr=000006&cmac=4B00064004B0B3D3", 200},
		{"/api/tag?e=0000000000000000", 400},
		{"/api/tag?picc_data=zz&cmac=00", 400},
		{"/api/tag?picc_data=00&picc_data=01&cmac=00", 400},
		{"/api/tagpt", 400}, {"/api/tag", 400}, {"/missing", 404},
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", c.path, nil))
		if w.Code != c.status {
			t.Fatalf("%s: %d %s", c.path, w.Code, w.Body.String())
		}
	}
}

func TestHTMLWithoutDatabase(t *testing.T) {
	h := handler(sdm.Verifier{Master: make([]byte, 16), DeriveMode: "legacy", MACParam: "cmac"})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/tag?picc_data=EF963FF7828658A599F3041510671E88&cmac=94EED9EE65337086", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Database tracking is disabled") {
		t.Fatal(w.Code, w.Body.String())
	}
}
