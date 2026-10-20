package main

import (
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/v0rtal/nfc-sdm-backend-go/sdm"
)

func TestTagTamperBadges(t *testing.T) {
	h := handler(sdm.Verifier{Master: make([]byte, 16), DeriveMode: "legacy", MACParam: "cmac"})
	for _, test := range []struct{ query, want string }{
		{"picc_data=EF963FF7828658A599F3041510671E88&cmac=94EED9EE65337086", `(?s)<span\s+class="badge badge-green"\s+title="[^"]*"\s*>\s*Authentic\s*</span\s*>`},
		{"picc_data=EF963FF7828658A599F3041510671E88&cmac=0000000000000000", `(?s)<span\s+class="badge badge-red"\s+title="[^"]*"\s*>\s*Counterfeit\s*</span\s*>`},
		{"", "Authenticity: Unknown"},
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/tagtt?"+test.query, nil))
		if !regexp.MustCompile(test.want).MatchString(w.Body.String()) || strings.Contains(w.Body.String(), "A valid signature authenticates") {
			t.Fatal(w.Body.String())
		}
	}
	for _, test := range []struct{ status, label, color string }{
		{"secure", "Tamper: Good", "badge-green"}, {"tampered_closed", "Tamper: Tampered", "badge-red"}, {"tampered_open", "Tamper: Tampered", "badge-red"}, {"not_initialized", "Tamper: Not initialized", "badge-neutral"}, {"unknown", "Tamper: Unknown", "badge-neutral"},
	} {
		label, color := tamperBadge(test.status, true)
		if label != test.label || color != test.color {
			t.Fatal(label, color)
		}
	}
	if _, color := tamperBadge("secure", false); color != "badge-neutral" {
		t.Fatal("Unverified tamper shown as secure")
	}
}
