package main

import (
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/v0rtal/nfc-sdm-backend-go/sdm"
)

// These public vectors are emitted by android/tools/GenerateInteropVectors.java using
// the writer's actual NDEF placeholder and Java crypto, then validated by Go.
func TestAndroidWriterMessages(t *testing.T) {
	data, err := os.ReadFile("testdata/android-sdm.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Mode, Master, URL, UID, Plaintext string
		Counter                           uint32
	}
	if err = json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		t.Run(c.Mode, func(t *testing.T) {
			master, err := hex.DecodeString(c.Master)
			if err != nil {
				t.Fatal(err)
			}
			u, err := url.Parse(c.URL)
			if err != nil {
				t.Fatal(err)
			}
			v := sdm.Verifier{Master: master, DeriveMode: c.Mode, MACParam: "cmac"}
			result, err := verifyQuery(v, u.Query(), false, true)
			if err != nil {
				t.Fatal(err)
			}
			if result.UID != c.UID || result.ReadCounter == nil || *result.ReadCounter != c.Counter || result.TamperStatus != "secure" || result.FileData == nil || !strings.EqualFold(*result.FileData, c.Plaintext) {
				t.Fatalf("unexpected Android message result: %+v", result)
			}
		})
	}
}
