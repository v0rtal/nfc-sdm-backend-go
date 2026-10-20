package sdm

import "testing"

func TestInvalidVerifierConfigurationDoesNotPanic(t *testing.T) {
	for _, verifier := range []Verifier{{}, {Master: make([]byte, 15), DeriveMode: "legacy"}, {Master: make([]byte, 16), DeriveMode: "typo"}} {
		if _, err := verifier.Plain(make([]byte, 7), make([]byte, 3), make([]byte, 8)); err == nil {
			t.Fatal("Invalid verifier accepted")
		}
		if _, err := verifier.Encrypted(make([]byte, 16), nil, make([]byte, 8), false, false); err == nil {
			t.Fatal("Invalid verifier accepted")
		}
	}
}
