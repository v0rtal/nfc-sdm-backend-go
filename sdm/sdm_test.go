package sdm

import (
	"encoding/hex"
	"testing"
)

func unhex(s string) []byte {
	b, e := hex.DecodeString(s)
	if e != nil {
		panic(e)
	}
	return b
}
func TestUpstreamVectors(t *testing.T) {
	cases := []struct {
		name, picc, file, mac, uid, plaintext, mode string
		counter                                     uint32
	}{
		{"AES", "EF963FF7828658A599F3041510671E88", "", "94EED9EE65337086", "04DE5F1EACC040", "", "AES", 61},
		{"AES file", "FD91EC264309878BE6345CBE53BADF40", "CEE9A53E3E463EF1F459635736738962", "ECC1E7F6C6C73BF6", "04958CAA5C5E80", "xxxxxxxxxxxxxxxx", "AES", 8},
		{"LRP file", "07D9CA2545881D4BFDD920BE1603268C0714420DD893A497", "D6E921C47DB4C17C56F979F81559BB83", "F9481AC7D855BDB6", "049B112A2F7080", "NTXXb7dz3PsYYBlU", "LRP", 4},
		{"LRP", "1FCBE61B3E4CAD980CBFDD333E7A4AC4A579569BAFD22C5F", "", "4231608BA7B02BA9", "04940E2A2F7080", "", "LRP", 3},
	}
	v := Verifier{Master: make([]byte, 16), DeriveMode: "legacy", MACParam: "cmac"}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, e := v.Encrypted(unhex(c.picc), unhex(c.file), unhex(c.mac), false, false)
			if e != nil {
				t.Fatal(e)
			}
			if r.UID != c.uid || r.ReadCounter == nil || *r.ReadCounter != c.counter || r.Mode != c.mode {
				t.Fatalf("unexpected result: %+v", r)
			}
			if c.plaintext != "" && (r.FileData == nil || *r.FileData != hex.EncodeToString([]byte(c.plaintext))) {
				t.Fatalf("wrong file: %+v", r)
			}
			bad := unhex(c.mac)
			bad[0] ^= 1
			if _, e = v.Encrypted(unhex(c.picc), unhex(c.file), bad, false, false); e == nil {
				t.Fatal("accepted invalid MAC")
			}
		})
	}
	if _, e := v.Plain(unhex("041E3C8A2D6B80"), unhex("000006"), unhex("4B00064004B0B3D3")); e != nil {
		t.Fatal(e)
	}
}
func TestStandardDiversification(t *testing.T) {
	m := unhex("C9EB67DF090AFF47C3B19A2516680B9D")
	for _, c := range []struct {
		uid   string
		n     byte
		undiv bool
		want  string
	}{{"", 1, true, "a13086f194d7bdfd108dd11716ea2bdf"}, {"010203040506AB", 1, false, "f18cdd9389d47ae7ab381e80e5ab6fe3"}, {"03030303030303", 2, false, "85f7cc459a5b4b2f5d1a5019ded61c88"}} {
		if got := hex.EncodeToString(DeriveKey(m, unhex(c.uid), c.n, "standard", c.undiv)); got != c.want {
			t.Fatalf("got %s want %s", got, c.want)
		}
	}
	v := Verifier{Master: unhex("47BBB68AFA73F31310BEEFCE5DDA692DBAD671A03FEAD5A9BBDBCF3CD6D4C521"), DeriveMode: "standard", MACParam: "cmac"}
	r, e := v.Encrypted(unhex("4F5B914723915D456C038FE658686CD5"), unhex("5CE7DCDEA93F5DA7AAA0AADC97485ABF"), unhex("FFCD8DE82AD05289"), true, true)
	if e != nil || r.UID != "047D5F2AAA6180" || r.TamperStatus != "secure" {
		t.Fatalf("%+v %v", r, e)
	}
}
func TestCMACRFC4493(t *testing.T) {
	k := unhex("2b7e151628aed2a6abf7158809cf4f3c")
	if got := hex.EncodeToString(CMAC(k, nil)); got != "bb1d6929e95937287fa37d129b756746" {
		t.Fatal(got)
	}
}

func TestLRPPolicyAndLengths(t *testing.T) {
	v := Verifier{Master: make([]byte, 16), DeriveMode: "legacy", MACParam: "cmac", RequireLRP: true}
	if _, e := v.Encrypted(unhex("EF963FF7828658A599F3041510671E88"), nil, unhex("94EED9EE65337086"), false, false); e == nil {
		t.Fatal("accepted AES")
	}
	if _, e := v.Encrypted(unhex("1FCBE61B3E4CAD980CBFDD333E7A4AC4A579569BAFD22C5F"), nil, unhex("4231608BA7B02BA9"), false, false); e != nil {
		t.Fatal(e)
	}
	if _, e := v.Plain(make([]byte, 7), make([]byte, 3), make([]byte, 8)); e == nil {
		t.Fatal("accepted plaintext")
	}
}
func FuzzEncrypted(f *testing.F) {
	f.Add([]byte{1}, []byte{}, []byte{})
	f.Add(unhex("EF963FF7828658A599F3041510671E88"), []byte{}, unhex("94EED9EE65337086"))
	v := Verifier{Master: make([]byte, 16), DeriveMode: "standard", MACParam: "cmac"}
	f.Fuzz(func(t *testing.T, picc, file, mac []byte) { v.Encrypted(picc, file, mac, false, true) })
}
