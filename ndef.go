package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"net/url"
	"os"
	"strings"
)

// ndef emits a complete Type 4 NDEF file image (NLEN included) for AES PICC mirroring.
func ndef(args []string) error {
	fs := flag.NewFlagSet("ndef", flag.ContinueOnError)
	base := fs.String("url", "", "absolute HTTPS endpoint, e.g. https://example.com/tag")
	if err := fs.Parse(args); err != nil {
		return err
	}
	u, e := url.Parse(*base)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return errors.New("provide an HTTPS URL without query, fragment, or credentials")
	}
	for _, c := range *base {
		if c < 33 || c > 126 {
			return errors.New("URL must use printable ASCII; percent-encode non-ASCII characters")
		}
	}
	piccName := env("ENC_PICC_DATA_PARAM", "picc_data")
	macName := env("SDMMAC_PARAM", "cmac")
	if piccName == "" || macName == "" || piccName == macName || piccName == "e" {
		return errors.New("invalid or conflicting parameter names")
	}
	text := strings.TrimPrefix(*base, "https://") + "?" + url.QueryEscape(piccName) + "="
	piccOffset := 7 + len(text)
	text += strings.Repeat("0", 32) + "&" + url.QueryEscape(macName) + "="
	macOffset := 7 + len(text)
	text += strings.Repeat("0", 16)
	if len(text)+7 > 256 {
		return errors.New("NDEF exceeds the 256-byte file; shorten the URL")
	}
	record := append([]byte{0xd1, 1, byte(len(text) + 1), 'U', 4}, []byte(text)...)
	file := append([]byte{byte(len(record) >> 8), byte(len(record))}, record...)
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"url_template": "https://" + text, "ndef_file_hex": hex.EncodeToString(file), "picc_data_offset": piccOffset, "sdm_mac_offset": macOffset, "sdm_mac_input_offset": macOffset, "mode": "AES", "sdm_meta_read_key_number": 1, "sdm_file_read_key_number": 2})
}
