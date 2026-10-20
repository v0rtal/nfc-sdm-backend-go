package sdm

import (
	"crypto/hmac"
	"encoding/hex"
	"errors"
	"strings"
)

var ErrInvalid = errors.New("invalid message or signature")

type Result struct {
	UID          string  `json:"uid"`
	ReadCounter  *uint32 `json:"read_ctr"`
	FileData     *string `json:"file_data,omitempty"`
	TamperStatus string  `json:"tt_status,omitempty"`
	Mode         string  `json:"enc_mode"`
}
type Verifier struct {
	Master     []byte
	DeriveMode string
	MACParam   string
	RequireLRP bool
}

// validConfiguration keeps invalid library configuration away from AES primitives,
// whose low-level APIs panic on a bad key size. HTTP startup validates this too.
func (v Verifier) validConfiguration() bool {
	return (len(v.Master) == 16 || len(v.Master) == 32) && (v.DeriveMode == "legacy" || v.DeriveMode == "standard")
}

func vector(prefix, picc []byte, lrpMode bool) []byte {
	out := append(append([]byte(nil), prefix...), picc...)
	if lrpMode {
		for (len(out)+2)%16 != 0 {
			out = append(out, 0)
		}
		return append(out, 0x1e, 0xe1)
	}
	for len(out)%16 != 0 {
		out = append(out, 0)
	}
	return out
}
func session(key, picc []byte, mode string, enc bool) []byte {
	if mode == "LRP" {
		return newLRP(key, 0).cmac(vector([]byte{0, 1, 0, 128}, picc, true))
	}
	prefix := []byte{0x3c, 0xc3, 0, 1, 0, 128}
	if enc {
		prefix[0], prefix[1] = 0xc3, 0x3c
	}
	return CMAC(key, vector(prefix, picc, false))
}
func mac(key, picc, file []byte, mode, name string, bulk bool) []byte {
	var input []byte
	if len(file) > 0 {
		input = []byte(strings.ToUpper(hex.EncodeToString(file)))
		if !bulk && name != "" {
			input = append(input, []byte("&"+name+"=")...)
		}
	}
	k := session(key, picc, mode, false)
	var full []byte
	if mode == "LRP" {
		full = newLRP(k, 0).cmac(input)
	} else {
		full = CMAC(k, input)
	}
	out := make([]byte, 8)
	for i := range out {
		out[i] = full[2*i+1]
	}
	return out
}
func (v Verifier) Plain(uid, ctr, signature []byte) (Result, error) {
	if !v.validConfiguration() || len(uid) != 7 || len(ctr) != 3 || len(signature) != 8 || v.RequireLRP {
		return Result{}, ErrInvalid
	}
	picc := append(append([]byte(nil), uid...), ctr[2], ctr[1], ctr[0])
	key := DeriveKey(v.Master, uid, 2, v.DeriveMode, false)
	if !hmac.Equal(signature, mac(key, picc, nil, "AES", v.MACParam, false)) {
		return Result{}, ErrInvalid
	}
	n := uint32(ctr[0])<<16 | uint32(ctr[1])<<8 | uint32(ctr[2])
	return Result{UID: strings.ToUpper(hex.EncodeToString(uid)), ReadCounter: &n, Mode: "AES"}, nil
}
func (v Verifier) Encrypted(piccEnc, file, signature []byte, bulk, tamper bool) (Result, error) {
	if !v.validConfiguration() || (len(piccEnc) != 16 && len(piccEnc) != 24) || len(signature) != 8 || len(file)%16 != 0 {
		return Result{}, ErrInvalid
	}
	mode := "AES"
	if len(piccEnc) == 24 {
		mode = "LRP"
	}
	if v.RequireLRP && mode != "LRP" {
		return Result{}, ErrInvalid
	}
	meta := DeriveKey(v.Master, nil, 1, v.DeriveMode, true)
	var pt []byte
	if mode == "AES" {
		pt = cbcDecrypt(meta, make([]byte, 16), piccEnc)
	} else {
		pt = newLRP(meta, 0).decrypt(piccEnc[8:], piccEnc[:8])
	}
	if pt[0]&0x8f != 0x87 { // Perform MAC work even for an unsupported decrypted UID header.
		key := DeriveKey(v.Master, make([]byte, 7), 2, v.DeriveMode, false)
		mac(key, make([]byte, 10), file, mode, v.MACParam, bulk)
		return Result{}, ErrInvalid
	}
	uid := pt[1:8]
	picc := pt[1:8]
	var ctr []byte
	var n *uint32
	if pt[0]&0x40 != 0 {
		ctr = pt[8:11]
		picc = pt[1:11]
		num := uint32(ctr[0]) | uint32(ctr[1])<<8 | uint32(ctr[2])<<16
		n = &num
	}
	key := DeriveKey(v.Master, uid, 2, v.DeriveMode, false)
	if !hmac.Equal(signature, mac(key, picc, file, mode, v.MACParam, bulk)) {
		return Result{}, ErrInvalid
	}
	res := Result{UID: strings.ToUpper(hex.EncodeToString(uid)), ReadCounter: n, Mode: mode}
	// Encrypted endpoints always include file_data and tt_status, matching upstream.
	empty := ""
	res.TamperStatus = empty
	if len(file) > 0 {
		if ctr == nil {
			return Result{}, ErrInvalid
		}
		k := session(key, picc, mode, true)
		var data []byte
		if mode == "AES" {
			ivInput := make([]byte, 16)
			copy(ivInput, ctr)
			data = cbcDecrypt(k, encrypt(k, ivInput), file)
		} else {
			data = newLRP(k, 1).decrypt(file, append(append([]byte(nil), ctr...), 0, 0, 0))
		}
		if bulk && (len(data) < 3 || int(data[2])+3 > len(data)) {
			return Result{}, ErrInvalid
		}
		encoded := hex.EncodeToString(data)
		res.FileData = &encoded
		if tamper {
			res.TamperStatus = map[string]string{"CC": "secure", "OC": "tampered_closed", "OO": "tampered_open", "II": "not_initialized", "NT": "not_supported"}[string(data[:2])]
			if res.TamperStatus == "" {
				res.TamperStatus = "unknown"
			}
		}
	}
	return res, nil
}
