// Package sdm verifies NTAG 424 DNA Secure Dynamic Messages.
package sdm

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
)

func encrypt(k, x []byte) []byte {
	b, _ := aes.NewCipher(k)
	out := make([]byte, 16)
	b.Encrypt(out, x)
	return out
}
func xor(a, b []byte) []byte {
	o := make([]byte, 16)
	for i := range o {
		o[i] = a[i] ^ b[i]
	}
	return o
}
func double(x []byte) []byte {
	o := make([]byte, 16)
	for i := 0; i < 16; i++ {
		o[i] = x[i] << 1
		if i < 15 {
			o[i] |= x[i+1] >> 7
		}
	}
	if x[0]&128 != 0 {
		o[15] ^= 0x87
	}
	return o
}
func cmacWith(data []byte, f func([]byte) []byte) []byte {
	k1 := double(f(make([]byte, 16)))
	k2 := double(k1)
	y := make([]byte, 16)
	for len(data) > 16 {
		y = f(xor(y, data[:16]))
		data = data[16:]
	}
	last := make([]byte, 16)
	copy(last, data)
	if len(data) == 16 {
		last = xor(last, k1)
	} else {
		last[len(data)] = 128
		last = xor(last, k2)
	}
	return f(xor(y, last))
}

// CMAC returns the RFC 4493 AES-CMAC of data. The key must be a valid AES key;
// verification entry points validate configuration before calling this primitive.
func CMAC(key, data []byte) []byte {
	return cmacWith(data, func(x []byte) []byte { return encrypt(key, x) })
}
func cbcDecrypt(k, iv, data []byte) []byte {
	b, _ := aes.NewCipher(k)
	out := make([]byte, len(data))
	cipher.NewCBCDecrypter(b, iv).CryptBlocks(out, data)
	return out
}

type lrp struct {
	p  [][]byte
	kp []byte
}

// newLRP expands the base key into the plaintext table and updated key selected by
// the NXP LRP construction. It is separate from the Android AES-only provisioner.
func newLRP(k []byte, u int) *lrp {
	l := &lrp{}
	aa := bytes.Repeat([]byte{0xaa}, 16)
	ff := bytes.Repeat([]byte{0x55}, 16)
	h := encrypt(k, ff)
	for i := 0; i < 16; i++ {
		l.p = append(l.p, encrypt(h, aa))
		h = encrypt(h, ff)
	}
	h = encrypt(k, aa)
	for i := 0; i <= u; i++ {
		l.kp = encrypt(h, aa)
		h = encrypt(h, ff)
	}
	return l
}
func (l *lrp) eval(x []byte) []byte {
	y := l.kp
	for _, b := range x {
		y = encrypt(y, l.p[b>>4])
		y = encrypt(y, l.p[b&15])
	}
	return encrypt(y, make([]byte, 16))
}
func (l *lrp) cmac(x []byte) []byte { return cmacWith(x, l.eval) }
func (l *lrp) decrypt(data, r []byte) []byte {
	r = append([]byte(nil), r...)
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += 16 {
		b, _ := aes.NewCipher(l.eval(r))
		b.Decrypt(out[i:i+16], data[i:i+16])
		for j := len(r) - 1; j >= 0; j-- {
			r[j]++
			if r[j] != 0 {
				break
			}
		}
	}
	return out
}
func hashMAC(k, x []byte, full bool) []byte {
	h := hmac.New(sha256.New, k)
	h.Write(x)
	out := h.Sum(nil)
	if !full {
		out = out[:16]
	}
	return out
}
func pbkdf(k, s []byte) []byte {
	// Compatibility requires a binary password and 5,000 HMAC-SHA512 rounds.
	// Replacing this with a string-oriented password helper changes deployed keys.
	h := hmac.New(sha512.New, k)
	h.Write(s)
	h.Write([]byte{0, 0, 0, 1})
	u := h.Sum(nil)
	out := append([]byte(nil), u...)
	for i := 1; i < 5000; i++ {
		h.Reset()
		h.Write(u)
		u = h.Sum(nil)
		for j := range out {
			out[j] ^= u[j]
		}
	}
	return out[:16]
}

// DeriveKey matches upstream's legacy and standard diversification, including its factory-key shortcut.
// Callers must supply a validated mode, a master secret, and a seven-byte UID for diversified keys.
func DeriveKey(master, uid []byte, n byte, mode string, undiversified bool) []byte {
	if bytes.Equal(master, make([]byte, 16)) {
		return make([]byte, 16)
	}
	if mode == "legacy" {
		salt := append([]byte("key"), uid...)
		if undiversified {
			salt = []byte("key_no_uid")
		}
		return pbkdf(master, append(salt, n))
	}
	if undiversified {
		return hashMAC(master, []byte("PICCDataKey"), false)
	}
	slot := hashMAC(master, append([]byte("SlotMasterKey"), n), false)
	div := hashMAC(hashMAC(master, []byte("DivBaseKey"), true), uid, false)
	return CMAC(slot, append([]byte{1}, div...))
}
