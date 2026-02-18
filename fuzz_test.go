//go:build go1.18

package goseal

import (
	"bytes"
	"testing"
)

func FuzzEncryptDecryptRoundTrip(f *testing.F) {
	kp, err := GenerateKeyPair()
	if err != nil {
		f.Fatalf("GenerateKeyPair: %v", err)
	}

	f.Add([]byte("hello"), []byte("aad"))
	f.Add([]byte(""), []byte(""))
	f.Add([]byte{0x00, 0x01, 0x02}, []byte("ctx"))

	f.Fuzz(func(t *testing.T, plaintext []byte, aad []byte) {
		token, err := EncryptForDevice(kp.Pub, plaintext, aad, "fuzz-kid", "")
		if err != nil {
			t.Fatalf("EncryptForDevice: %v", err)
		}

		got, err := DecryptForDevice(kp.Priv, token, aad)
		if err != nil {
			t.Fatalf("DecryptForDevice: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("plaintext mismatch")
		}
	})
}
