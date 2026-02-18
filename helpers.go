package goseal

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

func randRead(dst []byte) (int, error) {
	return io.ReadFull(rand.Reader, dst)
}

func randNonce() ([]byte, error) {
	n := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, n); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRandomSource, err)
	}
	return n, nil
}

func deriveKEK(shared []byte, epk []byte, devicePub []byte, aad []byte) ([]byte, error) {
	salt := make([]byte, 0, len(epk)+len(devicePub))
	salt = append(salt, epk...)
	salt = append(salt, devicePub...)

	info := make([]byte, 0, len(kekInfoLabel)+1+len(aad))
	info = append(info, []byte(kekInfoLabel)...)
	if len(aad) > 0 {
		info = append(info, '|')
		info = append(info, aad...)
	}

	h := hkdf.New(sha256.New, shared, salt, info)
	out := make([]byte, keySize)
	if _, err := io.ReadFull(h, out); err != nil {
		return nil, err
	}
	return out, nil
}

func isAllZero(b []byte) bool {
	var x byte
	for _, v := range b {
		x |= v
	}
	return x == 0
}

func b64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func b64d(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func randBytes(dst []byte) (int, error) {
	n, err := randRead(dst)
	if err != nil {
		return n, fmt.Errorf("%w: %v", ErrRandomSource, err)
	}
	return n, nil
}
