package goseal

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

type KeyPair struct {
	Priv [32]byte
	Pub  [32]byte
}

func GenerateKeyPair() (*KeyPair, error) {
	var kp KeyPair
	if _, err := io.ReadFull(rand.Reader, kp.Priv[:]); err != nil {
		return nil, err
	}
	// X25519 clamp
	kp.Priv[0] &= 248
	kp.Priv[31] &= 127
	kp.Priv[31] |= 64

	pub, err := curve25519.X25519(kp.Priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	copy(kp.Pub[:], pub)
	return &kp, nil
}

// Record — то, что кладём в БД (можно хранить как JSON).
type Record struct {
	V int `json:"v"`

	// Для "обёртки" DEK (ECIES-lite)
	EphemeralPub string `json:"epk"`  // b64url(32 bytes)
	NonceDEK     string `json:"ndek"` // b64url(12 bytes)
	WrappedDEK   string `json:"wdek"` // b64url(var)

	// Данные
	NonceData  string `json:"ndata"` // b64url(12 bytes)
	CipherText string `json:"ct"`    // b64url(var)
}

// EncryptForDevice: шифрует plaintext и упаковывает DEK под devicePub.
// aad — опционально: привязка к контексту (например "userID|recordID|v1").
func EncryptForDevice(devicePub [32]byte, plaintext []byte, aad []byte) (*Record, error) {
	// 1) DEK (data encryption key)
	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, fmt.Errorf("rand dek: %w", err)
	}

	// 2) Encrypt data with DEK
	aeadData, err := chacha20poly1305.New(dek)
	if err != nil {
		return nil, fmt.Errorf("aead data: %w", err)
	}
	nonceData := randNonce()
	cipherText := aeadData.Seal(nil, nonceData, plaintext, aad)

	// 3) Wrap DEK using ECIES-lite: ephemeral X25519 + HKDF -> KEK -> AEAD wrap
	epk, epriv, err := genEphemeral()
	if err != nil {
		return nil, err
	}

	shared, err := curve25519.X25519(epriv[:], devicePub[:])
	if err != nil {
		return nil, fmt.Errorf("ecdh: %w", err)
	}
	if isAllZero(shared) {
		return nil, errors.New("bad shared secret")
	}

	kek, err := deriveKEK(shared, epk[:], devicePub[:], aad)
	if err != nil {
		return nil, err
	}

	aeadKEK, err := chacha20poly1305.New(kek)
	if err != nil {
		return nil, fmt.Errorf("aead kek: %w", err)
	}
	nonceDEK := randNonce()
	wrappedDEK := aeadKEK.Seal(nil, nonceDEK, dek, aad)

	// 4) Build record
	rec := &Record{
		V:            1,
		EphemeralPub: b64(epk[:]),
		NonceDEK:     b64(nonceDEK),
		WrappedDEK:   b64(wrappedDEK),
		NonceData:    b64(nonceData),
		CipherText:   b64(cipherText),
	}
	return rec, nil
}

// DecryptForDevice: достаёт DEK приватником устройства, затем расшифровывает данные.
func DecryptForDevice(devicePriv [32]byte, rec *Record, aad []byte) ([]byte, error) {
	if rec == nil || rec.V != 1 {
		return nil, errors.New("unsupported record version")
	}

	epkBytes, err := b64d(rec.EphemeralPub)
	if err != nil || len(epkBytes) != 32 {
		return nil, errors.New("bad epk")
	}
	var epk [32]byte
	copy(epk[:], epkBytes)

	nonceDEK, err := b64d(rec.NonceDEK)
	if err != nil || len(nonceDEK) != chacha20poly1305.NonceSize {
		return nil, errors.New("bad nonceDEK")
	}
	wrappedDEK, err := b64d(rec.WrappedDEK)
	if err != nil {
		return nil, errors.New("bad wrappedDEK")
	}

	nonceData, err := b64d(rec.NonceData)
	if err != nil || len(nonceData) != chacha20poly1305.NonceSize {
		return nil, errors.New("bad nonceData")
	}
	cipherText, err := b64d(rec.CipherText)
	if err != nil {
		return nil, errors.New("bad ciphertext")
	}

	// 1) Re-derive KEK via X25519(devicePriv, epk)
	shared, err := curve25519.X25519(devicePriv[:], epk[:])
	if err != nil {
		return nil, fmt.Errorf("ecdh: %w", err)
	}
	if isAllZero(shared) {
		return nil, errors.New("bad shared secret")
	}

	// devicePub можно хранить отдельно; для контекста HKDF нам он не обязателен,
	// но лучше иметь его. Здесь используем только epk + aad.
	kek, err := deriveKEK(shared, epk[:], nil, aad)
	if err != nil {
		return nil, err
	}

	// 2) Unwrap DEK
	aeadKEK, err := chacha20poly1305.New(kek)
	if err != nil {
		return nil, err
	}
	dek, err := aeadKEK.Open(nil, nonceDEK, wrappedDEK, aad)
	if err != nil {
		return nil, errors.New("cannot unwrap DEK (wrong key or corrupted record)")
	}
	if len(dek) != 32 {
		return nil, errors.New("bad DEK length")
	}

	// 3) Decrypt data
	aeadData, err := chacha20poly1305.New(dek)
	if err != nil {
		return nil, err
	}
	plain, err := aeadData.Open(nil, nonceData, cipherText, aad)
	if err != nil {
		return nil, errors.New("cannot decrypt data (wrong key/aad or corrupted)")
	}

	return plain, nil
}

// --- helpers ---

func randNonce() []byte {
	n := make([]byte, chacha20poly1305.NonceSize)
	_, _ = io.ReadFull(rand.Reader, n)
	return n
}

func genEphemeral() (pub [32]byte, priv [32]byte, err error) {
	if _, err = io.ReadFull(rand.Reader, priv[:]); err != nil {
		return pub, priv, err
	}
	// clamp
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	p, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return pub, priv, err
	}
	copy(pub[:], p)
	return pub, priv, nil
}

// deriveKEK: HKDF(shared, salt=epk||devicePub, info="vaultcrypt v1 kek"||aad) -> 32 bytes
// devicePub может быть nil (если не хочется/негде хранить), но с ним чуть лучше контекст.
func deriveKEK(shared []byte, epk []byte, devicePub []byte, aad []byte) ([]byte, error) {
	salt := make([]byte, 0, 64)
	salt = append(salt, epk...)
	if devicePub != nil {
		salt = append(salt, devicePub...)
	}

	info := make([]byte, 0, 64+len(aad))
	info = append(info, []byte("vaultcrypt v1 kek")...)
	if len(aad) > 0 {
		info = append(info, '|')
		info = append(info, aad...)
	}

	h := hkdf.New(sha256.New, shared, salt, info)
	out := make([]byte, 32)
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
