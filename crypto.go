package goseal

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// EncryptForDevice encrypts plaintext and wraps DEK for devicePub.
// It returns a token string in the format: goseal.v1.<header>.<payload>
func EncryptForDevice(devicePub [keySize]byte, plaintext, aad []byte, kid string, aadHint string) (string, error) {
	dek := make([]byte, keySize)
	if _, err := randBytes(dek); err != nil {
		return "", err
	}

	aeadData, err := chacha20poly1305.New(dek)
	if err != nil {
		return "", fmt.Errorf("aead data: %w", err)
	}
	nonceData, err := randNonce()
	if err != nil {
		return "", err
	}
	cipherText := aeadData.Seal(nil, nonceData, plaintext, aad)

	epk, epriv, err := genEphemeral()
	if err != nil {
		return "", err
	}

	shared, err := curve25519.X25519(epriv[:], devicePub[:])
	if err != nil {
		return "", fmt.Errorf("ecdh: %w", err)
	}
	if isAllZero(shared) {
		return "", fmt.Errorf("%w: bad shared secret", ErrInvalidKey)
	}

	kek, err := deriveKEK(shared, epk[:], devicePub[:], aad)
	if err != nil {
		return "", err
	}

	aeadKEK, err := chacha20poly1305.New(kek)
	if err != nil {
		return "", fmt.Errorf("aead kek: %w", err)
	}
	nonceDEK, err := randNonce()
	if err != nil {
		return "", err
	}
	wrappedDEK := aeadKEK.Seal(nil, nonceDEK, dek, aad)

	// Build Token
	header := Header{
		V:       recordVersion,
		Alg:     Alg,
		KID:     kid,
		AADHint: aadHint,
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("header marshal: %w", err)
	}

	// Payload: epk(32) + ndek(12) + wdek(var) + ndata(12) + ct(var)
	var payload bytes.Buffer
	payload.Grow(len(epk) + len(nonceDEK) + len(wrappedDEK) + len(nonceData) + len(cipherText))
	payload.Write(epk[:])
	payload.Write(nonceDEK)
	payload.Write(wrappedDEK)
	payload.Write(nonceData)
	payload.Write(cipherText)

	return fmt.Sprintf("goseal.v%d.%s.%s", recordVersion, b64(headerJSON), b64(payload.Bytes())), nil
}

// DecryptForDevice unwraps DEK with devicePriv and decrypts payload from the token.
func DecryptForDevice(devicePriv [keySize]byte, token string, aad []byte) ([]byte, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 4 {
		return nil, fmt.Errorf("%w: malformed token", ErrInvalidToken)
	}
	if parts[0] != "goseal" {
		return nil, fmt.Errorf("%w: invalid prefix", ErrInvalidToken)
	}
	if parts[1] != fmt.Sprintf("v%d", recordVersion) {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedRecordVersion, parts[1])
	}

	// Decode Header
	headerJSON, err := b64d(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: bad header encoding", ErrInvalidToken)
	}
	var header Header
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("%w: bad header json", ErrInvalidToken)
	}
	if header.V != recordVersion {
		return nil, fmt.Errorf("%w: version mismatch in header", ErrUnsupportedRecordVersion)
	}
	if header.Alg != Alg {
		return nil, fmt.Errorf("%w: unsupported alg", ErrInvalidToken)
	}

	// Decode Payload
	payload, err := b64d(parts[3])
	if err != nil {
		return nil, fmt.Errorf("%w: bad payload encoding", ErrInvalidToken)
	}

	// Payload struct: epk(32) + ndek(12) + wdek(48) + ndata(12) + ct(var)
	minLen := keySize + nonceSize + (keySize + chacha20poly1305.Overhead) + nonceSize
	if len(payload) < minLen {
		return nil, fmt.Errorf("%w: payload too short", ErrInvalidToken)
	}

	offset := 0

	epkBytes := payload[offset : offset+keySize]
	offset += keySize

	nonceDEK := payload[offset : offset+nonceSize]
	offset += nonceSize

	wdekLen := keySize + chacha20poly1305.Overhead
	wrappedDEK := payload[offset : offset+wdekLen]
	offset += wdekLen

	nonceData := payload[offset : offset+nonceSize]
	offset += nonceSize

	cipherText := payload[offset:]

	var epk [keySize]byte
	copy(epk[:], epkBytes)

	scalar := devicePriv
	clampScalar(&scalar)

	devicePub, err := publicFromPrivate(scalar)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	shared, err := curve25519.X25519(scalar[:], epk[:])
	if err != nil {
		return nil, fmt.Errorf("ecdh: %w", err)
	}
	if isAllZero(shared) {
		return nil, fmt.Errorf("%w: bad shared secret", ErrInvalidKey)
	}

	kek, err := deriveKEK(shared, epk[:], devicePub[:], aad)
	if err != nil {
		return nil, err
	}

	aeadKEK, err := chacha20poly1305.New(kek)
	if err != nil {
		return nil, err
	}
	dek, err := aeadKEK.Open(nil, nonceDEK, wrappedDEK, aad)
	if err != nil {
		return nil, errors.Join(ErrKeyUnwrapFailed, err)
	}
	if len(dek) != keySize {
		return nil, fmt.Errorf("%w: bad DEK length", ErrInvalidToken)
	}

	aeadData, err := chacha20poly1305.New(dek)
	if err != nil {
		return nil, err
	}
	plain, err := aeadData.Open(nil, nonceData, cipherText, aad)
	if err != nil {
		return nil, errors.Join(ErrDataDecryptFailed, err)
	}

	return plain, nil
}
