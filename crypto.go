package goseal

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// Encrypt encrypts plaintext and wraps DEK for devicePub.
// It returns a token string in the format: goseal.v1.<header>.<payload>
func Encrypt(devicePub [keySize]byte, plaintext, aad []byte, kid string, aadHint string) (string, error) {
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

	// Payload
	p := payload{
		EPK:        b64(epk[:]),
		NonceDEK:   b64(nonceDEK),
		WrappedDEK: b64(wrappedDEK),
		NonceData:  b64(nonceData),
		CipherText: b64(cipherText),
	}
	payloadJSON, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("payload marshal: %w", err)
	}

	return fmt.Sprintf("goseal.v%d.%s.%s", recordVersion, b64(headerJSON), b64(payloadJSON)), nil
}

// Decrypt unwraps DEK with devicePriv and decrypts payload from the token.
func Decrypt(devicePriv [keySize]byte, token string, aad []byte) ([]byte, error) {
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
	payloadJSON, err := b64d(parts[3])
	if err != nil {
		return nil, fmt.Errorf("%w: bad payload encoding", ErrInvalidToken)
	}
	var p payload
	if err := json.Unmarshal(payloadJSON, &p); err != nil {
		return nil, fmt.Errorf("%w: bad payload json", ErrInvalidToken)
	}

	epkBytes, err := b64d(p.EPK)
	if err != nil || len(epkBytes) != keySize {
		return nil, fmt.Errorf("%w: bad epk", ErrInvalidToken)
	}

	nonceDEK, err := b64d(p.NonceDEK)
	if err != nil || len(nonceDEK) != nonceSize {
		return nil, fmt.Errorf("%w: bad nonceDEK", ErrInvalidToken)
	}

	wrappedDEK, err := b64d(p.WrappedDEK)
	if err != nil {
		return nil, fmt.Errorf("%w: bad wrappedDEK", ErrInvalidToken)
	}

	nonceData, err := b64d(p.NonceData)
	if err != nil || len(nonceData) != nonceSize {
		return nil, fmt.Errorf("%w: bad nonceData", ErrInvalidToken)
	}

	cipherText, err := b64d(p.CipherText)
	if err != nil {
		return nil, fmt.Errorf("%w: bad ciphertext", ErrInvalidToken)
	}

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
