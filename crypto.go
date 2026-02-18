package goseal

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// EncryptForDevice encrypts plaintext and wraps DEK for devicePub.
// aad optionally binds ciphertext to external context.
func EncryptForDevice(devicePub [keySize]byte, plaintext []byte, aad []byte) (*Record, error) {
	dek := make([]byte, keySize)
	if _, err := randBytes(dek); err != nil {
		return nil, err
	}

	aeadData, err := chacha20poly1305.New(dek)
	if err != nil {
		return nil, fmt.Errorf("aead data: %w", err)
	}
	nonceData, err := randNonce()
	if err != nil {
		return nil, err
	}
	cipherText := aeadData.Seal(nil, nonceData, plaintext, aad)

	epk, epriv, err := genEphemeral()
	if err != nil {
		return nil, err
	}

	shared, err := curve25519.X25519(epriv[:], devicePub[:])
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
		return nil, fmt.Errorf("aead kek: %w", err)
	}
	nonceDEK, err := randNonce()
	if err != nil {
		return nil, err
	}
	wrappedDEK := aeadKEK.Seal(nil, nonceDEK, dek, aad)

	return &Record{
		V:            recordVersion,
		EphemeralPub: b64(epk[:]),
		NonceDEK:     b64(nonceDEK),
		WrappedDEK:   b64(wrappedDEK),
		NonceData:    b64(nonceData),
		CipherText:   b64(cipherText),
	}, nil
}

// DecryptForDevice unwraps DEK with devicePriv and decrypts payload.
func DecryptForDevice(devicePriv [keySize]byte, rec *Record, aad []byte) ([]byte, error) {
	if rec == nil {
		return nil, fmt.Errorf("%w: nil record", ErrInvalidRecord)
	}
	if rec.V != recordVersion {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedRecordVersion, rec.V)
	}

	epkBytes, err := b64d(rec.EphemeralPub)
	if err != nil || len(epkBytes) != keySize {
		return nil, fmt.Errorf("%w: bad epk", ErrInvalidRecord)
	}
	var epk [keySize]byte
	copy(epk[:], epkBytes)

	nonceDEK, err := b64d(rec.NonceDEK)
	if err != nil || len(nonceDEK) != nonceSize {
		return nil, fmt.Errorf("%w: bad nonceDEK", ErrInvalidRecord)
	}
	wrappedDEK, err := b64d(rec.WrappedDEK)
	if err != nil {
		return nil, fmt.Errorf("%w: bad wrappedDEK", ErrInvalidRecord)
	}

	nonceData, err := b64d(rec.NonceData)
	if err != nil || len(nonceData) != nonceSize {
		return nil, fmt.Errorf("%w: bad nonceData", ErrInvalidRecord)
	}
	cipherText, err := b64d(rec.CipherText)
	if err != nil {
		return nil, fmt.Errorf("%w: bad ciphertext", ErrInvalidRecord)
	}

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
		return nil, fmt.Errorf("%w: bad DEK length", ErrInvalidRecord)
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

func randBytes(dst []byte) (int, error) {
	n, err := randRead(dst)
	if err != nil {
		return n, fmt.Errorf("%w: %v", ErrRandomSource, err)
	}
	return n, nil
}
