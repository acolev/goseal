package goseal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

// ProtectPrivateKey encrypts sourceKey using a password-derived key.
//
// It returns:
// - wrappedKeyB64: base64(nonce || ciphertext || tag)
// - saltB64: base64(random salt used for PBKDF2)
func ProtectPrivateKey(sourceKey string, password string) (wrappedKeyB64 string, saltB64 string, err error) {
	if sourceKey == "" || password == "" {
		return "", "", ErrInvalidKey
	}

	salt := make([]byte, wrapSaltSize)
	if _, err := randRead(salt); err != nil {
		return "", "", fmt.Errorf("%w: %v", ErrRandomSource, err)
	}

	wrappingKey := pbkdf2.Key([]byte(password), salt, wrapPBKDF2Iters, keySize, sha256.New)
	block, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return "", "", errors.Join(ErrKeyWrapFailed, err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", errors.Join(ErrKeyWrapFailed, err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := randRead(nonce); err != nil {
		return "", "", fmt.Errorf("%w: %v", ErrRandomSource, err)
	}

	sealed := aead.Seal(nil, nonce, []byte(sourceKey), nil)
	out := make([]byte, 0, len(nonce)+len(sealed))
	out = append(out, nonce...)
	out = append(out, sealed...)

	return b64(out), b64(salt), nil
}

// UnprotectPrivateKey decrypts base64-encoded wrappedKeyB64 using password and saltB64.
func UnprotectPrivateKey(wrappedKeyB64 string, saltB64 string, password string) (string, error) {
	if wrappedKeyB64 == "" || saltB64 == "" || password == "" {
		return "", ErrInvalidKey
	}

	payload, err := b64d(wrappedKeyB64)
	if err != nil || len(payload) < wrapMinCipherBytes {
		return "", fmt.Errorf("%w: bad wrapped key", ErrInvalidRecord)
	}
	salt, err := b64d(saltB64)
	if err != nil || len(salt) < 8 {
		return "", fmt.Errorf("%w: bad salt", ErrInvalidRecord)
	}

	wrappingKey := pbkdf2.Key([]byte(password), salt, wrapPBKDF2Iters, keySize, sha256.New)
	block, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return "", errors.Join(ErrKeyUnwrapFailed, err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", errors.Join(ErrKeyUnwrapFailed, err)
	}

	nonceSize := aead.NonceSize()
	if len(payload) < nonceSize+aead.Overhead() {
		return "", fmt.Errorf("%w: wrapped key too short", ErrInvalidRecord)
	}
	nonce := payload[:nonceSize]
	ciphertext := payload[nonceSize:]

	plain, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", errors.Join(ErrKeyUnwrapFailed, err)
	}

	return string(plain), nil
}
