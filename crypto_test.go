package goseal

import (
	"bytes"
	"errors"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	plaintext := []byte("hello production library")
	aad := []byte("user:42|record:99|v1")
	rec, err := Encrypt(kp.Pub, plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	got, err := Decrypt(kp.Priv, rec, aad)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext mismatch: got=%q want=%q", got, plaintext)
	}
}

func TestDecryptWrongPrivateKeyFails(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	other, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(other): %v", err)
	}

	rec, err := Encrypt(kp.Pub, []byte("secret"), []byte("aad"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	_, err = Decrypt(other.Priv, rec, []byte("aad"))
	if !errors.Is(err, ErrKeyUnwrapFailed) {
		t.Fatalf("expected ErrKeyUnwrapFailed, got %v", err)
	}
}

func TestDecryptWrongAADFails(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	rec, err := Encrypt(kp.Pub, []byte("secret"), []byte("aad-1"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	_, err = Decrypt(kp.Priv, rec, []byte("aad-2"))
	if !errors.Is(err, ErrKeyUnwrapFailed) {
		t.Fatalf("expected ErrKeyUnwrapFailed for wrong aad, got %v", err)
	}
}

func TestDecryptTamperedCiphertextFails(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	rec, err := Encrypt(kp.Pub, []byte("secret"), []byte("aad"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	ct, err := b64d(rec.CipherText)
	if err != nil {
		t.Fatalf("b64d: %v", err)
	}
	ct[len(ct)-1] ^= 0x01
	rec.CipherText = b64(ct)

	_, err = Decrypt(kp.Priv, rec, []byte("aad"))
	if !errors.Is(err, ErrDataDecryptFailed) {
		t.Fatalf("expected ErrDataDecryptFailed, got %v", err)
	}
}

func TestDecryptTamperedWrappedDEKFails(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	rec, err := Encrypt(kp.Pub, []byte("secret"), []byte("aad"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	wdek, err := b64d(rec.WrappedDEK)
	if err != nil {
		t.Fatalf("b64d(wdek): %v", err)
	}
	wdek[len(wdek)-1] ^= 0x01
	rec.WrappedDEK = b64(wdek)

	_, err = Decrypt(kp.Priv, rec, []byte("aad"))
	if !errors.Is(err, ErrKeyUnwrapFailed) {
		t.Fatalf("expected ErrKeyUnwrapFailed, got %v", err)
	}
}

func TestDecryptBadRecordFields(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	_, err = Decrypt(kp.Priv, nil, nil)
	if !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("expected ErrInvalidRecord for nil record, got %v", err)
	}

	rec, err := Encrypt(kp.Pub, []byte("secret"), nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	rec.V = 2
	_, err = Decrypt(kp.Priv, rec, nil)
	if !errors.Is(err, ErrUnsupportedRecordVersion) {
		t.Fatalf("expected ErrUnsupportedRecordVersion, got %v", err)
	}
}
