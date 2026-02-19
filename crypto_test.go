package goseal

import (
	"bytes"
	"errors"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	plaintext := []byte("hello production library")
	aad := []byte("user:42|record:99|v1")
	rec, err := Seal(kp.Pub, plaintext, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	got, err := Open(kp.Priv, rec, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext mismatch: got=%q want=%q", got, plaintext)
	}
}

func TestOpenWrongPrivateKeyFails(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	other, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(other): %v", err)
	}

	rec, err := Seal(kp.Pub, []byte("secret"), []byte("aad"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	_, err = Open(other.Priv, rec, []byte("aad"))
	if !errors.Is(err, ErrKeyUnwrapFailed) {
		t.Fatalf("expected ErrKeyUnwrapFailed, got %v", err)
	}
}

func TestOpenWrongAADFails(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	rec, err := Seal(kp.Pub, []byte("secret"), []byte("aad-1"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	_, err = Open(kp.Priv, rec, []byte("aad-2"))
	if !errors.Is(err, ErrKeyUnwrapFailed) {
		t.Fatalf("expected ErrKeyUnwrapFailed for wrong aad, got %v", err)
	}
}

func TestOpenTamperedCiphertextFails(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	rec, err := Seal(kp.Pub, []byte("secret"), []byte("aad"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	ct, err := b64d(rec.CipherText)
	if err != nil {
		t.Fatalf("b64d: %v", err)
	}
	ct[len(ct)-1] ^= 0x01
	rec.CipherText = b64(ct)

	_, err = Open(kp.Priv, rec, []byte("aad"))
	if !errors.Is(err, ErrDataDecryptFailed) {
		t.Fatalf("expected ErrDataDecryptFailed, got %v", err)
	}
}

func TestOpenTamperedWrappedDEKFails(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	rec, err := Seal(kp.Pub, []byte("secret"), []byte("aad"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	wdek, err := b64d(rec.WrappedDEK)
	if err != nil {
		t.Fatalf("b64d(wdek): %v", err)
	}
	wdek[len(wdek)-1] ^= 0x01
	rec.WrappedDEK = b64(wdek)

	_, err = Open(kp.Priv, rec, []byte("aad"))
	if !errors.Is(err, ErrKeyUnwrapFailed) {
		t.Fatalf("expected ErrKeyUnwrapFailed, got %v", err)
	}
}

func TestOpenBadRecordFields(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	_, err = Open(kp.Priv, nil, nil)
	if !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("expected ErrInvalidRecord for nil record, got %v", err)
	}

	rec, err := Seal(kp.Pub, []byte("secret"), nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	rec.V = 2
	_, err = Open(kp.Priv, rec, nil)
	if !errors.Is(err, ErrUnsupportedRecordVersion) {
		t.Fatalf("expected ErrUnsupportedRecordVersion, got %v", err)
	}
}
