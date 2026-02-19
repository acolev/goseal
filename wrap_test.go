package goseal

import (
	"errors"
	"testing"
)

func TestProtectUnprotectPrivateKeyRoundTrip(t *testing.T) {
	const (
		sourceKey = "my-master-key-123"
		password  = "very-strong-password"
	)

	wrapped, salt, err := ProtectPrivateKey(sourceKey, password)
	if err != nil {
		t.Fatalf("ProtectPrivateKey: %v", err)
	}
	if wrapped == "" || salt == "" {
		t.Fatalf("expected wrapped key and salt to be non-empty")
	}

	got, err := UnprotectPrivateKey(wrapped, salt, password)
	if err != nil {
		t.Fatalf("UnprotectPrivateKey: %v", err)
	}
	if got != sourceKey {
		t.Fatalf("key mismatch: got=%q want=%q", got, sourceKey)
	}
}

func TestUnprotectPrivateKeyWrongPasswordFails(t *testing.T) {
	wrapped, salt, err := ProtectPrivateKey("secret-key", "right-password")
	if err != nil {
		t.Fatalf("ProtectPrivateKey: %v", err)
	}

	_, err = UnprotectPrivateKey(wrapped, salt, "wrong-password")
	if !errors.Is(err, ErrKeyUnwrapFailed) {
		t.Fatalf("expected ErrKeyUnwrapFailed, got %v", err)
	}
}

func TestUnprotectPrivateKeyInvalidBase64Fails(t *testing.T) {
	_, err := UnprotectPrivateKey("not-base64", "also-not-base64", "password")
	if !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("expected ErrInvalidRecord, got %v", err)
	}
}
