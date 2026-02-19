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

	wrapped, salt, err := LockPrivateKey(sourceKey, password)
	if err != nil {
		t.Fatalf("LockPrivateKey: %v", err)
	}
	if wrapped == "" || salt == "" {
		t.Fatalf("expected wrapped key and salt to be non-empty")
	}

	got, err := UnlockPrivateKey(wrapped, salt, password)
	if err != nil {
		t.Fatalf("UnlockPrivateKey: %v", err)
	}
	if got != sourceKey {
		t.Fatalf("key mismatch: got=%q want=%q", got, sourceKey)
	}
}

func TestUnprotectPrivateKeyWrongPasswordFails(t *testing.T) {
	wrapped, salt, err := LockPrivateKey("secret-key", "right-password")
	if err != nil {
		t.Fatalf("LockPrivateKey: %v", err)
	}

	_, err = UnlockPrivateKey(wrapped, salt, "wrong-password")
	if !errors.Is(err, ErrKeyUnwrapFailed) {
		t.Fatalf("expected ErrKeyUnwrapFailed, got %v", err)
	}
}

func TestUnprotectPrivateKeyInvalidBase64Fails(t *testing.T) {
	_, err := UnlockPrivateKey("not-base64", "also-not-base64", "password")
	if !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("expected ErrInvalidRecord, got %v", err)
	}
}
