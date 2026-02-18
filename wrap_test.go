package goseal

import (
	"errors"
	"testing"
)

func TestWrapUnwrapKeyRoundTrip(t *testing.T) {
	const (
		sourceKey = "my-master-key-123"
		password  = "very-strong-password"
	)

	wrapped, salt, err := WrapKey(sourceKey, password)
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}
	if wrapped == "" || salt == "" {
		t.Fatalf("expected wrapped key and salt to be non-empty")
	}

	got, err := UnwrapKey(wrapped, salt, password)
	if err != nil {
		t.Fatalf("UnwrapKey: %v", err)
	}
	if got != sourceKey {
		t.Fatalf("key mismatch: got=%q want=%q", got, sourceKey)
	}
}

func TestUnwrapKeyWrongPasswordFails(t *testing.T) {
	wrapped, salt, err := WrapKey("secret-key", "right-password")
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}

	_, err = UnwrapKey(wrapped, salt, "wrong-password")
	if !errors.Is(err, ErrKeyUnwrapFailed) {
		t.Fatalf("expected ErrKeyUnwrapFailed, got %v", err)
	}
}

func TestUnwrapKeyInvalidBase64Fails(t *testing.T) {
	_, err := UnwrapKey("not-base64", "also-not-base64", "password")
	if !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("expected ErrInvalidRecord, got %v", err)
	}
}
