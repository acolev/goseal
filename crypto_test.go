package goseal

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("hello world")
	aad := []byte("context")
	kid := "test-key-id"
	aadHint := "test-aad-hint"

	token, err := Seal(kp.Pub, plaintext, aad, kid, aadHint)
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	// Verify token structure
	parts := strings.Split(token, ".")
	if len(parts) != 4 {
		t.Fatalf("expected 4 parts, got %d", len(parts))
	}
	if parts[0] != "goseal" || parts[1] != "v1" {
		t.Errorf("unexpected prefix/version: %s.%s", parts[0], parts[1])
	}

	// Verify header
	headerJSON, err := b64d(parts[2])
	if err != nil {
		t.Errorf("failed to decode header: %v", err)
	}
	var header Header
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Errorf("failed to unmarshal header: %v", err)
	}
	if header.KID != kid {
		t.Errorf("expected kid %q, got %q", kid, header.KID)
	}
	if header.AADHint != aadHint {
		t.Errorf("expected aadHint %q, got %q", aadHint, header.AADHint)
	}

	// Verify payload decoding
	decrypted, err := Open(kp.Priv, token, aad)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("expected %q, got %q", plaintext, decrypted)
	}
}

func TestOpenFailures(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	otherKP, _ := GenerateKeyPair()

	plaintext := []byte("secret")
	aad := []byte("aad")
	token, err := Seal(kp.Pub, plaintext, aad, "kid", "")
	if err != nil {
		t.Fatal(err)
	}

	// Test wrong private key
	if _, err := Open(otherKP.Priv, token, aad); err == nil {
		t.Error("expected error with wrong private key, got nil")
	}

	// Test wrong AAD
	if _, err := Open(kp.Priv, token, []byte("wrong")); err == nil {
		t.Error("expected error with wrong AAD, got nil")
	}

	// Test malformed token
	if _, err := Open(kp.Priv, "bad.token", aad); err == nil {
		t.Error("expected error with malformed token, got nil")
	}

	// Test tampered payload
	parts := strings.Split(token, ".")
	header := parts[2]
	payloadBytes, _ := b64d(parts[3])
	payloadBytes[len(payloadBytes)-1] ^= 0xFF // Flip last bit of ciphertext
	tamperedPayload := b64(payloadBytes)
	tamperedToken := "goseal.v1." + header + "." + tamperedPayload

	if _, err := Open(kp.Priv, tamperedToken, aad); err == nil {
		t.Error("expected error with tampered payload, got nil")
	}
}
