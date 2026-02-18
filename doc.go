// Package goseal provides envelope encryption for device-bound payloads.
//
// Scheme:
// 1. Generate random DEK (32 bytes).
// 2. Encrypt data using ChaCha20-Poly1305 with DEK.
// 3. Wrap DEK with ephemeral X25519 + HKDF-derived KEK + ChaCha20-Poly1305.
package goseal
