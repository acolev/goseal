# goseal Password-Based Key Wrapping Specification

This document defines an interoperability specification for:
- `WrapKey(sourceKey, password)`
- `UnwrapKey(wrappedKeyB64, saltB64, password)`

The goal is that different language implementations produce compatible results.

## Version

- Spec version: `wrap-v1`

## Algorithms and parameters

- KDF: `PBKDF2-HMAC-SHA256`
- PBKDF2 iterations: `600000`
- Derived key length: `32` bytes
- Salt length: `16` bytes (random)
- AEAD: `AES-256-GCM`
- Nonce length: `12` bytes (random)
- AAD: empty / not used
- Tag length: `16` bytes (default GCM tag size)
- Base64 encoding: URL-safe base64 without padding (RFC 4648 raw URL encoding)

## Input encoding

- `sourceKey` is a UTF-8 string.
- `password` is a UTF-8 string.
- KDF input bytes are the raw UTF-8 bytes of `password`.
- Plaintext bytes are the raw UTF-8 bytes of `sourceKey`.

## WrapKey output format

`WrapKey` returns two strings:

1. `saltB64`
- `salt = random(16 bytes)`
- `saltB64 = BASE64URL_NOPAD(salt)`

2. `wrappedKeyB64`
- Derive `wrappingKey`:
  - `wrappingKey = PBKDF2_HMAC_SHA256(password_bytes, salt, 600000, 32)`
- Generate `nonce = random(12 bytes)`
- Encrypt:
  - `ciphertextWithTag = AES_256_GCM_Seal(key=wrappingKey, nonce=nonce, plaintext=sourceKey_bytes, aad=nil)`
- Concatenate:
  - `payload = nonce || ciphertextWithTag`
- Encode:
  - `wrappedKeyB64 = BASE64URL_NOPAD(payload)`

## UnwrapKey process

Given `wrappedKeyB64`, `saltB64`, and `password`:

1. Decode:
- `salt = BASE64URL_NOPAD_DECODE(saltB64)`
- `payload = BASE64URL_NOPAD_DECODE(wrappedKeyB64)`

2. Validate minimal lengths:
- `len(salt) >= 8` (current implementation emits exactly 16)
- `len(payload) >= 12 + 16` (nonce + minimum GCM tag)

3. Derive key:
- `wrappingKey = PBKDF2_HMAC_SHA256(password_bytes, salt, 600000, 32)`

4. Split payload:
- `nonce = payload[0:12]`
- `ciphertextWithTag = payload[12:]`

5. Decrypt:
- `plaintext = AES_256_GCM_Open(key=wrappingKey, nonce=nonce, ciphertextWithTag, aad=nil)`
- On authentication failure, return unwrap/decrypt error.

6. Output:
- Return UTF-8 string from `plaintext` bytes.

## Error behavior (recommended)

- Invalid/empty inputs -> invalid key/input error.
- Base64 decode failure -> invalid record/format error.
- Auth tag mismatch or wrong password -> unwrap/decrypt failed error.
- Random source failure -> random source error.

## Security notes

- Use a cryptographically secure RNG for salt and nonce.
- Never reuse a nonce with the same derived key.
- Store `saltB64` alongside `wrappedKeyB64`; both are needed for unwrapping.
- Use strong passwords; PBKDF2 slows guessing but does not replace password entropy.
