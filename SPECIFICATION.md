# goseal Specification

This document defines cross-language interoperability requirements for `goseal`.

Covered APIs:
- `GenerateKeyPair()`
- `Seal(devicePub, plaintext, aad)`
- `Open(devicePriv, record, aad)`
- `ProtectPrivateKey(sourceKey, password)`
- `UnprotectPrivateKey(wrappedKeyB64, saltB64, password)`

## Versioning

- Record format version: `v=1`
- Envelope scheme identifier: `goseal-envelope-v1`
- Password-wrap scheme identifier: `goseal-wrap-v1`

## Common encoding rules

- Binary data in serialized records is encoded as URL-safe base64 without padding (RFC 4648 raw URL encoding).
- Strings are UTF-8.
- Random bytes must come from a cryptographically secure RNG.

## Constants

- X25519 scalar/public key length: `32` bytes
- DEK length: `32` bytes
- ChaCha20-Poly1305 nonce length: `12` bytes
- ChaCha20-Poly1305 tag length: `16` bytes
- HKDF hash: `SHA-256`
- HKDF info label prefix: `"goseal v1 kek"`

Password-wrap constants:
- PBKDF2 hash: `SHA-256`
- PBKDF2 iterations: `600000`
- PBKDF2 derived key length: `32` bytes
- PBKDF2 salt length (generated): `16` bytes
- AES-GCM nonce length: `12` bytes
- AES-GCM tag length: `16` bytes

## Key generation (`GenerateKeyPair`)

1. Generate random 32-byte private scalar.
2. Clamp scalar using X25519 clamping:
- `s[0] &= 248`
- `s[31] &= 127`
- `s[31] |= 64`
3. Compute public key:
- `pub = X25519(priv, basepoint)`
4. Return `{priv, pub}`.

## Envelope record format (`Seal` output)

JSON object fields:
- `v` (int): record version, must be `1`
- `epk` (string): base64url of 32-byte ephemeral X25519 public key
- `ndek` (string): base64url of 12-byte nonce for wrapped DEK encryption
- `wdek` (string): base64url of wrapped DEK ciphertext+tag (variable length)
- `ndata` (string): base64url of 12-byte nonce for payload encryption
- `ct` (string): base64url of payload ciphertext+tag (variable length)

Example shape:

```json
{
  "v": 1,
  "epk": "...",
  "ndek": "...",
  "wdek": "...",
  "ndata": "...",
  "ct": "..."
}
```

## Seal algorithm (`Seal`)

Inputs:
- `devicePub`: recipient X25519 public key (32 bytes)
- `plaintext`: bytes
- `aad`: bytes (optional, may be empty)

Steps:
1. Generate random `dek` (32 bytes).
2. Seal payload:
- `aeadData = ChaCha20Poly1305(dek)`
- `nonceData = random(12)`
- `ct = AEAD_Seal(aeadData, nonceData, plaintext, aad)`
3. Generate ephemeral keypair:
- random+clamp 32-byte `epriv`
- `epk = X25519(epriv, basepoint)`
4. Compute ECDH shared secret:
- `shared = X25519(epriv, devicePub)`
- reject if `shared` is all-zero bytes
5. Derive KEK with HKDF-SHA256:
- `salt = epk || devicePub`
- `info = "goseal v1 kek"` if `aad` empty
- `info = "goseal v1 kek" || "|" || aad` if `aad` non-empty
- `kek = HKDF_SHA256(ikm=shared, salt=salt, info=info, len=32)`
6. Wrap DEK:
- `aeadKEK = ChaCha20Poly1305(kek)`
- `nonceDEK = random(12)`
- `wdek = AEAD_Seal(aeadKEK, nonceDEK, dek, aad)`
7. Serialize as record fields using base64url-no-padding.

## Open algorithm (`Open`)

Inputs:
- `devicePriv`: recipient X25519 private scalar (32 bytes; implementation clamps before use)
- `record`: JSON structure described above
- `aad`: bytes (must match exactly what was used in `Seal`)

Steps:
1. Validate record:
- record must be non-null
- `v == 1`
- decode/length-check fields:
  - `epk` -> 32 bytes
  - `ndek` -> 12 bytes
  - `ndata` -> 12 bytes
  - `wdek`, `ct` -> decoded bytes (length >= tag handled by AEAD/open path)
2. Clamp `devicePriv` with X25519 clamping.
3. Recompute `devicePub = X25519(devicePriv, basepoint)`.
4. Compute shared secret:
- `shared = X25519(devicePriv, epk)`
- reject if all-zero
5. Derive `kek` with the same HKDF construction:
- `salt = epk || devicePub`
- `info` construction exactly as in Seal, including AAD behavior
6. Unwrap DEK:
- `dek = AEAD_Open(ChaCha20Poly1305(kek), nonceDEK, wdek, aad)`
- fail if authentication fails
- require `len(dek) == 32`
7. Open payload:
- `plaintext = AEAD_Open(ChaCha20Poly1305(dek), nonceData, ct, aad)`
- fail if authentication fails
8. Return plaintext bytes.

## Password-based key wrapping (`ProtectPrivateKey`/`UnprotectPrivateKey`)

### Input encoding

- `sourceKey` is UTF-8 string; plaintext bytes are raw UTF-8 bytes.
- `password` is UTF-8 string; KDF input is raw UTF-8 bytes.

### ProtectPrivateKey

1. Generate random `salt` (16 bytes).
2. Derive wrapping key:
- `wrappingKey = PBKDF2_HMAC_SHA256(password, salt, 600000, 32)`
3. Generate random `nonce` (12 bytes).
4. Seal with AES-256-GCM and empty AAD:
- `ciphertextWithTag = AES_GCM_Seal(wrappingKey, nonce, sourceKeyBytes, aad=nil)`
5. Build payload:
- `payload = nonce || ciphertextWithTag`
6. Return:
- `wrappedKeyB64 = BASE64URL_NOPAD(payload)`
- `saltB64 = BASE64URL_NOPAD(salt)`

### UnprotectPrivateKey

1. Decode:
- `payload = BASE64URL_NOPAD_DECODE(wrappedKeyB64)`
- `salt = BASE64URL_NOPAD_DECODE(saltB64)`
2. Validate minimum lengths:
- `len(payload) >= 12 + 16`
- `len(salt) >= 8` (generated salt is 16)
3. Derive wrapping key using same PBKDF2 params.
4. Split payload:
- `nonce = payload[0:12]`
- `ciphertextWithTag = payload[12:]`
5. Open using AES-256-GCM with empty AAD.
6. Return UTF-8 string from plaintext bytes.

## Interoperability notes

- For envelope records, AAD bytes must match exactly between encrypt/decrypt; any mismatch must fail authentication.
- Base64 variant must be raw URL-safe without `=` padding.
- X25519 clamping behavior must match exactly.
- Reject all-zero X25519 shared secrets.

## Error mapping guidance

Recommended categories (names may differ by language):
- Invalid key/input
- Invalid record/format
- Random source failure
- Key unwrap/authentication failure
- Data decrypt/authentication failure

Do not expose sensitive internals in production error messages.

## Security disclaimer

This project is provided as-is, without warranties. Cryptography can be misused.
Each integrator is responsible for code review, threat-model fit, and safe deployment.
