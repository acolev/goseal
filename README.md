# goseal

`goseal` is a Go library for device-bound envelope encryption using a compact token format: `goseal.v1.<header>.<payload>`.

1. Random DEK encrypts payload with ChaCha20-Poly1305.
2. DEK is wrapped for target device public key via ephemeral X25519 + HKDF + ChaCha20-Poly1305.
3. Output is a URL-safe string token.

## Install

```bash
go get github.com/acolev/goseal
```

## Quick start

```go
package main

import (
	"fmt"
	"log"

	"github.com/acolev/goseal"
)

func main() {
	// 1. Generate device keys (persist securely!)
	kp, err := goseal.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}

	// 2. Encrypt
	// You need: Recipient Public Key, Plaintext, Context (AAD), KeyID, AAD Hint (optional)
	aad := []byte("user:42|record:100")
	token, err := goseal.Encrypt(kp.Pub, []byte("secret payload"), aad, "key-1", "record-100")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Token: %s\n", token)

	// 3. Decrypt
    // You need: Recipient Private Key, Token, Context (AAD)
	plain, err := goseal.Decrypt(kp.Priv, token, aad)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(plain))
}
```

## Token Format

`goseal.v1.<header_b64url>.<payload_b64url>`

### Header
Base64URL encoded JSON:
```json
{
  "v": 1,
  "alg": "X25519-HKDF-SHA256-ChaCha20Poly1305",
  "kid": "given-key-id",
  "aad_hint": "optional-hint"
}
```

### Payload
Base64URL encoded JSON:
```json
{
  "epk": "...",   // Base64Url encoded 32 bytes
  "ndek": "...",  // Base64Url encoded 12 bytes
  "wdek": "...",  // Base64Url encoded variable bytes (wrapped DEK)
  "ndata": "...", // Base64Url encoded 12 bytes
  "ct": "..."     // Base64Url encoded variable bytes (ciphertext)
}
```

## Security notes

- Always use high-entropy device private keys and protect them at rest.
- Always set meaningful `aad` (for example, `tenant|user|record`) to bind ciphertext to context.
- Reject decryption on any integrity failure and do not retry with relaxed validation.

## Development

```bash
go test ./...
go test -race ./...
go vet ./...
go test -run=^$ -fuzz=FuzzEncryptDecryptRoundTrip -fuzztime=5s ./...
```
