# goseal

[![Go Report Card](https://goreportcard.com/badge/github.com/acolev/goseal)](https://goreportcard.com/report/github.com/acolev/goseal)

`goseal` is a Go library for device-bound envelope encryption:

1. Random DEK encrypts payload with ChaCha20-Poly1305.
2. DEK is wrapped for target device public key via ephemeral X25519 + HKDF + ChaCha20-Poly1305.

It also supports password-based key wrapping via PBKDF2(SHA-256) + AES-GCM (`WrapKey`/`UnwrapKey`).

Specification for cross-language implementations:
- [goseal Specification](./SPECIFICATION.md)

## Install

```bash
go get github.com/acolev/goseal
```

## Quick start

```go
package main

import (
	"fmt"

	"github.com/acolev/goseal"
)

func main() {
	kp, err := goseal.GenerateKeyPair()
	if err != nil {
		panic(err)
	}

	aad := []byte("user:42|record:100")
	rec, err := goseal.Encrypt(kp.Pub, []byte("secret payload"), aad)
	if err != nil {
		panic(err)
	}

	plain, err := goseal.Decrypt(kp.Priv, rec, aad)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(plain))
}
```

## Password-based key wrapping

```go
package main

import (
	"fmt"

	"github.com/acolev/goseal"
)

func main() {
	wrapped, salt, err := goseal.WrapKey("device-dek", "correct horse battery staple")
	if err != nil {
		panic(err)
	}

	unwrapped, err := goseal.UnwrapKey(wrapped, salt, "correct horse battery staple")
	if err != nil {
		panic(err)
	}

	fmt.Println(unwrapped)
}
```

## API stability

- Record format version is currently `v=1`.
- Backward-incompatible changes must bump major version.
- New record versions should keep older versions decryptable until deprecation is announced.

## Security notes

- Always use high-entropy device private keys and protect them at rest.
- Always set meaningful `aad` (for example, `tenant|user|record`) to bind ciphertext to context.
- Reject decryption on any integrity failure and do not retry with relaxed validation.
- For `WrapKey`/`UnwrapKey`, use strong passwords and store returned salt alongside wrapped key.

## Security disclaimer

This project is provided **as-is**, without warranty of any kind.
Cryptography is easy to misuse. You are responsible for reviewing the code,
understanding the threat model, and deciding whether it fits your use case.
The author(s) assume no liability for data loss, compromise, or damages
resulting from use of this software.

## Threat model (high level)

`goseal` is intended to protect data **at rest** (for example, database or object storage leaks)
when private keys remain secret.
It does **not** protect against compromise of private keys or passwords, or against an attacker
who already has both ciphertext and the required keys.

## Development

```bash
go test ./...
go test -race ./...
go vet ./...
go test -run=^$ -fuzz=FuzzEncryptDecryptRoundTrip -fuzztime=5s ./...
```
