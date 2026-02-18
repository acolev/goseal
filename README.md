# goseal

`goseal` is a Go library for device-bound envelope encryption:

1. Random DEK encrypts payload with ChaCha20-Poly1305.
2. DEK is wrapped for target device public key via ephemeral X25519 + HKDF + ChaCha20-Poly1305.

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
	rec, err := goseal.EncryptForDevice(kp.Pub, []byte("secret payload"), aad)
	if err != nil {
		panic(err)
	}

	plain, err := goseal.DecryptForDevice(kp.Priv, rec, aad)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(plain))
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

## Development

```bash
go test ./...
go test -race ./...
go vet ./...
go test -run=^$ -fuzz=FuzzEncryptDecryptRoundTrip -fuzztime=5s ./...
```
