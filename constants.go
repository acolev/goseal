package goseal

import "golang.org/x/crypto/chacha20poly1305"

const (
	recordVersion = 1
	keySize       = 32
	nonceSize     = chacha20poly1305.NonceSize
	kekInfoLabel  = "goseal v1 kek"

	wrapSaltSize       = 16
	wrapPBKDF2Iters    = 600000
	wrapMinCipherBytes = 12 + 16
)
