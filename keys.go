package goseal

import (
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
)

func GenerateKeyPair() (*KeyPair, error) {
	var kp KeyPair
	if _, err := io.ReadFull(rand.Reader, kp.Priv[:]); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRandomSource, err)
	}
	clampScalar(&kp.Priv)

	pub, err := curve25519.X25519(kp.Priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	copy(kp.Pub[:], pub)
	return &kp, nil
}

func publicFromPrivate(priv [keySize]byte) ([keySize]byte, error) {
	clampScalar(&priv)
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return [keySize]byte{}, err
	}
	var out [keySize]byte
	copy(out[:], pub)
	return out, nil
}

func genEphemeral() (pub [keySize]byte, priv [keySize]byte, err error) {
	if _, err = io.ReadFull(rand.Reader, priv[:]); err != nil {
		return pub, priv, fmt.Errorf("%w: %v", ErrRandomSource, err)
	}
	clampScalar(&priv)

	p, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return pub, priv, err
	}
	copy(pub[:], p)
	return pub, priv, nil
}

func clampScalar(s *[keySize]byte) {
	s[0] &= 248
	s[31] &= 127
	s[31] |= 64
}
