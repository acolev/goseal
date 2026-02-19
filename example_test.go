package goseal_test

import (
	"fmt"

	"github.com/acolev/goseal"
)

func ExampleSeal() {
	kp, err := goseal.GenerateKeyPair()
	if err != nil {
		panic(err)
	}

	rec, err := goseal.Seal(kp.Pub, []byte("top secret"), []byte("user:42"))
	if err != nil {
		panic(err)
	}

	plain, err := goseal.Open(kp.Priv, rec, []byte("user:42"))
	if err != nil {
		panic(err)
	}

	fmt.Println(string(plain))
	// Output: top secret
}

func ExampleProtectPrivateKey() {
	wrapped, salt, err := goseal.ProtectPrivateKey("device-dek", "correct horse battery staple")
	if err != nil {
		panic(err)
	}

	unwrapped, err := goseal.UnprotectPrivateKey(wrapped, salt, "correct horse battery staple")
	if err != nil {
		panic(err)
	}

	fmt.Println(unwrapped)
	// Output: device-dek
}
