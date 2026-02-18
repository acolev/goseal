package goseal_test

import (
	"fmt"

	"github.com/acolev/goseal"
)

func ExampleEncryptForDevice() {
	kp, err := goseal.GenerateKeyPair()
	if err != nil {
		panic(err)
	}

	rec, err := goseal.EncryptForDevice(kp.Pub, []byte("top secret"), []byte("user:42"))
	if err != nil {
		panic(err)
	}

	plain, err := goseal.DecryptForDevice(kp.Priv, rec, []byte("user:42"))
	if err != nil {
		panic(err)
	}

	fmt.Println(string(plain))
	// Output: top secret
}
