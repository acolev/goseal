package goseal_test

import (
	"fmt"
	"log"

	"github.com/acolev/goseal"
)

func ExampleEncryptForDevice() {
	kp, err := goseal.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}

	aad := []byte("user:42|record:100")
	token, err := goseal.EncryptForDevice(kp.Pub, []byte("secret payload"), aad, "key-1", "record-100")
	if err != nil {
		log.Fatal(err)
	}

	plain, err := goseal.DecryptForDevice(kp.Priv, token, aad)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(plain))
	// Output: secret payload
}
