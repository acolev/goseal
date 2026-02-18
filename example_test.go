package goseal_test

import (
	"fmt"
	"log"

	"github.com/acolev/goseal"
)

func ExampleEncrypt() {
	kp, err := goseal.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}

	aad := []byte("user:42|record:100")
	token, err := goseal.Encrypt(kp.Pub, []byte("secret payload"), aad, "key-1", "record-100")
	if err != nil {
		log.Fatal(err)
	}

	plain, err := goseal.Decrypt(kp.Priv, token, aad)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(plain))
	// Output: secret payload
}
