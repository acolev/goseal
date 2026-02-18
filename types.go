package goseal

type KeyPair struct {
	Priv [keySize]byte
	Pub  [keySize]byte
}

type Header struct {
	V       int    `json:"v"`
	Alg     string `json:"alg"`
	KID     string `json:"kid"`
	AADHint string `json:"aad_hint,omitempty"`
}
