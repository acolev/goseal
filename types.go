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

type payload struct {
	EPK        string `json:"epk"`
	NonceDEK   string `json:"ndek"`
	WrappedDEK string `json:"wdek"`
	NonceData  string `json:"ndata"`
	CipherText string `json:"ct"`
}
