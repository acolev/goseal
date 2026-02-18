package goseal

type KeyPair struct {
	Priv [keySize]byte
	Pub  [keySize]byte
}

// Record is the serialized encrypted envelope safe to store in DB/JSON.
type Record struct {
	V int `json:"v"`

	// ECIES-lite fields for DEK wrapping.
	EphemeralPub string `json:"epk"`  // b64url(32 bytes)
	NonceDEK     string `json:"ndek"` // b64url(12 bytes)
	WrappedDEK   string `json:"wdek"` // b64url(var)

	// Encrypted payload.
	NonceData  string `json:"ndata"` // b64url(12 bytes)
	CipherText string `json:"ct"`    // b64url(var)
}
