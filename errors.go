package goseal

import "errors"

var (
	ErrInvalidKey               = errors.New("invalid key")
	ErrInvalidToken             = errors.New("invalid token")
	ErrUnsupportedRecordVersion = errors.New("unsupported record version")
	ErrRandomSource             = errors.New("random source failure")
	ErrKeyUnwrapFailed          = errors.New("cannot unwrap DEK")
	ErrDataDecryptFailed        = errors.New("cannot decrypt data")
)
