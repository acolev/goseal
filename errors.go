package goseal

import "errors"

var (
	ErrInvalidKey               = errors.New("invalid key")
	ErrInvalidRecord            = errors.New("invalid record")
	ErrUnsupportedRecordVersion = errors.New("unsupported record version")
	ErrRandomSource             = errors.New("random source failure")
	ErrKeyUnwrapFailed          = errors.New("cannot unwrap DEK")
	ErrDataDecryptFailed        = errors.New("cannot decrypt data")
)
