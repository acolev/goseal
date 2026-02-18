package goseal

import "errors"

var (
	ErrInvalidKey               = errors.New("invalid key")
	ErrInvalidRecord            = errors.New("invalid record")
	ErrUnsupportedRecordVersion = errors.New("unsupported record version")
	ErrRandomSource             = errors.New("random source failure")
	ErrKeyWrapFailed            = errors.New("cannot wrap key")
	ErrKeyUnwrapFailed          = errors.New("cannot unwrap key")
	ErrDataDecryptFailed        = errors.New("cannot decrypt data")
)
