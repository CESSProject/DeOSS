package db

import "io"

type Reader interface {
	Has(key []byte) (bool, error)

	// Get fetch the given key if it's present in the key-value data store.
	Get(key []byte) ([]byte, error)
}

type Writer interface {
	// Put store the given key-value in the key-value data store
	Put(key []byte, value []byte) error

	// Delete removes the key from the key-value data store.
	Delete(key []byte) error
}

type Compacter interface {
	Compact(start []byte, limit []byte) error
}

type Cache interface {
	Reader
	Writer
	Compacter
	io.Closer
}
