package keystore

import "errors"

var (
	// ErrTPMNotAvailable is returned when a TPM device is not accessible
	ErrTPMNotAvailable = errors.New("TPM device not available")

	// ErrTPMNotSupported is returned on platforms without TPM support
	ErrTPMNotSupported = errors.New("TPM not supported on this platform")

	// ErrNoSealedKey is returned when no sealed key exists
	ErrNoSealedKey = errors.New("no sealed key found")

	// ErrSealFailed is returned when the sealing operation fails
	ErrSealFailed = errors.New("failed to seal key to TPM")

	// ErrUnsealFailed is returned when the unsealing operation fails
	ErrUnsealFailed = errors.New("failed to unseal key from TPM")

	// ErrKeyStoreNotInitialized is returned when the key store is not initialized
	ErrKeyStoreNotInitialized = errors.New("key store not initialized")
)
