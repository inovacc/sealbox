package keystore

import "errors"

var (
	// ErrTPMNotAvailable is returned when a TPM device is not accessible
	ErrTPMNotAvailable = errors.New("TPM device not available")

	// ErrTPMNotSupported is returned on platforms without TPM support
	ErrTPMNotSupported = errors.New("TPM not supported on this platform")

	// ErrNoSealedKey is returned when no sealed key exists
	ErrNoSealedKey = errors.New("no sealed key found")

	// ErrKeyExists is returned when trying to initialize but a key already exists
	ErrKeyExists = errors.New("sealed key already exists")

	// ErrSealFailed is returned when the sealing operation fails
	ErrSealFailed = errors.New("failed to seal key to TPM")

	// ErrUnsealFailed is returned when the unsealing operation fails
	ErrUnsealFailed = errors.New("failed to unseal key from TPM")

	// ErrKeyStoreNotInitialized is returned when the key store is not initialized
	ErrKeyStoreNotInitialized = errors.New("key store not initialized")

	// ErrKeyTooLarge is returned when the key exceeds the maximum sealable size
	ErrKeyTooLarge = errors.New("key exceeds maximum sealable size (1024 bytes)")

	// ErrKeyEmpty is returned when trying to seal an empty key
	ErrKeyEmpty = errors.New("cannot seal empty key")

	// ErrInvalidSealedData is returned when sealed data has invalid or missing fields
	ErrInvalidSealedData = errors.New("sealed data has invalid or missing fields")

	// ErrPCRMismatch is returned when PCR values do not match the sealed policy
	ErrPCRMismatch = errors.New("PCR values do not match sealed policy")

	// ErrPasswordRequired is returned when a password is required to unseal a key
	ErrPasswordRequired = errors.New("password required to unseal this key")

	// ErrInvalidPassword is returned when the provided password is incorrect
	ErrInvalidPassword = errors.New("invalid password for sealed key")

	// ErrPolicyFailed is returned when the policy session fails during unsealing
	ErrPolicyFailed = errors.New("policy session failed")

	// ErrInvalidPCRSelection is returned when PCR selection is invalid
	ErrInvalidPCRSelection = errors.New("invalid PCR selection")
)
