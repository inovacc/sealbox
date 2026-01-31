package sealbox

import "fmt"

// InitializeWith creates and seals a new key using the provided KeyManager and stores it.
// This variant allows dependency injection for testing.
// Returns ErrKeyExists if a sealed key already exists at the storage path.
func InitializeWith(km KeyManager, opts ...KeyStoreOption) error {
	store, err := NewKeyStore(opts...)
	if err != nil {
		return fmt.Errorf("failed to create key store: %w", err)
	}

	if store.Exists() {
		return ErrKeyExists
	}

	sealedData, err := km.GenerateAndSealKey()
	if err != nil {
		return fmt.Errorf("failed to generate and seal key: %w", err)
	}

	if err := store.Save(sealedData); err != nil {
		return fmt.Errorf("failed to save sealed key: %w", err)
	}

	return nil
}

// Initialize creates and seals a new key to the TPM and stores it.
// This is a high-level helper that combines KeyManager and KeyStore operations.
// Returns ErrKeyExists if a sealed key already exists at the storage path.
func Initialize(opts ...KeyStoreOption) error {
	if !IsAvailable() {
		return ErrTPMNotAvailable
	}

	// Check if key already exists
	store, err := NewKeyStore(opts...)
	if err != nil {
		return fmt.Errorf("failed to create key store: %w", err)
	}

	if store.Exists() {
		return ErrKeyExists
	}

	km, err := NewKeyManager()
	if err != nil {
		return fmt.Errorf("failed to create TPM key manager: %w", err)
	}

	defer func() { _ = km.Close() }()

	// Generate and seal a new random key
	sealedData, err := km.GenerateAndSealKey()
	if err != nil {
		return fmt.Errorf("failed to generate and seal key: %w", err)
	}

	if err := store.Save(sealedData); err != nil {
		return fmt.Errorf("failed to save sealed key: %w", err)
	}

	return nil
}

// Reset removes the existing TPM-sealed key from disk.
func Reset(opts ...KeyStoreOption) error {
	store, err := NewKeyStore(opts...)
	if err != nil {
		return fmt.Errorf("failed to create key store: %w", err)
	}

	return store.Delete()
}

// HasKey checks if a TPM-sealed key exists on disk.
func HasKey(opts ...KeyStoreOption) bool {
	store, err := NewKeyStore(opts...)
	if err != nil {
		return false
	}

	return store.Exists()
}

// GetKeyStorePath returns the path where the TPM-sealed key is stored.
func GetKeyStorePath(opts ...KeyStoreOption) (string, error) {
	store, err := NewKeyStore(opts...)
	if err != nil {
		return "", err
	}

	return store.Path(), nil
}

// GetSealedMasterKeyWith retrieves and unseals the master encryption key using the provided KeyManager.
// This variant allows dependency injection for testing.
// Returns the unsealed key that can be used for encryption operations.
func GetSealedMasterKeyWith(km KeyManager, opts ...KeyStoreOption) ([]byte, error) {
	store, err := NewKeyStore(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create key store: %w", err)
	}

	if !store.Exists() {
		return nil, ErrNoSealedKey
	}

	sealedData, err := store.Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load sealed key: %w", err)
	}

	key, err := km.UnsealKey(sealedData)
	if err != nil {
		return nil, fmt.Errorf("failed to unseal key: %w", err)
	}

	return key, nil
}

// GetSealedMasterKey retrieves and unseals the master encryption key from TPM.
// Returns the unsealed key that can be used for encryption operations.
func GetSealedMasterKey(opts ...KeyStoreOption) ([]byte, error) {
	if !IsAvailable() {
		return nil, ErrTPMNotAvailable
	}

	store, err := NewKeyStore(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create key store: %w", err)
	}

	if !store.Exists() {
		return nil, ErrNoSealedKey
	}

	km, err := NewKeyManager()
	if err != nil {
		return nil, fmt.Errorf("failed to create TPM key manager: %w", err)
	}

	defer func() { _ = km.Close() }()

	sealedData, err := store.Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load sealed key: %w", err)
	}

	key, err := km.UnsealKey(sealedData)
	if err != nil {
		return nil, fmt.Errorf("failed to unseal key: %w", err)
	}

	return key, nil
}
