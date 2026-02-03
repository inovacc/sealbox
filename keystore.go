package sealbox

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	// ErrKeystoreClosed is returned when operating on a closed keystore.
	ErrKeystoreClosed = errors.New("keystore is closed")

	// ErrNoRootSecret is returned when no root secret is available.
	ErrNoRootSecret = errors.New("no root secret available")
)

// KeystoreOption configures a Keystore.
type KeystoreOption func(*keystoreOptions)

type keystoreOptions struct {
	useTPM      bool
	password    []byte
	appName     string
	kekInfo     string
	autoSave    bool
	mockKeyFunc func() ([]byte, error) // For testing
}

// WithTPMRoot uses TPM to seal the root secret.
func WithTPMRoot() KeystoreOption {
	return func(o *keystoreOptions) {
		o.useTPM = true
	}
}

// WithPasswordRoot uses password-based key derivation (no TPM).
func WithPasswordRoot(password []byte) KeystoreOption {
	return func(o *keystoreOptions) {
		o.password = password
		o.useTPM = false
	}
}

// WithAppName sets the application name for key storage paths.
func WithAppName(name string) KeystoreOption {
	return func(o *keystoreOptions) {
		o.appName = name
	}
}

// WithKEKInfo sets the HKDF info parameter for KEK derivation.
func WithKEKInfo(info string) KeystoreOption {
	return func(o *keystoreOptions) {
		o.kekInfo = info
	}
}

// WithAutoSave enables automatic saving after modifications.
func WithAutoSave() KeystoreOption {
	return func(o *keystoreOptions) {
		o.autoSave = true
	}
}

// withMockRootSecret sets a mock function for root secret (testing only).
func withMockRootSecret(fn func() ([]byte, error)) KeystoreOption {
	return func(o *keystoreOptions) {
		o.mockKeyFunc = fn
	}
}

// Keystore manages TPM-rooted encryption keys with envelope encryption.
// It provides:
// - Root secret management (TPM-sealed or password-derived)
// - KEK derivation via HKDF
// - Per-profile master key management (keyring)
// - Per-profile DEK management (envelope encryption)
type Keystore struct {
	mu           sync.RWMutex
	path         string
	opts         keystoreOptions
	rootSecret   []byte
	kek          []byte
	keyring      *Keyring
	envelopes    map[string]*EnvelopeStore // profile -> envelope store
	closed       bool
}

// Open opens or creates a keystore at the given path.
func Open(path string, opts ...KeystoreOption) (*Keystore, error) {
	if path == "" {
		return nil, errors.New("path cannot be empty")
	}

	ks := &Keystore{
		path:      path,
		envelopes: make(map[string]*EnvelopeStore),
		opts: keystoreOptions{
			useTPM:  true,
			kekInfo: "keystore-kek-v1",
		},
	}

	for _, opt := range opts {
		opt(&ks.opts)
	}

	// Create directory
	if err := os.MkdirAll(path, 0700); err != nil {
		return nil, fmt.Errorf("failed to create keystore directory: %w", err)
	}
	_ = setDirPermissions(path)

	// Initialize keyring
	keyring, err := NewKeyring(path)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize keyring: %w", err)
	}
	ks.keyring = keyring

	// Get or create root secret
	if err := ks.initializeRootSecret(); err != nil {
		return nil, fmt.Errorf("failed to initialize root secret: %w", err)
	}

	// Derive KEK from root secret
	if err := ks.deriveKEK(); err != nil {
		ks.Close()
		return nil, fmt.Errorf("failed to derive KEK: %w", err)
	}

	// Set KEK on keyring
	if err := ks.keyring.SetKEK(ks.kek); err != nil {
		ks.Close()
		return nil, fmt.Errorf("failed to set KEK on keyring: %w", err)
	}

	return ks, nil
}

// initializeRootSecret gets or creates the root secret.
func (ks *Keystore) initializeRootSecret() error {
	// Mock for testing
	if ks.opts.mockKeyFunc != nil {
		secret, err := ks.opts.mockKeyFunc()
		if err != nil {
			return err
		}
		ks.rootSecret = secret
		return nil
	}

	// Password-based derivation
	if len(ks.opts.password) > 0 {
		salt, err := ks.keyring.GetSalt()
		if err != nil {
			return fmt.Errorf("failed to get salt: %w", err)
		}
		rootSecret, err := DeriveKey(ks.opts.password, salt, "root-secret")
		if err != nil {
			return fmt.Errorf("failed to derive root secret: %w", err)
		}
		ks.rootSecret = rootSecret
		return nil
	}

	// TPM-based root secret
	if ks.opts.useTPM {
		return ks.initializeTPMRoot()
	}

	return ErrNoRootSecret
}

// initializeTPMRoot gets or creates a TPM-sealed root secret.
func (ks *Keystore) initializeTPMRoot() error {
	storePath := filepath.Join(ks.path, "root.sealed")
	storeOpts := []KeyStoreOption{WithStorePath(storePath)}

	// Check if TPM is available
	if !IsAvailable() {
		return ErrTPMNotAvailable
	}

	// Check if sealed root exists
	if HasKey(storeOpts...) {
		// Get existing root
		rootSecret, err := GetSealedMasterKey(storeOpts...)
		if err != nil {
			return fmt.Errorf("failed to unseal root: %w", err)
		}
		ks.rootSecret = rootSecret
		return nil
	}

	// Initialize new sealed root
	if err := Initialize(storeOpts...); err != nil {
		return fmt.Errorf("failed to initialize TPM root: %w", err)
	}

	rootSecret, err := GetSealedMasterKey(storeOpts...)
	if err != nil {
		return fmt.Errorf("failed to get new root: %w", err)
	}
	ks.rootSecret = rootSecret
	return nil
}

// deriveKEK derives the Key Encryption Key from the root secret.
func (ks *Keystore) deriveKEK() error {
	salt, err := ks.keyring.GetSalt()
	if err != nil {
		return fmt.Errorf("failed to get salt: %w", err)
	}

	kek, err := DeriveKey(ks.rootSecret, salt, ks.opts.kekInfo)
	if err != nil {
		return fmt.Errorf("failed to derive KEK: %w", err)
	}

	ks.kek = kek
	return nil
}

// Close securely wipes keys from memory and closes the keystore.
func (ks *Keystore) Close() error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if ks.closed {
		return nil
	}

	// Save any modifications
	if ks.keyring != nil && ks.keyring.IsModified() {
		if err := ks.keyring.Save(); err != nil {
			return fmt.Errorf("failed to save keyring: %w", err)
		}
	}

	for _, env := range ks.envelopes {
		if env.IsModified() {
			if err := env.Save(); err != nil {
				return fmt.Errorf("failed to save envelope: %w", err)
			}
		}
	}

	// Wipe sensitive data
	if ks.rootSecret != nil {
		SecureZero(ks.rootSecret)
		ks.rootSecret = nil
	}
	if ks.kek != nil {
		SecureZero(ks.kek)
		ks.kek = nil
	}
	if ks.keyring != nil {
		ks.keyring.Lock()
	}

	ks.closed = true
	return nil
}

// Save saves all modified data.
func (ks *Keystore) Save() error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if ks.closed {
		return ErrKeystoreClosed
	}

	if ks.keyring.IsModified() {
		if err := ks.keyring.Save(); err != nil {
			return fmt.Errorf("failed to save keyring: %w", err)
		}
	}

	for _, env := range ks.envelopes {
		if env.IsModified() {
			if err := env.Save(); err != nil {
				return fmt.Errorf("failed to save envelope: %w", err)
			}
		}
	}

	return nil
}

// CreateProfile creates a new profile with a generated master key.
func (ks *Keystore) CreateProfile(name string) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if ks.closed {
		return ErrKeystoreClosed
	}

	if err := ks.keyring.CreateProfile(name); err != nil {
		return err
	}

	if ks.opts.autoSave {
		return ks.keyring.Save()
	}
	return nil
}

// GetProfileKey returns the master key for a profile.
func (ks *Keystore) GetProfileKey(name string) ([]byte, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	if ks.closed {
		return nil, ErrKeystoreClosed
	}

	return ks.keyring.GetProfileKey(name)
}

// HasProfile checks if a profile exists.
func (ks *Keystore) HasProfile(name string) bool {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	if ks.closed {
		return false
	}

	return ks.keyring.HasProfile(name)
}

// DeleteProfile removes a profile and its master key.
func (ks *Keystore) DeleteProfile(name string) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if ks.closed {
		return ErrKeystoreClosed
	}

	// Delete envelope store if exists
	if env, ok := ks.envelopes[name]; ok {
		if err := env.Delete(); err != nil {
			return fmt.Errorf("failed to delete envelope store: %w", err)
		}
		delete(ks.envelopes, name)
	}

	if err := ks.keyring.DeleteProfile(name); err != nil {
		return err
	}

	if ks.opts.autoSave {
		return ks.keyring.Save()
	}
	return nil
}

// ListProfiles returns all profile names.
func (ks *Keystore) ListProfiles() []string {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	if ks.closed {
		return nil
	}

	return ks.keyring.ListProfiles()
}

// getEnvelopeStore returns the envelope store for a profile, creating if needed.
func (ks *Keystore) getEnvelopeStore(profile string) (*EnvelopeStore, error) {
	if env, ok := ks.envelopes[profile]; ok {
		return env, nil
	}

	env, err := NewEnvelopeStore(ks.path, profile)
	if err != nil {
		return nil, err
	}

	ks.envelopes[profile] = env
	return env, nil
}

// GetOrCreateDEK gets or creates a DEK for a profile and data type.
func (ks *Keystore) GetOrCreateDEK(profile, dekType string) ([]byte, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if ks.closed {
		return nil, ErrKeystoreClosed
	}

	masterKey, err := ks.keyring.GetProfileKey(profile)
	if err != nil {
		return nil, fmt.Errorf("failed to get profile key: %w", err)
	}
	defer SecureZero(masterKey)

	env, err := ks.getEnvelopeStore(profile)
	if err != nil {
		return nil, err
	}

	dek, err := env.GetOrCreateDEK(dekType, masterKey)
	if err != nil {
		return nil, err
	}

	if ks.opts.autoSave && env.IsModified() {
		if err := env.Save(); err != nil {
			SecureZero(dek)
			return nil, fmt.Errorf("failed to save envelope: %w", err)
		}
	}

	return dek, nil
}

// Encrypt encrypts data using the profile's DEK for the given type.
func (ks *Keystore) Encrypt(profile, dekType string, plaintext []byte) ([]byte, error) {
	dek, err := ks.GetOrCreateDEK(profile, dekType)
	if err != nil {
		return nil, err
	}
	defer SecureZero(dek)

	return Encrypt(dek, plaintext)
}

// Decrypt decrypts data using the profile's DEK for the given type.
func (ks *Keystore) Decrypt(profile, dekType string, ciphertext []byte) ([]byte, error) {
	dek, err := ks.GetOrCreateDEK(profile, dekType)
	if err != nil {
		return nil, err
	}
	defer SecureZero(dek)

	return Decrypt(dek, ciphertext)
}

// RotateDEK generates a new DEK for a profile and data type.
// Returns old and new DEK for re-encryption of existing data.
func (ks *Keystore) RotateDEK(profile, dekType string) (oldDEK, newDEK []byte, err error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if ks.closed {
		return nil, nil, ErrKeystoreClosed
	}

	masterKey, err := ks.keyring.GetProfileKey(profile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get profile key: %w", err)
	}
	defer SecureZero(masterKey)

	env, err := ks.getEnvelopeStore(profile)
	if err != nil {
		return nil, nil, err
	}

	oldDEK, newDEK, err = env.RotateDEK(dekType, masterKey)
	if err != nil {
		return nil, nil, err
	}

	if ks.opts.autoSave {
		if err := env.Save(); err != nil {
			SecureZero(oldDEK)
			SecureZero(newDEK)
			return nil, nil, fmt.Errorf("failed to save envelope: %w", err)
		}
	}

	return oldDEK, newDEK, nil
}

// RotateProfile generates a new master key for a profile and re-encrypts all DEKs.
func (ks *Keystore) RotateProfile(profile string) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if ks.closed {
		return ErrKeystoreClosed
	}

	// Rotate profile key in keyring
	oldKey, newKey, err := ks.keyring.RotateProfileKey(profile)
	if err != nil {
		return fmt.Errorf("failed to rotate profile key: %w", err)
	}
	defer func() {
		SecureZero(oldKey)
		SecureZero(newKey)
	}()

	// Re-encrypt DEKs with new master key
	env, err := ks.getEnvelopeStore(profile)
	if err != nil {
		return err
	}

	if err := env.ReEncryptWithNewMasterKey(oldKey, newKey); err != nil {
		return fmt.Errorf("failed to re-encrypt DEKs: %w", err)
	}

	// Save changes
	if err := ks.keyring.Save(); err != nil {
		return fmt.Errorf("failed to save keyring: %w", err)
	}
	if err := env.Save(); err != nil {
		return fmt.Errorf("failed to save envelope: %w", err)
	}

	return nil
}

// ExportEncryptedDEK exports a DEK encrypted with the profile's master key.
// For storage in SQLite alongside encrypted data.
func (ks *Keystore) ExportEncryptedDEK(profile, dekType string) ([]byte, int, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	if ks.closed {
		return nil, 0, ErrKeystoreClosed
	}

	env, err := ks.getEnvelopeStore(profile)
	if err != nil {
		return nil, 0, err
	}

	return env.ExportEncryptedDEK(dekType)
}

// ImportEncryptedDEK imports a DEK encrypted with the profile's master key.
func (ks *Keystore) ImportEncryptedDEK(profile, dekType string, encryptedDEK []byte, version int) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if ks.closed {
		return ErrKeystoreClosed
	}

	env, err := ks.getEnvelopeStore(profile)
	if err != nil {
		return err
	}

	if err := env.ImportEncryptedDEK(dekType, encryptedDEK, version); err != nil {
		return err
	}

	if ks.opts.autoSave {
		return env.Save()
	}
	return nil
}

// GetProfileKeyVersion returns the version of a profile's master key.
func (ks *Keystore) GetProfileKeyVersion(profile string) (int, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	if ks.closed {
		return 0, ErrKeystoreClosed
	}

	return ks.keyring.GetProfileVersion(profile)
}

// ProfileMetadata contains profile key metadata for rotation tracking.
type ProfileMetadata struct {
	Version   int
	CreatedAt time.Time
	RotatedAt time.Time
}

// GetProfileMetadata returns metadata for a profile's key.
func (ks *Keystore) GetProfileMetadata(profile string) (*ProfileMetadata, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	if ks.closed {
		return nil, ErrKeystoreClosed
	}

	return ks.keyring.GetProfileMetadata(profile)
}

// Path returns the keystore path.
func (ks *Keystore) Path() string {
	return ks.path
}

// IsOpen returns true if the keystore is open.
func (ks *Keystore) IsOpen() bool {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return !ks.closed
}
