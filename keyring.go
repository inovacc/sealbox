package sealbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	// ErrProfileNotFound is returned when a profile doesn't exist in the keyring.
	ErrProfileNotFound = errors.New("profile not found in keyring")

	// ErrProfileExists is returned when trying to create a profile that already exists.
	ErrProfileExists = errors.New("profile already exists in keyring")

	// ErrKeyringLocked is returned when trying to access a locked keyring.
	ErrKeyringLocked = errors.New("keyring is locked")

	// ErrKeyringNotInitialized is returned when the keyring has no KEK.
	ErrKeyringNotInitialized = errors.New("keyring not initialized (no KEK)")
)

// ProfileKey represents a profile's master key and metadata.
type ProfileKey struct {
	// EncryptedKey is the master key encrypted with the KEK.
	EncryptedKey []byte `json:"encrypted_key"`

	// Version tracks key rotations.
	Version int `json:"version"`

	// CreatedAt is when the profile was created.
	CreatedAt time.Time `json:"created_at"`

	// RotatedAt is when the key was last rotated.
	RotatedAt time.Time `json:"rotated_at,omitempty"`
}

// KeyringData is the serializable representation of a keyring.
type KeyringData struct {
	Version  int                    `json:"version"`
	Salt     []byte                 `json:"salt"`
	Profiles map[string]*ProfileKey `json:"profiles"`
}

const keyringVersion = 1

// Keyring manages per-profile master keys, encrypted with a KEK.
type Keyring struct {
	mu       sync.RWMutex
	basePath string
	kek      []byte // Key Encryption Key (derived from root secret)
	salt     []byte
	profiles map[string]*ProfileKey
	modified bool
}

// NewKeyring creates a new keyring at the given path.
// The KEK must be set via SetKEK before any operations.
func NewKeyring(basePath string) (*Keyring, error) {
	if basePath == "" {
		return nil, errors.New("base path cannot be empty")
	}

	kr := &Keyring{
		basePath: basePath,
		profiles: make(map[string]*ProfileKey),
	}

	// Try to load existing keyring
	if err := kr.load(); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to load keyring: %w", err)
	}

	return kr, nil
}

// keyringFilePath returns the path to the keyring file.
func (kr *Keyring) keyringFilePath() string {
	return filepath.Join(kr.basePath, "keyring.json")
}

// load loads the keyring from disk.
func (kr *Keyring) load() error {
	data, err := os.ReadFile(kr.keyringFilePath())
	if err != nil {
		return err
	}

	var kd KeyringData
	if err := json.Unmarshal(data, &kd); err != nil {
		return fmt.Errorf("failed to unmarshal keyring: %w", err)
	}

	kr.salt = kd.Salt
	kr.profiles = kd.Profiles
	if kr.profiles == nil {
		kr.profiles = make(map[string]*ProfileKey)
	}
	kr.modified = false

	return nil
}

// Save persists the keyring to disk.
func (kr *Keyring) Save() error {
	kr.mu.Lock()
	defer kr.mu.Unlock()

	return kr.saveLocked()
}

func (kr *Keyring) saveLocked() error {
	if err := os.MkdirAll(kr.basePath, 0700); err != nil {
		return fmt.Errorf("failed to create keyring directory: %w", err)
	}

	kd := KeyringData{
		Version:  keyringVersion,
		Salt:     kr.salt,
		Profiles: kr.profiles,
	}

	data, err := json.MarshalIndent(kd, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal keyring: %w", err)
	}

	filePath := kr.keyringFilePath()
	if err := os.WriteFile(filePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write keyring: %w", err)
	}

	// Platform-specific permissions
	_ = setFilePermissions(filePath)
	_ = setDirPermissions(kr.basePath)

	kr.modified = false
	return nil
}

// SetKEK sets the Key Encryption Key used to encrypt/decrypt profile master keys.
// This must be called after loading the keyring and before any profile operations.
func (kr *Keyring) SetKEK(kek []byte) error {
	if len(kek) != KeySize {
		return ErrInvalidKeySize
	}

	kr.mu.Lock()
	defer kr.mu.Unlock()

	// Copy to prevent external modification
	kr.kek = make([]byte, KeySize)
	copy(kr.kek, kek)

	return nil
}

// IsUnlocked returns true if the keyring has a KEK set.
func (kr *Keyring) IsUnlocked() bool {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	return len(kr.kek) == KeySize
}

// Lock clears the KEK from memory.
func (kr *Keyring) Lock() {
	kr.mu.Lock()
	defer kr.mu.Unlock()

	if kr.kek != nil {
		SecureZero(kr.kek)
		kr.kek = nil
	}
}

// GetSalt returns the keyring salt, generating one if needed.
func (kr *Keyring) GetSalt() ([]byte, error) {
	kr.mu.Lock()
	defer kr.mu.Unlock()

	if len(kr.salt) == 0 {
		salt, err := GenerateSalt()
		if err != nil {
			return nil, err
		}
		kr.salt = salt
		kr.modified = true
	}

	// Return a copy
	salt := make([]byte, len(kr.salt))
	copy(salt, kr.salt)
	return salt, nil
}

// CreateProfile creates a new profile with a randomly generated master key.
func (kr *Keyring) CreateProfile(name string) error {
	kr.mu.Lock()
	defer kr.mu.Unlock()

	if len(kr.kek) != KeySize {
		return ErrKeyringLocked
	}

	if _, exists := kr.profiles[name]; exists {
		return ErrProfileExists
	}

	// Generate a new master key
	masterKey, err := GenerateKey()
	if err != nil {
		return fmt.Errorf("failed to generate master key: %w", err)
	}
	defer SecureZero(masterKey)

	// Encrypt with KEK
	encryptedKey, err := Encrypt(kr.kek, masterKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt master key: %w", err)
	}

	kr.profiles[name] = &ProfileKey{
		EncryptedKey: encryptedKey,
		Version:      1,
		CreatedAt:    time.Now(),
	}
	kr.modified = true

	return nil
}

// GetProfileKey retrieves and decrypts a profile's master key.
func (kr *Keyring) GetProfileKey(name string) ([]byte, error) {
	kr.mu.RLock()
	defer kr.mu.RUnlock()

	if len(kr.kek) != KeySize {
		return nil, ErrKeyringLocked
	}

	profile, exists := kr.profiles[name]
	if !exists {
		return nil, ErrProfileNotFound
	}

	masterKey, err := Decrypt(kr.kek, profile.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt master key: %w", err)
	}

	return masterKey, nil
}

// HasProfile checks if a profile exists.
func (kr *Keyring) HasProfile(name string) bool {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	_, exists := kr.profiles[name]
	return exists
}

// DeleteProfile removes a profile from the keyring.
func (kr *Keyring) DeleteProfile(name string) error {
	kr.mu.Lock()
	defer kr.mu.Unlock()

	if _, exists := kr.profiles[name]; !exists {
		return ErrProfileNotFound
	}

	delete(kr.profiles, name)
	kr.modified = true
	return nil
}

// ListProfiles returns all profile names.
func (kr *Keyring) ListProfiles() []string {
	kr.mu.RLock()
	defer kr.mu.RUnlock()

	names := make([]string, 0, len(kr.profiles))
	for name := range kr.profiles {
		names = append(names, name)
	}
	return names
}

// RotateProfileKey generates a new master key for a profile.
// Returns the old key (for re-encryption) and updates the profile.
func (kr *Keyring) RotateProfileKey(name string) (oldKey, newKey []byte, err error) {
	kr.mu.Lock()
	defer kr.mu.Unlock()

	if len(kr.kek) != KeySize {
		return nil, nil, ErrKeyringLocked
	}

	profile, exists := kr.profiles[name]
	if !exists {
		return nil, nil, ErrProfileNotFound
	}

	// Decrypt old key
	oldKey, err = Decrypt(kr.kek, profile.EncryptedKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decrypt old key: %w", err)
	}

	// Generate new key
	newKey, err = GenerateKey()
	if err != nil {
		SecureZero(oldKey)
		return nil, nil, fmt.Errorf("failed to generate new key: %w", err)
	}

	// Encrypt new key
	encryptedKey, err := Encrypt(kr.kek, newKey)
	if err != nil {
		SecureZero(oldKey)
		SecureZero(newKey)
		return nil, nil, fmt.Errorf("failed to encrypt new key: %w", err)
	}

	profile.EncryptedKey = encryptedKey
	profile.Version++
	profile.RotatedAt = time.Now()
	kr.modified = true

	return oldKey, newKey, nil
}

// GetProfileVersion returns the version of a profile's key.
func (kr *Keyring) GetProfileVersion(name string) (int, error) {
	kr.mu.RLock()
	defer kr.mu.RUnlock()

	profile, exists := kr.profiles[name]
	if !exists {
		return 0, ErrProfileNotFound
	}
	return profile.Version, nil
}

// IsModified returns true if the keyring has unsaved changes.
func (kr *Keyring) IsModified() bool {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	return kr.modified
}

// ReEncryptWithNewKEK re-encrypts all profile keys with a new KEK.
// Used during root secret rotation.
func (kr *Keyring) ReEncryptWithNewKEK(newKEK []byte) error {
	if len(newKEK) != KeySize {
		return ErrInvalidKeySize
	}

	kr.mu.Lock()
	defer kr.mu.Unlock()

	if len(kr.kek) != KeySize {
		return ErrKeyringLocked
	}

	for name, profile := range kr.profiles {
		// Decrypt with old KEK
		masterKey, err := Decrypt(kr.kek, profile.EncryptedKey)
		if err != nil {
			return fmt.Errorf("failed to decrypt profile '%s': %w", name, err)
		}

		// Re-encrypt with new KEK
		encryptedKey, err := Encrypt(newKEK, masterKey)
		SecureZero(masterKey)
		if err != nil {
			return fmt.Errorf("failed to re-encrypt profile '%s': %w", name, err)
		}

		profile.EncryptedKey = encryptedKey
	}

	// Update KEK
	copy(kr.kek, newKEK)
	kr.modified = true

	return nil
}
