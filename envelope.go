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
	// ErrDEKNotFound is returned when a DEK doesn't exist.
	ErrDEKNotFound = errors.New("DEK not found")

	// ErrDEKExists is returned when trying to create a DEK that already exists.
	ErrDEKExists = errors.New("DEK already exists")
)

// DEK represents a Data Encryption Key used for envelope encryption.
type DEK struct {
	// EncryptedKey is the DEK encrypted with the profile's master key.
	EncryptedKey []byte `json:"encrypted_key"`

	// Version tracks DEK rotations.
	Version int `json:"version"`

	// CreatedAt is when the DEK was created.
	CreatedAt time.Time `json:"created_at"`

	// RotatedAt is when the DEK was last rotated.
	RotatedAt time.Time `json:"rotated_at,omitempty"`
}

// DEKStoreData is the serializable representation of DEKs for a profile.
type DEKStoreData struct {
	Version int             `json:"version"`
	DEKs    map[string]*DEK `json:"deks"` // dekType -> DEK
}

const dekStoreVersion = 1

// EnvelopeStore manages Data Encryption Keys (DEKs) for envelope encryption.
// Each profile has its own DEK store, and each DEK type (e.g., "token", "config")
// has a separate DEK encrypted with the profile's master key.
type EnvelopeStore struct {
	mu       sync.RWMutex
	basePath string
	profile  string
	deks     map[string]*DEK
	modified bool
}

// NewEnvelopeStore creates a new envelope store for a profile.
func NewEnvelopeStore(basePath, profile string) (*EnvelopeStore, error) {
	if basePath == "" {
		return nil, errors.New("base path cannot be empty")
	}
	if profile == "" {
		return nil, errors.New("profile cannot be empty")
	}

	es := &EnvelopeStore{
		basePath: basePath,
		profile:  profile,
		deks:     make(map[string]*DEK),
	}

	if err := es.load(); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to load DEK store: %w", err)
	}

	return es, nil
}

// dekFilePath returns the path to the DEK store file.
func (es *EnvelopeStore) dekFilePath() string {
	return filepath.Join(es.basePath, "deks", es.profile+".json")
}

// load loads the DEK store from disk.
func (es *EnvelopeStore) load() error {
	data, err := os.ReadFile(es.dekFilePath())
	if err != nil {
		return err
	}

	var sd DEKStoreData
	if err := json.Unmarshal(data, &sd); err != nil {
		return fmt.Errorf("failed to unmarshal DEK store: %w", err)
	}

	es.deks = sd.DEKs
	if es.deks == nil {
		es.deks = make(map[string]*DEK)
	}
	es.modified = false

	return nil
}

// Save persists the DEK store to disk.
func (es *EnvelopeStore) Save() error {
	es.mu.Lock()
	defer es.mu.Unlock()

	return es.saveLocked()
}

func (es *EnvelopeStore) saveLocked() error {
	dir := filepath.Dir(es.dekFilePath())
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create DEK directory: %w", err)
	}

	sd := DEKStoreData{
		Version: dekStoreVersion,
		DEKs:    es.deks,
	}

	data, err := json.MarshalIndent(sd, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal DEK store: %w", err)
	}

	filePath := es.dekFilePath()
	if err := os.WriteFile(filePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write DEK store: %w", err)
	}

	_ = setFilePermissions(filePath)
	_ = setDirPermissions(dir)

	es.modified = false
	return nil
}

// GetOrCreateDEK returns an existing DEK or creates a new one.
// The masterKey is the profile's master key used to encrypt/decrypt the DEK.
func (es *EnvelopeStore) GetOrCreateDEK(dekType string, masterKey []byte) ([]byte, error) {
	es.mu.Lock()
	defer es.mu.Unlock()

	if len(masterKey) != KeySize {
		return nil, ErrInvalidKeySize
	}

	// Check if DEK exists
	if dek, exists := es.deks[dekType]; exists {
		// Decrypt and return
		return Decrypt(masterKey, dek.EncryptedKey)
	}

	// Create new DEK
	dekKey, err := GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate DEK: %w", err)
	}

	// Encrypt with master key
	encryptedKey, err := Encrypt(masterKey, dekKey)
	if err != nil {
		SecureZero(dekKey)
		return nil, fmt.Errorf("failed to encrypt DEK: %w", err)
	}

	es.deks[dekType] = &DEK{
		EncryptedKey: encryptedKey,
		Version:      1,
		CreatedAt:    time.Now(),
	}
	es.modified = true

	return dekKey, nil
}

// GetDEK retrieves a DEK by type.
func (es *EnvelopeStore) GetDEK(dekType string, masterKey []byte) ([]byte, error) {
	es.mu.RLock()
	defer es.mu.RUnlock()

	if len(masterKey) != KeySize {
		return nil, ErrInvalidKeySize
	}

	dek, exists := es.deks[dekType]
	if !exists {
		return nil, ErrDEKNotFound
	}

	return Decrypt(masterKey, dek.EncryptedKey)
}

// HasDEK checks if a DEK exists.
func (es *EnvelopeStore) HasDEK(dekType string) bool {
	es.mu.RLock()
	defer es.mu.RUnlock()
	_, exists := es.deks[dekType]
	return exists
}

// DeleteDEK removes a DEK.
func (es *EnvelopeStore) DeleteDEK(dekType string) error {
	es.mu.Lock()
	defer es.mu.Unlock()

	if _, exists := es.deks[dekType]; !exists {
		return ErrDEKNotFound
	}

	delete(es.deks, dekType)
	es.modified = true
	return nil
}

// ListDEKTypes returns all DEK types.
func (es *EnvelopeStore) ListDEKTypes() []string {
	es.mu.RLock()
	defer es.mu.RUnlock()

	types := make([]string, 0, len(es.deks))
	for t := range es.deks {
		types = append(types, t)
	}
	return types
}

// RotateDEK generates a new DEK and returns both old and new keys.
// The caller must re-encrypt data with the new key and call Save.
func (es *EnvelopeStore) RotateDEK(dekType string, masterKey []byte) (oldKey, newKey []byte, err error) {
	es.mu.Lock()
	defer es.mu.Unlock()

	if len(masterKey) != KeySize {
		return nil, nil, ErrInvalidKeySize
	}

	dek, exists := es.deks[dekType]
	if !exists {
		return nil, nil, ErrDEKNotFound
	}

	// Decrypt old DEK
	oldKey, err = Decrypt(masterKey, dek.EncryptedKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decrypt old DEK: %w", err)
	}

	// Generate new DEK
	newKey, err = GenerateKey()
	if err != nil {
		SecureZero(oldKey)
		return nil, nil, fmt.Errorf("failed to generate new DEK: %w", err)
	}

	// Encrypt new DEK
	encryptedKey, err := Encrypt(masterKey, newKey)
	if err != nil {
		SecureZero(oldKey)
		SecureZero(newKey)
		return nil, nil, fmt.Errorf("failed to encrypt new DEK: %w", err)
	}

	dek.EncryptedKey = encryptedKey
	dek.Version++
	dek.RotatedAt = time.Now()
	es.modified = true

	return oldKey, newKey, nil
}

// ReEncryptWithNewMasterKey re-encrypts all DEKs with a new master key.
// Used during profile key rotation.
func (es *EnvelopeStore) ReEncryptWithNewMasterKey(oldMasterKey, newMasterKey []byte) error {
	es.mu.Lock()
	defer es.mu.Unlock()

	if len(oldMasterKey) != KeySize || len(newMasterKey) != KeySize {
		return ErrInvalidKeySize
	}

	for dekType, dek := range es.deks {
		// Decrypt with old master key
		dekKey, err := Decrypt(oldMasterKey, dek.EncryptedKey)
		if err != nil {
			return fmt.Errorf("failed to decrypt DEK '%s': %w", dekType, err)
		}

		// Re-encrypt with new master key
		encryptedKey, err := Encrypt(newMasterKey, dekKey)
		SecureZero(dekKey)
		if err != nil {
			return fmt.Errorf("failed to re-encrypt DEK '%s': %w", dekType, err)
		}

		dek.EncryptedKey = encryptedKey
	}

	es.modified = true
	return nil
}

// GetDEKVersion returns the version of a DEK.
func (es *EnvelopeStore) GetDEKVersion(dekType string) (int, error) {
	es.mu.RLock()
	defer es.mu.RUnlock()

	dek, exists := es.deks[dekType]
	if !exists {
		return 0, ErrDEKNotFound
	}
	return dek.Version, nil
}

// IsModified returns true if the store has unsaved changes.
func (es *EnvelopeStore) IsModified() bool {
	es.mu.RLock()
	defer es.mu.RUnlock()
	return es.modified
}

// Delete removes the DEK store file from disk.
func (es *EnvelopeStore) Delete() error {
	es.mu.Lock()
	defer es.mu.Unlock()

	filePath := es.dekFilePath()
	if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete DEK store: %w", err)
	}

	es.deks = make(map[string]*DEK)
	es.modified = false
	return nil
}

// ExportEncryptedDEK returns the encrypted DEK for external storage.
// Useful for storing alongside encrypted data (e.g., in SQLite).
func (es *EnvelopeStore) ExportEncryptedDEK(dekType string) ([]byte, int, error) {
	es.mu.RLock()
	defer es.mu.RUnlock()

	dek, exists := es.deks[dekType]
	if !exists {
		return nil, 0, ErrDEKNotFound
	}

	// Return a copy
	encrypted := make([]byte, len(dek.EncryptedKey))
	copy(encrypted, dek.EncryptedKey)
	return encrypted, dek.Version, nil
}

// ImportEncryptedDEK imports a DEK from external storage.
func (es *EnvelopeStore) ImportEncryptedDEK(dekType string, encryptedKey []byte, version int) error {
	es.mu.Lock()
	defer es.mu.Unlock()

	if len(encryptedKey) == 0 {
		return errors.New("encrypted key cannot be empty")
	}

	es.deks[dekType] = &DEK{
		EncryptedKey: encryptedKey,
		Version:      version,
		CreatedAt:    time.Now(),
	}
	es.modified = true
	return nil
}
