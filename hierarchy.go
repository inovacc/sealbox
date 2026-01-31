//go:build linux || windows

package keystore

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// KeyHierarchy manages multiple sealed keys under a common storage.
// Each key is identified by a unique name within the hierarchy.
type KeyHierarchy struct {
	mu       sync.RWMutex
	basePath string
	keys     map[string]*SealedData
	modified bool
}

// KeyHierarchyData is the serializable representation of a key hierarchy.
type KeyHierarchyData struct {
	Version int                    `json:"version"`
	Keys    map[string]*SealedData `json:"keys"`
}

const keyHierarchyVersion = 1

// NewKeyHierarchy creates a new key hierarchy with the given base storage path.
// The base path should be a directory where the hierarchy file will be stored.
func NewKeyHierarchy(basePath string) (*KeyHierarchy, error) {
	if basePath == "" {
		return nil, fmt.Errorf("base path cannot be empty")
	}

	h := &KeyHierarchy{
		basePath: basePath,
		keys:     make(map[string]*SealedData),
	}

	// Try to load existing hierarchy
	if err := h.load(); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to load key hierarchy: %w", err)
	}

	return h, nil
}

// hierarchyFilePath returns the path to the hierarchy data file.
func (h *KeyHierarchy) hierarchyFilePath() string {
	return filepath.Join(h.basePath, "hierarchy.json")
}

// load loads the hierarchy from disk.
func (h *KeyHierarchy) load() error {
	data, err := os.ReadFile(h.hierarchyFilePath())
	if err != nil {
		return err
	}

	var hd KeyHierarchyData
	if err := json.Unmarshal(data, &hd); err != nil {
		return fmt.Errorf("failed to unmarshal hierarchy data: %w", err)
	}

	h.keys = hd.Keys
	if h.keys == nil {
		h.keys = make(map[string]*SealedData)
	}
	h.modified = false

	return nil
}

// Save persists the hierarchy to disk.
func (h *KeyHierarchy) Save() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Create directory if it doesn't exist
	if err := os.MkdirAll(h.basePath, 0700); err != nil {
		return fmt.Errorf("failed to create hierarchy directory: %w", err)
	}

	hd := KeyHierarchyData{
		Version: keyHierarchyVersion,
		Keys:    h.keys,
	}

	data, err := json.MarshalIndent(hd, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal hierarchy data: %w", err)
	}

	filePath := h.hierarchyFilePath()
	if err := os.WriteFile(filePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write hierarchy file: %w", err)
	}

	// Apply platform-specific permissions
	if err := setFilePermissions(filePath); err != nil {
		return fmt.Errorf("failed to set file permissions: %w", err)
	}
	if err := setDirPermissions(h.basePath); err != nil {
		return fmt.Errorf("failed to set directory permissions: %w", err)
	}

	h.modified = false
	return nil
}

// Add adds a new sealed key to the hierarchy.
// Returns an error if a key with the same name already exists.
func (h *KeyHierarchy) Add(name string, data *SealedData) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if name == "" {
		return fmt.Errorf("key name cannot be empty")
	}
	if data == nil {
		return fmt.Errorf("sealed data cannot be nil")
	}
	if _, exists := h.keys[name]; exists {
		return fmt.Errorf("key '%s' already exists in hierarchy", name)
	}

	h.keys[name] = data
	h.modified = true
	return nil
}

// Get retrieves a sealed key from the hierarchy by name.
func (h *KeyHierarchy) Get(name string) (*SealedData, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	data, exists := h.keys[name]
	return data, exists
}

// Remove removes a key from the hierarchy.
// Returns true if the key was found and removed.
func (h *KeyHierarchy) Remove(name string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	if _, exists := h.keys[name]; !exists {
		return false
	}

	delete(h.keys, name)
	h.modified = true
	return true
}

// List returns the names of all keys in the hierarchy.
func (h *KeyHierarchy) List() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	names := make([]string, 0, len(h.keys))
	for name := range h.keys {
		names = append(names, name)
	}
	return names
}

// Count returns the number of keys in the hierarchy.
func (h *KeyHierarchy) Count() int {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return len(h.keys)
}

// Exists checks if a key with the given name exists in the hierarchy.
func (h *KeyHierarchy) Exists(name string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()

	_, exists := h.keys[name]
	return exists
}

// IsModified returns true if the hierarchy has been modified since last save.
func (h *KeyHierarchy) IsModified() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return h.modified
}

// Clear removes all keys from the hierarchy.
func (h *KeyHierarchy) Clear() {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.keys = make(map[string]*SealedData)
	h.modified = true
}

// Delete removes the hierarchy file from disk.
func (h *KeyHierarchy) Delete() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	filePath := h.hierarchyFilePath()
	if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete hierarchy file: %w", err)
	}

	h.keys = make(map[string]*SealedData)
	h.modified = false
	return nil
}

// KeyHierarchyManager combines KeyManager with KeyHierarchy for convenient
// operations that seal/unseal keys directly into the hierarchy.
type KeyHierarchyManager struct {
	km KeyManager
	h  *KeyHierarchy
}

// NewKeyHierarchyManager creates a new manager combining a KeyManager with a KeyHierarchy.
func NewKeyHierarchyManager(km KeyManager, basePath string) (*KeyHierarchyManager, error) {
	h, err := NewKeyHierarchy(basePath)
	if err != nil {
		return nil, err
	}

	return &KeyHierarchyManager{
		km: km,
		h:  h,
	}, nil
}

// Hierarchy returns the underlying KeyHierarchy.
func (m *KeyHierarchyManager) Hierarchy() *KeyHierarchy {
	return m.h
}

// KeyManager returns the underlying KeyManager.
func (m *KeyHierarchyManager) KeyManager() KeyManager {
	return m.km
}

// GenerateKey generates a new random key, seals it, and adds it to the hierarchy.
func (m *KeyHierarchyManager) GenerateKey(name string) error {
	sealed, err := m.km.GenerateAndSealKey()
	if err != nil {
		return fmt.Errorf("failed to generate and seal key: %w", err)
	}

	if err := m.h.Add(name, sealed); err != nil {
		return err
	}

	return nil
}

// GenerateKeyWithOptions generates a new random key with options, seals it,
// and adds it to the hierarchy.
func (m *KeyHierarchyManager) GenerateKeyWithOptions(name string, opts ...SealOption) error {
	kmWithOpts, ok := m.km.(KeyManagerWithOptions)
	if !ok {
		return fmt.Errorf("key manager does not support options")
	}

	sealed, err := kmWithOpts.GenerateAndSealKeyWithOptions(opts...)
	if err != nil {
		return fmt.Errorf("failed to generate and seal key with options: %w", err)
	}

	if err := m.h.Add(name, sealed); err != nil {
		return err
	}

	return nil
}

// SealKey seals the provided key and adds it to the hierarchy.
func (m *KeyHierarchyManager) SealKey(name string, key []byte) error {
	sealed, err := m.km.SealKey(key)
	if err != nil {
		return fmt.Errorf("failed to seal key: %w", err)
	}

	if err := m.h.Add(name, sealed); err != nil {
		return err
	}

	return nil
}

// UnsealKey retrieves and unseals a key from the hierarchy.
func (m *KeyHierarchyManager) UnsealKey(name string) ([]byte, error) {
	sealed, exists := m.h.Get(name)
	if !exists {
		return nil, fmt.Errorf("key '%s' not found in hierarchy", name)
	}

	key, err := m.km.UnsealKey(sealed)
	if err != nil {
		return nil, fmt.Errorf("failed to unseal key '%s': %w", name, err)
	}

	return key, nil
}

// UnsealKeyWithOptions retrieves and unseals a key that requires options.
func (m *KeyHierarchyManager) UnsealKeyWithOptions(name string, opts ...SealOption) ([]byte, error) {
	sealed, exists := m.h.Get(name)
	if !exists {
		return nil, fmt.Errorf("key '%s' not found in hierarchy", name)
	}

	kmWithOpts, ok := m.km.(KeyManagerWithOptions)
	if !ok {
		return nil, fmt.Errorf("key manager does not support options")
	}

	key, err := kmWithOpts.UnsealKeyWithOptions(sealed, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to unseal key '%s': %w", name, err)
	}

	return key, nil
}

// Save saves the hierarchy to disk.
func (m *KeyHierarchyManager) Save() error {
	return m.h.Save()
}

// Close closes the key manager and optionally saves the hierarchy.
func (m *KeyHierarchyManager) Close(save bool) error {
	if save && m.h.IsModified() {
		if err := m.h.Save(); err != nil {
			return err
		}
	}
	return m.km.Close()
}
