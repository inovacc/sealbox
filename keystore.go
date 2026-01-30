package tpm

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

const (
	// DefaultKeyFileName is the default name of the file storing the sealed key
	DefaultKeyFileName = ".clonr_sealed_key"

	// DefaultAppName is the default application name for storage paths
	DefaultAppName = "clonr"
)

// FileKeyStore implements KeyStore using the filesystem.
type FileKeyStore struct {
	storePath string
}

// KeyStoreOption configures a FileKeyStore.
type KeyStoreOption func(*FileKeyStore)

// WithStorePath sets a custom storage path.
func WithStorePath(path string) KeyStoreOption {
	return func(s *FileKeyStore) {
		s.storePath = path
	}
}

// WithAppName sets the application name for default path calculation.
func WithAppName(appName string) KeyStoreOption {
	return func(s *FileKeyStore) {
		if s.storePath == "" {
			s.storePath = getDefaultStorePath(appName, DefaultKeyFileName)
		}
	}
}

// WithFileName sets the key file name for default path calculation.
func WithFileName(fileName string) KeyStoreOption {
	return func(s *FileKeyStore) {
		if s.storePath == "" {
			s.storePath = getDefaultStorePath(DefaultAppName, fileName)
		}
	}
}

// NewKeyStore creates a new FileKeyStore with the given options.
func NewKeyStore(opts ...KeyStoreOption) (*FileKeyStore, error) {
	s := &FileKeyStore{}

	for _, opt := range opts {
		opt(s)
	}

	// Use default path if not set
	if s.storePath == "" {
		s.storePath = getDefaultStorePath(DefaultAppName, DefaultKeyFileName)
	}

	return s, nil
}

// getDefaultStorePath returns the platform-specific default storage path.
func getDefaultStorePath(appName, fileName string) string {
	var configDir string

	switch runtime.GOOS {
	case "windows":
		configDir = os.Getenv("LOCALAPPDATA")
		if configDir == "" {
			configDir = os.Getenv("APPDATA")
		}
		configDir = filepath.Join(configDir, appName)

	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			home = "."
		}
		configDir = filepath.Join(home, "Library", "Application Support", appName)

	default: // linux and others
		configDir = os.Getenv("XDG_CONFIG_HOME")
		if configDir == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				home = "."
			}
			configDir = filepath.Join(home, ".config", appName)
		} else {
			configDir = filepath.Join(configDir, appName)
		}
	}

	return filepath.Join(configDir, fileName)
}

// Save stores sealed data to disk.
func (s *FileKeyStore) Save(data *SealedData) error {
	if s.storePath == "" {
		return ErrKeyStoreNotInitialized
	}

	// Ensure directory exists
	dir := filepath.Dir(s.storePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Marshal the sealed data to JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal sealed data: %w", err)
	}

	// Write to file with restricted permissions (owner read/write only)
	if err := os.WriteFile(s.storePath, jsonData, 0600); err != nil {
		return fmt.Errorf("failed to write sealed key file: %w", err)
	}

	return nil
}

// Load retrieves sealed data from disk.
func (s *FileKeyStore) Load() (*SealedData, error) {
	if s.storePath == "" {
		return nil, ErrKeyStoreNotInitialized
	}

	jsonData, err := os.ReadFile(s.storePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNoSealedKey
		}
		return nil, fmt.Errorf("failed to read sealed key file: %w", err)
	}

	var data SealedData
	if err := json.Unmarshal(jsonData, &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal sealed data: %w", err)
	}

	return &data, nil
}

// Exists checks if sealed data exists on disk.
func (s *FileKeyStore) Exists() bool {
	if s.storePath == "" {
		return false
	}
	_, err := os.Stat(s.storePath)
	return err == nil
}

// Delete removes sealed data from disk.
func (s *FileKeyStore) Delete() error {
	if s.storePath == "" {
		return ErrKeyStoreNotInitialized
	}

	if err := os.Remove(s.storePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete sealed key: %w", err)
	}

	return nil
}

// Path returns the storage path.
func (s *FileKeyStore) Path() string {
	return s.storePath
}
