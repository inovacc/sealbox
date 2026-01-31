package keystore

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// FileKeyStore implements KeyStore using the filesystem.
type FileKeyStore struct {
	storePath string
}

// KeyStoreOption configures a FileKeyStore.
type KeyStoreOption func(*FileKeyStore)

// WithStorePath sets a custom storage path directly.
// Use this when you want full control over where the sealed key is stored.
func WithStorePath(path string) KeyStoreOption {
	return func(s *FileKeyStore) {
		s.storePath = path
	}
}

// WithAppConfig sets the application name and file name for platform-specific path calculation.
// The path is calculated as:
//   - Linux: ~/.config/{appName}/{fileName}
//   - Windows: %LOCALAPPDATA%\{appName}\{fileName}
//   - macOS: ~/Library/Application Support/{appName}/{fileName}
func WithAppConfig(appName, fileName string) KeyStoreOption {
	return func(s *FileKeyStore) {
		if s.storePath == "" {
			s.storePath = getDefaultStorePath(appName, fileName)
		}
	}
}

// NewKeyStore creates a new FileKeyStore with the given options.
// At least one option (WithStorePath or WithAppConfig) must be provided.
func NewKeyStore(opts ...KeyStoreOption) (*FileKeyStore, error) {
	if len(opts) == 0 {
		return nil, ErrKeyStoreNotInitialized
	}

	s := &FileKeyStore{}

	for _, opt := range opts {
		opt(s)
	}

	if s.storePath == "" {
		return nil, ErrKeyStoreNotInitialized
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
	if data == nil {
		return fmt.Errorf("sealed data cannot be nil")
	}

	if s.storePath == "" {
		return ErrKeyStoreNotInitialized
	}

	// Ensure directory exists with restrictive permissions
	dir := filepath.Dir(s.storePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Set restrictive permissions on directory (platform-specific)
	// Non-fatal: continue even if ACL setting fails (MkdirAll already set basic Unix permissions)
	_ = setDirPermissions(dir)

	// Marshal the sealed data to JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal sealed data: %w", err)
	}

	// Write to file with restricted permissions (owner read/write only)
	if err := os.WriteFile(s.storePath, jsonData, 0600); err != nil {
		return fmt.Errorf("failed to write sealed key file: %w", err)
	}

	// Set restrictive permissions on file (platform-specific)
	// Non-fatal: continue even if ACL setting fails (WriteFile already set basic Unix permissions)
	_ = setFilePermissions(s.storePath)

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
