package sealbox

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Tests for the testable helper variants (InitializeWith, GetSealedMasterKeyWith)

func TestInitializeWith(t *testing.T) {
	km := NewMockKeyManager()
	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "test.key")

	err := InitializeWith(km, WithStorePath(storePath))
	if err != nil {
		t.Fatalf("InitializeWith failed: %v", err)
	}

	// Verify the file was created
	if _, err := os.Stat(storePath); os.IsNotExist(err) {
		t.Error("sealed key file was not created")
	}
}

func TestInitializeWith_KeyExists(t *testing.T) {
	km := NewMockKeyManager()
	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "test.key")

	// First initialization should succeed
	err := InitializeWith(km, WithStorePath(storePath))
	if err != nil {
		t.Fatalf("first InitializeWith failed: %v", err)
	}

	// Second initialization should fail with ErrKeyExists
	err = InitializeWith(km, WithStorePath(storePath))
	if !errors.Is(err, ErrKeyExists) {
		t.Errorf("expected ErrKeyExists, got %v", err)
	}
}

func TestInitializeWith_NoOptions(t *testing.T) {
	km := NewMockKeyManager()

	err := InitializeWith(km)
	if !errors.Is(err, ErrKeyStoreNotInitialized) {
		t.Errorf("expected ErrKeyStoreNotInitialized, got %v", err)
	}
}

func TestInitializeWith_GenerateError(t *testing.T) {
	customErr := errors.New("generate failed")
	km := NewMockKeyManager()
	km.GenerateFunc = func() (*SealedData, error) {
		return nil, customErr
	}

	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "test.key")

	err := InitializeWith(km, WithStorePath(storePath))
	if err == nil {
		t.Fatal("expected error")
	}

	if !errors.Is(err, customErr) {
		t.Errorf("expected wrapped custom error, got %v", err)
	}
}

func TestGetSealedMasterKeyWith(t *testing.T) {
	km := NewMockKeyManager()
	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "test.key")

	// Initialize first
	err := InitializeWith(km, WithStorePath(storePath))
	if err != nil {
		t.Fatalf("InitializeWith failed: %v", err)
	}

	// Retrieve the key
	key, err := GetSealedMasterKeyWith(km, WithStorePath(storePath))
	if err != nil {
		t.Fatalf("GetSealedMasterKeyWith failed: %v", err)
	}

	if len(key) != sealedKeySize {
		t.Errorf("expected key size %d, got %d", sealedKeySize, len(key))
	}
}

func TestGetSealedMasterKeyWith_NoKey(t *testing.T) {
	km := NewMockKeyManager()
	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "nonexistent.key")

	_, err := GetSealedMasterKeyWith(km, WithStorePath(storePath))
	if !errors.Is(err, ErrNoSealedKey) {
		t.Errorf("expected ErrNoSealedKey, got %v", err)
	}
}

func TestGetSealedMasterKeyWith_NoOptions(t *testing.T) {
	km := NewMockKeyManager()

	_, err := GetSealedMasterKeyWith(km)
	if !errors.Is(err, ErrKeyStoreNotInitialized) {
		t.Errorf("expected ErrKeyStoreNotInitialized, got %v", err)
	}
}

func TestGetSealedMasterKeyWith_UnsealError(t *testing.T) {
	// Use two separate mock key managers to simulate different TPMs
	km1 := NewMockKeyManager()
	km2 := NewMockKeyManager()

	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "test.key")

	// Initialize with km1
	err := InitializeWith(km1, WithStorePath(storePath))
	if err != nil {
		t.Fatalf("InitializeWith failed: %v", err)
	}

	// Try to unseal with km2 (different mock, doesn't know the key)
	_, err = GetSealedMasterKeyWith(km2, WithStorePath(storePath))
	if err == nil {
		t.Fatal("expected error when unsealing with different key manager")
	}
}

func TestHasKey_WithMock(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "test.key")

	// Should return false when no key exists
	if HasKey(WithStorePath(storePath)) {
		t.Error("expected HasKey to return false for nonexistent key")
	}

	// Create a key using mock
	km := NewMockKeyManager()

	err := InitializeWith(km, WithStorePath(storePath))
	if err != nil {
		t.Fatalf("InitializeWith failed: %v", err)
	}

	// Should return true now
	if !HasKey(WithStorePath(storePath)) {
		t.Error("expected HasKey to return true after initialization")
	}
}

func TestReset_WithMock(t *testing.T) {
	km := NewMockKeyManager()
	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "test.key")

	// Initialize
	err := InitializeWith(km, WithStorePath(storePath))
	if err != nil {
		t.Fatalf("InitializeWith failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(storePath); os.IsNotExist(err) {
		t.Fatal("key file should exist before reset")
	}

	// Reset
	err = Reset(WithStorePath(storePath))
	if err != nil {
		t.Fatalf("Reset failed: %v", err)
	}

	// Verify a file is gone
	if _, err := os.Stat(storePath); !os.IsNotExist(err) {
		t.Error("key file should not exist after reset")
	}
}
