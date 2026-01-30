package keystore

import (
	"path/filepath"
	"testing"
)

func skipIfNoTPM(t *testing.T) {
	if !IsAvailable() {
		t.Skip("TPM not available, skipping test")
	}
}

func TestIsAvailable(t *testing.T) {
	// This test always runs - just checks the function doesn't panic
	available := IsAvailable()
	t.Logf("TPM available: %v", available)
}

func TestNewKeyManager(t *testing.T) {
	skipIfNoTPM(t)

	km, err := NewKeyManager()
	if err != nil {
		t.Fatalf("NewKeyManager failed: %v", err)
	}
	defer km.Close()
}

func TestGenerateAndSealKey(t *testing.T) {
	skipIfNoTPM(t)

	km, err := NewKeyManager()
	if err != nil {
		t.Fatalf("NewKeyManager failed: %v", err)
	}
	defer km.Close()

	sealed, err := km.GenerateAndSealKey()
	if err != nil {
		t.Fatalf("GenerateAndSealKey failed: %v", err)
	}

	if len(sealed.PublicArea) == 0 {
		t.Error("PublicArea is empty")
	}
	if len(sealed.PrivateArea) == 0 {
		t.Error("PrivateArea is empty")
	}
	if len(sealed.SealedBlobPublic) == 0 {
		t.Error("SealedBlobPublic is empty")
	}
}

func TestSealUnsealKey(t *testing.T) {
	skipIfNoTPM(t)

	km, err := NewKeyManager()
	if err != nil {
		t.Fatalf("NewKeyManager failed: %v", err)
	}
	defer km.Close()

	// Generate and seal
	original := []byte("test-key-material-32-bytes-long!")
	sealed, err := km.SealKey(original)
	if err != nil {
		t.Fatalf("SealKey failed: %v", err)
	}

	// Unseal
	unsealed, err := km.UnsealKey(sealed)
	if err != nil {
		t.Fatalf("UnsealKey failed: %v", err)
	}

	if string(unsealed) != string(original) {
		t.Errorf("unsealed key doesn't match original: got %q, want %q", unsealed, original)
	}
}

func TestUnsealKey_NilData(t *testing.T) {
	skipIfNoTPM(t)

	km, err := NewKeyManager()
	if err != nil {
		t.Fatalf("NewKeyManager failed: %v", err)
	}
	defer km.Close()

	_, err = km.UnsealKey(nil)
	if err == nil {
		t.Error("expected error when unsealing nil data")
	}
}

func TestInitialize(t *testing.T) {
	skipIfNoTPM(t)

	path := filepath.Join(t.TempDir(), "init_test.key")
	opts := WithStorePath(path)

	// First initialize should succeed
	if err := Initialize(opts); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Second initialize should return ErrKeyExists
	if err := Initialize(opts); err != ErrKeyExists {
		t.Errorf("expected ErrKeyExists, got %v", err)
	}
}

func TestInitialize_NoTPM(t *testing.T) {
	if IsAvailable() {
		t.Skip("TPM is available, skipping no-TPM test")
	}

	path := filepath.Join(t.TempDir(), "init_test.key")
	opts := WithStorePath(path)

	err := Initialize(opts)
	if err != ErrTPMNotAvailable {
		t.Errorf("expected ErrTPMNotAvailable, got %v", err)
	}
}

func TestGetSealedMasterKey(t *testing.T) {
	skipIfNoTPM(t)

	path := filepath.Join(t.TempDir(), "master_test.key")
	opts := WithStorePath(path)

	// Initialize first
	if err := Initialize(opts); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Get sealed master key
	key, err := GetSealedMasterKey(opts)
	if err != nil {
		t.Fatalf("GetSealedMasterKey failed: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("expected 32-byte key, got %d bytes", len(key))
	}
}

func TestGetSealedMasterKey_NoKey(t *testing.T) {
	skipIfNoTPM(t)

	path := filepath.Join(t.TempDir(), "nonexistent.key")
	opts := WithStorePath(path)

	_, err := GetSealedMasterKey(opts)
	if err != ErrNoSealedKey {
		t.Errorf("expected ErrNoSealedKey, got %v", err)
	}
}

func TestEndToEnd(t *testing.T) {
	skipIfNoTPM(t)

	path := filepath.Join(t.TempDir(), "e2e_test.key")
	opts := WithStorePath(path)

	// 1. Check no key exists
	if HasKey(opts) {
		t.Fatal("expected no key to exist initially")
	}

	// 2. Initialize
	if err := Initialize(opts); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// 3. Check key exists
	if !HasKey(opts) {
		t.Fatal("expected key to exist after Initialize")
	}

	// 4. Get key
	key1, err := GetSealedMasterKey(opts)
	if err != nil {
		t.Fatalf("GetSealedMasterKey failed: %v", err)
	}

	// 5. Get key again - should be same
	key2, err := GetSealedMasterKey(opts)
	if err != nil {
		t.Fatalf("GetSealedMasterKey second call failed: %v", err)
	}

	if string(key1) != string(key2) {
		t.Error("keys should be identical")
	}

	// 6. Reset
	if err := Reset(opts); err != nil {
		t.Fatalf("Reset failed: %v", err)
	}

	// 7. Check no key exists
	if HasKey(opts) {
		t.Fatal("expected no key after Reset")
	}
}
