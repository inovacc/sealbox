package sealbox

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestNewKeyStore_RequiresOption(t *testing.T) {
	_, err := NewKeyStore()
	if !errors.Is(err, ErrKeyStoreNotInitialized) {
		t.Errorf("expected ErrKeyStoreNotInitialized, got %v", err)
	}
}

func TestNewKeyStore_WithStorePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.key")

	store, err := NewKeyStore(WithStorePath(path))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if store.Path() != path {
		t.Errorf("expected path %s, got %s", path, store.Path())
	}
}

func TestFileKeyStore_SaveLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.key")

	store, err := NewKeyStore(WithStorePath(path))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Test Exists before save
	if store.Exists() {
		t.Error("expected Exists() to return false before save")
	}

	// Test Save
	data := &SealedData{
		PublicArea:       []byte("public"),
		PrivateArea:      []byte("private"),
		SealedBlobPublic: []byte("blob_public"),
	}
	if err := store.Save(data); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Test Exists after save
	if !store.Exists() {
		t.Error("expected Exists() to return true after save")
	}

	// Test Load
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if string(loaded.PublicArea) != "public" {
		t.Errorf("expected PublicArea 'public', got '%s'", loaded.PublicArea)
	}

	if string(loaded.PrivateArea) != "private" {
		t.Errorf("expected PrivateArea 'private', got '%s'", loaded.PrivateArea)
	}
}

func TestFileKeyStore_SaveNilData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.key")

	store, err := NewKeyStore(WithStorePath(path))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = store.Save(nil)
	if err == nil {
		t.Error("expected error when saving nil data")
	}
}

func TestFileKeyStore_LoadNonExistent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonexistent.key")

	store, err := NewKeyStore(WithStorePath(path))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = store.Load()
	if !errors.Is(err, ErrNoSealedKey) {
		t.Errorf("expected ErrNoSealedKey, got %v", err)
	}
}

func TestFileKeyStore_Delete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.key")

	store, err := NewKeyStore(WithStorePath(path))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Save first
	data := &SealedData{PublicArea: []byte("test")}
	if err := store.Save(data); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Delete
	if err := store.Delete(); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify deleted
	if store.Exists() {
		t.Error("expected Exists() to return false after delete")
	}
}

func TestFileKeyStore_DeleteNonExistent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonexistent.key")

	store, err := NewKeyStore(WithStorePath(path))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Delete non-existent should not error
	if err := store.Delete(); err != nil {
		t.Errorf("Delete non-existent file should not error, got %v", err)
	}
}

func TestHasKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.key")
	opts := WithStorePath(path)

	// Before save
	if HasKey(opts) {
		t.Error("expected HasKey to return false before save")
	}

	// Save a key
	store, _ := NewKeyStore(opts)
	_ = store.Save(&SealedData{PublicArea: []byte("test")})

	// After save
	if !HasKey(opts) {
		t.Error("expected HasKey to return true after save")
	}
}

func TestGetKeyStorePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.key")
	opts := WithStorePath(path)

	result, err := GetKeyStorePath(opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result != path {
		t.Errorf("expected %s, got %s", path, result)
	}
}

func TestReset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.key")
	opts := WithStorePath(path)

	// Create a file
	store, _ := NewKeyStore(opts)
	_ = store.Save(&SealedData{PublicArea: []byte("test")})

	// Reset
	if err := Reset(opts); err != nil {
		t.Fatalf("Reset failed: %v", err)
	}

	// Verify deleted
	if HasKey(opts) {
		t.Error("expected HasKey to return false after Reset")
	}
}

func TestReset_NoOptions(t *testing.T) {
	err := Reset()
	if err == nil {
		t.Error("expected error with no options")
	}
}

func TestGetKeyStorePath_NoOptions(t *testing.T) {
	_, err := GetKeyStorePath()
	if !errors.Is(err, ErrKeyStoreNotInitialized) {
		t.Errorf("expected ErrKeyStoreNotInitialized, got %v", err)
	}
}

func TestHasKey_NoOptions(t *testing.T) {
	if HasKey() {
		t.Error("expected HasKey to return false with no options")
	}
}

func TestFileKeyStore_SaveCreatesDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	nestedPath := filepath.Join(tmpDir, "nested", "deep", "test.key")

	store, err := NewKeyStore(WithStorePath(nestedPath))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data := &SealedData{
		PublicArea:       []byte("public"),
		PrivateArea:      []byte("private"),
		SealedBlobPublic: []byte("blob"),
	}

	if err := store.Save(data); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Verify the file was created
	if !store.Exists() {
		t.Error("expected file to exist after save")
	}
}

func TestFileKeyStore_LoadInvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.key")

	// Write invalid JSON
	if err := os.WriteFile(path, []byte("not valid json"), 0600); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	store, err := NewKeyStore(WithStorePath(path))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = store.Load()
	if err == nil {
		t.Error("expected error loading invalid JSON")
	}
}

func TestFileKeyStore_ExistsEmptyPath(t *testing.T) {
	store := &FileKeyStore{storePath: ""}
	if store.Exists() {
		t.Error("expected Exists to return false for empty path")
	}
}

func TestFileKeyStore_DeleteEmptyPath(t *testing.T) {
	store := &FileKeyStore{storePath: ""}

	err := store.Delete()
	if !errors.Is(err, ErrKeyStoreNotInitialized) {
		t.Errorf("expected ErrKeyStoreNotInitialized, got %v", err)
	}
}

func TestFileKeyStore_SaveEmptyPath(t *testing.T) {
	store := &FileKeyStore{storePath: ""}

	err := store.Save(&SealedData{PublicArea: []byte("test")})
	if !errors.Is(err, ErrKeyStoreNotInitialized) {
		t.Errorf("expected ErrKeyStoreNotInitialized, got %v", err)
	}
}

func TestFileKeyStore_LoadEmptyPath(t *testing.T) {
	store := &FileKeyStore{storePath: ""}

	_, err := store.Load()
	if !errors.Is(err, ErrKeyStoreNotInitialized) {
		t.Errorf("expected ErrKeyStoreNotInitialized, got %v", err)
	}
}

func TestFileKeyStore_PathEmpty(t *testing.T) {
	store := &FileKeyStore{storePath: ""}
	if store.Path() != "" {
		t.Error("expected empty path")
	}
}

// Ensure temp directories are cleaned up
func TestMain(m *testing.M) {
	code := m.Run()
	os.Exit(code)
}
