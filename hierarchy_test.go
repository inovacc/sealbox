package sealbox

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestNewKeyHierarchy(t *testing.T) {
	tmpDir := t.TempDir()

	h, err := NewKeyHierarchy(tmpDir)
	if err != nil {
		t.Fatalf("NewKeyHierarchy() error = %v", err)
	}

	if h == nil {
		t.Fatal("NewKeyHierarchy() returned nil")
	}

	if h.Count() != 0 {
		t.Errorf("Count() = %d, want 0", h.Count())
	}
}

func TestNewKeyHierarchy_EmptyPath(t *testing.T) {
	_, err := NewKeyHierarchy("")
	if err == nil {
		t.Error("NewKeyHierarchy('') should return error")
	}
}

func TestKeyHierarchy_AddAndGet(t *testing.T) {
	tmpDir := t.TempDir()
	h, _ := NewKeyHierarchy(tmpDir)

	sealed := &SealedData{
		PublicArea:       []byte("pub"),
		PrivateArea:      []byte("priv"),
		SealedBlobPublic: []byte("sealed"),
	}

	err := h.Add("test-key", sealed)
	if err != nil {
		t.Fatalf("Add() error = %v", err)
	}

	got, exists := h.Get("test-key")
	if !exists {
		t.Error("Get() returned exists = false, want true")
	}

	if got == nil {
		t.Fatal("Get() returned nil")
	}

	if string(got.PublicArea) != "pub" {
		t.Errorf("PublicArea = %s, want 'pub'", got.PublicArea)
	}
}

func TestKeyHierarchy_AddDuplicate(t *testing.T) {
	tmpDir := t.TempDir()
	h, _ := NewKeyHierarchy(tmpDir)

	sealed := &SealedData{PublicArea: []byte("pub"), PrivateArea: []byte("priv"), SealedBlobPublic: []byte("sealed")}

	_ = h.Add("key", sealed)

	err := h.Add("key", sealed)
	if err == nil {
		t.Error("Add() duplicate key should return error")
	}
}

func TestKeyHierarchy_AddEmptyName(t *testing.T) {
	tmpDir := t.TempDir()
	h, _ := NewKeyHierarchy(tmpDir)

	sealed := &SealedData{PublicArea: []byte("pub"), PrivateArea: []byte("priv"), SealedBlobPublic: []byte("sealed")}

	err := h.Add("", sealed)
	if err == nil {
		t.Error("Add('') should return error")
	}
}

func TestKeyHierarchy_AddNilData(t *testing.T) {
	tmpDir := t.TempDir()
	h, _ := NewKeyHierarchy(tmpDir)

	err := h.Add("key", nil)
	if err == nil {
		t.Error("Add() with nil data should return error")
	}
}

func TestKeyHierarchy_Remove(t *testing.T) {
	tmpDir := t.TempDir()
	h, _ := NewKeyHierarchy(tmpDir)

	sealed := &SealedData{PublicArea: []byte("pub"), PrivateArea: []byte("priv"), SealedBlobPublic: []byte("sealed")}
	_ = h.Add("key", sealed)

	removed := h.Remove("key")
	if !removed {
		t.Error("Remove() returned false, want true")
	}

	_, exists := h.Get("key")
	if exists {
		t.Error("Get() after Remove() should return exists = false")
	}
}

func TestKeyHierarchy_RemoveNonExistent(t *testing.T) {
	tmpDir := t.TempDir()
	h, _ := NewKeyHierarchy(tmpDir)

	removed := h.Remove("non-existent")
	if removed {
		t.Error("Remove() non-existent key should return false")
	}
}

func TestKeyHierarchy_List(t *testing.T) {
	tmpDir := t.TempDir()
	h, _ := NewKeyHierarchy(tmpDir)

	sealed := &SealedData{PublicArea: []byte("pub"), PrivateArea: []byte("priv"), SealedBlobPublic: []byte("sealed")}
	_ = h.Add("key1", sealed)
	_ = h.Add("key2", sealed)
	_ = h.Add("key3", sealed)

	names := h.List()
	sort.Strings(names)

	expected := []string{"key1", "key2", "key3"}
	if len(names) != len(expected) {
		t.Fatalf("List() returned %d names, want %d", len(names), len(expected))
	}

	for i, name := range names {
		if name != expected[i] {
			t.Errorf("List()[%d] = %s, want %s", i, name, expected[i])
		}
	}
}

func TestKeyHierarchy_Exists(t *testing.T) {
	tmpDir := t.TempDir()
	h, _ := NewKeyHierarchy(tmpDir)

	sealed := &SealedData{PublicArea: []byte("pub"), PrivateArea: []byte("priv"), SealedBlobPublic: []byte("sealed")}
	_ = h.Add("key", sealed)

	if !h.Exists("key") {
		t.Error("Exists() returned false, want true")
	}

	if h.Exists("non-existent") {
		t.Error("Exists() returned true for non-existent key")
	}
}

func TestKeyHierarchy_Clear(t *testing.T) {
	tmpDir := t.TempDir()
	h, _ := NewKeyHierarchy(tmpDir)

	sealed := &SealedData{PublicArea: []byte("pub"), PrivateArea: []byte("priv"), SealedBlobPublic: []byte("sealed")}
	_ = h.Add("key1", sealed)
	_ = h.Add("key2", sealed)

	h.Clear()

	if h.Count() != 0 {
		t.Errorf("Count() after Clear() = %d, want 0", h.Count())
	}

	if !h.IsModified() {
		t.Error("IsModified() after Clear() should be true")
	}
}

func TestKeyHierarchy_SaveAndLoad(t *testing.T) {
	tmpDir := t.TempDir()

	// Create and save
	h1, _ := NewKeyHierarchy(tmpDir)
	sealed := &SealedData{
		Version:          1,
		PublicArea:       []byte("pub-area"),
		PrivateArea:      []byte("priv-area"),
		SealedBlobPublic: []byte("sealed-pub"),
	}

	_ = h1.Add("key1", sealed)
	if err := h1.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Load in new instance
	h2, err := NewKeyHierarchy(tmpDir)
	if err != nil {
		t.Fatalf("NewKeyHierarchy() after Save() error = %v", err)
	}

	got, exists := h2.Get("key1")
	if !exists {
		t.Fatal("Get() after load should find key")
	}

	if string(got.PublicArea) != "pub-area" {
		t.Errorf("PublicArea = %s, want 'pub-area'", got.PublicArea)
	}
}

func TestKeyHierarchy_Delete(t *testing.T) {
	tmpDir := t.TempDir()

	h, _ := NewKeyHierarchy(tmpDir)
	sealed := &SealedData{PublicArea: []byte("pub"), PrivateArea: []byte("priv"), SealedBlobPublic: []byte("sealed")}
	_ = h.Add("key", sealed)
	_ = h.Save()

	err := h.Delete()
	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	// Verify file is gone
	filePath := filepath.Join(tmpDir, "hierarchy.json")
	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		t.Error("hierarchy file should be deleted")
	}

	// Verify hierarchy is cleared
	if h.Count() != 0 {
		t.Errorf("Count() after Delete() = %d, want 0", h.Count())
	}
}

func TestKeyHierarchy_IsModified(t *testing.T) {
	tmpDir := t.TempDir()
	h, _ := NewKeyHierarchy(tmpDir)

	// New hierarchy is not modified (no changes)
	if h.IsModified() {
		t.Error("New hierarchy should not be modified")
	}

	// Add key marks as modified
	sealed := &SealedData{PublicArea: []byte("pub"), PrivateArea: []byte("priv"), SealedBlobPublic: []byte("sealed")}

	_ = h.Add("key", sealed)
	if !h.IsModified() {
		t.Error("After Add() should be modified")
	}

	// Save clears modified flag
	_ = h.Save()
	if h.IsModified() {
		t.Error("After Save() should not be modified")
	}

	// Remove marks as modified
	h.Remove("key")

	if !h.IsModified() {
		t.Error("After Remove() should be modified")
	}
}

func TestKeyHierarchyManager_GenerateAndUnsealKey(t *testing.T) {
	tmpDir := t.TempDir()

	// Use mock key manager
	km := NewMockKeyManager()

	defer func() { _ = km.Close() }()

	mgr, err := NewKeyHierarchyManager(km, tmpDir)
	if err != nil {
		t.Fatalf("NewKeyHierarchyManager() error = %v", err)
	}

	// Generate a key
	err = mgr.GenerateKey("test-key")
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	// Verify key exists
	if !mgr.Hierarchy().Exists("test-key") {
		t.Error("Key should exist after GenerateKey()")
	}

	// Unseal the key
	key, err := mgr.UnsealKey("test-key")
	if err != nil {
		t.Fatalf("UnsealKey() error = %v", err)
	}

	if len(key) != 32 {
		t.Errorf("Key length = %d, want 32", len(key))
	}
}

func TestKeyHierarchyManager_SealKey(t *testing.T) {
	tmpDir := t.TempDir()

	km := NewMockKeyManager()

	defer func() { _ = km.Close() }()

	mgr, _ := NewKeyHierarchyManager(km, tmpDir)

	originalKey := []byte("my-secret-key-12345678901234567")

	err := mgr.SealKey("my-key", originalKey)
	if err != nil {
		t.Fatalf("SealKey() error = %v", err)
	}

	// Unseal and verify
	unsealed, err := mgr.UnsealKey("my-key")
	if err != nil {
		t.Fatalf("UnsealKey() error = %v", err)
	}

	if string(unsealed) != string(originalKey) {
		t.Errorf("Unsealed key = %s, want %s", unsealed, originalKey)
	}
}

func TestKeyHierarchyManager_UnsealKeyNotFound(t *testing.T) {
	tmpDir := t.TempDir()

	km := NewMockKeyManager()

	defer func() { _ = km.Close() }()

	mgr, _ := NewKeyHierarchyManager(km, tmpDir)

	_, err := mgr.UnsealKey("non-existent")
	if err == nil {
		t.Error("UnsealKey() non-existent should return error")
	}
}

func TestKeyHierarchyManager_Close(t *testing.T) {
	tmpDir := t.TempDir()

	km := NewMockKeyManager()
	mgr, _ := NewKeyHierarchyManager(km, tmpDir)

	// Generate key and close with save
	_ = mgr.GenerateKey("key")

	err := mgr.Close(true)
	if err != nil {
		t.Fatalf("Close(true) error = %v", err)
	}

	// Verify file was saved
	filePath := filepath.Join(tmpDir, "hierarchy.json")
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		t.Error("hierarchy file should exist after Close(true)")
	}
}

func TestKeyHierarchyManager_CloseNoSave(t *testing.T) {
	tmpDir := t.TempDir()

	km := NewMockKeyManager()
	mgr, _ := NewKeyHierarchyManager(km, tmpDir)

	// Generate key and close without save
	_ = mgr.GenerateKey("key")

	err := mgr.Close(false)
	if err != nil {
		t.Fatalf("Close(false) error = %v", err)
	}

	// Verify file was NOT saved
	filePath := filepath.Join(tmpDir, "hierarchy.json")
	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		t.Error("hierarchy file should not exist after Close(false)")
	}
}

func TestKeyHierarchyManager_MultipleKeys(t *testing.T) {
	tmpDir := t.TempDir()

	km := NewMockKeyManager()

	defer func() { _ = km.Close() }()

	mgr, _ := NewKeyHierarchyManager(km, tmpDir)

	// Generate multiple keys
	for i := range 5 {
		name := "key-" + string(rune('a'+i))
		if err := mgr.GenerateKey(name); err != nil {
			t.Fatalf("GenerateKey(%s) error = %v", name, err)
		}
	}

	// Verify count
	if mgr.Hierarchy().Count() != 5 {
		t.Errorf("Count() = %d, want 5", mgr.Hierarchy().Count())
	}

	// Unseal each key
	for i := range 5 {
		name := "key-" + string(rune('a'+i))

		key, err := mgr.UnsealKey(name)
		if err != nil {
			t.Errorf("UnsealKey(%s) error = %v", name, err)
		}

		if len(key) != 32 {
			t.Errorf("Key %s length = %d, want 32", name, len(key))
		}
	}
}
