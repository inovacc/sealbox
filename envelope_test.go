package sealbox

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnvelopeStore(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "envelope-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	masterKey, _ := GenerateKey()

	t.Run("create envelope store", func(t *testing.T) {
		es, err := NewEnvelopeStore(tmpDir, "testprofile")
		if err != nil {
			t.Fatalf("NewEnvelopeStore() error = %v", err)
		}
		if es == nil {
			t.Fatal("NewEnvelopeStore() returned nil")
		}
	})

	t.Run("get or create DEK", func(t *testing.T) {
		es, _ := NewEnvelopeStore(filepath.Join(tmpDir, "dek1"), "profile")

		dek, err := es.GetOrCreateDEK("token", masterKey)
		if err != nil {
			t.Fatalf("GetOrCreateDEK() error = %v", err)
		}
		if len(dek) != KeySize {
			t.Errorf("DEK length = %d, want %d", len(dek), KeySize)
		}

		// Get again should return same DEK
		dek2, err := es.GetOrCreateDEK("token", masterKey)
		if err != nil {
			t.Fatalf("GetOrCreateDEK() second call error = %v", err)
		}
		if string(dek) != string(dek2) {
			t.Error("GetOrCreateDEK() should return same DEK")
		}
	})

	t.Run("different DEK types", func(t *testing.T) {
		es, _ := NewEnvelopeStore(filepath.Join(tmpDir, "dektypes"), "profile")

		dek1, _ := es.GetOrCreateDEK("token", masterKey)
		dek2, _ := es.GetOrCreateDEK("config", masterKey)

		if string(dek1) == string(dek2) {
			t.Error("different DEK types should have different keys")
		}
	})

	t.Run("has DEK", func(t *testing.T) {
		es, _ := NewEnvelopeStore(filepath.Join(tmpDir, "hasdek"), "profile")
		_, _ = es.GetOrCreateDEK("exists", masterKey)

		if !es.HasDEK("exists") {
			t.Error("HasDEK() = false, want true")
		}
		if es.HasDEK("notexists") {
			t.Error("HasDEK() = true for missing, want false")
		}
	})

	t.Run("list DEK types", func(t *testing.T) {
		es, _ := NewEnvelopeStore(filepath.Join(tmpDir, "list"), "profile")
		_, _ = es.GetOrCreateDEK("type1", masterKey)
		_, _ = es.GetOrCreateDEK("type2", masterKey)

		types := es.ListDEKTypes()
		if len(types) != 2 {
			t.Errorf("ListDEKTypes() count = %d, want 2", len(types))
		}
	})

	t.Run("delete DEK", func(t *testing.T) {
		es, _ := NewEnvelopeStore(filepath.Join(tmpDir, "deldek"), "profile")
		_, _ = es.GetOrCreateDEK("todelete", masterKey)

		if err := es.DeleteDEK("todelete"); err != nil {
			t.Fatalf("DeleteDEK() error = %v", err)
		}
		if es.HasDEK("todelete") {
			t.Error("DEK should be deleted")
		}
	})

	t.Run("save and reload", func(t *testing.T) {
		path := filepath.Join(tmpDir, "persist")
		es, _ := NewEnvelopeStore(path, "profile")
		dek1, _ := es.GetOrCreateDEK("token", masterKey)
		_ = es.Save()

		// Reload
		es2, _ := NewEnvelopeStore(path, "profile")
		dek2, err := es2.GetDEK("token", masterKey)
		if err != nil {
			t.Fatalf("GetDEK() after reload error = %v", err)
		}

		if string(dek1) != string(dek2) {
			t.Error("DEK should match after reload")
		}
	})

	t.Run("rotate DEK", func(t *testing.T) {
		es, _ := NewEnvelopeStore(filepath.Join(tmpDir, "rotate"), "profile")
		origDEK, _ := es.GetOrCreateDEK("rotatable", masterKey)
		origVersion, _ := es.GetDEKVersion("rotatable")

		oldDEK, newDEK, err := es.RotateDEK("rotatable", masterKey)
		if err != nil {
			t.Fatalf("RotateDEK() error = %v", err)
		}

		if string(oldDEK) != string(origDEK) {
			t.Error("returned old DEK should match original")
		}
		if string(oldDEK) == string(newDEK) {
			t.Error("new DEK should be different from old")
		}

		newVersion, _ := es.GetDEKVersion("rotatable")
		if newVersion != origVersion+1 {
			t.Errorf("version = %d, want %d", newVersion, origVersion+1)
		}
	})

	t.Run("export and import DEK", func(t *testing.T) {
		es, _ := NewEnvelopeStore(filepath.Join(tmpDir, "export"), "profile")
		origDEK, _ := es.GetOrCreateDEK("exportable", masterKey)

		encrypted, version, err := es.ExportEncryptedDEK("exportable")
		if err != nil {
			t.Fatalf("ExportEncryptedDEK() error = %v", err)
		}

		// Import into new store
		es2, _ := NewEnvelopeStore(filepath.Join(tmpDir, "import"), "profile")
		if err := es2.ImportEncryptedDEK("imported", encrypted, version); err != nil {
			t.Fatalf("ImportEncryptedDEK() error = %v", err)
		}

		importedDEK, err := es2.GetDEK("imported", masterKey)
		if err != nil {
			t.Fatalf("GetDEK() after import error = %v", err)
		}

		if string(origDEK) != string(importedDEK) {
			t.Error("imported DEK should match original")
		}
	})

	t.Run("re-encrypt with new master key", func(t *testing.T) {
		es, _ := NewEnvelopeStore(filepath.Join(tmpDir, "reencrypt"), "profile")
		origDEK, _ := es.GetOrCreateDEK("token", masterKey)

		newMasterKey, _ := GenerateKey()
		if err := es.ReEncryptWithNewMasterKey(masterKey, newMasterKey); err != nil {
			t.Fatalf("ReEncryptWithNewMasterKey() error = %v", err)
		}

		// Old master key should fail
		_, err := es.GetDEK("token", masterKey)
		if err == nil {
			t.Error("GetDEK() with old master key should fail")
		}

		// New master key should work
		dek, err := es.GetDEK("token", newMasterKey)
		if err != nil {
			t.Fatalf("GetDEK() with new master key error = %v", err)
		}

		if string(dek) != string(origDEK) {
			t.Error("DEK value should be unchanged after re-encryption")
		}
	})
}
