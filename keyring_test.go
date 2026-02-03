package sealbox

import (
	"os"
	"path/filepath"
	"testing"
)

func TestKeyring(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "keyring-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create KEK
	kek, _ := GenerateKey()

	t.Run("create keyring", func(t *testing.T) {
		kr, err := NewKeyring(tmpDir)
		if err != nil {
			t.Fatalf("NewKeyring() error = %v", err)
		}
		if err := kr.SetKEK(kek); err != nil {
			t.Fatalf("SetKEK() error = %v", err)
		}
		if !kr.IsUnlocked() {
			t.Error("keyring should be unlocked after SetKEK")
		}
	})

	t.Run("create and get profile", func(t *testing.T) {
		kr, _ := NewKeyring(tmpDir)
		_ = kr.SetKEK(kek)

		if err := kr.CreateProfile("work"); err != nil {
			t.Fatalf("CreateProfile() error = %v", err)
		}

		if !kr.HasProfile("work") {
			t.Error("HasProfile() = false, want true")
		}

		key, err := kr.GetProfileKey("work")
		if err != nil {
			t.Fatalf("GetProfileKey() error = %v", err)
		}
		if len(key) != KeySize {
			t.Errorf("GetProfileKey() key length = %d, want %d", len(key), KeySize)
		}
	})

	t.Run("duplicate profile fails", func(t *testing.T) {
		kr, _ := NewKeyring(tmpDir)
		_ = kr.SetKEK(kek)
		_ = kr.CreateProfile("dup")

		err := kr.CreateProfile("dup")
		if err != ErrProfileExists {
			t.Errorf("CreateProfile() duplicate error = %v, want ErrProfileExists", err)
		}
	})

	t.Run("missing profile fails", func(t *testing.T) {
		kr, _ := NewKeyring(tmpDir)
		_ = kr.SetKEK(kek)

		_, err := kr.GetProfileKey("nonexistent")
		if err != ErrProfileNotFound {
			t.Errorf("GetProfileKey() missing error = %v, want ErrProfileNotFound", err)
		}
	})

	t.Run("locked keyring fails operations", func(t *testing.T) {
		kr, _ := NewKeyring(tmpDir)
		// Don't set KEK

		err := kr.CreateProfile("test")
		if err != ErrKeyringLocked {
			t.Errorf("CreateProfile() locked error = %v, want ErrKeyringLocked", err)
		}
	})

	t.Run("list profiles", func(t *testing.T) {
		kr, _ := NewKeyring(filepath.Join(tmpDir, "list"))
		_ = kr.SetKEK(kek)
		_ = kr.CreateProfile("profile1")
		_ = kr.CreateProfile("profile2")

		profiles := kr.ListProfiles()
		if len(profiles) != 2 {
			t.Errorf("ListProfiles() count = %d, want 2", len(profiles))
		}
	})

	t.Run("delete profile", func(t *testing.T) {
		kr, _ := NewKeyring(filepath.Join(tmpDir, "delete"))
		_ = kr.SetKEK(kek)
		_ = kr.CreateProfile("todelete")

		if err := kr.DeleteProfile("todelete"); err != nil {
			t.Fatalf("DeleteProfile() error = %v", err)
		}
		if kr.HasProfile("todelete") {
			t.Error("profile should be deleted")
		}
	})

	t.Run("save and reload", func(t *testing.T) {
		path := filepath.Join(tmpDir, "persist")
		kr, _ := NewKeyring(path)
		_ = kr.SetKEK(kek)
		_ = kr.CreateProfile("persist")

		key1, _ := kr.GetProfileKey("persist")

		if err := kr.Save(); err != nil {
			t.Fatalf("Save() error = %v", err)
		}

		// Reload
		kr2, _ := NewKeyring(path)
		_ = kr2.SetKEK(kek)

		key2, err := kr2.GetProfileKey("persist")
		if err != nil {
			t.Fatalf("GetProfileKey() after reload error = %v", err)
		}

		if string(key1) != string(key2) {
			t.Error("keys should match after reload")
		}
	})

	t.Run("rotate profile key", func(t *testing.T) {
		kr, _ := NewKeyring(filepath.Join(tmpDir, "rotate"))
		_ = kr.SetKEK(kek)
		_ = kr.CreateProfile("rotatable")

		oldKey, _ := kr.GetProfileKey("rotatable")
		oldVersion, _ := kr.GetProfileVersion("rotatable")

		retOld, retNew, err := kr.RotateProfileKey("rotatable")
		if err != nil {
			t.Fatalf("RotateProfileKey() error = %v", err)
		}

		if string(retOld) != string(oldKey) {
			t.Error("returned old key should match previous key")
		}
		if string(retOld) == string(retNew) {
			t.Error("new key should be different from old key")
		}

		newVersion, _ := kr.GetProfileVersion("rotatable")
		if newVersion != oldVersion+1 {
			t.Errorf("version = %d, want %d", newVersion, oldVersion+1)
		}
	})

	t.Run("lock clears kek", func(t *testing.T) {
		kr, _ := NewKeyring(filepath.Join(tmpDir, "lock"))
		_ = kr.SetKEK(kek)
		_ = kr.CreateProfile("test")

		kr.Lock()
		if kr.IsUnlocked() {
			t.Error("keyring should be locked")
		}

		_, err := kr.GetProfileKey("test")
		if err != ErrKeyringLocked {
			t.Errorf("GetProfileKey() after lock error = %v, want ErrKeyringLocked", err)
		}
	})
}
