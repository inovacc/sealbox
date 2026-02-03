package sealbox

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// mockRootSecret returns a deterministic root secret for testing.
func mockRootSecret() ([]byte, error) {
	return bytes.Repeat([]byte{0x42}, KeySize), nil
}

func TestKeystore(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "keystore-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	t.Run("open with password", func(t *testing.T) {
		path := filepath.Join(tmpDir, "pwd")
		ks, err := Open(path, WithPasswordRoot([]byte("test-password")))
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		defer func() { _ = ks.Close() }()

		if !ks.IsOpen() {
			t.Error("keystore should be open")
		}
	})

	t.Run("open with mock root", func(t *testing.T) {
		path := filepath.Join(tmpDir, "mock")
		ks, err := Open(path, withMockRootSecret(mockRootSecret))
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		defer func() { _ = ks.Close() }()

		if !ks.IsOpen() {
			t.Error("keystore should be open")
		}
	})

	t.Run("create profile", func(t *testing.T) {
		path := filepath.Join(tmpDir, "profile")
		ks, _ := Open(path, withMockRootSecret(mockRootSecret))
		defer func() { _ = ks.Close() }()

		if err := ks.CreateProfile("work"); err != nil {
			t.Fatalf("CreateProfile() error = %v", err)
		}

		if !ks.HasProfile("work") {
			t.Error("HasProfile() = false, want true")
		}
	})

	t.Run("list profiles", func(t *testing.T) {
		path := filepath.Join(tmpDir, "listprofiles")
		ks, _ := Open(path, withMockRootSecret(mockRootSecret))
		defer func() { _ = ks.Close() }()

		_ = ks.CreateProfile("profile1")
		_ = ks.CreateProfile("profile2")

		profiles := ks.ListProfiles()
		if len(profiles) != 2 {
			t.Errorf("ListProfiles() count = %d, want 2", len(profiles))
		}
	})

	t.Run("delete profile", func(t *testing.T) {
		path := filepath.Join(tmpDir, "delprofile")
		ks, _ := Open(path, withMockRootSecret(mockRootSecret))
		defer func() { _ = ks.Close() }()

		_ = ks.CreateProfile("todelete")
		if err := ks.DeleteProfile("todelete"); err != nil {
			t.Fatalf("DeleteProfile() error = %v", err)
		}
		if ks.HasProfile("todelete") {
			t.Error("profile should be deleted")
		}
	})

	t.Run("encrypt and decrypt", func(t *testing.T) {
		path := filepath.Join(tmpDir, "encrypt")
		ks, _ := Open(path, withMockRootSecret(mockRootSecret))
		defer func() { _ = ks.Close() }()

		_ = ks.CreateProfile("enctest")
		plaintext := []byte("secret data")

		ciphertext, err := ks.Encrypt("enctest", "token", plaintext)
		if err != nil {
			t.Fatalf("Encrypt() error = %v", err)
		}

		if bytes.Equal(ciphertext, plaintext) {
			t.Error("ciphertext should differ from plaintext")
		}

		decrypted, err := ks.Decrypt("enctest", "token", ciphertext)
		if err != nil {
			t.Fatalf("Decrypt() error = %v", err)
		}

		if !bytes.Equal(decrypted, plaintext) {
			t.Errorf("Decrypt() = %s, want %s", decrypted, plaintext)
		}
	})

	t.Run("different profiles have different DEKs", func(t *testing.T) {
		path := filepath.Join(tmpDir, "diffprofiles")
		ks, _ := Open(path, withMockRootSecret(mockRootSecret))
		defer func() { _ = ks.Close() }()

		_ = ks.CreateProfile("profile1")
		_ = ks.CreateProfile("profile2")

		dek1, _ := ks.GetOrCreateDEK("profile1", "token")
		dek2, _ := ks.GetOrCreateDEK("profile2", "token")

		if bytes.Equal(dek1, dek2) {
			t.Error("different profiles should have different DEKs")
		}
	})

	t.Run("rotate DEK", func(t *testing.T) {
		path := filepath.Join(tmpDir, "rotatedek")
		ks, _ := Open(path, withMockRootSecret(mockRootSecret))
		defer func() { _ = ks.Close() }()

		_ = ks.CreateProfile("rottest")
		plaintext := []byte("original data")

		// Encrypt with original DEK
		ciphertext, _ := ks.Encrypt("rottest", "token", plaintext)

		// Rotate DEK
		oldDEK, newDEK, err := ks.RotateDEK("rottest", "token")
		if err != nil {
			t.Fatalf("RotateDEK() error = %v", err)
		}
		defer SecureZero(oldDEK)
		defer SecureZero(newDEK)

		if bytes.Equal(oldDEK, newDEK) {
			t.Error("new DEK should differ from old")
		}

		// Decrypt old ciphertext with old DEK manually
		decrypted, err := Decrypt(oldDEK, ciphertext)
		if err != nil {
			t.Fatalf("Decrypt with old DEK error = %v", err)
		}
		if !bytes.Equal(decrypted, plaintext) {
			t.Error("old DEK should still decrypt old data")
		}

		// Re-encrypt with new DEK
		newCiphertext, _ := Encrypt(newDEK, plaintext)

		// Current DEK should be the new one
		decrypted2, _ := ks.Decrypt("rottest", "token", newCiphertext)
		if !bytes.Equal(decrypted2, plaintext) {
			t.Error("new DEK should decrypt new ciphertext")
		}
	})

	t.Run("rotate profile", func(t *testing.T) {
		path := filepath.Join(tmpDir, "rotprofile")
		ks, _ := Open(path, withMockRootSecret(mockRootSecret))
		defer func() { _ = ks.Close() }()

		_ = ks.CreateProfile("rotprofile")
		plaintext := []byte("test data")

		// Create DEK and encrypt
		_, _ = ks.Encrypt("rotprofile", "token", plaintext)

		v1, _ := ks.GetProfileKeyVersion("rotprofile")

		// Rotate profile
		if err := ks.RotateProfile("rotprofile"); err != nil {
			t.Fatalf("RotateProfile() error = %v", err)
		}

		v2, _ := ks.GetProfileKeyVersion("rotprofile")
		if v2 != v1+1 {
			t.Errorf("version = %d, want %d", v2, v1+1)
		}

		// Can still encrypt/decrypt after rotation
		ciphertext, _ := ks.Encrypt("rotprofile", "token", plaintext)
		decrypted, err := ks.Decrypt("rotprofile", "token", ciphertext)
		if err != nil {
			t.Fatalf("Decrypt() after rotation error = %v", err)
		}
		if !bytes.Equal(decrypted, plaintext) {
			t.Error("decrypt after rotation failed")
		}
	})

	t.Run("export and import DEK", func(t *testing.T) {
		path := filepath.Join(tmpDir, "exportdek")
		ks, _ := Open(path, withMockRootSecret(mockRootSecret))
		defer func() { _ = ks.Close() }()

		_ = ks.CreateProfile("export")
		plaintext := []byte("exportable data")

		ciphertext, _ := ks.Encrypt("export", "token", plaintext)
		encryptedDEK, version, err := ks.ExportEncryptedDEK("export", "token")
		if err != nil {
			t.Fatalf("ExportEncryptedDEK() error = %v", err)
		}

		// Import into same profile with different type
		if err := ks.ImportEncryptedDEK("export", "imported", encryptedDEK, version); err != nil {
			t.Fatalf("ImportEncryptedDEK() error = %v", err)
		}

		// Should be able to decrypt with imported DEK
		decrypted, err := ks.Decrypt("export", "imported", ciphertext)
		if err != nil {
			t.Fatalf("Decrypt() with imported DEK error = %v", err)
		}
		if !bytes.Equal(decrypted, plaintext) {
			t.Error("decrypt with imported DEK failed")
		}
	})

	t.Run("persistence across open/close", func(t *testing.T) {
		path := filepath.Join(tmpDir, "persist")
		plaintext := []byte("persistent data")

		// First session: create profile, encrypt data
		ks1, _ := Open(path, withMockRootSecret(mockRootSecret), WithAutoSave())
		_ = ks1.CreateProfile("persist")
		ciphertext, _ := ks1.Encrypt("persist", "token", plaintext)
		_ = ks1.Close()

		// Second session: decrypt data
		ks2, _ := Open(path, withMockRootSecret(mockRootSecret))
		defer func() { _ = ks2.Close() }()

		if !ks2.HasProfile("persist") {
			t.Fatal("profile should persist across sessions")
		}

		decrypted, err := ks2.Decrypt("persist", "token", ciphertext)
		if err != nil {
			t.Fatalf("Decrypt() in new session error = %v", err)
		}
		if !bytes.Equal(decrypted, plaintext) {
			t.Error("decryption failed in new session")
		}
	})

	t.Run("closed keystore returns error", func(t *testing.T) {
		path := filepath.Join(tmpDir, "closed")
		ks, _ := Open(path, withMockRootSecret(mockRootSecret))
		_ = ks.Close()

		if err := ks.CreateProfile("test"); err != ErrKeystoreClosed {
			t.Errorf("CreateProfile() on closed error = %v, want ErrKeystoreClosed", err)
		}

		_, err := ks.Encrypt("test", "token", []byte("data"))
		if err != ErrKeystoreClosed {
			t.Errorf("Encrypt() on closed error = %v, want ErrKeystoreClosed", err)
		}
	})
}
