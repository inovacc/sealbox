package sealbox

import (
	"bytes"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	if len(key) != KeySize {
		t.Errorf("GenerateKey() key length = %d, want %d", len(key), KeySize)
	}

	// Generate another key and ensure they're different
	key2, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() second call error = %v", err)
	}
	if bytes.Equal(key, key2) {
		t.Error("GenerateKey() generated identical keys")
	}
}

func TestGenerateSalt(t *testing.T) {
	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt() error = %v", err)
	}
	if len(salt) != SaltSize {
		t.Errorf("GenerateSalt() salt length = %d, want %d", len(salt), SaltSize)
	}
}

func TestDeriveKey(t *testing.T) {
	secret := []byte("test-secret-key-material")
	salt := make([]byte, SaltSize)

	t.Run("basic derivation", func(t *testing.T) {
		key, err := DeriveKey(secret, salt, "test-info")
		if err != nil {
			t.Fatalf("DeriveKey() error = %v", err)
		}
		if len(key) != KeySize {
			t.Errorf("DeriveKey() key length = %d, want %d", len(key), KeySize)
		}
	})

	t.Run("same inputs produce same key", func(t *testing.T) {
		key1, _ := DeriveKey(secret, salt, "test-info")
		key2, _ := DeriveKey(secret, salt, "test-info")
		if !bytes.Equal(key1, key2) {
			t.Error("DeriveKey() with same inputs produced different keys")
		}
	})

	t.Run("different info produces different key", func(t *testing.T) {
		key1, _ := DeriveKey(secret, salt, "info-1")
		key2, _ := DeriveKey(secret, salt, "info-2")
		if bytes.Equal(key1, key2) {
			t.Error("DeriveKey() with different info produced same keys")
		}
	})

	t.Run("different salt produces different key", func(t *testing.T) {
		salt2 := make([]byte, SaltSize)
		salt2[0] = 1
		key1, _ := DeriveKey(secret, salt, "test-info")
		key2, _ := DeriveKey(secret, salt2, "test-info")
		if bytes.Equal(key1, key2) {
			t.Error("DeriveKey() with different salt produced same keys")
		}
	})

	t.Run("empty secret returns error", func(t *testing.T) {
		_, err := DeriveKey(nil, salt, "test-info")
		if err == nil {
			t.Error("DeriveKey() with empty secret should error")
		}
	})
}

func TestEncryptDecrypt(t *testing.T) {
	key, _ := GenerateKey()
	plaintext := []byte("Hello, World! This is a test message.")

	t.Run("basic encrypt/decrypt", func(t *testing.T) {
		ciphertext, err := Encrypt(key, plaintext)
		if err != nil {
			t.Fatalf("Encrypt() error = %v", err)
		}

		decrypted, err := Decrypt(key, ciphertext)
		if err != nil {
			t.Fatalf("Decrypt() error = %v", err)
		}

		if !bytes.Equal(plaintext, decrypted) {
			t.Errorf("Decrypt() = %s, want %s", decrypted, plaintext)
		}
	})

	t.Run("ciphertext is different from plaintext", func(t *testing.T) {
		ciphertext, _ := Encrypt(key, plaintext)
		if bytes.Equal(ciphertext, plaintext) {
			t.Error("Encrypt() ciphertext equals plaintext")
		}
	})

	t.Run("same plaintext produces different ciphertext (random nonce)", func(t *testing.T) {
		ct1, _ := Encrypt(key, plaintext)
		ct2, _ := Encrypt(key, plaintext)
		if bytes.Equal(ct1, ct2) {
			t.Error("Encrypt() produced identical ciphertext for same plaintext")
		}
	})

	t.Run("wrong key fails decryption", func(t *testing.T) {
		wrongKey, _ := GenerateKey()
		ciphertext, _ := Encrypt(key, plaintext)
		_, err := Decrypt(wrongKey, ciphertext)
		if err == nil {
			t.Error("Decrypt() with wrong key should fail")
		}
	})

	t.Run("invalid key size", func(t *testing.T) {
		_, err := Encrypt([]byte("short"), plaintext)
		if err != ErrInvalidKeySize {
			t.Errorf("Encrypt() with short key error = %v, want ErrInvalidKeySize", err)
		}

		ciphertext, _ := Encrypt(key, plaintext)
		_, err = Decrypt([]byte("short"), ciphertext)
		if err != ErrInvalidKeySize {
			t.Errorf("Decrypt() with short key error = %v, want ErrInvalidKeySize", err)
		}
	})

	t.Run("invalid ciphertext", func(t *testing.T) {
		_, err := Decrypt(key, []byte("short"))
		if err != ErrInvalidCiphertext {
			t.Errorf("Decrypt() with short ciphertext error = %v, want ErrInvalidCiphertext", err)
		}
	})

	t.Run("tampered ciphertext", func(t *testing.T) {
		ciphertext, _ := Encrypt(key, plaintext)
		ciphertext[len(ciphertext)-1] ^= 0xFF // Flip bits
		_, err := Decrypt(key, ciphertext)
		if err != ErrDecryptFailed {
			t.Errorf("Decrypt() with tampered ciphertext error = %v, want ErrDecryptFailed", err)
		}
	})

	t.Run("empty plaintext", func(t *testing.T) {
		ciphertext, err := Encrypt(key, []byte{})
		if err != nil {
			t.Fatalf("Encrypt() empty plaintext error = %v", err)
		}
		decrypted, err := Decrypt(key, ciphertext)
		if err != nil {
			t.Fatalf("Decrypt() empty plaintext error = %v", err)
		}
		if len(decrypted) != 0 {
			t.Error("Decrypt() empty plaintext should return empty")
		}
	})
}
