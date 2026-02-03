package sealbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

const (
	// KeySize is the size of AES-256 keys in bytes.
	KeySize = 32

	// NonceSize is the size of AES-GCM nonces in bytes.
	NonceSize = 12

	// SaltSize is the recommended size for HKDF salts.
	SaltSize = 32
)

var (
	// ErrInvalidKeySize is returned when a key has invalid size.
	ErrInvalidKeySize = errors.New("invalid key size: expected 32 bytes")

	// ErrInvalidCiphertext is returned when ciphertext is too short.
	ErrInvalidCiphertext = errors.New("ciphertext too short")

	// ErrDecryptFailed is returned when decryption fails (wrong key or corrupted data).
	ErrDecryptFailed = errors.New("decryption failed")
)

// GenerateKey generates a cryptographically secure random 32-byte key.
func GenerateKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}
	return key, nil
}

// GenerateSalt generates a cryptographically secure random salt.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	return salt, nil
}

// DeriveKey derives a key using HKDF with SHA3-256.
// The info parameter provides context separation (e.g., "kek", "profile:work").
func DeriveKey(secret, salt []byte, info string) ([]byte, error) {
	if len(secret) == 0 {
		return nil, errors.New("secret cannot be empty")
	}

	reader := hkdf.New(sha3.New256, secret, salt, []byte(info))
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}
	return key, nil
}

// Encrypt encrypts plaintext using AES-256-GCM.
// Returns nonce || ciphertext || tag.
func Encrypt(key, plaintext []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Seal appends ciphertext + tag to nonce
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts ciphertext using AES-256-GCM.
// Expects nonce || ciphertext || tag format.
func Decrypt(key, ciphertext []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, ErrInvalidCiphertext
	}

	nonce, ciphertextBytes := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return nil, ErrDecryptFailed
	}

	return plaintext, nil
}
