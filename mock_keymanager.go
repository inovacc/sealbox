package keystore

import (
	"crypto/rand"
	"crypto/sha256"
	"io"
	"sync"
)

// MockKeyManager implements KeyManager for testing without TPM hardware.
// It simulates TPM seal/unseal operations using in-memory storage.
type MockKeyManager struct {
	mu sync.Mutex

	// SealFunc allows customizing SealKey behavior in tests.
	// If nil, uses default mock implementation.
	SealFunc func(key []byte) (*SealedData, error)

	// UnsealFunc allows customizing UnsealKey behavior in tests.
	// If nil, uses default mock implementation.
	UnsealFunc func(data *SealedData) ([]byte, error)

	// GenerateFunc allows customizing GenerateAndSealKey behavior in tests.
	// If nil, uses default mock implementation.
	GenerateFunc func() (*SealedData, error)

	// CloseFunc allows customizing Close behavior in tests.
	// If nil, returns nil.
	CloseFunc func() error

	// sealedKeys maps sealed data hash to original key for mock unsealing
	sealedKeys map[string][]byte
}

// NewMockKeyManager creates a new MockKeyManager with default behavior.
func NewMockKeyManager() *MockKeyManager {
	return &MockKeyManager{
		sealedKeys: make(map[string][]byte),
	}
}

// SealKey seals a key using the mock implementation.
func (m *MockKeyManager) SealKey(key []byte) (*SealedData, error) {
	if m.SealFunc != nil {
		return m.SealFunc(key)
	}

	// Apply same validation as real implementation
	if len(key) == 0 {
		return nil, ErrKeyEmpty
	}
	if len(key) > maxSealableSize {
		return nil, ErrKeyTooLarge
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Generate mock sealed data
	publicArea := make([]byte, 32)
	privateArea := make([]byte, 64)
	sealedBlobPublic := make([]byte, 32)

	if _, err := io.ReadFull(rand.Reader, publicArea); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand.Reader, privateArea); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand.Reader, sealedBlobPublic); err != nil {
		return nil, err
	}

	sealed := &SealedData{
		PublicArea:       publicArea,
		PrivateArea:      privateArea,
		SealedBlobPublic: sealedBlobPublic,
	}

	// Store the key for later unsealing using hash of sealed data as key
	hash := m.hashSealedData(sealed)
	m.sealedKeys[hash] = append([]byte(nil), key...)

	return sealed, nil
}

// UnsealKey unseals a key using the mock implementation.
func (m *MockKeyManager) UnsealKey(data *SealedData) ([]byte, error) {
	if m.UnsealFunc != nil {
		return m.UnsealFunc(data)
	}

	// Apply same validation as real implementation
	if data == nil {
		return nil, ErrUnsealFailed
	}
	if len(data.PublicArea) == 0 || len(data.PrivateArea) == 0 || len(data.SealedBlobPublic) == 0 {
		return nil, ErrInvalidSealedData
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	hash := m.hashSealedData(data)
	key, ok := m.sealedKeys[hash]
	if !ok {
		return nil, ErrUnsealFailed
	}

	// Return a copy to prevent mutation
	return append([]byte(nil), key...), nil
}

// GenerateAndSealKey generates a random key and seals it.
func (m *MockKeyManager) GenerateAndSealKey() (*SealedData, error) {
	if m.GenerateFunc != nil {
		return m.GenerateFunc()
	}

	key := make([]byte, sealedKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}

	return m.SealKey(key)
}

// Close releases resources (no-op for mock).
func (m *MockKeyManager) Close() error {
	if m.CloseFunc != nil {
		return m.CloseFunc()
	}
	return nil
}

// hashSealedData creates a deterministic hash of sealed data for lookup.
func (m *MockKeyManager) hashSealedData(data *SealedData) string {
	h := sha256.New()
	h.Write(data.PublicArea)
	h.Write(data.PrivateArea)
	h.Write(data.SealedBlobPublic)
	return string(h.Sum(nil))
}

// Reset clears all sealed keys from the mock (useful between tests).
func (m *MockKeyManager) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sealedKeys = make(map[string][]byte)
}
