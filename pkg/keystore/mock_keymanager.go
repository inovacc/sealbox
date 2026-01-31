package keystore

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"sync"
)

// mockSealedEntry stores sealed key data with policy metadata for mock unsealing.
type mockSealedEntry struct {
	key         []byte
	password    []byte
	pcrDigest   []byte
	hasPassword bool
	hasPCR      bool
}

// MockKeyManager implements KeyManager and KeyManagerWithOptions for testing without TPM hardware.
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

	// SealWithOptionsFunc allows customizing SealKeyWithOptions behavior in tests.
	SealWithOptionsFunc func(key []byte, opts ...SealOption) (*SealedData, error)

	// UnsealWithOptionsFunc allows customizing UnsealKeyWithOptions behavior in tests.
	UnsealWithOptionsFunc func(data *SealedData, opts ...SealOption) ([]byte, error)

	// ReadPCRsFunc allows customizing ReadPCRs behavior in tests.
	ReadPCRsFunc func(hash uint16, pcrs ...uint) ([][]byte, error)

	// sealedKeys maps sealed data hash to entry for mock unsealing
	sealedKeys map[string]*mockSealedEntry

	// mockPCRs stores mock PCR values for testing
	mockPCRs map[uint][]byte
}

// NewMockKeyManager creates a new MockKeyManager with default behavior.
func NewMockKeyManager() *MockKeyManager {
	return &MockKeyManager{
		sealedKeys: make(map[string]*mockSealedEntry),
		mockPCRs:   make(map[uint][]byte),
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
	m.sealedKeys[hash] = &mockSealedEntry{
		key: append([]byte(nil), key...),
	}

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

	entry, ok := m.sealedKeys[hash]
	if !ok {
		return nil, ErrUnsealFailed
	}

	// Return a copy to prevent mutation
	return append([]byte(nil), entry.key...), nil
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

	m.sealedKeys = make(map[string]*mockSealedEntry)
	m.mockPCRs = make(map[uint][]byte)
}

// SetMockPCR sets a mock PCR value for testing.
func (m *MockKeyManager) SetMockPCR(index uint, value []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.mockPCRs[index] = append([]byte(nil), value...)
}

// SealKeyWithOptions seals a key with optional PCR binding and/or password protection.
func (m *MockKeyManager) SealKeyWithOptions(key []byte, opts ...SealOption) (*SealedData, error) {
	if m.SealWithOptionsFunc != nil {
		return m.SealWithOptionsFunc(key, opts...)
	}

	// Apply same validation as real implementation
	if len(key) == 0 {
		return nil, ErrKeyEmpty
	}

	if len(key) > maxSealableSize {
		return nil, ErrKeyTooLarge
	}

	cfg := applySealOptions(opts...)

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

	// Compute mock PCR digest if PCRs are selected
	var (
		pcrDigest    []byte
		pcrSelection *SealedPCRSelection
	)

	if cfg.pcrSelection != nil {
		if cfg.pcrSelection.Digest != nil {
			pcrDigest = cfg.pcrSelection.Digest
		} else {
			// Compute from mock PCRs
			h := sha256.New()

			for _, pcr := range cfg.pcrSelection.PCRs {
				if val, ok := m.mockPCRs[pcr]; ok {
					h.Write(val)
				} else {
					// Use zero value for unset PCRs
					h.Write(make([]byte, 32))
				}
			}

			pcrDigest = h.Sum(nil)
		}

		pcrSelection = &SealedPCRSelection{
			HashAlg: uint16(cfg.pcrSelection.Hash),
			PCRs:    cfg.pcrSelection.PCRs,
			Digest:  pcrDigest,
		}
	}

	// Compute mock policy digest
	var policyDigest []byte

	if cfg.hasPolicy() {
		h := sha256.New()
		if pcrDigest != nil {
			h.Write(pcrDigest)
		}

		if len(cfg.password) > 0 {
			h.Write(cfg.password)
		}

		policyDigest = h.Sum(nil)
	}

	sealed := &SealedData{
		Version:          SealedDataV2,
		PublicArea:       publicArea,
		PrivateArea:      privateArea,
		SealedBlobPublic: sealedBlobPublic,
		PolicyDigest:     policyDigest,
		PCRSelection:     pcrSelection,
		HasPassword:      len(cfg.password) > 0,
	}

	// Store the key with policy info for later unsealing
	hash := m.hashSealedData(sealed)
	m.sealedKeys[hash] = &mockSealedEntry{
		key:         append([]byte(nil), key...),
		password:    append([]byte(nil), cfg.password...),
		pcrDigest:   pcrDigest,
		hasPassword: len(cfg.password) > 0,
		hasPCR:      cfg.pcrSelection != nil,
	}

	return sealed, nil
}

// UnsealKeyWithOptions unseals data that may require policy authorization.
func (m *MockKeyManager) UnsealKeyWithOptions(data *SealedData, opts ...SealOption) ([]byte, error) {
	if m.UnsealWithOptionsFunc != nil {
		return m.UnsealWithOptionsFunc(data, opts...)
	}

	// Apply same validation as real implementation
	if data == nil {
		return nil, ErrUnsealFailed
	}

	if len(data.PublicArea) == 0 || len(data.PrivateArea) == 0 || len(data.SealedBlobPublic) == 0 {
		return nil, ErrInvalidSealedData
	}

	cfg := applySealOptions(opts...)

	m.mu.Lock()
	defer m.mu.Unlock()

	hash := m.hashSealedData(data)

	entry, ok := m.sealedKeys[hash]
	if !ok {
		return nil, ErrUnsealFailed
	}

	// Check password if required
	if entry.hasPassword {
		if len(cfg.password) == 0 {
			return nil, ErrPasswordRequired
		}

		if !bytes.Equal(cfg.password, entry.password) {
			return nil, ErrInvalidPassword
		}
	}

	// Check PCR values if required
	if entry.hasPCR && data.PCRSelection != nil {
		// Compute current mock PCR digest
		h := sha256.New()

		for _, pcr := range data.PCRSelection.PCRs {
			if val, ok := m.mockPCRs[pcr]; ok {
				h.Write(val)
			} else {
				h.Write(make([]byte, 32))
			}
		}

		currentDigest := h.Sum(nil)

		if !bytes.Equal(currentDigest, entry.pcrDigest) {
			return nil, ErrPCRMismatch
		}
	}

	// Return a copy to prevent mutation
	return append([]byte(nil), entry.key...), nil
}

// GenerateAndSealKeyWithOptions generates a random key and seals it with options.
func (m *MockKeyManager) GenerateAndSealKeyWithOptions(opts ...SealOption) (*SealedData, error) {
	key := make([]byte, sealedKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	defer SecureZero(key)

	return m.SealKeyWithOptions(key, opts...)
}

// ReadPCRs reads the mock PCR values.
func (m *MockKeyManager) ReadPCRs(hash uint16, pcrs ...uint) ([][]byte, error) {
	if m.ReadPCRsFunc != nil {
		return m.ReadPCRsFunc(hash, pcrs...)
	}

	if len(pcrs) == 0 {
		return nil, ErrInvalidPCRSelection
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	result := make([][]byte, len(pcrs))
	for i, pcr := range pcrs {
		if val, ok := m.mockPCRs[pcr]; ok {
			result[i] = append([]byte(nil), val...)
		} else {
			// Return zero value for unset PCRs
			result[i] = make([]byte, 32)
		}
	}

	return result, nil
}
