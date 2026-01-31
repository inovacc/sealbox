//go:build !linux && !windows

package keystore

// stubKeyManager is a placeholder for unsupported platforms.
type stubKeyManager struct{}

// IsAvailable returns false on unsupported platforms.
func IsAvailable() bool {
	return false
}

// NewKeyManager returns an error on unsupported platforms.
func NewKeyManager() (KeyManager, error) {
	return nil, ErrTPMNotSupported
}

// Close is a no-op on unsupported platforms.
func (m *stubKeyManager) Close() error {
	return nil
}

// SealKey returns an error on unsupported platforms.
func (m *stubKeyManager) SealKey(key []byte) (*SealedData, error) {
	return nil, ErrTPMNotSupported
}

// UnsealKey returns an error on unsupported platforms.
func (m *stubKeyManager) UnsealKey(data *SealedData) ([]byte, error) {
	return nil, ErrTPMNotSupported
}

// GenerateAndSealKey returns an error on unsupported platforms.
func (m *stubKeyManager) GenerateAndSealKey() (*SealedData, error) {
	return nil, ErrTPMNotSupported
}
