//go:build windows

package keystore

import (
	"fmt"

	"github.com/inovacc/keystore/internal/tpm/tpm2/transport/windowstpm"
)

// windowsKeyManager implements KeyManager for Windows using TPM 2.0 via TBS.
type windowsKeyManager struct {
	baseKeyManager
}

// IsAvailable checks if a TPM device is accessible on Windows via TBS.
func IsAvailable() bool {
	tpmConn, err := windowstpm.Open()
	if err != nil {
		return false
	}

	_ = tpmConn.Close()

	return true
}

// NewKeyManager creates a new TPM key manager for Windows.
func NewKeyManager() (KeyManager, error) {
	tpmConn, err := windowstpm.Open()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTPMNotAvailable, err)
	}

	return &windowsKeyManager{
		baseKeyManager: baseKeyManager{tpm: tpmConn},
	}, nil
}
