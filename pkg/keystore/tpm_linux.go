//go:build linux

package keystore

import (
	"fmt"
	"os"

	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

const (
	// defaultTPMDevice is the default TPM device path on Linux
	defaultTPMDevice = "/dev/tpmrm0"
)

// linuxKeyManager implements KeyManager for Linux using TPM 2.0.
type linuxKeyManager struct {
	baseKeyManager
}

// IsAvailable checks if a TPM device is accessible on Linux.
func IsAvailable() bool {
	device := getTPMDevice()

	if _, err := os.Stat(device); os.IsNotExist(err) {
		return false
	}

	tpmConn, err := linuxtpm.Open(device)
	if err != nil {
		return false
	}

	_ = tpmConn.Close()
	return true
}

// NewKeyManager creates a new TPM key manager for Linux.
func NewKeyManager() (KeyManager, error) {
	device := getTPMDevice()

	if _, err := os.Stat(device); os.IsNotExist(err) {
		return nil, fmt.Errorf("%w: device %s not found", ErrTPMNotAvailable, device)
	}

	tpmConn, err := linuxtpm.Open(device)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTPMNotAvailable, err)
	}

	return &linuxKeyManager{
		baseKeyManager: baseKeyManager{tpm: tpmConn},
	}, nil
}

// getTPMDevice returns the TPM device path.
func getTPMDevice() string {
	device := os.Getenv("TPM_DEVICE")
	if device == "" {
		device = defaultTPMDevice
	}
	return device
}
