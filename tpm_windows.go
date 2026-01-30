//go:build windows

package tpm

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/windowstpm"
)

const (
	// sealedKeySize is the key size for sealed keys (32 bytes = 256 bits for AES-256)
	sealedKeySize = 32
)

// windowsKeyManager implements KeyManager for Windows using TPM 2.0 via TBS.
type windowsKeyManager struct {
	tpm transport.TPMCloser
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
		tpm: tpmConn,
	}, nil
}

// Close releases TPM resources.
func (m *windowsKeyManager) Close() error {
	if m.tpm != nil {
		return m.tpm.Close()
	}
	return nil
}

// createPrimaryKey creates a primary key in the TPM for sealing operations.
func (m *windowsKeyManager) createPrimaryKey() (*tpm2.CreatePrimaryResponse, error) {
	primaryTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			Decrypt:             true,
			Restricted:          true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					KeyBits: tpm2.NewTPMUSymKeyBits(
						tpm2.TPMAlgAES,
						tpm2.TPMKeyBits(256),
					),
					Mode: tpm2.NewTPMUSymMode(
						tpm2.TPMAlgAES,
						tpm2.TPMAlgCFB,
					),
				},
				KeyBits: 2048,
			},
		),
	}

	createPrimary := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(primaryTemplate),
	}

	return createPrimary.Execute(m.tpm)
}

// SealKey seals a key to the TPM.
func (m *windowsKeyManager) SealKey(key []byte) (*SealedData, error) {
	// Create primary key for sealing
	primaryResp, err := m.createPrimaryKey()
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create primary key: %v", ErrSealFailed, err)
	}

	defer func() {
		flushContext := tpm2.FlushContext{
			FlushHandle: primaryResp.ObjectHandle,
		}
		_, _ = flushContext.Execute(m.tpm)
	}()

	// Create a sealed object containing our key
	sealTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:     true,
			FixedParent:  true,
			UserWithAuth: true,
		},
	}

	// Create sensitive data structure with the key to seal
	inSensitive := tpm2.TPM2BSensitiveCreate{
		Sensitive: &tpm2.TPMSSensitiveCreate{
			Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{
				Buffer: key,
			}),
		},
	}

	create := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryResp.ObjectHandle,
			Name:   primaryResp.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InSensitive: inSensitive,
		InPublic:    tpm2.New2B(sealTemplate),
	}

	createResp, err := create.Execute(m.tpm)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create sealed object: %v", ErrSealFailed, err)
	}

	// Marshal the public area of the primary key
	pubBytes := tpm2.Marshal(primaryResp.OutPublic)

	// Get the private and public areas of the sealed object
	privBytes := tpm2.Marshal(createResp.OutPrivate)
	sealedPubBytes := tpm2.Marshal(createResp.OutPublic)

	return &SealedData{
		PublicArea:       pubBytes,
		PrivateArea:      privBytes,
		SealedBlob:       privBytes,
		SealedBlobPublic: sealedPubBytes,
	}, nil
}

// UnsealKey unseals a key from the TPM.
func (m *windowsKeyManager) UnsealKey(data *SealedData) ([]byte, error) {
	// Recreate the primary key (deterministic, so same key as before)
	primaryResp, err := m.createPrimaryKey()
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create primary key: %v", ErrUnsealFailed, err)
	}

	defer func() {
		flushContext := tpm2.FlushContext{
			FlushHandle: primaryResp.ObjectHandle,
		}
		_, _ = flushContext.Execute(m.tpm)
	}()

	// Unmarshal the sealed object
	outPrivate, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](data.PrivateArea)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to unmarshal private area: %v", ErrUnsealFailed, err)
	}

	outPublic, err := tpm2.Unmarshal[tpm2.TPM2BPublic](data.SealedBlobPublic)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to unmarshal public area: %v", ErrUnsealFailed, err)
	}

	// Load the sealed object
	load := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryResp.ObjectHandle,
			Name:   primaryResp.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPrivate: *outPrivate,
		InPublic:  *outPublic,
	}

	loadResp, err := load.Execute(m.tpm)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to load sealed object: %v", ErrUnsealFailed, err)
	}

	defer func() {
		flushContext := tpm2.FlushContext{
			FlushHandle: loadResp.ObjectHandle,
		}
		_, _ = flushContext.Execute(m.tpm)
	}()

	// Unseal the data
	unseal := tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{
			Handle: loadResp.ObjectHandle,
			Name:   loadResp.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
	}

	unsealResp, err := unseal.Execute(m.tpm)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to unseal data: %v", ErrUnsealFailed, err)
	}

	return unsealResp.OutData.Buffer, nil
}

// GenerateAndSealKey generates a random key and seals it to the TPM.
func (m *windowsKeyManager) GenerateAndSealKey() (*SealedData, error) {
	// Generate a random 32-byte key
	key := make([]byte, sealedKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}

	return m.SealKey(key)
}
