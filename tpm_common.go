//go:build linux || windows

package keystore

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/inovacc/keystore/internal/tpm/tpm2"
	"github.com/inovacc/keystore/internal/tpm/tpm2/transport"
)

const (
	// sealedKeySize is the key size for sealed keys (32 bytes = 256 bits for AES-256)
	sealedKeySize = 32

	// maxSealableSize is the maximum size of data that can be sealed to the TPM
	maxSealableSize = 1024
)

// baseKeyManager contains common TPM operations shared across platforms.
type baseKeyManager struct {
	tpm transport.TPMCloser
}

// Close releases TPM resources.
func (m *baseKeyManager) Close() error {
	if m.tpm != nil {
		return m.tpm.Close()
	}
	return nil
}

// createPrimaryKey creates a primary key in the TPM for sealing operations.
func (m *baseKeyManager) createPrimaryKey() (*tpm2.CreatePrimaryResponse, error) {
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
func (m *baseKeyManager) SealKey(key []byte) (*SealedData, error) {
	if len(key) == 0 {
		return nil, ErrKeyEmpty
	}
	if len(key) > maxSealableSize {
		return nil, fmt.Errorf("%w: got %d bytes", ErrKeyTooLarge, len(key))
	}

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

	sealTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:     true,
			FixedParent:  true,
			UserWithAuth: true,
		},
	}

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

	pubBytes := tpm2.Marshal(primaryResp.OutPublic)
	privBytes := tpm2.Marshal(createResp.OutPrivate)
	sealedPubBytes := tpm2.Marshal(createResp.OutPublic)

	return &SealedData{
		PublicArea:       pubBytes,
		PrivateArea:      privBytes,
		SealedBlobPublic: sealedPubBytes,
	}, nil
}

// UnsealKey unseals a key from the TPM.
func (m *baseKeyManager) UnsealKey(data *SealedData) ([]byte, error) {
	if data == nil {
		return nil, fmt.Errorf("%w: sealed data cannot be nil", ErrUnsealFailed)
	}
	if len(data.PublicArea) == 0 || len(data.PrivateArea) == 0 || len(data.SealedBlobPublic) == 0 {
		return nil, ErrInvalidSealedData
	}

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

	outPrivate, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](data.PrivateArea)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to unmarshal private area: %v", ErrUnsealFailed, err)
	}

	outPublic, err := tpm2.Unmarshal[tpm2.TPM2BPublic](data.SealedBlobPublic)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to unmarshal public area: %v", ErrUnsealFailed, err)
	}

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
func (m *baseKeyManager) GenerateAndSealKey() (*SealedData, error) {
	key := make([]byte, sealedKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}

	return m.SealKey(key)
}
