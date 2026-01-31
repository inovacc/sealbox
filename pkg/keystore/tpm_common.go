//go:build linux || windows

package keystore

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/google/go-tpm/tpm2"
	tpm3 "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
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
func (m *baseKeyManager) createPrimaryKey() (*tpm3.CreatePrimaryResponse, error) {
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

	createPrimary := tpm3.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm3.New2B(primaryTemplate),
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
		flushContext := tpm3.FlushContext{
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

	create := tpm3.Create{
		ParentHandle: tpm3.AuthHandle{
			Handle: primaryResp.ObjectHandle,
			Name:   primaryResp.Name,
			Auth:   tpm3.PasswordAuth(nil),
		},
		InSensitive: inSensitive,
		InPublic:    tpm3.New2B(sealTemplate),
	}

	createResp, err := create.Execute(m.tpm)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create sealed object: %v", ErrSealFailed, err)
	}

	pubBytes := tpm3.Marshal(primaryResp.OutPublic)
	privBytes := tpm3.Marshal(createResp.OutPrivate)
	sealedPubBytes := tpm3.Marshal(createResp.OutPublic)

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
		flushContext := tpm3.FlushContext{
			FlushHandle: primaryResp.ObjectHandle,
		}
		_, _ = flushContext.Execute(m.tpm)
	}()

	outPrivate, err := tpm3.Unmarshal[tpm2.TPM2BPrivate](data.PrivateArea)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to unmarshal private area: %v", ErrUnsealFailed, err)
	}

	outPublic, err := tpm3.Unmarshal[tpm2.TPM2BPublic](data.SealedBlobPublic)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to unmarshal public area: %v", ErrUnsealFailed, err)
	}

	load := tpm3.Load{
		ParentHandle: tpm3.AuthHandle{
			Handle: primaryResp.ObjectHandle,
			Name:   primaryResp.Name,
			Auth:   tpm3.PasswordAuth(nil),
		},
		InPrivate: *outPrivate,
		InPublic:  *outPublic,
	}

	loadResp, err := load.Execute(m.tpm)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to load sealed object: %v", ErrUnsealFailed, err)
	}

	defer func() {
		flushContext := tpm3.FlushContext{
			FlushHandle: loadResp.ObjectHandle,
		}
		_, _ = flushContext.Execute(m.tpm)
	}()

	unseal := tpm3.Unseal{
		ItemHandle: tpm3.AuthHandle{
			Handle: loadResp.ObjectHandle,
			Name:   loadResp.Name,
			Auth:   tpm3.PasswordAuth(nil),
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
	defer SecureZero(key)

	return m.SealKey(key)
}

// SealKeyWithOptions seals a key with optional PCR binding and/or password protection.
func (m *baseKeyManager) SealKeyWithOptions(key []byte, opts ...SealOption) (*SealedData, error) {
	if len(key) == 0 {
		return nil, ErrKeyEmpty
	}

	if len(key) > maxSealableSize {
		return nil, fmt.Errorf("%w: got %d bytes", ErrKeyTooLarge, len(key))
	}

	cfg := applySealOptions(opts...)

	// If no policy options, delegate to simple SealKey
	if !cfg.hasPolicy() {
		return m.SealKey(key)
	}

	primaryResp, err := m.createPrimaryKey()
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create primary key: %v", ErrSealFailed, err)
	}

	defer func() {
		fc := tpm3.FlushContext{FlushHandle: primaryResp.ObjectHandle}
		_, _ = fc.Execute(m.tpm)
	}()

	ph := newPolicyHelper(m.tpm)

	// Compute policy digest
	policyDigest, err := ph.computeTrialPolicyDigest(cfg)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to compute policy digest: %v", ErrSealFailed, err)
	}

	// Compute PCR digest if using PCR binding
	var pcrDigest []byte

	if cfg.pcrSelection != nil {
		if cfg.pcrSelection.Digest != nil {
			pcrDigest = cfg.pcrSelection.Digest
		} else {
			pcrDigest, err = ph.computePCRDigest(cfg.pcrSelection.Hash, cfg.pcrSelection.PCRs...)
			if err != nil {
				return nil, fmt.Errorf("%w: failed to compute PCR digest: %v", ErrSealFailed, err)
			}
		}
	}

	// Build seal template with policy
	sealTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:    true,
			FixedParent: true,
			// UserWithAuth is false when using policy-based auth
		},
		AuthPolicy: tpm2.TPM2BDigest{
			Buffer: policyDigest,
		},
	}

	// Build sensitive data with optional password
	inSensitive := tpm2.TPM2BSensitiveCreate{
		Sensitive: &tpm2.TPMSSensitiveCreate{
			Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{
				Buffer: key,
			}),
		},
	}
	if len(cfg.password) > 0 {
		inSensitive.Sensitive.UserAuth = tpm2.TPM2BAuth{
			Buffer: cfg.password,
		}
	}

	create := tpm3.Create{
		ParentHandle: tpm3.AuthHandle{
			Handle: primaryResp.ObjectHandle,
			Name:   primaryResp.Name,
			Auth:   tpm3.PasswordAuth(nil),
		},
		InSensitive: inSensitive,
		InPublic:    tpm3.New2B(sealTemplate),
	}

	createResp, err := create.Execute(m.tpm)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create sealed object: %v", ErrSealFailed, err)
	}

	pubBytes := tpm3.Marshal(primaryResp.OutPublic)
	privBytes := tpm3.Marshal(createResp.OutPrivate)
	sealedPubBytes := tpm3.Marshal(createResp.OutPublic)

	return &SealedData{
		Version:          SealedDataV2,
		PublicArea:       pubBytes,
		PrivateArea:      privBytes,
		SealedBlobPublic: sealedPubBytes,
		PolicyDigest:     policyDigest,
		PCRSelection:     buildSealedPCRSelection(cfg.pcrSelection, pcrDigest),
		HasPassword:      len(cfg.password) > 0,
	}, nil
}

// UnsealKeyWithOptions unseals data that may require policy authorization.
func (m *baseKeyManager) UnsealKeyWithOptions(data *SealedData, opts ...SealOption) ([]byte, error) {
	if data == nil {
		return nil, fmt.Errorf("%w: sealed data cannot be nil", ErrUnsealFailed)
	}

	if len(data.PublicArea) == 0 || len(data.PrivateArea) == 0 || len(data.SealedBlobPublic) == 0 {
		return nil, ErrInvalidSealedData
	}

	// For V1 data or data without policy, use simple unseal
	if !data.RequiresPolicy() {
		return m.UnsealKey(data)
	}

	cfg := applySealOptions(opts...)

	// Validate that required credentials are provided
	if data.HasPassword && len(cfg.password) == 0 {
		return nil, ErrPasswordRequired
	}

	// Reconstruct PCR selection from sealed data if needed
	if data.PCRSelection != nil && cfg.pcrSelection == nil {
		cfg.pcrSelection = &PCRSelection{
			Hash:   tpm2.TPMIAlgHash(data.PCRSelection.HashAlg),
			PCRs:   data.PCRSelection.PCRs,
			Digest: data.PCRSelection.Digest,
		}
	}

	primaryResp, err := m.createPrimaryKey()
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create primary key: %v", ErrUnsealFailed, err)
	}

	defer func() {
		fc := tpm3.FlushContext{FlushHandle: primaryResp.ObjectHandle}
		_, _ = fc.Execute(m.tpm)
	}()

	outPrivate, err := tpm3.Unmarshal[tpm2.TPM2BPrivate](data.PrivateArea)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to unmarshal private area: %v", ErrUnsealFailed, err)
	}

	outPublic, err := tpm3.Unmarshal[tpm2.TPM2BPublic](data.SealedBlobPublic)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to unmarshal public area: %v", ErrUnsealFailed, err)
	}

	load := tpm3.Load{
		ParentHandle: tpm3.AuthHandle{
			Handle: primaryResp.ObjectHandle,
			Name:   primaryResp.Name,
			Auth:   tpm3.PasswordAuth(nil),
		},
		InPrivate: *outPrivate,
		InPublic:  *outPublic,
	}

	loadResp, err := load.Execute(m.tpm)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to load sealed object: %v", ErrUnsealFailed, err)
	}

	defer func() {
		fc := tpm3.FlushContext{FlushHandle: loadResp.ObjectHandle}
		_, _ = fc.Execute(m.tpm)
	}()

	// Create policy session for unsealing
	ph := newPolicyHelper(m.tpm)

	sess, cleanup, err := ph.createPolicySession(cfg)
	if err != nil {
		// Check for specific policy failures
		if data.PCRSelection != nil {
			return nil, fmt.Errorf("%w: %v", ErrPCRMismatch, err)
		}

		return nil, fmt.Errorf("%w: %v", ErrPolicyFailed, err)
	}

	defer func() { _ = cleanup() }()

	unseal := tpm3.Unseal{
		ItemHandle: tpm3.AuthHandle{
			Handle: loadResp.ObjectHandle,
			Name:   loadResp.Name,
			Auth:   sess,
		},
	}

	unsealResp, err := unseal.Execute(m.tpm)
	if err != nil {
		// Map TPM errors to our error types
		if data.HasPassword {
			return nil, fmt.Errorf("%w: %v", ErrInvalidPassword, err)
		}

		if data.PCRSelection != nil {
			return nil, fmt.Errorf("%w: %v", ErrPCRMismatch, err)
		}

		return nil, fmt.Errorf("%w: failed to unseal data: %v", ErrUnsealFailed, err)
	}

	return unsealResp.OutData.Buffer, nil
}

// GenerateAndSealKeyWithOptions generates a random key and seals it with options.
func (m *baseKeyManager) GenerateAndSealKeyWithOptions(opts ...SealOption) (*SealedData, error) {
	key := make([]byte, sealedKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}
	defer SecureZero(key)

	return m.SealKeyWithOptions(key, opts...)
}

// ReadPCRs reads the current values of the specified PCRs.
func (m *baseKeyManager) ReadPCRs(hash uint16, pcrs ...uint) ([][]byte, error) {
	if len(pcrs) == 0 {
		return nil, ErrInvalidPCRSelection
	}

	ph := newPolicyHelper(m.tpm)

	return ph.readPCRValues(tpm2.TPMIAlgHash(hash), pcrs...)
}
