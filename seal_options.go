//go:build linux || windows

package sealbox

import (
	"github.com/google/go-tpm/tpm2"
)

// SealOption configures sealing behavior.
type SealOption func(*sealConfig)

// sealConfig holds the configuration for sealing operations.
type sealConfig struct {
	password       []byte
	pcrSelection   *PCRSelection
	sessionEncrypt bool
}

// PCRSelection specifies which PCRs to bind during sealing.
type PCRSelection struct {
	// Hash is the hash algorithm for PCR values (SHA256 recommended).
	Hash tpm2.TPMIAlgHash

	// PCRs is the list of PCR indices to bind (e.g., 0, 1, 2, 7).
	PCRs []uint

	// Digest is the expected PCR digest. If nil, current PCR values are read.
	Digest []byte
}

// WithPassword protects the sealed key with a password.
// The password is required during unsealing.
func WithPassword(password []byte) SealOption {
	return func(c *sealConfig) {
		c.password = password
	}
}

// WithPCRs binds the sealed key to the current values of the specified PCRs.
// The key can only be unsealed if the PCR values match.
func WithPCRs(hash tpm2.TPMIAlgHash, pcrs ...uint) SealOption {
	return func(c *sealConfig) {
		c.pcrSelection = &PCRSelection{
			Hash: hash,
			PCRs: pcrs,
		}
	}
}

// WithPCRDigest binds the sealed key to a specific PCR digest.
// Use this when you know the expected PCR values in advance.
func WithPCRDigest(hash tpm2.TPMIAlgHash, digest []byte, pcrs ...uint) SealOption {
	return func(c *sealConfig) {
		c.pcrSelection = &PCRSelection{
			Hash:   hash,
			PCRs:   pcrs,
			Digest: digest,
		}
	}
}

// WithSessionEncryption enables parameter encryption for the TPM session.
// This provides additional protection for the sealed data in transit.
func WithSessionEncryption() SealOption {
	return func(c *sealConfig) {
		c.sessionEncrypt = true
	}
}

// applySealOptions applies the given options to a sealConfig.
func applySealOptions(opts ...SealOption) *sealConfig {
	cfg := &sealConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	return cfg
}

// hasPolicy returns true if the config requires a policy session.
func (c *sealConfig) hasPolicy() bool {
	return c.pcrSelection != nil || len(c.password) > 0
}
