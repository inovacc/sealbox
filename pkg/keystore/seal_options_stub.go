//go:build !linux && !windows

package keystore

// SealOption configures sealing behavior.
// On unsupported platforms, options are accepted but have no effect.
type SealOption func(*sealConfig)

// sealConfig holds the configuration for sealing operations.
type sealConfig struct {
	password       []byte
	pcrSelection   *PCRSelection
	sessionEncrypt bool
}

// PCRSelection specifies which PCRs to bind during sealing.
type PCRSelection struct {
	// Hash is the hash algorithm for PCR values.
	Hash uint16

	// PCRs is the list of PCR indices to bind.
	PCRs []uint

	// Digest is the expected PCR digest.
	Digest []byte
}

// WithPassword protects the sealed key with a password.
func WithPassword(password []byte) SealOption {
	return func(c *sealConfig) {
		c.password = password
	}
}

// WithPCRs binds the sealed key to the current values of the specified PCRs.
func WithPCRs(hash uint16, pcrs ...uint) SealOption {
	return func(c *sealConfig) {
		c.pcrSelection = &PCRSelection{
			Hash: hash,
			PCRs: pcrs,
		}
	}
}

// WithPCRDigest binds the sealed key to a specific PCR digest.
func WithPCRDigest(hash uint16, digest []byte, pcrs ...uint) SealOption {
	return func(c *sealConfig) {
		c.pcrSelection = &PCRSelection{
			Hash:   hash,
			PCRs:   pcrs,
			Digest: digest,
		}
	}
}

// WithSessionEncryption enables parameter encryption for the TPM session.
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
