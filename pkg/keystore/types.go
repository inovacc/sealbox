package keystore

// SealedDataVersion is the version of the SealedData format.
const (
	// SealedDataV1 is the original format without policy metadata.
	SealedDataV1 = 1
	// SealedDataV2 adds policy metadata for PCR and password protection.
	SealedDataV2 = 2
)

// SealedData represents the data needed to unseal a key from the TPM.
// This structure is platform-independent and can be serialized to JSON.
type SealedData struct {
	// Version indicates the format version (0 or 1 = V1, 2 = V2).
	// V1 data is treated as version 1 for backward compatibility.
	Version int `json:"version,omitempty"`

	// PublicArea is the public portion of the primary sealing key
	PublicArea []byte `json:"public_area"`

	// PrivateArea is the encrypted private portion of the sealed object
	PrivateArea []byte `json:"private_area"`

	// SealedBlobPublic is the public area of the sealed object
	SealedBlobPublic []byte `json:"sealed_blob_public"`

	// PolicyDigest is the policy digest used during sealing (V2 only).
	// Empty if no policy was used.
	PolicyDigest []byte `json:"policy_digest,omitempty"`

	// PCRSelection contains the PCR binding configuration (V2 only).
	// Nil if no PCR binding was used.
	PCRSelection *SealedPCRSelection `json:"pcr_selection,omitempty"`

	// HasPassword indicates whether a password is required for unsealing (V2 only).
	HasPassword bool `json:"has_password,omitempty"`
}

// SealedPCRSelection stores PCR binding metadata in sealed data.
type SealedPCRSelection struct {
	// HashAlg is the hash algorithm identifier (e.g., 0x000B for SHA256).
	HashAlg uint16 `json:"hash_alg"`

	// PCRs is the list of PCR indices that were bound.
	PCRs []uint `json:"pcrs"`

	// Digest is the PCR digest that was bound.
	Digest []byte `json:"digest"`
}

// GetVersion returns the effective version of the sealed data.
// Returns SealedDataV1 for version 0 or 1 (backward compatibility).
func (s *SealedData) GetVersion() int {
	if s.Version < SealedDataV2 {
		return SealedDataV1
	}

	return s.Version
}

// RequiresPolicy returns true if the sealed data requires a policy session.
func (s *SealedData) RequiresPolicy() bool {
	return len(s.PolicyDigest) > 0 || s.PCRSelection != nil || s.HasPassword
}

// KeyManager defines the interface for TPM key operations.
// Implementations are platform-specific.
type KeyManager interface {
	// SealKey seals arbitrary data to the TPM.
	// The sealed data can only be recovered on the same TPM.
	SealKey(key []byte) (*SealedData, error)

	// UnsealKey retrieves sealed data from the TPM.
	// Returns the original key material.
	UnsealKey(data *SealedData) ([]byte, error)

	// GenerateAndSealKey creates a random 32-byte key and seals it.
	// This is the recommended way to create new sealed keys.
	GenerateAndSealKey() (*SealedData, error)

	// Close releases any TPM resources.
	Close() error
}

// KeyManagerWithOptions extends KeyManager with policy-based sealing operations.
type KeyManagerWithOptions interface {
	KeyManager

	// SealKeyWithOptions seals data with optional PCR binding and/or password protection.
	SealKeyWithOptions(key []byte, opts ...SealOption) (*SealedData, error)

	// UnsealKeyWithOptions unseals data that may require policy authorization.
	UnsealKeyWithOptions(data *SealedData, opts ...SealOption) ([]byte, error)

	// GenerateAndSealKeyWithOptions generates a random key and seals it with options.
	GenerateAndSealKeyWithOptions(opts ...SealOption) (*SealedData, error)

	// ReadPCRs reads the current values of the specified PCRs.
	ReadPCRs(hash uint16, pcrs ...uint) ([][]byte, error)
}

// KeyStore defines the interface for persisting sealed keys to disk.
type KeyStore interface {
	// Save stores sealed data to disk
	Save(data *SealedData) error

	// Load retrieves sealed data from disk
	Load() (*SealedData, error)

	// Exists checks if sealed data exists
	Exists() bool

	// Delete removes sealed data from disk
	Delete() error

	// Path returns the storage path
	Path() string
}
