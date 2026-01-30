package tpm

// SealedData represents the data needed to unseal a key from the TPM.
// This structure is platform-independent and can be serialized to JSON.
type SealedData struct {
	// PublicArea is the public portion of the sealing key
	PublicArea []byte `json:"public_area"`

	// PrivateArea is the encrypted private portion
	PrivateArea []byte `json:"private_area"`

	// SealedBlob is the actual sealed data
	SealedBlob []byte `json:"sealed_blob"`

	// SealedBlobPublic is the public area of the sealed blob
	SealedBlobPublic []byte `json:"sealed_blob_public"`
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

// KeyStore defines the interface for persisting sealed keys to disk.
type KeyStore interface {
	// Save stores sealed data to disk
	Save(data *SealedData) error

	// Load retrieves sealed data from disk
	Load() (*SealedData, error)

	// There exists checks if sealed data exists
	Exists() bool

	// Delete removes sealed data from disk
	Delete() error

	// Path returns the storage path
	Path() string
}
