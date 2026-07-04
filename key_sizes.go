package sealbox

// Key-size constants shared across all platforms. These live in an
// unconstrained file (not tpm_common.go, which is //go:build linux || windows)
// because mock_keymanager.go — which compiles on every platform, including
// darwin — depends on them. Keeping them here fixes the darwin build without
// widening the TPM build tag onto a platform that has no TPM backend.
const (
	// sealedKeySize is the key size for sealed keys (32 bytes = 256 bits for AES-256).
	sealedKeySize = 32

	// maxSealableSize is the maximum size of data that can be sealed to the TPM.
	maxSealableSize = 1024
)
