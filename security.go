package sealbox

import (
	"unsafe"
)

// SecureZero overwrites the contents of a byte slice with zeros.
// This helps prevent sensitive data from remaining in memory.
//
// Note: The Go runtime may copy memory during garbage collection,
// so this is a best-effort mitigation, not a guarantee.
func SecureZero(b []byte) {
	if len(b) == 0 {
		return
	}
	// Use volatile-like access pattern to prevent compiler optimization
	ptr := unsafe.Pointer(&b[0])
	for i := range b {
		*(*byte)(unsafe.Add(ptr, i)) = 0
	}
}

// SecureZeroString attempts to zero a string's underlying bytes.
// Note: Strings are immutable in Go, so this only works if the string
// was created from a mutable source (e.g., []byte conversion).
// Use with caution - this may cause undefined behavior in some cases.
func SecureZeroString(s *string) {
	if s == nil || len(*s) == 0 {
		return
	}
	// Get the underlying bytes - this is unsafe but necessary for security
	b := unsafe.Slice(unsafe.StringData(*s), len(*s))
	SecureZero(b)
}

// WithKeyCleanup executes a function with a key and ensures the key is zeroed afterward.
// This provides a safe way to use sensitive key material.
//
// Example:
//
//	var result []byte
//	err := WithKeyCleanup(sensitiveKey, func(key []byte) error {
//	    // Use the key
//	    result = encrypt(data, key)
//	    return nil
//	})
func WithKeyCleanup(key []byte, fn func([]byte) error) error {
	defer SecureZero(key)
	return fn(key)
}

// CopyAndZero copies the source slice and zeros the original.
// Returns a new slice that the caller is responsible for zeroing.
func CopyAndZero(src []byte) []byte {
	if len(src) == 0 {
		return nil
	}

	dst := make([]byte, len(src))
	copy(dst, src)
	SecureZero(src)

	return dst
}
