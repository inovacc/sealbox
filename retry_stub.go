//go:build !linux && !windows

package keystore

import "time"

// RetryConfig configures retry behavior for TPM operations.
type RetryConfig struct {
	MaxRetries    int
	InitialDelay  time.Duration
	MaxDelay      time.Duration
	BackoffFactor float64
}

// DefaultRetryConfig returns the default retry configuration.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries:    3,
		InitialDelay:  10 * time.Millisecond,
		MaxDelay:      1 * time.Second,
		BackoffFactor: 2.0,
	}
}

// IsRetryableTPMError always returns false on unsupported platforms.
func IsRetryableTPMError(err error) bool {
	return false
}

// IsAuthFailure always returns false on unsupported platforms.
func IsAuthFailure(err error) bool {
	return false
}

// IsPCRError always returns false on unsupported platforms.
func IsPCRError(err error) bool {
	return false
}

// WithRetry executes the function once on unsupported platforms.
func WithRetry[T any](cfg RetryConfig, fn func() (T, error)) (T, error) {
	return fn()
}

// WithRetryNoResult executes the function once on unsupported platforms.
func WithRetryNoResult(cfg RetryConfig, fn func() error) error {
	return fn()
}
