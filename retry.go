//go:build linux || windows

package keystore

import (
	"errors"
	"time"

	"github.com/inovacc/keystore/internal/tpm/tpm2"
)

// RetryConfig configures retry behavior for TPM operations.
type RetryConfig struct {
	// MaxRetries is the maximum number of retry attempts (default: 3)
	MaxRetries int

	// InitialDelay is the delay before the first retry (default: 10ms)
	InitialDelay time.Duration

	// MaxDelay is the maximum delay between retries (default: 1s)
	MaxDelay time.Duration

	// BackoffFactor multiplies the delay after each retry (default: 2.0)
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

// retryableTPMErrors contains TPM return codes that indicate transient failures
// where retrying the operation may succeed.
var retryableTPMErrors = map[tpm2.TPMRC]struct{}{
	tpm2.TPMRCRetry:          {}, // TPM was not able to start the command
	tpm2.TPMRCYielded:        {}, // TPM suspended operation, forward progress was made
	tpm2.TPMRCTesting:        {}, // TPM is performing self-tests
	tpm2.TPMRCMemory:         {}, // Out of shared object/session memory
	tpm2.TPMRCSessionMemory:  {}, // Out of memory for session contexts
	tpm2.TPMRCObjectMemory:   {}, // Out of memory for object contexts
	tpm2.TPMRCSessionHandles: {}, // Out of session handles
	tpm2.TPMRCNVRate:         {}, // TPM is rate-limiting NV accesses
	tpm2.TPMRCNVUnavailable:  {}, // NV is not currently accessible
}

// IsRetryableTPMError checks if the given error is a retryable TPM error.
// Retryable errors indicate transient TPM state issues where retrying
// the operation may succeed after a short delay.
func IsRetryableTPMError(err error) bool {
	if err == nil {
		return false
	}

	// Check if it's a TPMRC error
	var tpmRC tpm2.TPMRC
	if errors.As(err, &tpmRC) {
		_, retryable := retryableTPMErrors[tpmRC]
		return retryable || tpmRC.IsWarning()
	}

	return false
}

// IsAuthFailure checks if the error indicates an authentication failure.
// These errors should NOT be retried as they indicate incorrect credentials.
func IsAuthFailure(err error) bool {
	if err == nil {
		return false
	}

	var tpmRC tpm2.TPMRC
	if errors.As(err, &tpmRC) {
		return errors.Is(tpmRC, tpm2.TPMRCAuthFail) ||
			errors.Is(tpmRC, tpm2.TPMRCBadAuth) ||
			errors.Is(tpmRC, tpm2.TPMRCPolicy) ||
			errors.Is(tpmRC, tpm2.TPMRCPolicyFail)
	}

	return false
}

// IsPCRError checks if the error indicates a PCR mismatch.
func IsPCRError(err error) bool {
	if err == nil {
		return false
	}

	var tpmRC tpm2.TPMRC
	if errors.As(err, &tpmRC) {
		return errors.Is(tpmRC, tpm2.TPMRCPCR) ||
			errors.Is(tpmRC, tpm2.TPMRCPCRChanged)
	}

	return false
}

// WithRetry executes the given function with retry logic for transient TPM errors.
// The function will be retried up to MaxRetries times if it returns a retryable error.
// Non-retryable errors (like authentication failures) are returned immediately.
func WithRetry[T any](cfg RetryConfig, fn func() (T, error)) (T, error) {
	var result T
	var lastErr error
	delay := cfg.InitialDelay

	for attempt := 0; attempt <= cfg.MaxRetries; attempt++ {
		result, lastErr = fn()
		if lastErr == nil {
			return result, nil
		}

		// Don't retry non-retryable errors
		if !IsRetryableTPMError(lastErr) {
			return result, lastErr
		}

		// Don't sleep on the last attempt
		if attempt < cfg.MaxRetries {
			time.Sleep(delay)
			delay = time.Duration(float64(delay) * cfg.BackoffFactor)
			if delay > cfg.MaxDelay {
				delay = cfg.MaxDelay
			}
		}
	}

	return result, lastErr
}

// WithRetryNoResult executes the given function with retry logic.
// This is a convenience wrapper for functions that don't return a result.
func WithRetryNoResult(cfg RetryConfig, fn func() error) error {
	_, err := WithRetry(cfg, func() (struct{}, error) {
		return struct{}{}, fn()
	})
	return err
}
