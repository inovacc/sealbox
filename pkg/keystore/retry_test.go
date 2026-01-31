package keystore

import (
	"errors"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
)

func TestIsRetryableTPMError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "non-TPM error",
			err:      errors.New("some error"),
			expected: false,
		},
		{
			name:     "TPM_RC_RETRY",
			err:      tpm2.TPMRCRetry,
			expected: true,
		},
		{
			name:     "TPM_RC_YIELDED",
			err:      tpm2.TPMRCYielded,
			expected: true,
		},
		{
			name:     "TPM_RC_MEMORY",
			err:      tpm2.TPMRCMemory,
			expected: true,
		},
		{
			name:     "TPM_RC_SESSION_MEMORY",
			err:      tpm2.TPMRCSessionMemory,
			expected: true,
		},
		{
			name:     "TPM_RC_NV_RATE",
			err:      tpm2.TPMRCNVRate,
			expected: true,
		},
		{
			name:     "TPM_RC_AUTH_FAIL (not retryable)",
			err:      tpm2.TPMRCAuthFail,
			expected: false,
		},
		{
			name:     "TPM_RC_PCR (not retryable)",
			err:      tpm2.TPMRCPCR,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsRetryableTPMError(tt.err)
			if result != tt.expected {
				t.Errorf("IsRetryableTPMError(%v) = %v, want %v", tt.err, result, tt.expected)
			}
		})
	}
}

func TestIsAuthFailure(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "TPM_RC_AUTH_FAIL",
			err:      tpm2.TPMRCAuthFail,
			expected: true,
		},
		{
			name:     "TPM_RC_BAD_AUTH",
			err:      tpm2.TPMRCBadAuth,
			expected: true,
		},
		{
			name:     "TPM_RC_POLICY",
			err:      tpm2.TPMRCPolicy,
			expected: true,
		},
		{
			name:     "TPM_RC_POLICY_FAIL",
			err:      tpm2.TPMRCPolicyFail,
			expected: true,
		},
		{
			name:     "TPM_RC_RETRY (not auth failure)",
			err:      tpm2.TPMRCRetry,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsAuthFailure(tt.err)
			if result != tt.expected {
				t.Errorf("IsAuthFailure(%v) = %v, want %v", tt.err, result, tt.expected)
			}
		})
	}
}

func TestIsPCRError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "TPM_RC_PCR",
			err:      tpm2.TPMRCPCR,
			expected: true,
		},
		{
			name:     "TPM_RC_PCR_CHANGED",
			err:      tpm2.TPMRCPCRChanged,
			expected: true,
		},
		{
			name:     "TPM_RC_RETRY (not PCR error)",
			err:      tpm2.TPMRCRetry,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsPCRError(tt.err)
			if result != tt.expected {
				t.Errorf("IsPCRError(%v) = %v, want %v", tt.err, result, tt.expected)
			}
		})
	}
}

func TestDefaultRetryConfig(t *testing.T) {
	cfg := DefaultRetryConfig()

	if cfg.MaxRetries != 3 {
		t.Errorf("MaxRetries = %d, want 3", cfg.MaxRetries)
	}

	if cfg.InitialDelay != 10*time.Millisecond {
		t.Errorf("InitialDelay = %v, want 10ms", cfg.InitialDelay)
	}

	if cfg.MaxDelay != 1*time.Second {
		t.Errorf("MaxDelay = %v, want 1s", cfg.MaxDelay)
	}

	if cfg.BackoffFactor != 2.0 {
		t.Errorf("BackoffFactor = %v, want 2.0", cfg.BackoffFactor)
	}
}

func TestWithRetry_Success(t *testing.T) {
	cfg := DefaultRetryConfig()
	cfg.InitialDelay = 1 * time.Millisecond

	callCount := 0

	result, err := WithRetry(cfg, func() (string, error) {
		callCount++
		return "success", nil
	})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if result != "success" {
		t.Errorf("result = %v, want 'success'", result)
	}

	if callCount != 1 {
		t.Errorf("callCount = %d, want 1", callCount)
	}
}

func TestWithRetry_RetryableError(t *testing.T) {
	cfg := RetryConfig{
		MaxRetries:    2,
		InitialDelay:  1 * time.Millisecond,
		MaxDelay:      10 * time.Millisecond,
		BackoffFactor: 2.0,
	}

	callCount := 0

	result, err := WithRetry(cfg, func() (string, error) {
		callCount++
		if callCount < 3 {
			return "", tpm2.TPMRCRetry
		}

		return "success", nil
	})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if result != "success" {
		t.Errorf("result = %v, want 'success'", result)
	}

	if callCount != 3 {
		t.Errorf("callCount = %d, want 3", callCount)
	}
}

func TestWithRetry_NonRetryableError(t *testing.T) {
	cfg := RetryConfig{
		MaxRetries:    3,
		InitialDelay:  1 * time.Millisecond,
		MaxDelay:      10 * time.Millisecond,
		BackoffFactor: 2.0,
	}

	callCount := 0
	_, err := WithRetry(cfg, func() (string, error) {
		callCount++
		return "", tpm2.TPMRCAuthFail
	})

	if !errors.Is(err, tpm2.TPMRCAuthFail) {
		t.Errorf("expected TPM_RC_AUTH_FAIL error, got: %v", err)
	}

	if callCount != 1 {
		t.Errorf("callCount = %d, want 1 (should not retry non-retryable errors)", callCount)
	}
}

func TestWithRetry_MaxRetriesExceeded(t *testing.T) {
	cfg := RetryConfig{
		MaxRetries:    2,
		InitialDelay:  1 * time.Millisecond,
		MaxDelay:      10 * time.Millisecond,
		BackoffFactor: 2.0,
	}

	callCount := 0
	_, err := WithRetry(cfg, func() (string, error) {
		callCount++
		return "", tpm2.TPMRCRetry
	})

	if !errors.Is(err, tpm2.TPMRCRetry) {
		t.Errorf("expected TPM_RC_RETRY error, got: %v", err)
	}
	// Initial call + 2 retries = 3 total calls
	if callCount != 3 {
		t.Errorf("callCount = %d, want 3", callCount)
	}
}

func TestWithRetryNoResult(t *testing.T) {
	cfg := RetryConfig{
		MaxRetries:    1,
		InitialDelay:  1 * time.Millisecond,
		MaxDelay:      10 * time.Millisecond,
		BackoffFactor: 2.0,
	}

	callCount := 0

	err := WithRetryNoResult(cfg, func() error {
		callCount++
		if callCount < 2 {
			return tpm2.TPMRCMemory
		}

		return nil
	})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if callCount != 2 {
		t.Errorf("callCount = %d, want 2", callCount)
	}
}
