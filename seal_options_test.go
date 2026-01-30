package keystore

import (
	"testing"

	"github.com/inovacc/keystore/internal/tpm/tpm2"
)

func TestWithPassword(t *testing.T) {
	password := []byte("secret123")
	opt := WithPassword(password)
	cfg := &sealConfig{}
	opt(cfg)

	if string(cfg.password) != string(password) {
		t.Errorf("WithPassword: got %v, want %v", cfg.password, password)
	}
}

func TestWithPCRs(t *testing.T) {
	opt := WithPCRs(tpm2.TPMAlgSHA256, 0, 1, 7)
	cfg := &sealConfig{}
	opt(cfg)

	if cfg.pcrSelection == nil {
		t.Fatal("WithPCRs: pcrSelection is nil")
	}
	if cfg.pcrSelection.Hash != tpm2.TPMAlgSHA256 {
		t.Errorf("WithPCRs: Hash got %v, want %v", cfg.pcrSelection.Hash, tpm2.TPMAlgSHA256)
	}
	if len(cfg.pcrSelection.PCRs) != 3 {
		t.Errorf("WithPCRs: len(PCRs) got %d, want 3", len(cfg.pcrSelection.PCRs))
	}
	if cfg.pcrSelection.Digest != nil {
		t.Error("WithPCRs: Digest should be nil")
	}
}

func TestWithPCRDigest(t *testing.T) {
	digest := []byte("test-digest-value-32bytes-long!!")
	opt := WithPCRDigest(tpm2.TPMAlgSHA256, digest, 0, 7)
	cfg := &sealConfig{}
	opt(cfg)

	if cfg.pcrSelection == nil {
		t.Fatal("WithPCRDigest: pcrSelection is nil")
	}
	if string(cfg.pcrSelection.Digest) != string(digest) {
		t.Errorf("WithPCRDigest: Digest got %v, want %v", cfg.pcrSelection.Digest, digest)
	}
	if len(cfg.pcrSelection.PCRs) != 2 {
		t.Errorf("WithPCRDigest: len(PCRs) got %d, want 2", len(cfg.pcrSelection.PCRs))
	}
}

func TestWithSessionEncryption(t *testing.T) {
	opt := WithSessionEncryption()
	cfg := &sealConfig{}
	opt(cfg)

	if !cfg.sessionEncrypt {
		t.Error("WithSessionEncryption: sessionEncrypt should be true")
	}
}

func TestApplySealOptions(t *testing.T) {
	password := []byte("pass")
	cfg := applySealOptions(
		WithPassword(password),
		WithPCRs(tpm2.TPMAlgSHA256, 0),
		WithSessionEncryption(),
	)

	if string(cfg.password) != string(password) {
		t.Errorf("applySealOptions: password mismatch")
	}
	if cfg.pcrSelection == nil {
		t.Error("applySealOptions: pcrSelection is nil")
	}
	if !cfg.sessionEncrypt {
		t.Error("applySealOptions: sessionEncrypt should be true")
	}
}

func TestSealConfigHasPolicy(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *sealConfig
		expected bool
	}{
		{
			name:     "empty config",
			cfg:      &sealConfig{},
			expected: false,
		},
		{
			name: "with password only",
			cfg: &sealConfig{
				password: []byte("secret"),
			},
			expected: true,
		},
		{
			name: "with PCR only",
			cfg: &sealConfig{
				pcrSelection: &PCRSelection{
					Hash: tpm2.TPMAlgSHA256,
					PCRs: []uint{0},
				},
			},
			expected: true,
		},
		{
			name: "with both",
			cfg: &sealConfig{
				password: []byte("secret"),
				pcrSelection: &PCRSelection{
					Hash: tpm2.TPMAlgSHA256,
					PCRs: []uint{0},
				},
			},
			expected: true,
		},
		{
			name: "with session encryption only",
			cfg: &sealConfig{
				sessionEncrypt: true,
			},
			expected: false, // session encryption alone doesn't require policy
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.cfg.hasPolicy()
			if result != tc.expected {
				t.Errorf("hasPolicy() = %v, want %v", result, tc.expected)
			}
		})
	}
}
