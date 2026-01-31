package sealbox

import (
	"bytes"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

func TestMockKeyManagerSealWithOptions(t *testing.T) {
	t.Run("seal with password", func(t *testing.T) {
		m := NewMockKeyManager()
		defer m.Reset()

		key := []byte("test-key-32-bytes-long-here!!!!")
		password := []byte("secret123")

		sealed, err := m.SealKeyWithOptions(key, WithPassword(password))
		if err != nil {
			t.Fatalf("SealKeyWithOptions failed: %v", err)
		}

		if sealed.Version != SealedDataV2 {
			t.Errorf("Version = %d, want %d", sealed.Version, SealedDataV2)
		}

		if !sealed.HasPassword {
			t.Error("HasPassword should be true")
		}

		if len(sealed.PolicyDigest) == 0 {
			t.Error("PolicyDigest should not be empty")
		}
	})

	t.Run("seal with PCRs", func(t *testing.T) {
		m := NewMockKeyManager()
		defer m.Reset()

		// Set mock PCR values
		m.SetMockPCR(0, bytes.Repeat([]byte{0xAA}, 32))
		m.SetMockPCR(7, bytes.Repeat([]byte{0xBB}, 32))

		key := []byte("test-key-32-bytes-long-here!!!!")

		sealed, err := m.SealKeyWithOptions(key, WithPCRs(tpm2.TPMAlgSHA256, 0, 7))
		if err != nil {
			t.Fatalf("SealKeyWithOptions failed: %v", err)
		}

		if sealed.PCRSelection == nil {
			t.Fatal("PCRSelection should not be nil")
		}

		if len(sealed.PCRSelection.PCRs) != 2 {
			t.Errorf("len(PCRs) = %d, want 2", len(sealed.PCRSelection.PCRs))
		}

		if len(sealed.PCRSelection.Digest) == 0 {
			t.Error("PCR Digest should not be empty")
		}
	})

	t.Run("seal with password and PCRs", func(t *testing.T) {
		m := NewMockKeyManager()
		defer m.Reset()

		m.SetMockPCR(0, bytes.Repeat([]byte{0xCC}, 32))

		key := []byte("test-key-32-bytes-long-here!!!!")
		password := []byte("secret")

		sealed, err := m.SealKeyWithOptions(key,
			WithPassword(password),
			WithPCRs(tpm2.TPMAlgSHA256, 0),
		)
		if err != nil {
			t.Fatalf("SealKeyWithOptions failed: %v", err)
		}

		if !sealed.HasPassword {
			t.Error("HasPassword should be true")
		}

		if sealed.PCRSelection == nil {
			t.Fatal("PCRSelection should not be nil")
		}
	})
}

func TestMockKeyManagerUnsealWithOptions(t *testing.T) {
	t.Run("unseal with correct password", func(t *testing.T) {
		m := NewMockKeyManager()
		defer m.Reset()

		key := []byte("test-key-32-bytes-long-here!!!!")
		password := []byte("secret123")

		sealed, err := m.SealKeyWithOptions(key, WithPassword(password))
		if err != nil {
			t.Fatalf("SealKeyWithOptions failed: %v", err)
		}

		unsealed, err := m.UnsealKeyWithOptions(sealed, WithPassword(password))
		if err != nil {
			t.Fatalf("UnsealKeyWithOptions failed: %v", err)
		}

		if !bytes.Equal(unsealed, key) {
			t.Errorf("unsealed key mismatch")
		}
	})

	t.Run("unseal without required password", func(t *testing.T) {
		m := NewMockKeyManager()
		defer m.Reset()

		key := []byte("test-key-32-bytes-long-here!!!!")
		password := []byte("secret123")

		sealed, err := m.SealKeyWithOptions(key, WithPassword(password))
		if err != nil {
			t.Fatalf("SealKeyWithOptions failed: %v", err)
		}

		_, err = m.UnsealKeyWithOptions(sealed)
		if err != ErrPasswordRequired {
			t.Errorf("expected ErrPasswordRequired, got %v", err)
		}
	})

	t.Run("unseal with wrong password", func(t *testing.T) {
		m := NewMockKeyManager()
		defer m.Reset()

		key := []byte("test-key-32-bytes-long-here!!!!")
		password := []byte("secret123")

		sealed, err := m.SealKeyWithOptions(key, WithPassword(password))
		if err != nil {
			t.Fatalf("SealKeyWithOptions failed: %v", err)
		}

		_, err = m.UnsealKeyWithOptions(sealed, WithPassword([]byte("wrongpassword")))
		if err != ErrInvalidPassword {
			t.Errorf("expected ErrInvalidPassword, got %v", err)
		}
	})

	t.Run("unseal with matching PCRs", func(t *testing.T) {
		m := NewMockKeyManager()
		defer m.Reset()

		pcrValue := bytes.Repeat([]byte{0xDD}, 32)
		m.SetMockPCR(0, pcrValue)

		key := []byte("test-key-32-bytes-long-here!!!!")

		sealed, err := m.SealKeyWithOptions(key, WithPCRs(tpm2.TPMAlgSHA256, 0))
		if err != nil {
			t.Fatalf("SealKeyWithOptions failed: %v", err)
		}

		// PCRs haven't changed, should succeed
		unsealed, err := m.UnsealKeyWithOptions(sealed)
		if err != nil {
			t.Fatalf("UnsealKeyWithOptions failed: %v", err)
		}

		if !bytes.Equal(unsealed, key) {
			t.Errorf("unsealed key mismatch")
		}
	})

	t.Run("unseal with changed PCRs", func(t *testing.T) {
		m := NewMockKeyManager()
		defer m.Reset()

		m.SetMockPCR(0, bytes.Repeat([]byte{0xEE}, 32))

		key := []byte("test-key-32-bytes-long-here!!!!")

		sealed, err := m.SealKeyWithOptions(key, WithPCRs(tpm2.TPMAlgSHA256, 0))
		if err != nil {
			t.Fatalf("SealKeyWithOptions failed: %v", err)
		}

		// Change PCR value
		m.SetMockPCR(0, bytes.Repeat([]byte{0xFF}, 32))

		_, err = m.UnsealKeyWithOptions(sealed)
		if err != ErrPCRMismatch {
			t.Errorf("expected ErrPCRMismatch, got %v", err)
		}
	})
}

func TestMockKeyManagerGenerateAndSealWithOptions(t *testing.T) {
	m := NewMockKeyManager()
	defer m.Reset()

	password := []byte("secret")

	sealed, err := m.GenerateAndSealKeyWithOptions(WithPassword(password))
	if err != nil {
		t.Fatalf("GenerateAndSealKeyWithOptions failed: %v", err)
	}

	if !sealed.HasPassword {
		t.Error("HasPassword should be true")
	}

	if sealed.Version != SealedDataV2 {
		t.Errorf("Version = %d, want %d", sealed.Version, SealedDataV2)
	}

	// Should be able to unseal with correct password
	_, err = m.UnsealKeyWithOptions(sealed, WithPassword(password))
	if err != nil {
		t.Fatalf("UnsealKeyWithOptions failed: %v", err)
	}
}

func TestMockKeyManagerReadPCRs(t *testing.T) {
	m := NewMockKeyManager()
	defer m.Reset()

	// Set some mock PCRs
	pcr0 := bytes.Repeat([]byte{0x11}, 32)
	pcr7 := bytes.Repeat([]byte{0x77}, 32)

	m.SetMockPCR(0, pcr0)
	m.SetMockPCR(7, pcr7)

	values, err := m.ReadPCRs(uint16(tpm2.TPMAlgSHA256), 0, 7, 16)
	if err != nil {
		t.Fatalf("ReadPCRs failed: %v", err)
	}

	if len(values) != 3 {
		t.Fatalf("len(values) = %d, want 3", len(values))
	}

	if !bytes.Equal(values[0], pcr0) {
		t.Errorf("PCR 0 value mismatch")
	}

	if !bytes.Equal(values[1], pcr7) {
		t.Errorf("PCR 7 value mismatch")
	}
	// PCR 16 should be zero (not set)
	if !bytes.Equal(values[2], make([]byte, 32)) {
		t.Errorf("PCR 16 should be zero")
	}
}

func TestMockKeyManagerReadPCRsEmpty(t *testing.T) {
	m := NewMockKeyManager()

	_, err := m.ReadPCRs(uint16(tpm2.TPMAlgSHA256))
	if err != ErrInvalidPCRSelection {
		t.Errorf("expected ErrInvalidPCRSelection, got %v", err)
	}
}
