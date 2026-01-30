package keystore

import (
	"bytes"
	"testing"
)

func TestSecureZero(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"empty slice", []byte{}},
		{"nil slice", nil},
		{"single byte", []byte{0xFF}},
		{"multiple bytes", []byte{0x01, 0x02, 0x03, 0x04}},
		{"32 bytes", bytes.Repeat([]byte{0xAB}, 32)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			SecureZero(tc.input)
			for i, b := range tc.input {
				if b != 0 {
					t.Errorf("SecureZero: byte at index %d is %d, want 0", i, b)
				}
			}
		})
	}
}

func TestWithKeyCleanup(t *testing.T) {
	key := []byte{0x01, 0x02, 0x03, 0x04}
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)

	var receivedKey []byte
	err := WithKeyCleanup(key, func(k []byte) error {
		receivedKey = make([]byte, len(k))
		copy(receivedKey, k)
		return nil
	})

	if err != nil {
		t.Fatalf("WithKeyCleanup returned error: %v", err)
	}

	// Check that the function received the correct key
	if !bytes.Equal(receivedKey, keyCopy) {
		t.Errorf("WithKeyCleanup: received key %v, want %v", receivedKey, keyCopy)
	}

	// Check that the original key was zeroed
	for i, b := range key {
		if b != 0 {
			t.Errorf("WithKeyCleanup: key byte at index %d is %d, want 0", i, b)
		}
	}
}

func TestCopyAndZero(t *testing.T) {
	t.Run("non-empty slice", func(t *testing.T) {
		original := []byte{0x01, 0x02, 0x03, 0x04}
		expected := []byte{0x01, 0x02, 0x03, 0x04}

		result := CopyAndZero(original)

		// Check that result has correct values
		if !bytes.Equal(result, expected) {
			t.Errorf("CopyAndZero: result %v, want %v", result, expected)
		}

		// Check that original was zeroed
		for i, b := range original {
			if b != 0 {
				t.Errorf("CopyAndZero: original byte at index %d is %d, want 0", i, b)
			}
		}
	})

	t.Run("empty slice", func(t *testing.T) {
		result := CopyAndZero([]byte{})
		if result != nil {
			t.Errorf("CopyAndZero: expected nil for empty slice, got %v", result)
		}
	})

	t.Run("nil slice", func(t *testing.T) {
		result := CopyAndZero(nil)
		if result != nil {
			t.Errorf("CopyAndZero: expected nil for nil slice, got %v", result)
		}
	})
}
