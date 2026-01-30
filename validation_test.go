package keystore

import (
	"errors"
	"testing"
)

func TestMockKeyManager_SealKey_EmptyKey(t *testing.T) {
	km := NewMockKeyManager()

	_, err := km.SealKey([]byte{})
	if err == nil {
		t.Fatal("expected error for empty key")
	}
	if !errors.Is(err, ErrKeyEmpty) {
		t.Errorf("expected ErrKeyEmpty, got %v", err)
	}
}

func TestMockKeyManager_SealKey_TooLarge(t *testing.T) {
	km := NewMockKeyManager()

	largeKey := make([]byte, maxSealableSize+1)
	_, err := km.SealKey(largeKey)
	if err == nil {
		t.Fatal("expected error for oversized key")
	}
	if !errors.Is(err, ErrKeyTooLarge) {
		t.Errorf("expected ErrKeyTooLarge, got %v", err)
	}
}

func TestMockKeyManager_SealKey_MaxSize(t *testing.T) {
	km := NewMockKeyManager()

	maxKey := make([]byte, maxSealableSize)
	for i := range maxKey {
		maxKey[i] = byte(i % 256)
	}

	sealed, err := km.SealKey(maxKey)
	if err != nil {
		t.Fatalf("unexpected error for max size key: %v", err)
	}
	if sealed == nil {
		t.Fatal("expected sealed data, got nil")
	}
}

func TestMockKeyManager_UnsealKey_NilData(t *testing.T) {
	km := NewMockKeyManager()

	_, err := km.UnsealKey(nil)
	if err == nil {
		t.Fatal("expected error for nil data")
	}
	if !errors.Is(err, ErrUnsealFailed) {
		t.Errorf("expected ErrUnsealFailed, got %v", err)
	}
}

func TestMockKeyManager_UnsealKey_EmptyPublicArea(t *testing.T) {
	km := NewMockKeyManager()

	data := &SealedData{
		PublicArea:       []byte{},
		PrivateArea:      []byte{1, 2, 3},
		SealedBlobPublic: []byte{4, 5, 6},
	}

	_, err := km.UnsealKey(data)
	if err == nil {
		t.Fatal("expected error for empty public area")
	}
	if !errors.Is(err, ErrInvalidSealedData) {
		t.Errorf("expected ErrInvalidSealedData, got %v", err)
	}
}

func TestMockKeyManager_UnsealKey_EmptyPrivateArea(t *testing.T) {
	km := NewMockKeyManager()

	data := &SealedData{
		PublicArea:       []byte{1, 2, 3},
		PrivateArea:      []byte{},
		SealedBlobPublic: []byte{4, 5, 6},
	}

	_, err := km.UnsealKey(data)
	if err == nil {
		t.Fatal("expected error for empty private area")
	}
	if !errors.Is(err, ErrInvalidSealedData) {
		t.Errorf("expected ErrInvalidSealedData, got %v", err)
	}
}

func TestMockKeyManager_UnsealKey_EmptySealedBlobPublic(t *testing.T) {
	km := NewMockKeyManager()

	data := &SealedData{
		PublicArea:       []byte{1, 2, 3},
		PrivateArea:      []byte{4, 5, 6},
		SealedBlobPublic: []byte{},
	}

	_, err := km.UnsealKey(data)
	if err == nil {
		t.Fatal("expected error for empty sealed blob public")
	}
	if !errors.Is(err, ErrInvalidSealedData) {
		t.Errorf("expected ErrInvalidSealedData, got %v", err)
	}
}

func TestMockKeyManager_SealUnseal_RoundTrip(t *testing.T) {
	km := NewMockKeyManager()

	originalKey := []byte("test-secret-key-32-bytes-long!!")

	sealed, err := km.SealKey(originalKey)
	if err != nil {
		t.Fatalf("SealKey failed: %v", err)
	}

	unsealed, err := km.UnsealKey(sealed)
	if err != nil {
		t.Fatalf("UnsealKey failed: %v", err)
	}

	if string(unsealed) != string(originalKey) {
		t.Errorf("key mismatch: got %q, want %q", unsealed, originalKey)
	}
}

func TestMockKeyManager_GenerateAndSealKey(t *testing.T) {
	km := NewMockKeyManager()

	sealed, err := km.GenerateAndSealKey()
	if err != nil {
		t.Fatalf("GenerateAndSealKey failed: %v", err)
	}

	if sealed == nil {
		t.Fatal("expected sealed data, got nil")
	}

	unsealed, err := km.UnsealKey(sealed)
	if err != nil {
		t.Fatalf("UnsealKey failed: %v", err)
	}

	if len(unsealed) != sealedKeySize {
		t.Errorf("expected key size %d, got %d", sealedKeySize, len(unsealed))
	}
}

func TestMockKeyManager_UnsealKey_UnknownData(t *testing.T) {
	km := NewMockKeyManager()

	// Create fake sealed data that was never sealed by this mock
	data := &SealedData{
		PublicArea:       []byte{1, 2, 3, 4, 5, 6, 7, 8},
		PrivateArea:      []byte{9, 10, 11, 12, 13, 14, 15, 16},
		SealedBlobPublic: []byte{17, 18, 19, 20, 21, 22, 23, 24},
	}

	_, err := km.UnsealKey(data)
	if err == nil {
		t.Fatal("expected error for unknown sealed data")
	}
	if !errors.Is(err, ErrUnsealFailed) {
		t.Errorf("expected ErrUnsealFailed, got %v", err)
	}
}

func TestMockKeyManager_Close(t *testing.T) {
	km := NewMockKeyManager()

	err := km.Close()
	if err != nil {
		t.Errorf("unexpected error from Close: %v", err)
	}
}

func TestMockKeyManager_CustomFunctions(t *testing.T) {
	km := NewMockKeyManager()

	customErr := errors.New("custom error")

	km.SealFunc = func(key []byte) (*SealedData, error) {
		return nil, customErr
	}

	_, err := km.SealKey([]byte("test"))
	if !errors.Is(err, customErr) {
		t.Errorf("expected custom error, got %v", err)
	}

	km.UnsealFunc = func(data *SealedData) ([]byte, error) {
		return nil, customErr
	}

	_, err = km.UnsealKey(&SealedData{
		PublicArea:       []byte{1},
		PrivateArea:      []byte{2},
		SealedBlobPublic: []byte{3},
	})
	if !errors.Is(err, customErr) {
		t.Errorf("expected custom error, got %v", err)
	}

	km.GenerateFunc = func() (*SealedData, error) {
		return nil, customErr
	}

	_, err = km.GenerateAndSealKey()
	if !errors.Is(err, customErr) {
		t.Errorf("expected custom error, got %v", err)
	}

	km.CloseFunc = func() error {
		return customErr
	}

	err = km.Close()
	if !errors.Is(err, customErr) {
		t.Errorf("expected custom error, got %v", err)
	}
}

func TestMockKeyManager_Reset(t *testing.T) {
	km := NewMockKeyManager()

	// Seal a key
	sealed, err := km.SealKey([]byte("test-key"))
	if err != nil {
		t.Fatalf("SealKey failed: %v", err)
	}

	// Verify we can unseal it
	_, err = km.UnsealKey(sealed)
	if err != nil {
		t.Fatalf("UnsealKey failed before reset: %v", err)
	}

	// Reset the mock
	km.Reset()

	// Should no longer be able to unseal
	_, err = km.UnsealKey(sealed)
	if err == nil {
		t.Fatal("expected error after reset")
	}
}

func TestMockKeyManager_SealKey_ValidSizes(t *testing.T) {
	km := NewMockKeyManager()

	tests := []struct {
		name string
		size int
	}{
		{"min size", 1},
		{"small key", 16},
		{"medium key", 64},
		{"aes-256 key", 32},
		{"large key", 512},
		{"max size", maxSealableSize},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.size)
			for i := range key {
				key[i] = byte(i % 256)
			}

			sealed, err := km.SealKey(key)
			if err != nil {
				t.Fatalf("SealKey failed for size %d: %v", tt.size, err)
			}

			unsealed, err := km.UnsealKey(sealed)
			if err != nil {
				t.Fatalf("UnsealKey failed: %v", err)
			}

			if len(unsealed) != tt.size {
				t.Errorf("expected unsealed size %d, got %d", tt.size, len(unsealed))
			}
		})
	}
}

func TestMockKeyManager_MultipleKeys(t *testing.T) {
	km := NewMockKeyManager()

	keys := [][]byte{
		[]byte("key-one-32-bytes-exactly-here!!"),
		[]byte("key-two-also-32-bytes-exactly!!"),
		[]byte("key-three-32-bytes-padded-ok!!!"),
	}

	sealed := make([]*SealedData, len(keys))
	var err error

	// Seal all keys
	for i, key := range keys {
		sealed[i], err = km.SealKey(key)
		if err != nil {
			t.Fatalf("SealKey %d failed: %v", i, err)
		}
	}

	// Unseal in reverse order
	for i := len(keys) - 1; i >= 0; i-- {
		unsealed, err := km.UnsealKey(sealed[i])
		if err != nil {
			t.Fatalf("UnsealKey %d failed: %v", i, err)
		}
		if string(unsealed) != string(keys[i]) {
			t.Errorf("key %d mismatch: got %q, want %q", i, unsealed, keys[i])
		}
	}
}
