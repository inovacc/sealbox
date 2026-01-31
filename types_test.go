package sealbox

import (
	"testing"
)

func TestSealedDataGetVersion(t *testing.T) {
	tests := []struct {
		name     string
		data     SealedData
		expected int
	}{
		{
			name:     "version 0 returns V1",
			data:     SealedData{Version: 0},
			expected: SealedDataV1,
		},
		{
			name:     "version 1 returns V1",
			data:     SealedData{Version: 1},
			expected: SealedDataV1,
		},
		{
			name:     "version 2 returns V2",
			data:     SealedData{Version: 2},
			expected: SealedDataV2,
		},
		{
			name:     "version 3 returns 3",
			data:     SealedData{Version: 3},
			expected: 3,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.data.GetVersion()
			if result != tc.expected {
				t.Errorf("GetVersion() = %d, want %d", result, tc.expected)
			}
		})
	}
}

func TestSealedDataRequiresPolicy(t *testing.T) {
	tests := []struct {
		name     string
		data     SealedData
		expected bool
	}{
		{
			name:     "empty data",
			data:     SealedData{},
			expected: false,
		},
		{
			name: "with policy digest",
			data: SealedData{
				PolicyDigest: []byte{1, 2, 3},
			},
			expected: true,
		},
		{
			name: "with PCR selection",
			data: SealedData{
				PCRSelection: &SealedPCRSelection{
					HashAlg: 0x000B,
					PCRs:    []uint{0, 7},
				},
			},
			expected: true,
		},
		{
			name: "with password flag",
			data: SealedData{
				HasPassword: true,
			},
			expected: true,
		},
		{
			name: "V1 data without policy fields",
			data: SealedData{
				Version:          SealedDataV1,
				PublicArea:       []byte{1, 2, 3},
				PrivateArea:      []byte{4, 5, 6},
				SealedBlobPublic: []byte{7, 8, 9},
			},
			expected: false,
		},
		{
			name: "V2 data with all policy fields",
			data: SealedData{
				Version:      SealedDataV2,
				PolicyDigest: []byte{1, 2, 3},
				PCRSelection: &SealedPCRSelection{
					HashAlg: 0x000B,
					PCRs:    []uint{0},
				},
				HasPassword: true,
			},
			expected: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.data.RequiresPolicy()
			if result != tc.expected {
				t.Errorf("RequiresPolicy() = %v, want %v", result, tc.expected)
			}
		})
	}
}

func TestSealedPCRSelection(t *testing.T) {
	sel := &SealedPCRSelection{
		HashAlg: 0x000B, // SHA256
		PCRs:    []uint{0, 1, 7},
		Digest:  []byte{0xAA, 0xBB, 0xCC},
	}

	if sel.HashAlg != 0x000B {
		t.Errorf("HashAlg = %x, want 0x000B", sel.HashAlg)
	}

	if len(sel.PCRs) != 3 {
		t.Errorf("len(PCRs) = %d, want 3", len(sel.PCRs))
	}

	if len(sel.Digest) != 3 {
		t.Errorf("len(Digest) = %d, want 3", len(sel.Digest))
	}
}
