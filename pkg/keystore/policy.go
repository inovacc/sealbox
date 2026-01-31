//go:build linux || windows

package keystore

import (
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// policyHelper provides utilities for computing and executing TPM policies.
type policyHelper struct {
	tpm transport.TPMCloser
}

// newPolicyHelper creates a new policy helper for the given TPM connection.
func newPolicyHelper(tpm transport.TPMCloser) *policyHelper {
	return &policyHelper{tpm: tpm}
}

// computePCRDigest computes the digest of the specified PCR values.
func (p *policyHelper) computePCRDigest(hash tpm2.TPMIAlgHash, pcrs ...uint) ([]byte, error) {
	if len(pcrs) == 0 {
		return nil, ErrInvalidPCRSelection
	}

	// Build PCR selection
	selection := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      hash,
				PCRSelect: tpm2.PCClientCompatible.PCRs(pcrs...),
			},
		},
	}

	// Read PCR values
	pcrRead := tpm2.PCRRead{
		PCRSelectionIn: selection,
	}

	pcrResp, err := pcrRead.Execute(p.tpm)
	if err != nil {
		return nil, fmt.Errorf("failed to read PCRs: %w", err)
	}

	// Concatenate all PCR values
	var pcrValues []byte
	for _, digest := range pcrResp.PCRValues.Digests {
		pcrValues = append(pcrValues, digest.Buffer...)
	}

	// Hash the concatenated values
	hashAlg, err := hash.Hash()
	if err != nil {
		return nil, fmt.Errorf("invalid hash algorithm: %w", err)
	}

	h := hashAlg.New()
	h.Write(pcrValues)

	return h.Sum(nil), nil
}

// readPCRValues reads the current values of the specified PCRs.
func (p *policyHelper) readPCRValues(hash tpm2.TPMIAlgHash, pcrs ...uint) ([][]byte, error) {
	if len(pcrs) == 0 {
		return nil, ErrInvalidPCRSelection
	}

	selection := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      hash,
				PCRSelect: tpm2.PCClientCompatible.PCRs(pcrs...),
			},
		},
	}

	pcrRead := tpm2.PCRRead{
		PCRSelectionIn: selection,
	}

	pcrResp, err := pcrRead.Execute(p.tpm)
	if err != nil {
		return nil, fmt.Errorf("failed to read PCRs: %w", err)
	}

	result := make([][]byte, len(pcrResp.PCRValues.Digests))
	for i, digest := range pcrResp.PCRValues.Digests {
		result[i] = make([]byte, len(digest.Buffer))
		copy(result[i], digest.Buffer)
	}

	return result, nil
}

// computeTrialPolicyDigest computes a policy digest using a trial session.
// This allows computing the policy digest without actually creating a sealed object.
func (p *policyHelper) computeTrialPolicyDigest(cfg *sealConfig) ([]byte, error) {
	// Create a trial policy session
	sess, cleanup, err := tpm2.PolicySession(p.tpm, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	if err != nil {
		return nil, fmt.Errorf("failed to create trial session: %w", err)
	}

	defer func() { _ = cleanup() }()

	// Execute policy commands
	if err := p.executePolicyCommands(sess.Handle(), cfg); err != nil {
		return nil, err
	}

	// Get the policy digest
	pgd := tpm2.PolicyGetDigest{
		PolicySession: sess.Handle(),
	}

	pgdResp, err := pgd.Execute(p.tpm)
	if err != nil {
		return nil, fmt.Errorf("failed to get policy digest: %w", err)
	}

	return pgdResp.PolicyDigest.Buffer, nil
}

// executePolicyCommands executes the appropriate policy commands for the config.
func (p *policyHelper) executePolicyCommands(sessHandle tpm2.TPMHandle, cfg *sealConfig) error {
	// PCR policy (if configured)
	if cfg.pcrSelection != nil {
		pcrDigest := cfg.pcrSelection.Digest
		if pcrDigest == nil {
			// Compute current PCR digest
			var err error

			pcrDigest, err = p.computePCRDigest(cfg.pcrSelection.Hash, cfg.pcrSelection.PCRs...)
			if err != nil {
				return fmt.Errorf("failed to compute PCR digest: %w", err)
			}
		}

		policyPCR := tpm2.PolicyPCR{
			PolicySession: sessHandle,
			PcrDigest: tpm2.TPM2BDigest{
				Buffer: pcrDigest,
			},
			Pcrs: tpm2.TPMLPCRSelection{
				PCRSelections: []tpm2.TPMSPCRSelection{
					{
						Hash:      cfg.pcrSelection.Hash,
						PCRSelect: tpm2.PCClientCompatible.PCRs(cfg.pcrSelection.PCRs...),
					},
				},
			},
		}
		if _, err := policyPCR.Execute(p.tpm); err != nil {
			return fmt.Errorf("failed to execute PolicyPCR: %w", err)
		}
	}

	// Password/AuthValue policy (if configured)
	if len(cfg.password) > 0 {
		policyAuthValue := tpm2.PolicyAuthValue{
			PolicySession: sessHandle,
		}
		if _, err := policyAuthValue.Execute(p.tpm); err != nil {
			return fmt.Errorf("failed to execute PolicyAuthValue: %w", err)
		}
	}

	return nil
}

// createPolicySession creates a policy session for unsealing.
func (p *policyHelper) createPolicySession(cfg *sealConfig) (tpm2.Session, func() error, error) {
	var opts []tpm2.AuthOption
	if len(cfg.password) > 0 {
		opts = append(opts, tpm2.Auth(cfg.password))
	}

	sess, cleanup, err := tpm2.PolicySession(p.tpm, tpm2.TPMAlgSHA256, 16, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create policy session: %w", err)
	}

	// Execute policy commands to match the sealed object's policy
	if err := p.executePolicyCommands(sess.Handle(), cfg); err != nil {
		_ = cleanup()
		return nil, nil, err
	}

	return sess, cleanup, nil
}

// buildSealedPCRSelection creates a SealedPCRSelection from a PCRSelection and computed digest.
func buildSealedPCRSelection(sel *PCRSelection, digest []byte) *SealedPCRSelection {
	if sel == nil {
		return nil
	}

	return &SealedPCRSelection{
		HashAlg: uint16(sel.Hash),
		PCRs:    sel.PCRs,
		Digest:  digest,
	}
}
