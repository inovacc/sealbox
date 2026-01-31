// Package keystore provides cross-platform TPM 2.0 key management.
//
// This package enables hardware-backed encryption using Trusted Platform Module (TPM) 2.0.
// Keys sealed to the TPM are bound to the hardware and cannot be extracted or used on
// other machines.
//
// # Platform Support
//
//   - Linux: Full support via /dev/tpmrm0
//   - Windows: Full support via TPM Base Services (TBS)
//   - macOS: Not supported (Secure Enclave differs from TPM)
//
// # Quick Start
//
//	// Check availability
//	if !sealbox.IsAvailable() {
//	    log.Fatal("TPM not available")
//	}
//
//	// Initialize (creates and seals a new key)
//	opts := sealbox.WithStorePath("/path/to/sealed.key")
//	if err := sealbox.Initialize(opts); err != nil {
//	    log.Fatal(err)
//	}
//
//	// Later: retrieve the sealed key
//	key, err := sealbox.GetSealedMasterKey(opts)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// # Low-Level API
//
// For more control, use the KeyManager and KeyStore interfaces directly:
//
//	km, err := sealbox.NewKeyManager()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer km.Close()
//
//	sealed, err := km.GenerateAndSealKey()
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	store, _ := sealbox.NewKeyStore(sealbox.WithStorePath("/path/to/sealed.key"))
//	store.Save(sealed)
//
// # Security Considerations
//
// TPM-sealed keys provide strong protection against offline attacks, but users should
// understand the implications:
//
//   - Keys cannot be backed up (by design)
//   - Keys are machine-bound and will be lost if TPM is cleared or hardware fails
//   - BIOS/UEFI updates may invalidate sealed keys
//
// See README.md for detailed security information.
package sealbox
