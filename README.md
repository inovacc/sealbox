# Keystore - Hardware-Backed Key Management

A cross-platform Go package for TPM 2.0 (Trusted Platform Module) key sealing and unsealing operations.

> **Status: Development** - See [ROADMAP.md](ROADMAP.md) for progress.

## What It Does

This module provides **hardware-backed encryption key management** using your computer's TPM chip. Keys sealed to the TPM:

- Cannot be extracted or copied
- Only work on the machine where they were created
- Are protected even if an attacker has full disk access

```
┌─────────────────────────────────────────────────────────────┐
│                      Your Application                        │
├─────────────────────────────────────────────────────────────┤
│                    keystore package                          │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │
│  │ Initialize()│    │ GetSealed   │    │   Reset()   │     │
│  │             │    │ MasterKey() │    │             │     │
│  └──────┬──────┘    └──────┬──────┘    └─────────────┘     │
├─────────┼──────────────────┼────────────────────────────────┤
│         ▼                  ▼                                 │
│  ┌─────────────┐    ┌─────────────┐                         │
│  │ KeyManager  │    │  KeyStore   │                         │
│  │ (TPM ops)   │    │ (file ops)  │                         │
│  └──────┬──────┘    └──────┬──────┘                         │
├─────────┼──────────────────┼────────────────────────────────┤
│         ▼                  ▼                                 │
│    TPM 2.0 Chip        Filesystem                           │
│   (hardware)         (~/.config/app/)                       │
└─────────────────────────────────────────────────────────────┘
```

### Key Sealing Process

```
SEAL (one-time setup):
  Random 32 bytes  ──▶  TPM encrypts  ──▶  Sealed blob  ──▶  Save to disk

UNSEAL (every use):
  Load from disk  ──▶  TPM decrypts  ──▶  Original key  ──▶  Use in app
```

### Why Use TPM?

| Without TPM | With TPM (this module) |
|-------------|------------------------|
| Key stored in plain file | Key encrypted by hardware |
| Attacker copies file = has key | Attacker copies file = useless blob |
| Key works on any machine | Key only works on THIS machine |
| Software-only protection | Hardware-backed protection |

## Use Cases

- **Password Manager** - Derive master password from TPM-sealed key
- **Credential Storage** - Protect API tokens, SSH keys
- **Disk Encryption** - Seal disk encryption keys to TPM
- **Application Secrets** - Machine-bound secret storage

## Features

- **Hardware-bound encryption** - Keys are sealed to the TPM and cannot be extracted
- **Cross-platform** - Supports Linux and Windows (macOS Secure Enclave planned)
- **PCR binding** - Optional binding to Platform Configuration Register values
- **Password protection** - Optional password requirement for unsealing
- **Secure key storage** - Sealed blobs stored with platform-appropriate permissions
- **Windows ACLs** - Proper Windows file permissions (current user only)
- **Memory zeroing** - Utilities for clearing sensitive data from memory
- **Simple API** - Easy-to-use interfaces for key management
- **Forked go-tpm** - Includes forked [google/go-tpm](https://github.com/google/go-tpm) for customization

## Installation

```bash
go get github.com/inovacc/keystore
```

## Requirements

### Linux
- TPM 2.0 device (`/dev/tpmrm0`)
- User must have read/write access to TPM device
- Add user to `tss` group: `sudo usermod -aG tss $USER`

### Windows
- Windows 10/11 with TPM 2.0
- TPM enabled in BIOS/UEFI
- No administrator rights required

### macOS
- Not yet supported (Secure Enclave integration planned)

## Quick Start

```go
package main

import (
    "fmt"
    "log"

    "github.com/inovacc/keystore"
)

func main() {
    // Check if TPM is available
    if !keystore.IsAvailable() {
        log.Fatal("TPM not available on this system")
    }

    // Configure storage path (required - no defaults)
    // Option 1: Use platform-specific path
    opts := keystore.WithAppConfig("myapp", "sealed.key")
    // Option 2: Use explicit path
    // opts := keystore.WithStorePath("/path/to/sealed.key")

    // Initialize: generate, seal, and store a new key
    if err := keystore.Initialize(opts); err != nil {
        if err == keystore.ErrKeyExists {
            log.Println("Key already exists, skipping initialization")
        } else {
            log.Fatalf("Failed to initialize: %v", err)
        }
    }

    // Later: retrieve the sealed key
    key, err := keystore.GetSealedMasterKey(opts)
    if err != nil {
        log.Fatalf("Failed to get sealed key: %v", err)
    }

    fmt.Printf("Unsealed key length: %d bytes\n", len(key))
}
```

### Low-Level API

For more control, use the KeyManager and KeyStore interfaces directly:

```go
km, err := keystore.NewKeyManager()
if err != nil {
    log.Fatal(err)
}
defer km.Close()

// Generate and seal a random key
sealed, err := km.GenerateAndSealKey()
if err != nil {
    log.Fatalf("Failed to seal key: %v", err)
}

// Store the sealed data (path is required)
store, err := keystore.NewKeyStore(keystore.WithAppConfig("myapp", "sealed.key"))
if err != nil {
    log.Fatalf("Failed to create key store: %v", err)
}

if err := store.Save(sealed); err != nil {
    log.Fatalf("Failed to save sealed key: %v", err)
}

fmt.Printf("Key sealed and stored at: %s\n", store.Path())
```

### Security Options API

For enhanced security, use policy-based sealing with PCR binding and/or password protection:

```go
import "github.com/google/go-tpm/tpm2"

km, err := keystore.NewKeyManager()
if err != nil {
    log.Fatal(err)
}
defer km.Close()

// Seal with password protection
sealed, err := km.SealKeyWithOptions(myKey,
    keystore.WithPassword([]byte("my-secret-password")),
)

// Seal with PCR binding (key only works if PCRs match)
sealed, err := km.SealKeyWithOptions(myKey,
    keystore.WithPCRs(tpm2.TPMAlgSHA256, 0, 1, 7),
)

// Seal with both password AND PCR binding
sealed, err := km.SealKeyWithOptions(myKey,
    keystore.WithPassword([]byte("password")),
    keystore.WithPCRs(tpm2.TPMAlgSHA256, 0, 7),
)

// Unseal with password
key, err := km.UnsealKeyWithOptions(sealed,
    keystore.WithPassword([]byte("my-secret-password")),
)

// Read current PCR values
pcrValues, err := km.ReadPCRs(uint16(tpm2.TPMAlgSHA256), 0, 1, 7)
```

### Memory Security

Use the provided utilities to zero sensitive data after use:

```go
// Zero a byte slice
keystore.SecureZero(sensitiveKey)

// Use key with automatic cleanup
err := keystore.WithKeyCleanup(key, func(k []byte) error {
    // Use the key
    return encrypt(data, k)
})
// Key is automatically zeroed after function returns
```

## API Reference

### Functions

#### `IsAvailable() bool`

Checks if TPM hardware is accessible on the current system.

```go
if keystore.IsAvailable() {
    fmt.Println("TPM is available")
}
```

#### `NewKeyManager() (KeyManager, error)`

Creates a new TPM key manager for sealing/unsealing operations.

```go
km, err := keystore.NewKeyManager()
if err != nil {
    log.Fatal(err)
}
defer km.Close()
```

#### `NewKeyStore(opts ...KeyStoreOption) (*FileKeyStore, error)`

Creates a key store for persisting sealed data to disk. **At least one option is required.**

```go
// Option 1: Platform-specific path (~/.config/myapp/sealed.key on Linux)
store, err := keystore.NewKeyStore(keystore.WithAppConfig("myapp", "sealed.key"))

// Option 2: Explicit path
store, err := keystore.NewKeyStore(keystore.WithStorePath("/path/to/sealed.key"))
```

#### `WithAppConfig(appName, fileName string) KeyStoreOption`

Configures platform-specific storage path:
- Linux: `~/.config/{appName}/{fileName}`
- Windows: `%LOCALAPPDATA%\{appName}\{fileName}`
- macOS: `~/Library/Application Support/{appName}/{fileName}`

#### `WithStorePath(path string) KeyStoreOption`

Sets an explicit storage path.

### Interfaces

#### `KeyManager`

```go
type KeyManager interface {
    // SealKey seals arbitrary data to the TPM
    SealKey(key []byte) (*SealedData, error)

    // UnsealKey retrieves sealed data from TPM
    UnsealKey(data *SealedData) ([]byte, error)

    // GenerateAndSealKey creates and seals a random 32-byte key
    GenerateAndSealKey() (*SealedData, error)

    // Close releases TPM resources
    Close() error
}
```

#### `KeyManagerWithOptions`

Extended interface for policy-based sealing (PCR binding, passwords):

```go
type KeyManagerWithOptions interface {
    KeyManager

    // SealKeyWithOptions seals with optional PCR binding and/or password
    SealKeyWithOptions(key []byte, opts ...SealOption) (*SealedData, error)

    // UnsealKeyWithOptions unseals data requiring policy authorization
    UnsealKeyWithOptions(data *SealedData, opts ...SealOption) ([]byte, error)

    // GenerateAndSealKeyWithOptions generates and seals with options
    GenerateAndSealKeyWithOptions(opts ...SealOption) (*SealedData, error)

    // ReadPCRs reads current PCR values
    ReadPCRs(hash uint16, pcrs ...uint) ([][]byte, error)
}
```

#### `KeyStore`

```go
type KeyStore interface {
    // Save stores sealed data to disk
    Save(data *SealedData) error

    // Load retrieves sealed data from disk
    Load() (*SealedData, error)

    // Exists checks if sealed data exists
    Exists() bool

    // Delete removes sealed data
    Delete() error

    // Path returns the storage path
    Path() string
}
```

### Types

#### `SealedData`

```go
type SealedData struct {
    // Version indicates format (0/1=V1, 2=V2 with policy)
    Version          int                  `json:"version,omitempty"`
    PublicArea       []byte               `json:"public_area"`
    PrivateArea      []byte               `json:"private_area"`
    SealedBlobPublic []byte               `json:"sealed_blob_public"`
    // V2 fields (policy metadata)
    PolicyDigest     []byte               `json:"policy_digest,omitempty"`
    PCRSelection     *SealedPCRSelection  `json:"pcr_selection,omitempty"`
    HasPassword      bool                 `json:"has_password,omitempty"`
}
```

#### `SealOption`

Functional options for sealing operations:

```go
// Protect with password
keystore.WithPassword(password []byte)

// Bind to PCR values (reads current values)
keystore.WithPCRs(hash tpm2.TPMIAlgHash, pcrs ...uint)

// Bind to specific PCR digest
keystore.WithPCRDigest(hash tpm2.TPMIAlgHash, digest []byte, pcrs ...uint)

// Enable session encryption
keystore.WithSessionEncryption()
```

## Storage Locations

When using `WithAppConfig(appName, fileName)`:

| Platform | Path Template |
|----------|---------------|
| Linux    | `~/.config/{appName}/{fileName}` |
| Windows  | `%LOCALAPPDATA%\{appName}\{fileName}` |
| macOS    | `~/Library/Application Support/{appName}/{fileName}` |

Example: `WithAppConfig("myapp", "master.key")` on Linux creates `~/.config/myapp/master.key`

## Security Considerations

### Threat Model

This package protects against:
- **Offline attacks** - Sealed keys cannot be decrypted without the TPM
- **Key extraction** - Key material never leaves the TPM in plaintext
- **Credential theft** - Even with disk access, attacker cannot recover keys
- **System state changes** - PCR binding detects boot/config modifications
- **Stolen sealed blobs** - Password protection adds another layer

This package does NOT protect against:
- **Physical TPM attacks** - Advanced hardware attacks on the TPM chip
- **Runtime memory attacks** - Keys are briefly in memory during use (use `SecureZero()`)
- **Malware with root access** - Can use TPM while system is running

### Best Practices

1. **No backup capability** - TPM-sealed keys cannot be backed up by design
2. **Machine-bound** - Keys only work on the machine where they were created
3. **BIOS updates** - May invalidate sealed keys (re-seal after update)
4. **TPM clear** - Clearing TPM in BIOS destroys all sealed keys
5. **Use PCR binding** - Bind to PCRs 0, 1, 7 to detect boot changes
6. **Add password protection** - Combine with PCR binding for defense in depth
7. **Zero sensitive memory** - Use `SecureZero()` or `WithKeyCleanup()` after use

### Key Derivation

For password-based applications (like KeePass), derive a password from the sealed key:

```go
import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
)

func DerivePassword(key []byte, domain string) string {
    h := hmac.New(sha256.New, key)
    h.Write([]byte(domain))
    return hex.EncodeToString(h.Sum(nil))
}

// Usage
key, _ := km.UnsealKey(sealed)
password := DerivePassword(key, "keepass")
```

## Platform-Specific Notes

### Linux

Uses forked `go-tpm` with the Linux TPM Resource Manager (`/dev/tpmrm0`).

```bash
# Check TPM availability
ls -la /dev/tpmrm0

# Add user to tss group for access
sudo usermod -aG tss $USER
newgrp tss  # Apply immediately
```

### Windows

Uses forked `go-tpm` with Windows TPM Base Services (TBS).

```powershell
# Check TPM status
Get-Tpm

# Verify TPM is ready
(Get-Tpm).TpmReady
```

## Error Handling

```go
var (
    // TPM availability
    ErrTPMNotAvailable        = errors.New("TPM device not available")
    ErrTPMNotSupported        = errors.New("TPM not supported on this platform")

    // Key operations
    ErrNoSealedKey            = errors.New("no sealed key found")
    ErrKeyExists              = errors.New("sealed key already exists")
    ErrSealFailed             = errors.New("failed to seal key to TPM")
    ErrUnsealFailed           = errors.New("failed to unseal key from TPM")
    ErrKeyStoreNotInitialized = errors.New("key store not initialized")
    ErrKeyTooLarge            = errors.New("key exceeds maximum sealable size")
    ErrKeyEmpty               = errors.New("cannot seal empty key")
    ErrInvalidSealedData      = errors.New("sealed data has invalid fields")

    // Policy errors (Phase 3)
    ErrPCRMismatch            = errors.New("PCR values do not match sealed policy")
    ErrPasswordRequired       = errors.New("password required to unseal this key")
    ErrInvalidPassword        = errors.New("invalid password for sealed key")
    ErrPolicyFailed           = errors.New("policy session failed")
    ErrInvalidPCRSelection    = errors.New("invalid PCR selection")
)
```

## Testing

```bash
# Run tests (requires TPM or simulator)
task test

# Or directly with go
go test -v ./...

# Run with software TPM simulator (Linux)
swtpm socket --tpmstate dir=/tmp/tpm --tpm2 --ctrl type=tcp,port=2322 &
TPM_DEVICE=/tmp/tpm go test -v ./...
```

## Dependencies

- `internal/tpm/` - Forked from [github.com/google/go-tpm](https://github.com/google/go-tpm)
  - See [internal/tpm/forked.md](pkg/keystore/internal/tpm/forked.md) for 64 tracked upstream issues

## Examples

- [secret-store](examples/secret-store/) - TPM-backed secret storage CLI application

## Documentation

- [ROADMAP.md](ROADMAP.md) - Development phases, local issues, timeline
- [internal/tpm/forked.md](pkg/keystore/internal/tpm/forked.md) - Upstream go-tpm issues by priority

## License

MIT License - See [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please see the [ROADMAP.md](ROADMAP.md) for planned features and known issues.
