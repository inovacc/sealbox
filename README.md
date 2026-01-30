# Keystore - Hardware-Backed Key Management

A cross-platform Go package for TPM 2.0 (Trusted Platform Module) key sealing and unsealing operations.

> **⚠️ Status: Development** - Contains critical bugs that block compilation. See [ROADMAP.md](ROADMAP.md) for details.

## Features

- **Hardware-bound encryption** - Keys are sealed to the TPM and cannot be extracted
- **Cross-platform** - Supports Linux and Windows (macOS Secure Enclave planned)
- **No password required** - Authentication happens automatically via TPM
- **Secure key storage** - Sealed blobs stored in platform-specific secure locations
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

    // Create a new key manager
    km, err := keystore.NewKeyManager()
    if err != nil {
        log.Fatalf("Failed to create key manager: %v", err)
    }
    defer km.Close()

    // Generate and seal a random key
    sealed, err := km.GenerateAndSealKey()
    if err != nil {
        log.Fatalf("Failed to seal key: %v", err)
    }

    // Store the sealed data
    store, err := keystore.NewKeyStore()
    if err != nil {
        log.Fatalf("Failed to create key store: %v", err)
    }

    if err := store.Save(sealed); err != nil {
        log.Fatalf("Failed to save sealed key: %v", err)
    }

    fmt.Printf("Key sealed and stored at: %s\n", store.Path())

    // Later: unseal the key
    loaded, err := store.Load()
    if err != nil {
        log.Fatalf("Failed to load sealed key: %v", err)
    }

    key, err := km.UnsealKey(loaded)
    if err != nil {
        log.Fatalf("Failed to unseal key: %v", err)
    }

    fmt.Printf("Unsealed key length: %d bytes\n", len(key))
}
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

#### `NewKeyStore() (KeyStore, error)`

Creates a key store for persisting sealed data to disk.

```go
store, err := keystore.NewKeyStore()
if err != nil {
    log.Fatal(err)
}
```

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
    PublicArea       []byte `json:"public_area"`
    PrivateArea      []byte `json:"private_area"`
    SealedBlob       []byte `json:"sealed_blob"`
    SealedBlobPublic []byte `json:"sealed_blob_public"`
}
```

## Storage Locations

| Platform | Sealed Key Path |
|----------|-----------------|
| Linux    | `~/.config/clonr/.clonr_sealed_key` |
| Windows  | `%LOCALAPPDATA%\clonr\.clonr_sealed_key` |
| macOS    | `~/Library/Application Support/clonr/.clonr_sealed_key` |

## Security Considerations

### Threat Model

This package protects against:
- **Offline attacks** - Sealed keys cannot be decrypted without the TPM
- **Key extraction** - Key material never leaves the TPM in plaintext
- **Credential theft** - Even with disk access, attacker cannot recover keys

This package does NOT protect against:
- **Physical TPM attacks** - Advanced hardware attacks on the TPM chip
- **Runtime memory attacks** - Keys are briefly in memory during use
- **Malware with root access** - Can use TPM while system is running

### Best Practices

1. **No backup capability** - TPM-sealed keys cannot be backed up by design
2. **Machine-bound** - Keys only work on the machine where they were created
3. **BIOS updates** - May invalidate sealed keys (re-seal after update)
4. **TPM clear** - Clearing TPM in BIOS destroys all sealed keys

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
    ErrTPMNotAvailable = errors.New("TPM device not available")
    ErrTPMNotSupported = errors.New("TPM not supported on this platform")
    ErrNoSealedKey     = errors.New("no sealed key found")
    ErrSealFailed      = errors.New("failed to seal key to TPM")
    ErrUnsealFailed    = errors.New("failed to unseal key from TPM")
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
  - See [internal/tpm/forked.md](internal/tpm/forked.md) for 46 tracked upstream issues

## Documentation

- [ROADMAP.md](ROADMAP.md) - Development phases, local issues, timeline
- [internal/tpm/forked.md](internal/tpm/forked.md) - Upstream go-tpm issues by priority

## License

MIT License - See [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please see the [ROADMAP.md](ROADMAP.md) for planned features and known issues.
