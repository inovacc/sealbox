# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Cross-platform Go library (`package keystore`) for TPM 2.0 (Trusted Platform Module) key sealing and unsealing operations. Hardware-bound encryption where sealed keys cannot be extracted or used on other machines.

**Status:** Development - Phase 3 (Security Hardening) complete. See [ROADMAP.md](ROADMAP.md) for details.

## Build & Test Commands

```bash
task test              # Run all tests with coverage
task test:unit         # Run unit tests only (skip integration)
task lint              # Run golangci-lint
task lint:fix          # Lint and auto-fix issues
task check             # Run all quality checks (fmt, vet, lint, test)
task build:dev         # Build development snapshot with goreleaser
```

Single test: `go test -v -run TestFunctionName ./...`

## Architecture

### Project Structure

```
keystore/
├── *.go                    # Public API (package keystore)
├── internal/tpm/           # Forked go-tpm library
│   ├── forked.md           # Attribution & upstream issues
│   ├── examples/           # TPM usage examples
│   ├── legacy/tpm2/        # Legacy TPM 2.0 API
│   ├── tpm/                # TPM 1.2 support
│   └── tpm2/               # TPM 2.0 core (transport/, test/)
├── ROADMAP.md              # Development phases & local issues
└── CLAUDE.md               # This file
```

### Platform-Specific Implementation Pattern

Uses build tags to provide platform-specific implementations of the same interface:

| File | Build Tag | Platform |
|------|-----------|----------|
| `tpm_linux.go` | `//go:build linux` | Linux via `/dev/tpmrm0` |
| `tpm_windows.go` | `//go:build windows` | Windows via TPM Base Services |
| `tpm_stub.go` | `//go:build !linux && !windows` | Stub returning `ErrTPMNotSupported` |

All platform files export the same public functions (`IsAvailable()`, `NewKeyManager()`) with platform-specific internal implementations (`linuxKeyManager`, `windowsKeyManager`, `stubKeyManager`).

### Core Abstractions

- **KeyManager** (`types.go`): Interface for TPM operations (SealKey, UnsealKey, GenerateAndSealKey, Close)
- **KeyManagerWithOptions** (`types.go`): Extended interface with PCR/password policy support
- **KeyStore** (`keystore.go`): Filesystem persistence with platform-specific default paths using functional options pattern
- **SealedData** (`types.go`): Versioned serializable struct (V1=basic, V2=with policy metadata)

### Security Features (Phase 3)

- **PCR Binding** (`seal_options.go`): Seal keys to Platform Configuration Register values
- **Password Protection** (`seal_options.go`): Optional password requirement for unsealing
- **Policy Sessions** (`policy.go`): TPM policy computation and session management
- **Windows ACLs** (`keystore_windows.go`): Proper Windows file permissions using internal acl package
- **Memory Zeroing** (`security.go`): `SecureZero()` and `WithKeyCleanup()` for sensitive data

### High-Level API

`helpers.go` provides convenience functions that compose KeyManager and KeyStore:
- `Initialize()` - Generate, seal, and store a new key
- `GetSealedMasterKey()` - Load and unseal the stored key
- `HasKey()`, `Reset()`, `GetKeyStorePath()`

## Dependencies

- `internal/tpm/` - Forked from [github.com/google/go-tpm](https://github.com/google/go-tpm)
  - See `internal/tpm/forked.md` for upstream issues (46 open)

## Testing Notes

- Tests require TPM hardware or a software TPM simulator
- Linux can use `swtpm` for simulation
- Environment variable `TPM_DEVICE` overrides the default device path on Linux
- Mock key manager available for unit tests without TPM: `NewMockKeyManager()`

## Key Files

| File | Purpose |
|------|---------|
| `types.go` | Core interfaces and SealedData struct |
| `tpm_common.go` | Shared TPM operations (seal/unseal with options) |
| `policy.go` | Policy session helpers for PCR/password |
| `seal_options.go` | Functional options for sealing |
| `security.go` | Memory zeroing utilities |
| `keystore.go` | File-based key storage |
| `keystore_windows.go` | Windows ACL handling |
| `keystore_unix.go` | Unix permissions |
| `mock_keymanager.go` | Mock for testing |
