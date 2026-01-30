# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Cross-platform Go library for TPM 2.0 (Trusted Platform Module) key sealing and unsealing operations. Hardware-bound encryption where sealed keys cannot be extracted or used on other machines.

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
- **KeyStore** (`keystore.go`): Filesystem persistence with platform-specific default paths using functional options pattern
- **SealedData** (`types.go`): Serializable struct containing TPM public/private areas

### High-Level API

`helpers.go` provides convenience functions that compose KeyManager and KeyStore:
- `Initialize()` - Generate, seal, and store a new key
- `GetSealedMasterKey()` - Load and unseal the stored key
- `HasKey()`, `Reset()`, `GetKeyStorePath()`

## Dependencies

- `github.com/google/go-tpm` - TPM 2.0 library (uses `tpm2` and `transport` subpackages)

## Testing Notes

- Tests require TPM hardware or a software TPM simulator
- Linux can use `swtpm` for simulation
- Environment variable `TPM_DEVICE` overrides the default device path on Linux
