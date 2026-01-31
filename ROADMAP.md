# Keystore Roadmap

This roadmap outlines the development plan for the cross-platform TPM keystore package.

## Summary

| Metric | Value |
|--------|-------|
| Local Issues | 0 open (Phase 1, 2 & 3 complete) |
| Upstream Issues (go-tpm) | 64 (3 critical, 10 high, 16 medium, 35 low) |
| Upstream Issues (go-tpm-tools) | 7 relevant (45+ total, most are cloud/attestation) |
| Test Coverage | 81.2% |
| Build Status | ✅ Passing |
| Security Features | PCR binding, password protection, Windows ACLs, memory zeroing |

## Platform Status

| Platform | Status | Notes |
|----------|--------|-------|
| Linux    | ✅ Implemented | TPM 2.0 via `/dev/tpmrm0` |
| Windows  | ✅ Implemented | TPM 2.0 via TBS API |
| macOS    | 🔲 Stub | Returns `ErrTPMNotSupported` |

---

## Phase 1: Bug Fixes (Critical)

**Goal:** Fix compilation errors and bugs identified in code analysis.

### Critical (Blocks Compilation)

- [x] Fix package name mismatch
  - [x] `doc.go` declares `package tpm`, all others declare `package keystore`
  - [x] Updated doc comments to use `keystore` package name

- [x] ~~Add missing constants~~ → Changed to require options (no defaults)
  - [x] `NewKeyStore()` now requires `WithStorePath` or `WithAppConfig`
  - [x] Returns `ErrKeyStoreNotInitialized` if no path provided

### High Priority

- [x] Fix duplicate option functions in `keystore.go:26-42`
  - [x] Removed duplicate `WithFileName` function
  - [x] Renamed `WithAppName` to `WithAppConfig(appName, fileName)`

- [x] Fix redundant `SealedData` field
  - [x] Removed `SealedBlob` field (was identical to `PrivateArea`)
  - [x] Updated all references in code and docs

### Medium Priority

- [x] Add nil checks
  - [x] `UnsealKey(data *SealedData)` - check if `data` is nil
  - [x] `Save(data *SealedData)` - check if `data` is nil

- [x] Fix `Initialize()` to check if key already exists
  - [x] Returns `ErrKeyExists` if key already exists

- [x] Remove unused `device` field from `linuxKeyManager` struct

- [x] Fix typo in `types.go:47` comment: "There exists" → "Exists"

### Deliverables

- [x] Code compiles without errors
- [x] All nil pointer dereferences prevented
- [x] No redundant code

---

## Phase 2: Code Quality & Testing

**Goal:** Reduce duplication, add tests, improve maintainability.

### Tasks

- [x] Refactor platform code to reduce duplication
  - [x] Created `tpm_common.go` with `baseKeyManager` struct
  - [x] Extracted shared TPM logic (SealKey, UnsealKey, GenerateAndSealKey, createPrimaryKey)
  - [x] Platform files now only contain transport-specific code (~60 lines → ~35 lines each)

- [x] Add unit tests
  - [x] `keystore.go` - FileKeyStore operations (`helpers_test.go`)
  - [x] `helpers.go` - High-level API (`helpers_test.go`)
  - [x] Mock KeyManager interface for testing (`mock_keymanager.go`)

- [x] Add TPM simulator support for integration tests
  - [x] Integration with `swtpm` (Software TPM)
  - [x] CI pipeline with simulated TPM (`.github/workflows/test.yml`)

- [x] Add input validation
  - [x] Validate key size in `SealKey()` - max 1024 bytes
  - [x] Validate empty key in `SealKey()`
  - [x] Validate `SealedData` fields in `UnsealKey()`
  - [x] Added `ErrKeyTooLarge`, `ErrKeyEmpty`, `ErrInvalidSealedData` errors

- [x] Improve error handling
  - [x] Wrap all TPM errors with context (already done in tpm_common.go)
  - [x] Add retry logic for transient failures (`retry.go`)
  - [x] TPM error classification helpers (IsRetryableTPMError, IsAuthFailure, IsPCRError)

### Deliverables

- [x] 80%+ test coverage (target)
- [x] CI pipeline with TPM simulator
- [x] Reduced code duplication

---

## Phase 3: Security Hardening

**Goal:** Add security features and audit existing implementation.

**Status:** ✅ Complete

### Tasks

- [x] Add PCR (Platform Configuration Register) support
  - [x] Seal keys to specific PCR values via `WithPCRs()` option
  - [x] Read current PCR values via `ReadPCRs()` method
  - [x] Pre-computed PCR digest support via `WithPCRDigest()`

- [x] Add password/policy protection for sealed objects
  - [x] Password-protected sealing via `WithPassword()` option
  - [x] Combined PCR + password policies supported
  - [x] Policy session management in `policy.go`

- [x] Windows file permissions
  - [x] Proper ACLs using internal `acl` package
  - [x] Current-user-only access on Windows
  - [x] Platform-specific `keystore_windows.go` and `keystore_unix.go`

- [x] Security audit
  - [x] Added `SecureZero()` for zeroing sensitive data
  - [x] Added `WithKeyCleanup()` helper for safe key usage
  - [x] Proper handle cleanup with defer in all TPM operations
  - [x] Versioned `SealedData` (V1/V2) for backward compatibility

### New Files Created

| File | Purpose |
|------|---------|
| `seal_options.go` | Functional options (WithPassword, WithPCRs, etc.) |
| `policy.go` | Policy computation and session helpers |
| `security.go` | Memory zeroing utilities |
| `keystore_windows.go` | Windows ACL handling |
| `keystore_unix.go` | Unix permissions |

### New Errors Added

- `ErrPCRMismatch` - PCR values don't match sealed policy
- `ErrPasswordRequired` - Password required but not provided
- `ErrInvalidPassword` - Wrong password for sealed key
- `ErrPolicyFailed` - Policy session failed
- `ErrInvalidPCRSelection` - Invalid PCR selection

### Deliverables

- [x] PCR policy sealing option
- [x] Password protection option
- [x] Combined policy support
- [x] Platform-appropriate file permissions
- [x] Memory zeroing utilities

---

## Phase 4: macOS Secure Enclave (Stretch Goal)

**Goal:** Evaluate and potentially implement macOS hardware security.

### Research Required

macOS does NOT have TPM. The Secure Enclave provides similar functionality:

| Feature | TPM 2.0 | Secure Enclave |
|---------|---------|----------------|
| Key storage | Yes | Yes |
| Sealing | Yes | No (different model) |
| Biometric auth | No | Yes (Touch ID/Face ID) |
| API | Standard | Apple-specific |

### Options

#### Option A: Secure Enclave Keys

```go
// Conceptual - requires CGO and Security.framework
import "github.com/inovacc/clonr/pkg/tpm/darwin"

func createSecureEnclaveKey() error {
    // Uses kSecAttrTokenIDSecureEnclave
    // Requires biometric or passcode authentication
}
```

**Pros:**
- True hardware-backed security
- Biometric authentication

**Cons:**
- Requires CGO
- Complex Apple frameworks
- Different security model than TPM

#### Option B: Keychain with Strong Protection

```go
import "github.com/keybase/go-keychain"

func storeInKeychain(key []byte) error {
    item := keychain.NewItem()
    item.SetSecClass(keychain.SecClassGenericPassword)
    item.SetAccessible(keychain.AccessibleWhenUnlockedThisDeviceOnly)
    // ...
}
```

**Pros:**
- Simpler implementation
- No CGO required
- Well-tested library

**Cons:**
- Not true hardware-backed
- Can be accessed by root

#### Option C: Stub Only

Return `ErrTPMNotSupported` on macOS, recommend Linux/Windows for TPM features.

### Tasks (If Proceeding)

- [ ] Evaluate Secure Enclave feasibility
  - [ ] CGO complexity
  - [ ] API compatibility with TPM model
  - [ ] User experience (biometric prompts)

- [ ] Choose implementation approach
  - [ ] Secure Enclave (if feasible)
  - [ ] Keychain fallback
  - [ ] Stub only

- [ ] Implement chosen approach
  - [ ] `tpm_darwin.go` with build tags
  - [ ] Integration tests on macOS
  - [ ] Documentation

### Deliverables

- [ ] Decision document
- [ ] Implementation (if chosen)
- [ ] macOS-specific documentation

---

## Phase 5: Advanced Features

**Goal:** Add advanced TPM features for power users.

### Planned Features

#### Key Hierarchy

Support multiple sealed keys under a primary:

```go
type KeyHierarchy struct {
    Primary   *SealedData
    Children  map[string]*SealedData
}

func (km *KeyManager) CreateChildKey(parent *SealedData, name string) (*SealedData, error)
```

#### Attestation

Remote attestation support:

```go
type AttestationData struct {
    Quote     []byte
    Signature []byte
    PCRs      map[int][]byte
}

func (km *KeyManager) CreateAttestation(nonce []byte) (*AttestationData, error)
```

### Deliverables

- [ ] Key hierarchy support
- [ ] Remote attestation (if needed)

---

## Timeline

| Phase | Target | Status |
|-------|--------|--------|
| Phase 1: Bug Fixes | Q1 2025 | ✅ Complete |
| Phase 2: Code Quality & Testing | Q1 2025 | ✅ Complete |
| Phase 3: Security Hardening | Q1 2025 | ✅ Complete |
| Phase 4: macOS (Research) | Q2 2025 | 🔲 Not Started |
| Phase 5: Advanced Features | Q3 2025 | 🔲 Not Started |

---

## Dependencies

### Required

| Package | Version | Purpose |
|---------|---------|---------|
| `github.com/google/go-tpm` | v0.9.8+ | TPM 2.0 operations |

### Optional (Testing)

| Tool | Purpose |
|------|---------|
| `swtpm` | Software TPM simulator |
| `tpm2-tools` | TPM debugging utilities |

---

## Known Issues

Issues discovered during code analysis that need to be addressed:

| Issue | Severity | File | Line |
|-------|----------|------|------|
| ~~Package mismatch (`tpm` vs `keystore`)~~ | ~~Critical~~ | ~~`doc.go`~~ | ✅ Fixed |
| ~~Missing defaults~~ | ~~Critical~~ | ~~`keystore.go`~~ | ✅ Changed to require options |
| ~~Duplicate `WithAppName`/`WithFileName` functions~~ | ~~High~~ | ~~`keystore.go`~~ | ✅ Fixed |
| ~~Redundant `SealedBlob` field~~ | ~~Medium~~ | ~~`types.go`~~ | ✅ Removed |
| ~~No nil check in `UnsealKey`~~ | ~~Medium~~ | ~~`tpm_*.go`~~ | ✅ Fixed |
| ~~`Initialize` overwrites existing key~~ | ~~Medium~~ | ~~`helpers.go`~~ | ✅ Fixed |
| ~~Unused `device` field~~ | ~~Low~~ | ~~`tpm_linux.go`~~ | ✅ Removed |
| ~~Typo "There exists"~~ | ~~Trivial~~ | ~~`types.go`~~ | ✅ Fixed |

### Forked Dependencies

| Package | Status | Notes |
|---------|--------|-------|
| `internal/tpm/` | ✅ Working | Forked go-tpm, imports updated |
| `internal/tpm-tools/simulator/` | ✅ Fixed | Imports updated to internal paths |
| `internal/tpm-tools/` (other) | ⚠️ External imports | 342 external imports across 111 files - not used by main package |

**Note:** The `internal/tpm-tools/` package still has many external Google imports. This doesn't affect the main keystore functionality since only the simulator package is used, and that has been fixed.

---

## Contributing

### Before Contributing

⚠️ **Note:** Phase 1 bugs must be fixed before the code compiles. Start there.

### Adding a New Platform

1. Create `tpm_<platform>.go` with build tag
2. Implement `KeyManager` interface
3. Implement `IsAvailable()` function
4. Add platform-specific tests
5. Update documentation

### Code Style

```go
// Always check TPM availability first
if !IsAvailable() {
    return nil, ErrTPMNotAvailable
}

// Always close TPM connections
tpm, err := openTPM()
if err != nil {
    return nil, fmt.Errorf("failed to open TPM: %w", err)
}
defer tpm.Close()

// Flush handles after use
defer func() {
    flushContext := tpm2.FlushContext{FlushHandle: handle}
    _, _ = flushContext.Execute(tpm)
}()

// Always check for nil before dereferencing
if data == nil {
    return nil, errors.New("data cannot be nil")
}
```

---

## References

- [go-tpm Documentation](https://pkg.go.dev/github.com/google/go-tpm)
- [TPM 2.0 Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
- [Windows TBS API](https://docs.microsoft.com/en-us/windows/win32/tbs/tpm-base-services-portal)
- [Apple Secure Enclave](https://support.apple.com/guide/security/secure-enclave-sec59b0b31ff/web)
- [Linux TPM Subsystem](https://www.kernel.org/doc/html/latest/security/tpm/index.html)
