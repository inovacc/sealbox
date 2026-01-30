# Keystore Roadmap

This roadmap outlines the development plan for the cross-platform TPM keystore package.

## Summary

| Metric | Value |
|--------|-------|
| Local Issues | 10 (2 critical, 2 high, 4 medium, 2 low) |
| Upstream Issues | 46 (3 critical, 8 high, 12 medium, 23 low) |
| Test Coverage | 73.1% |
| Build Status | ✅ Passing |

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

- [ ] Fix redundant `SealedData` field
  - [ ] `SealedBlob` and `PrivateArea` are assigned identical values
  - [ ] Either remove `SealedBlob` or fix the assignment

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
- [ ] No redundant code (SealedBlob field still needs review)

---

## Phase 2: Code Quality & Testing

**Goal:** Reduce duplication, add tests, improve maintainability.

### Tasks

- [ ] Refactor platform code to reduce duplication
  - [ ] `tpm_linux.go` and `tpm_windows.go` share ~95% identical code
  - [ ] Extract shared TPM logic into common functions
  - [ ] Keep only transport-specific code in platform files

- [ ] Add unit tests
  - [ ] `keystore.go` - FileKeyStore operations
  - [ ] `helpers.go` - High-level API
  - [ ] Mock KeyManager interface for testing

- [ ] Add TPM simulator support for integration tests
  - [ ] Integration with `swtpm` (Software TPM)
  - [ ] CI pipeline with simulated TPM

- [ ] Add input validation
  - [ ] Validate key size in `SealKey()` (TPM has limits)
  - [ ] Validate `SealedData` fields before unmarshaling

- [ ] Improve error handling
  - [ ] Wrap all TPM errors with context
  - [ ] Add retry logic for transient failures

### Deliverables

- [ ] 80%+ test coverage
- [ ] CI pipeline with TPM simulator
- [ ] Reduced code duplication

---

## Phase 3: Security Hardening

**Goal:** Add security features and audit existing implementation.

### Tasks

- [ ] Add PCR (Platform Configuration Register) support
  - [ ] Seal keys to specific PCR values
  - [ ] Detect system state changes
  - [ ] Optional: Unseal only in known-good state

- [ ] Add password/policy protection for sealed objects
  - [ ] Currently uses `tpm2.PasswordAuth(nil)` (no protection)
  - [ ] Add option for password-protected sealing

- [ ] Windows file permissions
  - [ ] Unix permissions `0600` have no effect on Windows
  - [ ] Implement proper ACLs for Windows

- [ ] Security audit
  - [ ] Review key derivation
  - [ ] Verify proper handle cleanup
  - [ ] Check for memory leaks of sensitive data
  - [ ] Zero sensitive data after use

### Deliverables

- [ ] PCR policy sealing option
- [ ] Security review document
- [ ] Platform-appropriate file permissions

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
| Phase 1: Bug Fixes | Q1 2025 | 🔴 Blocked (Critical bugs) |
| Phase 2: Code Quality & Testing | Q1 2025 | 🔲 Not Started |
| Phase 3: Security Hardening | Q2 2025 | 🔲 Not Started |
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
| Package mismatch (`tpm` vs `keystore`) | Critical | `doc.go` | 59 |
| Missing `DefaultAppName`, `DefaultKeyFileName` | Critical | `keystore.go` | 54 |
| Duplicate `WithAppName`/`WithFileName` functions | High | `keystore.go` | 26-42 |
| Redundant `SealedBlob` field | Medium | `types.go` | 13 |
| No nil check in `UnsealKey` | Medium | `tpm_*.go` | - |
| `Initialize` overwrites existing key | Medium | `helpers.go` | 7 |
| Unused `device` field | Low | `tpm_linux.go` | 26 |
| Typo "There exists" | Trivial | `types.go` | 47 |

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
