# TPM Package Roadmap

This roadmap outlines the development plan for the cross-platform TPM package.

## Current Status

| Platform | Status | Notes |
|----------|--------|-------|
| Linux    | ✅ Working | TPM 2.0 via `/dev/tpmrm0` |
| Windows  | 🔲 Planned | TPM 2.0 via TBS API |
| macOS    | 🔲 Research | Secure Enclave (not TPM) |

---

## Phase 1: Package Foundation

**Goal:** Extract and refactor existing Linux TPM code into a reusable package.

### Tasks

- [ ] Create package structure
  ```
  pkg/tpm/
  ├── doc.go
  ├── interfaces.go
  ├── errors.go
  ├── sealed_data.go
  ├── keystore.go
  ├── tpm_linux.go
  ├── tpm_stub.go
  └── tpm_test.go
  ```

- [ ] Define public interfaces
  - [ ] `KeyManager` - TPM key operations
  - [ ] `KeyStore` - Sealed data persistence
  - [ ] `SealedData` - Cross-platform data structure

- [ ] Migrate Linux implementation
  - [ ] Copy from `internal/core/tpm.go`
  - [ ] Copy from `internal/core/tpm_keystore.go`
  - [ ] Update to implement new interfaces

- [ ] Create stub for unsupported platforms
  - [ ] Return `ErrTPMNotSupported` on all operations
  - [ ] `IsAvailable()` returns `false`

- [ ] Update `internal/core/` to use `pkg/tpm`
  - [ ] Import new package
  - [ ] Remove duplicated code
  - [ ] Maintain backward compatibility

### Deliverables

- [ ] Working `pkg/tpm` package
- [ ] All existing tests passing
- [ ] No breaking changes to clonr CLI

---

## Phase 2: Linux Hardening

**Goal:** Improve Linux implementation with better testing and error handling.

### Tasks

- [ ] Add TPM simulator support for testing
  - [ ] Integration with `swtpm` (Software TPM)
  - [ ] CI pipeline with simulated TPM
  - [ ] Mock interface for unit tests

- [ ] Improve error handling
  - [ ] Wrap all TPM errors with context
  - [ ] Add retry logic for transient failures
  - [ ] Better error messages for common issues

- [ ] Add PCR (Platform Configuration Register) support
  - [ ] Seal keys to specific PCR values
  - [ ] Detect system state changes
  - [ ] Optional: Unseal only in known-good state

- [ ] Performance optimizations
  - [ ] Connection pooling for TPM device
  - [ ] Benchmark sealing/unsealing operations
  - [ ] Cache primary key handle

- [ ] Security audit
  - [ ] Review key derivation
  - [ ] Verify proper handle cleanup
  - [ ] Check for memory leaks of sensitive data

### Deliverables

- [ ] 80%+ test coverage
- [ ] CI pipeline with TPM simulator
- [ ] Performance benchmarks
- [ ] Security review document

---

## Phase 3: Windows TPM 2.0

**Goal:** Add Windows support using TPM Base Services (TBS).

### Research

The `go-tpm` library supports Windows via the TBS API:

```go
import "github.com/google/go-tpm/tpm2/transport/tbs"

func openTPM() (transport.TPMCloser, error) {
    return tbs.Open()
}
```

### Tasks

- [ ] Research Windows TPM APIs
  - [x] Confirm `go-tpm` TBS support
  - [ ] Test on Windows 10/11 with TPM
  - [ ] Document permission requirements

- [ ] Implement `tpm_windows.go`
  - [ ] `IsAvailable()` - Check TBS accessibility
  - [ ] `NewKeyManager()` - Open TBS connection
  - [ ] `SealKey()` / `UnsealKey()` - Same logic as Linux
  - [ ] `Close()` - Release TBS handle

- [ ] Windows-specific key storage
  - [ ] Path: `%LOCALAPPDATA%\clonr\.clonr_sealed_key`
  - [ ] Proper file permissions (ACLs)
  - [ ] Handle path with spaces

- [ ] Testing
  - [ ] Manual testing on Windows hardware
  - [ ] CI with Windows runner (if TPM available)
  - [ ] Cross-compile verification

- [ ] Documentation
  - [ ] Windows setup guide
  - [ ] Troubleshooting common issues
  - [ ] PowerShell commands for TPM status

### Windows-Specific Considerations

| Aspect | Details |
|--------|---------|
| API | TPM Base Services (TBS) via `go-tpm` |
| Device | No device path needed (TBS handles it) |
| Permissions | Standard user (no admin required) |
| Storage | `%LOCALAPPDATA%\clonr\` |

### Deliverables

- [ ] Working Windows implementation
- [ ] Windows installation guide
- [ ] Cross-platform CI builds

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

#### PCR Policy Sealing

Seal keys to Platform Configuration Register values:

```go
type SealOptions struct {
    // PCRs to bind the key to
    PCRSelection []int

    // Expected PCR values (optional)
    PCRValues map[int][]byte
}

func (km *KeyManager) SealKeyWithPolicy(key []byte, opts SealOptions) (*SealedData, error)
```

**Use cases:**
- Unseal only with specific boot configuration
- Detect tampering or system changes
- Enterprise security policies

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

- [ ] PCR policy sealing
- [ ] Key hierarchy support
- [ ] Remote attestation (if needed)

---

## Timeline

| Phase | Target | Status |
|-------|--------|--------|
| Phase 1: Package Foundation | Q1 2025 | 🔲 Not Started |
| Phase 2: Linux Hardening | Q1 2025 | 🔲 Not Started |
| Phase 3: Windows TPM 2.0 | Q2 2025 | 🔲 Not Started |
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

## Contributing

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
```

---

## References

- [go-tpm Documentation](https://pkg.go.dev/github.com/google/go-tpm)
- [TPM 2.0 Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
- [Windows TBS API](https://docs.microsoft.com/en-us/windows/win32/tbs/tpm-base-services-portal)
- [Apple Secure Enclave](https://support.apple.com/guide/security/secure-enclave-sec59b0b31ff/web)
- [Linux TPM Subsystem](https://www.kernel.org/doc/html/latest/security/tpm/index.html)
