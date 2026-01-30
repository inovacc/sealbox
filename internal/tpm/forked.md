this code was forked from https://github.com/google/go-tpm

## Upstream Open Issues (46 total)

Issues categorized by priority for this keystore implementation.

---

### Critical (3)

Blocks core functionality or cross-platform support.

| Issue | Title | Reason |
|-------|-------|--------|
| [#416](https://github.com/google/go-tpm/issues/416) | Don't write beyond the value of `TPMPTNVBufferMax` | NV write failures on some platforms |
| [#373](https://github.com/google/go-tpm/issues/373) | Windows and linux packages are different | Breaks cross-platform API consistency |
| [#275](https://github.com/google/go-tpm/issues/275) | Windows TPM Base Services (TBS) - Missing Functionality | Windows support incomplete |

---

### High (8)

Important features or significant bugs affecting reliability.

| Issue | Title | Reason |
|-------|-------|--------|
| [#422](https://github.com/google/go-tpm/issues/422) | Add `DictionaryAttackLockReset` support | Needed to recover from TPM lockouts |
| [#405](https://github.com/google/go-tpm/issues/405) | Use NULL tickets when tickets aren't provided | Policy session failures |
| [#361](https://github.com/google/go-tpm/issues/361) | missing Name for 'SignHandle' parameter | Signing operations broken |
| [#326](https://github.com/google/go-tpm/issues/326) | Missing ExtraData in Quote | Attestation broken |
| [#246](https://github.com/google/go-tpm/issues/246) | Basic Sealing and Unsealing | Core functionality for this project |
| [#242](https://github.com/google/go-tpm/issues/242) | ReadPCRs returns empty map without error when using SHA256 | Silent failures |
| [#121](https://github.com/google/go-tpm/issues/121) | tpm2/credactivation: Generate uses the wrong hash algorithm | Security bug |
| [#59](https://github.com/google/go-tpm/issues/59) | Retry command on TPM_RC_RETRY | Reliability |

---

### Medium (12)

Nice-to-have features, security improvements, minor bugs.

| Issue | Title | Reason |
|-------|-------|--------|
| [#393](https://github.com/google/go-tpm/issues/393) | Support TPM2_PCR_Allocate command | PCR sealing support |
| [#401](https://github.com/google/go-tpm/issues/401) | Consider an update to PolicyCommand or a new interface for working with policy sessions | Better policy API |
| [#346](https://github.com/google/go-tpm/issues/346) | Support for RSAEncrypt and RSADecrypt commands | Extended crypto ops |
| [#340](https://github.com/google/go-tpm/issues/340) | Support As(TPMRC) for format-1 errors | Better error handling |
| [#273](https://github.com/google/go-tpm/issues/273) | Policy sessions need to know authValue for parameter encryption | Policy encryption |
| [#259](https://github.com/google/go-tpm/issues/259) | TPM sniffing attacks and session encryption | Security hardening |
| [#249](https://github.com/google/go-tpm/issues/249) | Support importing HMAC keys and operations | HMAC support |
| [#245](https://github.com/google/go-tpm/issues/245) | Implement TPM2_VerifySignature | Signature verification |
| [#223](https://github.com/google/go-tpm/issues/223) | Implement tpm2_duplicate | Key migration |
| [#222](https://github.com/google/go-tpm/issues/222) | Add API to open TCP based TPM device | Simulator/remote TPM |
| [#262](https://github.com/google/go-tpm/issues/262) | decodeCertify not returning signature | Certification bug |
| [#201](https://github.com/google/go-tpm/issues/201) | TPM2 Quote takes an Algorithm where it should take a Scheme | API correctness |

---

### Low (23)

Code quality, legacy support, minor improvements, documentation.

| Issue | Title | Category |
|-------|-------|----------|
| [#419](https://github.com/google/go-tpm/issues/419) | old version of go-tpm-tools | Dependencies |
| [#410](https://github.com/google/go-tpm/issues/410) | Typo in TPM 1.2 NVReadValue function when ReadEKCert is called with owner certs | Legacy (TPM 1.2) |
| [#389](https://github.com/google/go-tpm/issues/389) | Possible Typo in TPMUAsymScheme Method? | Typo |
| [#378](https://github.com/google/go-tpm/issues/378) | Using TPM key ctx file created with TPM2 Tools to sign data | Interop |
| [#367](https://github.com/google/go-tpm/issues/367) | broken CI | Upstream CI |
| [#348](https://github.com/google/go-tpm/issues/348) | TPM Simulator reporting unrecognised command over socket | Simulator |
| [#336](https://github.com/google/go-tpm/issues/336) | Consider an UnmarshalReader API for types | API improvement |
| [#327](https://github.com/google/go-tpm/issues/327) | Use `crypto/ecdh` for tpmdirect | Modernization |
| [#312](https://github.com/google/go-tpm/issues/312) | Load TSS2 Private Key generated with tpm2tss-genkey | Interop |
| [#309](https://github.com/google/go-tpm/issues/309) | Add a Compare function | API improvement |
| [#307](https://github.com/google/go-tpm/issues/307) | support passing []byte as TPM2B | API improvement |
| [#303](https://github.com/google/go-tpm/issues/303) | reduce repetitive, nested structs by proving a defaults package | Code quality |
| [#298](https://github.com/google/go-tpm/issues/298) | Add helper for tpmDirect ObjectAttributes | API improvement |
| [#292](https://github.com/google/go-tpm/issues/292) | Make a marshallable interface/type constraint | Code quality |
| [#278](https://github.com/google/go-tpm/issues/278) | Add remaining TPM commands to TPMDirect API | Completeness |
| [#260](https://github.com/google/go-tpm/issues/260) | Typo in session attribute | Typo |
| [#244](https://github.com/google/go-tpm/issues/244) | Only signing schemes are settable on TPMS_RSA_PARMS | API limitation |
| [#179](https://github.com/google/go-tpm/issues/179) | Expose/use sequence variants of TPM2_Hash | Feature |
| [#170](https://github.com/google/go-tpm/issues/170) | Mark go.mod as requiring at least 1.13 | Build |
| [#164](https://github.com/google/go-tpm/issues/164) | Example for storing & fetching string/bytes ? | Documentation |
| [#93](https://github.com/google/go-tpm/issues/93) | Refactor all uses of tpmutil.Pack to pass addressable values | Code quality |
| [#91](https://github.com/google/go-tpm/issues/91) | TPM1.2: Some tests against a simulator fail erroneously | Legacy (TPM 1.2) |
| [#87](https://github.com/google/go-tpm/issues/87) | Run a TPM simulator in kokoro and run all available tests | Upstream CI |