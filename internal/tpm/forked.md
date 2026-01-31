this code was forked from https://github.com/google/go-tpm

**Last updated:** 2025-01-30

## Upstream Open Issues (64 total)

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

### High (10)

Important features or significant bugs affecting reliability.

| Issue | Title | Reason |
|-------|-------|--------|
| [#423](https://github.com/google/go-tpm/issues/423) | Prepare ecdsa code for Go 1.26 deprecations | Go compatibility |
| [#422](https://github.com/google/go-tpm/issues/422) | Add `DictionaryAttackLockReset` support | Needed to recover from TPM lockouts |
| [#420](https://github.com/google/go-tpm/issues/420) | Fix cipher block size as IV length for legacy credential activation | Security fix |
| [#405](https://github.com/google/go-tpm/issues/405) | Use NULL tickets when tickets aren't provided | Policy session failures |
| [#403](https://github.com/google/go-tpm/issues/403) | Allow policy session to be extended more programatically | Policy improvements |
| [#361](https://github.com/google/go-tpm/issues/361) | missing Name for 'SignHandle' parameter | Signing operations broken |
| [#326](https://github.com/google/go-tpm/issues/326) | Missing ExtraData in Quote | Attestation broken |
| [#246](https://github.com/google/go-tpm/issues/246) | Basic Sealing and Unsealing | Core functionality for this project |
| [#242](https://github.com/google/go-tpm/issues/242) | ReadPCRs returns empty map without error when using SHA256 | Silent failures |
| [#121](https://github.com/google/go-tpm/issues/121) | tpm2/credactivation: Generate uses the wrong hash algorithm | Security bug |

---

### Medium (16)

Nice-to-have features, security improvements, minor bugs.

| Issue | Title | Reason |
|-------|-------|--------|
| [#401](https://github.com/google/go-tpm/issues/401) | Consider an update to PolicyCommand or a new interface for working with policy sessions | Better policy API |
| [#400](https://github.com/google/go-tpm/issues/400) | add test-vector-based unit test for KDFa and KDFe | Test coverage |
| [#393](https://github.com/google/go-tpm/issues/393) | Support TPM2_PCR_Allocate command | PCR sealing support |
| [#346](https://github.com/google/go-tpm/issues/346) | Support for RSAEncrypt and RSADecrypt commands | Extended crypto ops |
| [#343](https://github.com/google/go-tpm/issues/343) | Seal info w EK pub or cert on systems without TPM | Offline sealing |
| [#340](https://github.com/google/go-tpm/issues/340) | Support As(TPMRC) for format-1 errors | Better error handling |
| [#321](https://github.com/google/go-tpm/issues/321) | add github actions tests | CI improvements |
| [#319](https://github.com/google/go-tpm/issues/319) | add TPM2_SelfTest and TPM2_GetTestResult | TPM diagnostics |
| [#313](https://github.com/google/go-tpm/issues/313) | Add ReadPCRsRaw() to tpm2 | PCR reading |
| [#273](https://github.com/google/go-tpm/issues/273) | Policy sessions need to know authValue for parameter encryption | Policy encryption |
| [#274](https://github.com/google/go-tpm/issues/274) | Make tpm2 quote functions accept PCR selections for multiple banks | Quote improvements |
| [#262](https://github.com/google/go-tpm/issues/262) | decodeCertify not returning signature | Certification bug |
| [#259](https://github.com/google/go-tpm/issues/259) | TPM sniffing attacks and session encryption | Security hardening |
| [#249](https://github.com/google/go-tpm/issues/249) | Support importing HMAC keys and operations | HMAC support |
| [#245](https://github.com/google/go-tpm/issues/245) | Implement TPM2_VerifySignature | Signature verification |
| [#223](https://github.com/google/go-tpm/issues/223) | Implement tpm2_duplicate | Key migration |

---

### Low (35)

Code quality, legacy support, minor improvements, documentation.

| Issue | Title | Category |
|-------|-------|----------|
| [#419](https://github.com/google/go-tpm/issues/419) | old version of go-tpm-tools | Dependencies |
| [#411](https://github.com/google/go-tpm/issues/411) | Fix Typo in TPM1.2 nvReadValue function when commandAuth is passed | Legacy (TPM 1.2) |
| [#410](https://github.com/google/go-tpm/issues/410) | Typo in TPM 1.2 NVReadValue function when ReadEKCert is called with owner certs | Legacy (TPM 1.2) |
| [#389](https://github.com/google/go-tpm/issues/389) | Possible Typo in TPMUAsymScheme Method? | Typo |
| [#378](https://github.com/google/go-tpm/issues/378) | Using TPM key ctx file created with TPM2 Tools to sign data | Interop |
| [#367](https://github.com/google/go-tpm/issues/367) | broken CI | Upstream CI |
| [#362](https://github.com/google/go-tpm/issues/362) | fix missing Name for 'SignHandle' parameter | Bug fix PR |
| [#348](https://github.com/google/go-tpm/issues/348) | TPM Simulator reporting unrecognised command over socket | Simulator |
| [#339](https://github.com/google/go-tpm/issues/339) | feat: mssim wireshark friendly | Debugging |
| [#336](https://github.com/google/go-tpm/issues/336) | Consider an UnmarshalReader API for types | API improvement |
| [#327](https://github.com/google/go-tpm/issues/327) | Use `crypto/ecdh` for tpmdirect | Modernization |
| [#312](https://github.com/google/go-tpm/issues/312) | Load TSS2 Private Key generated with tpm2tss-genkey | Interop |
| [#311](https://github.com/google/go-tpm/issues/311) | Add TPMS_ID_OBJECT structure | API completeness |
| [#309](https://github.com/google/go-tpm/issues/309) | Add a Compare function | API improvement |
| [#307](https://github.com/google/go-tpm/issues/307) | support passing []byte as TPM2B | API improvement |
| [#303](https://github.com/google/go-tpm/issues/303) | reduce repetitive, nested structs by proving a defaults package | Code quality |
| [#298](https://github.com/google/go-tpm/issues/298) | Add helper for tpmDirect ObjectAttributes | API improvement |
| [#292](https://github.com/google/go-tpm/issues/292) | Make a marshallable interface/type constraint | Code quality |
| [#278](https://github.com/google/go-tpm/issues/278) | Add remaining TPM commands to TPMDirect API | Completeness |
| [#261](https://github.com/google/go-tpm/issues/261) | Add ComputeAuthTimeout expiry overflow reproducer | Testing |
| [#260](https://github.com/google/go-tpm/issues/260) | Typo in session attribute | Typo |
| [#244](https://github.com/google/go-tpm/issues/244) | Only signing schemes are settable on TPMS_RSA_PARMS | API limitation |
| [#222](https://github.com/google/go-tpm/issues/222) | Add API to open TCP based TPM device | Simulator/remote TPM |
| [#201](https://github.com/google/go-tpm/issues/201) | TPM2 Quote takes an Algorithm where it should take a Scheme | API correctness |
| [#179](https://github.com/google/go-tpm/issues/179) | Expose/use sequence variants of TPM2_Hash | Feature |
| [#170](https://github.com/google/go-tpm/issues/170) | Mark go.mod as requiring at least 1.13 | Build |
| [#164](https://github.com/google/go-tpm/issues/164) | Example for storing & fetching string/bytes ? | Documentation |
| [#109](https://github.com/google/go-tpm/issues/109) | Implement some additional hierarchy control and dictionary attack functions for TPM2 | Feature |
| [#99](https://github.com/google/go-tpm/issues/99) | Add a tpm-startup example | Documentation |
| [#94](https://github.com/google/go-tpm/issues/94) | Implement example to generate a fake EK certificate | Documentation |
| [#93](https://github.com/google/go-tpm/issues/93) | Refactor all uses of tpmutil.Pack to pass addressable values | Code quality |

---

## Notes

- Issue #59 (Retry command on TPM_RC_RETRY) appears to be closed
- Issue #91 and #87 (TPM 1.2 related) appear to be closed
- Several new issues added since last review, mostly API improvements and bug fixes