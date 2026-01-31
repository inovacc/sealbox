this code was forked from https://github.com/google/go-tpm-tools

**Last updated:** 2025-01-30

## Upstream Open Issues (45+ total)

Issues relevant to this keystore implementation. Most issues are related to cloud attestation and container security which are not directly used by this project.

---

### Relevant Issues

Issues that may affect this keystore implementation.

| Issue | Title | Reason |
|-------|-------|--------|
| [#611](https://github.com/google/go-tpm-tools/issues/611) | simulator incompatible with `go mod vendor` | Affects vendored builds |
| [#577](https://github.com/google/go-tpm-tools/issues/577) | Minimum go version should be 1.21 | Go version requirement |
| [#568](https://github.com/google/go-tpm-tools/issues/568) | Can't run released gotpm on Mac | macOS support |
| [#564](https://github.com/google/go-tpm-tools/issues/564) | Will there be support for SM2 and SM4 algo? | Chinese crypto algorithms |
| [#536](https://github.com/google/go-tpm-tools/issues/536) | Update vendored TPM simulator code to use TCG | Simulator updates |
| [#480](https://github.com/google/go-tpm-tools/issues/480) | Use recommended crypto library to create ECC seed | Security improvement |
| [#462](https://github.com/google/go-tpm-tools/issues/462) | Support new TPMDirect API | API modernization |

---

### Not Relevant

Most issues are for cloud/container attestation features not used by keystore:

- Confidential Computing / TEE attestation (#628, #620, #617, etc.)
- Container/launcher features (#602, #595, #487, etc.)
- SEV-SNP / TDX support (#604, #575, #524, #504, etc.)
- Cloud Build / CI improvements (#616, #615, #614, etc.)

---

## Notes

- This project primarily uses the simulator package for testing
- Cloud attestation features are not needed for basic key sealing
- The TPMDirect API migration (#462) may require future updates
