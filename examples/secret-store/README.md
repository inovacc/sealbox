# Secret Store Example

A simple command-line secret storage application using TPM-backed encryption.

## How It Works

```
┌─────────────────────────────────────────────────────────────┐
│                     Secret Store                             │
├─────────────────────────────────────────────────────────────┤
│  "api-key" ──▶ derive key ──▶ AES-GCM encrypt ──▶ secrets.json
│                    │
│                    ▼
│              Master Key (32 bytes)
│                    │
│                    ▼
│              TPM Unseal
│                    │
│                    ▼
│              master.key (sealed blob on disk)
└─────────────────────────────────────────────────────────────┘
```

1. **Master Key**: A 32-byte random key sealed to the TPM
2. **Key Derivation**: Each secret gets its own encryption key derived from master key using HMAC-SHA256
3. **Encryption**: Secrets are encrypted with AES-256-GCM
4. **Storage**: Encrypted secrets stored in JSON file

## Security Properties

- Master key is hardware-protected by TPM
- Each secret has a unique encryption key
- Copying `secrets.json` to another machine = useless (can't unseal master key)
- Even with root access, attacker must use this machine's TPM

## Usage

```bash
# Build
go build -o secret-store .

# Initialize (creates TPM-sealed master key)
./secret-store init

# Store a secret
./secret-store set github-token
# Enter secret: ghp_xxxxxxxxxxxx

# Retrieve a secret
./secret-store get github-token

# List all secrets
./secret-store list

# Delete a secret
./secret-store delete github-token

# Check status
./secret-store status

# Reset everything (deletes master key and all secrets)
./secret-store reset
```

## Example Session

```
$ ./secret-store init
TPM key initialized successfully
Your secrets are now protected by hardware encryption

$ ./secret-store set database-password
Enter secret for 'database-password': mysecretpassword
Secret 'database-password' stored successfully

$ ./secret-store set api-key
Enter secret for 'api-key': sk-1234567890
Secret 'api-key' stored successfully

$ ./secret-store list
Stored secrets:
  - database-password
  - api-key

$ ./secret-store get api-key
sk-1234567890

$ ./secret-store status
TPM Status:
  Available: true
  Key initialized: true
  Key path: C:\Users\...\AppData\Local\secret-store\master.key
  Secrets stored: 2
```

## Files Created

| File | Location | Contents |
|------|----------|----------|
| `master.key` | Platform config dir | TPM-sealed master key (encrypted blob) |
| `secrets.json` | Platform config dir | AES-encrypted secrets (unusable without TPM) |

## Limitations

- No backup - if TPM is cleared, all secrets are lost
- Machine-bound - secrets only accessible on this machine
- No sharing - can't export secrets to another device
