# TPM Package Branding

This document explains how to customize the TPM package for your application.

## Default Configuration

| Setting | Default Value | Description |
|---------|---------------|-------------|
| App Name | `clonr` | Used in config directory path |
| Key File | `.clonr_sealed_key` | Hidden file for sealed key |

## Storage Paths

Storage paths are determined by platform and app name:

| Platform | Path Template |
|----------|---------------|
| Linux | `~/.config/{AppName}/{KeyFileName}` |
| Windows | `%LOCALAPPDATA%\{AppName}\{KeyFileName}` |
| macOS | `~/Library/Application Support/{AppName}/{KeyFileName}` |

### Default Paths

```
Linux:   ~/.config/clonr/.clonr_sealed_key
Windows: C:\Users\<user>\AppData\Local\clonr\.clonr_sealed_key
macOS:   ~/Library/Application Support/clonr/.clonr_sealed_key
```

## Customization

### Option 1: Custom App Name

```go
store, err := tpm.NewKeyStore(
    tpm.WithAppName("myapp"),
)
// Linux: ~/.config/myapp/.clonr_sealed_key
```

### Option 2: Custom Key File Name

```go
store, err := tpm.NewKeyStore(
    tpm.WithFileName(".myapp_sealed_key"),
)
// Linux: ~/.config/clonr/.myapp_sealed_key
```

### Option 3: Both App Name and Key File

```go
store, err := tpm.NewKeyStore(
    tpm.WithAppName("myapp"),
    tpm.WithFileName(".myapp_sealed_key"),
)
// Linux: ~/.config/myapp/.myapp_sealed_key
```

### Option 4: Custom Full Path

```go
store, err := tpm.NewKeyStore(
    tpm.WithStorePath("/custom/path/to/sealed.key"),
)
// Uses exact path specified
```

## Integration Example

```go
package main

import (
    "fmt"
    "log"

    "github.com/inovacc/clonr/pkg/tpm"
)

func main() {
    if !tpm.IsAvailable() {
        log.Fatal("TPM not available")
    }

    // Create key manager
    km, err := tpm.NewKeyManager()
    if err != nil {
        log.Fatal(err)
    }
    defer km.Close()

    // Create custom key store
    store, err := tpm.NewKeyStore(
        tpm.WithAppName("myapp"),
        tpm.WithFileName(".myapp_key"),
    )
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Key path: %s\n", store.Path())

    // Initialize if needed
    if !store.Exists() {
        sealed, err := km.GenerateAndSealKey()
        if err != nil {
            log.Fatal(err)
        }
        if err := store.Save(sealed); err != nil {
            log.Fatal(err)
        }
        fmt.Println("Key initialized")
    }

    // Load and unseal
    sealed, err := store.Load()
    if err != nil {
        log.Fatal(err)
    }

    key, err := km.UnsealKey(sealed)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Retrieved %d-byte key\n", len(key))
}
```

## KeyStore Options Reference

| Option | Description |
|--------|-------------|
| `WithAppName(name)` | Sets application name for path |
| `WithFileName(name)` | Sets key file name |
| `WithStorePath(path)` | Sets complete custom path |

## Best Practices

1. **Use hidden files** - Prefix with `.` to hide key files
2. **Consistent naming** - Use same app name across your application
3. **Don't change after init** - Changing paths after keys exist will break access

## Forking for Your Application

To create a fully branded TPM package:

1. Copy `pkg/tpm/` to your project
2. Update `DefaultAppName` in `keystore.go`
3. Update `DefaultKeyFileName` in `keystore.go`
4. Update package documentation

```go
// keystore.go
const (
    DefaultKeyFileName = ".myapp_sealed_key"
    DefaultAppName     = "myapp"
)
```
