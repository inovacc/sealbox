// Example: TPM-backed Secret Store
//
// This example demonstrates how to use the keystore package to create
// a simple secret storage application with hardware-backed encryption.
//
// The TPM-sealed master key is used to derive encryption keys for
// storing application secrets securely.
//
// Usage:
//
//	go run main.go init          # Initialize TPM key (first time only)
//	go run main.go set <name>    # Store a secret (reads from stdin)
//	go run main.go get <name>    # Retrieve a secret
//	go run main.go list          # List all secret names
//	go run main.go delete <name> # Delete a secret
//	go run main.go reset         # Delete TPM key and all secrets
package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/inovacc/keystore"
)

const (
	appName  = "secret-store"
	keyFile  = "master.key"
	dataFile = "secrets.json"
)

// SecretStore holds encrypted secrets
type SecretStore struct {
	Secrets map[string]string `json:"secrets"` // name -> encrypted value (hex)
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]

	switch cmd {
	case "init":
		cmdInit()
	case "set":
		if len(os.Args) < 3 {
			fmt.Println("Usage: secret-store set <name>")
			os.Exit(1)
		}
		cmdSet(os.Args[2])
	case "get":
		if len(os.Args) < 3 {
			fmt.Println("Usage: secret-store get <name>")
			os.Exit(1)
		}
		cmdGet(os.Args[2])
	case "list":
		cmdList()
	case "delete":
		if len(os.Args) < 3 {
			fmt.Println("Usage: secret-store delete <name>")
			os.Exit(1)
		}
		cmdDelete(os.Args[2])
	case "reset":
		cmdReset()
	case "status":
		cmdStatus()
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("TPM-backed Secret Store")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  secret-store init          Initialize TPM key (first time)")
	fmt.Println("  secret-store set <name>    Store a secret (reads from stdin)")
	fmt.Println("  secret-store get <name>    Retrieve a secret")
	fmt.Println("  secret-store list          List all secret names")
	fmt.Println("  secret-store delete <name> Delete a secret")
	fmt.Println("  secret-store reset         Delete TPM key and all secrets")
	fmt.Println("  secret-store status        Show TPM and key status")
}

func keystoreOpts() keystore.KeyStoreOption {
	return keystore.WithAppConfig(appName, keyFile)
}

func cmdInit() {
	// Check TPM availability
	if !keystore.IsAvailable() {
		fmt.Println("Error: TPM is not available on this system")
		os.Exit(1)
	}

	// Initialize the TPM-sealed key
	err := keystore.Initialize(keystoreOpts())
	if err == keystore.ErrKeyExists {
		fmt.Println("TPM key already initialized")
		return
	}
	if err != nil {
		fmt.Printf("Error initializing TPM key: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("TPM key initialized successfully")
	fmt.Println("Your secrets are now protected by hardware encryption")
}

func cmdSet(name string) {
	masterKey := getMasterKey()

	// Read secret from stdin
	fmt.Printf("Enter secret for '%s': ", name)
	reader := bufio.NewReader(os.Stdin)
	secret, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("Error reading input: %v\n", err)
		os.Exit(1)
	}
	secret = strings.TrimSpace(secret)

	if secret == "" {
		fmt.Println("Error: secret cannot be empty")
		os.Exit(1)
	}

	// Derive encryption key for this secret
	encKey := deriveKey(masterKey, "encrypt:"+name)

	// Encrypt the secret
	encrypted, err := encrypt([]byte(secret), encKey)
	if err != nil {
		fmt.Printf("Error encrypting secret: %v\n", err)
		os.Exit(1)
	}

	// Load existing secrets
	store := loadSecrets()

	// Store the encrypted secret
	store.Secrets[name] = hex.EncodeToString(encrypted)

	// Save secrets
	saveSecrets(store)

	fmt.Printf("Secret '%s' stored successfully\n", name)
}

func cmdGet(name string) {
	masterKey := getMasterKey()

	// Load secrets
	store := loadSecrets()

	// Get encrypted secret
	encryptedHex, ok := store.Secrets[name]
	if !ok {
		fmt.Printf("Error: secret '%s' not found\n", name)
		os.Exit(1)
	}

	// Decode hex
	encrypted, err := hex.DecodeString(encryptedHex)
	if err != nil {
		fmt.Printf("Error decoding secret: %v\n", err)
		os.Exit(1)
	}

	// Derive decryption key
	encKey := deriveKey(masterKey, "encrypt:"+name)

	// Decrypt
	decrypted, err := decrypt(encrypted, encKey)
	if err != nil {
		fmt.Printf("Error decrypting secret: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(decrypted))
}

func cmdList() {
	store := loadSecrets()

	if len(store.Secrets) == 0 {
		fmt.Println("No secrets stored")
		return
	}

	fmt.Println("Stored secrets:")
	for name := range store.Secrets {
		fmt.Printf("  - %s\n", name)
	}
}

func cmdDelete(name string) {
	store := loadSecrets()

	if _, ok := store.Secrets[name]; !ok {
		fmt.Printf("Error: secret '%s' not found\n", name)
		os.Exit(1)
	}

	delete(store.Secrets, name)
	saveSecrets(store)

	fmt.Printf("Secret '%s' deleted\n", name)
}

func cmdReset() {
	fmt.Print("This will delete the TPM key and all secrets. Continue? (yes/no): ")
	reader := bufio.NewReader(os.Stdin)
	answer, _ := reader.ReadString('\n')
	answer = strings.TrimSpace(strings.ToLower(answer))

	if answer != "yes" {
		fmt.Println("Aborted")
		return
	}

	// Delete secrets file
	secretsPath := getSecretsPath()
	_ = os.Remove(secretsPath)

	// Reset TPM key
	err := keystore.Reset(keystoreOpts())
	if err != nil {
		fmt.Printf("Error resetting TPM key: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("TPM key and all secrets deleted")
}

func cmdStatus() {
	fmt.Println("TPM Status:")
	fmt.Printf("  Available: %v\n", keystore.IsAvailable())
	fmt.Printf("  Key initialized: %v\n", keystore.HasKey(keystoreOpts()))

	path, err := keystore.GetKeyStorePath(keystoreOpts())
	if err == nil {
		fmt.Printf("  Key path: %s\n", path)
	}

	store := loadSecrets()
	fmt.Printf("  Secrets stored: %d\n", len(store.Secrets))
}

// getMasterKey retrieves and unseals the master key from TPM
func getMasterKey() []byte {
	if !keystore.HasKey(keystoreOpts()) {
		fmt.Println("Error: TPM key not initialized. Run 'secret-store init' first.")
		os.Exit(1)
	}

	key, err := keystore.GetSealedMasterKey(keystoreOpts())
	if err != nil {
		fmt.Printf("Error retrieving master key: %v\n", err)
		os.Exit(1)
	}

	return key
}

// deriveKey derives a key from the master key using HMAC-SHA256
func deriveKey(masterKey []byte, context string) []byte {
	h := hmac.New(sha256.New, masterKey)
	h.Write([]byte(context))
	return h.Sum(nil)
}

// encrypt encrypts data using AES-GCM
func encrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// decrypt decrypts data using AES-GCM
func decrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// getSecretsPath returns the path to the secrets file
func getSecretsPath() string {
	// Use same directory as the keystore
	keyPath, _ := keystore.GetKeyStorePath(keystoreOpts())
	return filepath.Join(filepath.Dir(keyPath), dataFile)
}

// loadSecrets loads the secrets store from disk
func loadSecrets() *SecretStore {
	store := &SecretStore{
		Secrets: make(map[string]string),
	}

	data, err := os.ReadFile(getSecretsPath())
	if err != nil {
		return store // Return empty store if file doesn't exist
	}

	_ = json.Unmarshal(data, store)
	if store.Secrets == nil {
		store.Secrets = make(map[string]string)
	}

	return store
}

// saveSecrets saves the secrets store to disk
func saveSecrets(store *SecretStore) {
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		fmt.Printf("Error encoding secrets: %v\n", err)
		os.Exit(1)
	}

	path := getSecretsPath()

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		fmt.Printf("Error creating directory: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		fmt.Printf("Error saving secrets: %v\n", err)
		os.Exit(1)
	}
}
