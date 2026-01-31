//go:build !linux && !windows

package sealbox

// KeyHierarchy manages multiple sealed keys under a common storage.
type KeyHierarchy struct{}

// KeyHierarchyData is the serializable representation of a key hierarchy.
type KeyHierarchyData struct {
	Version int                    `json:"version"`
	Keys    map[string]*SealedData `json:"keys"`
}

// NewKeyHierarchy returns an error on unsupported platforms.
func NewKeyHierarchy(basePath string) (*KeyHierarchy, error) {
	return nil, ErrTPMNotSupported
}

func (h *KeyHierarchy) Save() error {
	return ErrTPMNotSupported
}

func (h *KeyHierarchy) Add(name string, data *SealedData) error {
	return ErrTPMNotSupported
}

func (h *KeyHierarchy) Get(name string) (*SealedData, bool) {
	return nil, false
}

func (h *KeyHierarchy) Remove(name string) bool {
	return false
}

func (h *KeyHierarchy) List() []string {
	return nil
}

func (h *KeyHierarchy) Count() int {
	return 0
}

func (h *KeyHierarchy) Exists(name string) bool {
	return false
}

func (h *KeyHierarchy) IsModified() bool {
	return false
}

func (h *KeyHierarchy) Clear() {}

func (h *KeyHierarchy) Delete() error {
	return ErrTPMNotSupported
}

// KeyHierarchyManager combines KeyManager with KeyHierarchy.
type KeyHierarchyManager struct{}

// NewKeyHierarchyManager returns an error on unsupported platforms.
func NewKeyHierarchyManager(km KeyManager, basePath string) (*KeyHierarchyManager, error) {
	return nil, ErrTPMNotSupported
}

func (m *KeyHierarchyManager) Hierarchy() *KeyHierarchy {
	return nil
}

func (m *KeyHierarchyManager) KeyManager() KeyManager {
	return nil
}

func (m *KeyHierarchyManager) GenerateKey(name string) error {
	return ErrTPMNotSupported
}

func (m *KeyHierarchyManager) GenerateKeyWithOptions(name string, opts ...SealOption) error {
	return ErrTPMNotSupported
}

func (m *KeyHierarchyManager) SealKey(name string, key []byte) error {
	return ErrTPMNotSupported
}

func (m *KeyHierarchyManager) UnsealKey(name string) ([]byte, error) {
	return nil, ErrTPMNotSupported
}

func (m *KeyHierarchyManager) UnsealKeyWithOptions(name string, opts ...SealOption) ([]byte, error) {
	return nil, ErrTPMNotSupported
}

func (m *KeyHierarchyManager) Save() error {
	return ErrTPMNotSupported
}

func (m *KeyHierarchyManager) Close(save bool) error {
	return ErrTPMNotSupported
}
