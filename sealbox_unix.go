//go:build !windows

package sealbox

import (
	"os"
)

// setFilePermissions sets restrictive permissions on the file.
// On Unix systems, this sets the file to owner read/write only (0600).
func setFilePermissions(path string) error {
	return os.Chmod(path, 0600)
}

// setDirPermissions sets restrictive permissions on the directory.
// On Unix systems, this sets the directory to owner read/write/execute only (0700).
func setDirPermissions(path string) error {
	return os.Chmod(path, 0700)
}
