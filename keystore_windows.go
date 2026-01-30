//go:build windows

package keystore

import (
	"os/user"

	acl "github.com/inovacc/keystore/internal/acl"
	"golang.org/x/sys/windows"
)

// setFilePermissions sets restrictive permissions on the file.
// On Windows, this sets ACLs to allow only the current user read/write access.
func setFilePermissions(path string) error {
	currentUser, err := user.Current()
	if err != nil {
		return err
	}

	// Grant current user full control, deny everyone else
	return acl.Apply(
		path,
		true,  // replace existing ACL
		false, // don't inherit from parent
		acl.GrantName(windows.GENERIC_READ|windows.GENERIC_WRITE, currentUser.Username),
	)
}

// setDirPermissions sets restrictive permissions on the directory.
// On Windows, this sets ACLs to allow only the current user full access.
func setDirPermissions(path string) error {
	currentUser, err := user.Current()
	if err != nil {
		return err
	}

	// Grant current user full control on directory
	return acl.Apply(
		path,
		true,  // replace existing ACL
		false, // don't inherit from parent
		acl.GrantName(windows.GENERIC_ALL, currentUser.Username),
	)
}
