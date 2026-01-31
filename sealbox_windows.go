//go:build windows

package sealbox

import (
	"os/user"

	acl2 "github.com/hectane/go-acl"
	"golang.org/x/sys/windows"
)

// setFilePermissions sets restrictive permissions on the file.
// On Windows, this sets ACLs to allow only the current user read/write access.
func setFilePermissions(path string) error {
	currentUser, err := user.Current()
	if err != nil {
		return err
	}

	// Grant the current user full control, deny everyone else
	return acl2.Apply(
		path,
		true,  // replace existing ACL
		false, // don't inherit from parent
		acl2.GrantName(windows.GENERIC_READ|windows.GENERIC_WRITE, currentUser.Username),
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
	return acl2.Apply(
		path,
		true,  // replace existing ACL
		false, // don't inherit from parent
		acl2.GrantName(windows.GENERIC_ALL, currentUser.Username),
	)
}
