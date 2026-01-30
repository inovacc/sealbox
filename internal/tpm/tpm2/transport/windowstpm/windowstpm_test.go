//go:build windows

package windowstpm

import (
	"os"
	"testing"

	testhelper "github.com/inovacc/keystore/internal/tpm/tpm2/transport/test"
)

func TestLocalTPM(t *testing.T) {
	testhelper.RunTest(t, []error{os.ErrNotExist, os.ErrPermission, ErrNotTPM20}, Open)
}
