//go:build !linux && !darwin

package backend

import (
	"context"
	"fmt"
	"os"
	"runtime"
)

func acquireSoftwareKeyLock(context.Context, string) (func() error, error) {
	return nil, fmt.Errorf("software key locking is unsupported on %s", runtime.GOOS)
}

func softwareFileLinkCount(*os.File) (uint64, error) {
	return 0, fmt.Errorf("software key link-count checks are unsupported on %s", runtime.GOOS)
}
