package policy

import (
	"fmt"
	"os"
	"runtime"
)

func EnsurePrivateFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat private file %s: %w", path, err)
	}
	if runtime.GOOS == "windows" {
		// Windows ACLs do not map cleanly to POSIX mode bits.
		return nil
	}
	mode := info.Mode().Perm()
	if mode != 0o600 {
		return fmt.Errorf("private key file %s must have 0600 permission, got %o", path, mode)
	}
	return nil
}

func EnsurePlaintextOutputAllowed(out string) error {
	if out == "-" {
		return nil
	}
	if out == "" {
		return fmt.Errorf("plaintext stdout is blocked by default; provide --out <file> or explicit --out -")
	}
	return nil
}
