package policy

import (
	"fmt"
	"os"
)

func EnsurePrivateFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat private file %s: %w", path, err)
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
