package io

import (
	"fmt"
	"os"
)

func ReadInput(path string) ([]byte, error) {
	if path == "" || path == "-" {
		return os.ReadFile("/dev/stdin")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read input file %s: %w", path, err)
	}
	return b, nil
}

func WriteOutput(path string, b []byte) error {
	if path == "" || path == "-" {
		if _, err := os.Stdout.Write(b); err != nil {
			return fmt.Errorf("write stdout: %w", err)
		}
		return nil
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("write output file %s: %w", path, err)
	}
	return nil
}
