package io

import (
	"fmt"
	"os"
)

type WriteOptions struct {
	NoClobber bool
}

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
	return WriteOutputWithOptions(path, b, WriteOptions{})
}

func WriteOutputWithOptions(path string, b []byte, opts WriteOptions) error {
	if path == "" || path == "-" {
		if _, err := os.Stdout.Write(b); err != nil {
			return fmt.Errorf("write stdout: %w", err)
		}
		return nil
	}
	if opts.NoClobber {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return fmt.Errorf("write output file %s: %w", path, err)
		}
		defer f.Close()
		if _, err := f.Write(b); err != nil {
			return fmt.Errorf("write output file %s: %w", path, err)
		}
		return nil
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("write output file %s: %w", path, err)
	}
	return nil
}

func WriteTempOutput(b []byte) (string, error) {
	f, err := os.CreateTemp("", "ende-plaintext-*")
	if err != nil {
		return "", fmt.Errorf("create temp output file: %w", err)
	}
	name := f.Name()
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		os.Remove(name)
		return "", fmt.Errorf("chmod temp output file %s: %w", name, err)
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		os.Remove(name)
		return "", fmt.Errorf("write temp output file %s: %w", name, err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("close temp output file %s: %w", name, err)
	}
	return name, nil
}
