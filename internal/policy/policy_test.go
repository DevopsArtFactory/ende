package policy

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestEnsurePrivateFile(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "k")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EnsurePrivateFile(p); err != nil {
		t.Fatalf("expected pass for 0600: %v", err)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		if err := EnsurePrivateFile(p); err != nil {
			t.Fatalf("expected Windows permission check bypass: %v", err)
		}
		return
	}
	if err := EnsurePrivateFile(p); err == nil {
		t.Fatal("expected failure for 0644")
	}
}

func TestEnsurePlaintextOutputAllowed(t *testing.T) {
	if err := EnsurePlaintextOutputAllowed("-"); err != nil {
		t.Fatalf("explicit stdout should pass: %v", err)
	}
	if err := EnsurePlaintextOutputAllowed("out.txt"); err != nil {
		t.Fatalf("file output should pass: %v", err)
	}
	if err := EnsurePlaintextOutputAllowed(""); err == nil {
		t.Fatal("empty output should fail")
	}
}
