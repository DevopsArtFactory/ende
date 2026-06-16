package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/kuma/ende/internal/keyring"
)

func TestInitCommandCreatesLocalKeyAndPrintsShareCode(t *testing.T) {
	t.Setenv("ENDE_CONFIG_DIR", t.TempDir())

	cmd := newInitCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--name", "alice"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("init command failed: %v", err)
	}

	got := out.String()
	if !strings.Contains(got, "created local key alice") {
		t.Fatalf("expected create message, got:\n%s", got)
	}
	if !strings.Contains(got, sharePrefix) {
		t.Fatalf("expected share code, got:\n%s", got)
	}

	store, err := keyring.Load()
	if err != nil {
		t.Fatalf("load keyring: %v", err)
	}
	if _, ok := store.Key("alice"); !ok {
		t.Fatal("expected alice key in keyring")
	}
	if store.DefaultSigner() != "alice" {
		t.Fatalf("expected alice default signer, got %q", store.DefaultSigner())
	}
}

func TestInitCommandReusesExistingLocalKey(t *testing.T) {
	t.Setenv("ENDE_CONFIG_DIR", t.TempDir())

	first := newInitCommand()
	first.SetArgs([]string{"--name", "alice"})
	if err := first.Execute(); err != nil {
		t.Fatalf("first init failed: %v", err)
	}

	second := newInitCommand()
	var out bytes.Buffer
	second.SetOut(&out)
	second.SetArgs([]string{"--name", "alice"})
	if err := second.Execute(); err != nil {
		t.Fatalf("second init failed: %v", err)
	}
	if !strings.Contains(out.String(), "using existing local key alice") {
		t.Fatalf("expected reuse message, got:\n%s", out.String())
	}
}

func TestInitCommandPrintsKeyserverGuidance(t *testing.T) {
	t.Setenv("ENDE_CONFIG_DIR", t.TempDir())

	cmd := newInitCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--name", "alice", "--keyserver", "https://keys.example.com/"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("init command failed: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "https://keys.example.com/v1/peers/alice") {
		t.Fatalf("expected publish URL, got:\n%s", got)
	}
	if !strings.Contains(got, "https://keys.example.com/v1/share/alice") {
		t.Fatalf("expected share URL, got:\n%s", got)
	}
}

func TestInitCommandRejectsInvalidKeyserverURL(t *testing.T) {
	t.Setenv("ENDE_CONFIG_DIR", t.TempDir())

	cmd := newInitCommand()
	cmd.SetArgs([]string{"--name", "alice", "--keyserver", "://bad"})

	if err := cmd.Execute(); err == nil {
		t.Fatal("expected invalid keyserver URL error")
	}
}

func TestSanitizeInitName(t *testing.T) {
	got := sanitizeInitName(`domain\Alice Smith!`)
	if got != "Alice-Smith" {
		t.Fatalf("unexpected sanitized name: %q", got)
	}
}
