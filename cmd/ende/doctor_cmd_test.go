package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kuma/ende/internal/keyring"
)

func TestDoctorCommandHealthyConfig(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("ENDE_CONFIG_DIR", configDir)

	agePath := filepath.Join(configDir, "alice.agekey")
	signPath := filepath.Join(configDir, "alice.signkey")
	writeDoctorTestFile(t, agePath, "age-secret\n", 0o600)
	writeDoctorTestFile(t, signPath, "sign-secret\n", 0o600)

	store, err := keyring.Load()
	if err != nil {
		t.Fatalf("load keyring: %v", err)
	}
	store.AddKey(keyring.KeyEntry{
		ID:          "alice",
		AgeIdentity: agePath,
		SignPrivate: signPath,
		SignPublic:  "alice-public",
	})
	if err := store.AddSender("alice", "alice-public", "local-key", "", true); err != nil {
		t.Fatalf("add sender: %v", err)
	}
	if err := store.SetDefaultSigner("alice"); err != nil {
		t.Fatalf("set default signer: %v", err)
	}
	if err := store.Save(); err != nil {
		t.Fatalf("save keyring: %v", err)
	}

	cmd := newDoctorCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("doctor command failed: %v", err)
	}

	got := out.String()
	if !strings.Contains(got, "[ok] default_signer: default signer is alice") {
		t.Fatalf("expected default signer ok message, got:\n%s", got)
	}
	if !strings.Contains(got, "summary: ok=") {
		t.Fatalf("expected summary output, got:\n%s", got)
	}
}

func TestDoctorCommandReportsWarningsAndFailures(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("ENDE_CONFIG_DIR", configDir)

	agePath := filepath.Join(configDir, "bob.agekey")
	signPath := filepath.Join(configDir, "bob.signkey")
	writeDoctorTestFile(t, agePath, "age-secret\n", 0o600)
	writeDoctorTestFile(t, signPath, "sign-secret\n", 0o644)

	store, err := keyring.Load()
	if err != nil {
		t.Fatalf("load keyring: %v", err)
	}
	store.AddKey(keyring.KeyEntry{
		ID:          "bob",
		AgeIdentity: agePath,
		SignPrivate: signPath,
		SignPublic:  "bob-public",
	})
	if err := store.AddRecipient("bob", "age1bobrecipient", "register", "", false); err != nil {
		t.Fatalf("add recipient: %v", err)
	}
	if err := store.Save(); err != nil {
		t.Fatalf("save keyring: %v", err)
	}

	cmd := newDoctorCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	err = cmd.Execute()
	if err == nil {
		t.Fatal("expected doctor command to fail")
	}

	got := out.String()
	if !strings.Contains(got, "[warn] default_signer: no default signer configured") {
		t.Fatalf("expected default signer warning, got:\n%s", got)
	}
	if !strings.Contains(got, "[warn] alias[bob]: recipient exists without a matching trusted sender entry") {
		t.Fatalf("expected alias warning, got:\n%s", got)
	}
	if !strings.Contains(got, "[fail] key[bob].sign_private:") {
		t.Fatalf("expected private key failure, got:\n%s", got)
	}
}

func writeDoctorTestFile(t *testing.T, path, contents string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), mode); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
