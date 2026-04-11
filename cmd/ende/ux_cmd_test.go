package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/kuma/ende/internal/keyring"
)

func TestSetupCommandGeneratesKeyAndShare(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("ENDE_CONFIG_DIR", configDir)

	cmd := newSetupCommand()
	cmd.SetArgs([]string{"--name", "alice"})
	var out bytes.Buffer
	var errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("setup command failed: %v", err)
	}

	result := out.String()
	for _, want := range []string{
		"generated key alice",
		"share: ENDE-PUB-1:",
		"Next steps:",
		"ende add-peer",
		"ende send -t <peer>",
	} {
		if !strings.Contains(result, want) {
			t.Fatalf("expected output to contain %q\nfull output:\n%s", want, result)
		}
	}

	store, err := keyring.Load()
	if err != nil {
		t.Fatalf("load keyring: %v", err)
	}
	if store.DefaultSigner() != "alice" {
		t.Fatalf("default signer = %q, want alice", store.DefaultSigner())
	}
	if _, ok := store.Key("alice"); !ok {
		t.Fatal("expected key alice to exist")
	}
}

func TestTaskOrientedAliasesPresent(t *testing.T) {
	if !containsAlias(newEncryptCommand().Aliases, "send") {
		t.Fatal("encrypt command should expose send alias")
	}
	if !containsAlias(newDecryptCommand().Aliases, "receive") {
		t.Fatal("decrypt command should expose receive alias")
	}
	if !containsAlias(newRegisterCommand().Aliases, "add-peer") {
		t.Fatal("register command should expose add-peer alias")
	}
}

func containsAlias(aliases []string, want string) bool {
	for _, alias := range aliases {
		if alias == want {
			return true
		}
	}
	return false
}
