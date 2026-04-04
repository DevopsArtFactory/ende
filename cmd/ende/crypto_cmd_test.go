package main

import (
	"bytes"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/kuma/ende/internal/keyring"
)

func TestSha256Hex(t *testing.T) {
	// Deterministic hash
	h1 := sha256Hex("hello")
	h2 := sha256Hex("hello")
	if h1 != h2 {
		t.Fatal("sha256Hex should be deterministic")
	}
	if len(h1) != 64 {
		t.Fatalf("expected 64 hex chars, got %d", len(h1))
	}

	// Different inputs produce different hashes
	h3 := sha256Hex("world")
	if h1 == h3 {
		t.Fatal("different inputs should produce different hashes")
	}
}

func TestShort(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", ""},
		{"short", "short"},
		{"exactly12ch", "exactly12ch"},
		{"exactly12chr", "exactly12chr"},
		{"longerthan12chars", "longerthan12"},
		{"abcdefghijklmnop", "abcdefghijkl"},
	}
	for _, tt := range tests {
		got := short(tt.input)
		if got != tt.want {
			t.Errorf("short(%q) = %q, want %q",
				tt.input, got, tt.want)
		}
	}
}

func TestResolveRecipientIncludesAliasSummary(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity: %v", err)
	}
	recipient := identity.Recipient().String()
	store := &keyring.Store{
		Data: keyring.File{
			Recipients: map[string]keyring.RecipientEntry{
				"bob": {
					Alias:       "bob",
					AgePublic:   recipient,
					Fingerprint: keyring.FingerprintAgePublicKey(recipient),
					Source:      "register",
				},
			},
		},
	}

	_, hint, summary, err := resolveRecipient(store, "bob")
	if err != nil {
		t.Fatalf("resolveRecipient: %v", err)
	}
	if hint != "bob" {
		t.Fatalf("hint = %q, want %q", hint, "bob")
	}
	if summary.Label != "bob" {
		t.Fatalf("summary label = %q, want %q", summary.Label, "bob")
	}
	if summary.Source != "register" {
		t.Fatalf("summary source = %q, want %q", summary.Source, "register")
	}
	if summary.Fingerprint == "" {
		t.Fatal("expected fingerprint summary")
	}
}

func TestConfirmEncryptAcceptsYes(t *testing.T) {
	var errBuf bytes.Buffer
	err := confirmEncrypt(strings.NewReader("yes\n"), &errBuf, encryptSummary{
		SignerID: "alice",
		Recipients: []encryptRecipientSummary{
			{Label: "bob", Fingerprint: "abc123", Source: "register"},
		},
		OutputPath: "secret.txt",
		Format:     "armored text",
	})
	if err != nil {
		t.Fatalf("confirmEncrypt: %v", err)
	}
	got := errBuf.String()
	if !strings.Contains(got, "recipient: bob") {
		t.Fatalf("expected recipient summary, got:\n%s", got)
	}
	if !strings.Contains(got, "Continue? [y/N]: ") {
		t.Fatalf("expected confirmation prompt, got:\n%s", got)
	}
}

func TestConfirmEncryptRejectsNegativeAnswer(t *testing.T) {
	var errBuf bytes.Buffer
	err := confirmEncrypt(strings.NewReader("n\n"), &errBuf, encryptSummary{
		SignerID:   "alice",
		OutputPath: "-",
		Format:     "armored text",
	})
	if err == nil {
		t.Fatal("expected cancellation error")
	}
	if !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("unexpected error: %v", err)
	}
}
