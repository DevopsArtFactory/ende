package main

import (
	"strings"
	"testing"
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

func TestDecryptCommandRejectsOutTempWithOut(t *testing.T) {
	cmd := newDecryptCommand()
	cmd.SetArgs([]string{"--out-temp", "--out", "plain.txt"})
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected command to fail")
	}
	if !strings.Contains(err.Error(), "--out-temp cannot be used with --out") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecryptCommandRejectsOutTempWithTextOut(t *testing.T) {
	cmd := newDecryptCommand()
	cmd.SetArgs([]string{"--out-temp", "--text-out"})
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected command to fail")
	}
	if !strings.Contains(err.Error(), "--text-out cannot be used with --out-temp") {
		t.Fatalf("unexpected error: %v", err)
	}
}
