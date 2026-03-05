package main

import "testing"

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
