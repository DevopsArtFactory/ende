package main

import (
	"strings"
	"testing"
)

func TestEncodeDecodeShareToken(t *testing.T) {
	id := "alice"
	recipient := "age1qqnv7zhqs2gm0"
	signingPub := "dGVzdC1zaWduaW5nLXB1Ymxp"

	token, err := encodeShareToken(id, recipient, signingPub)
	if err != nil {
		t.Fatalf("encodeShareToken: %v", err)
	}
	if !strings.HasPrefix(token, sharePrefix) {
		t.Fatalf("token missing prefix: %s", token)
	}

	p, err := decodeShareToken(token)
	if err != nil {
		t.Fatalf("decodeShareToken: %v", err)
	}
	if p.ID != id {
		t.Fatalf("id mismatch: got %s", p.ID)
	}
	if p.Recipient != recipient {
		t.Fatalf("recipient mismatch: got %s", p.Recipient)
	}
	if p.SigningPublic != signingPub {
		t.Fatalf("signing public mismatch: got %s", p.SigningPublic)
	}
	if p.Version != 1 {
		t.Fatalf("version mismatch: got %d", p.Version)
	}
}

func TestDecodeShareTokenInvalidPrefix(t *testing.T) {
	_, err := decodeShareToken("INVALID-PREFIX:abc")
	if err == nil {
		t.Fatal("expected error for invalid prefix")
	}
}

func TestDecodeShareTokenInvalidBase64(t *testing.T) {
	_, err := decodeShareToken(sharePrefix + "!!!invalid-base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestDecodeShareTokenInvalidJSON(t *testing.T) {
	// Valid base64 but invalid JSON
	_, err := decodeShareToken(sharePrefix + "bm90LWpzb24")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestEncodeShareTokenWhitespace(t *testing.T) {
	token, err := encodeShareToken("  alice  ", "  age1key  ", "  pub  ")
	if err != nil {
		t.Fatalf("encodeShareToken: %v", err)
	}
	p, err := decodeShareToken(token)
	if err != nil {
		t.Fatalf("decodeShareToken: %v", err)
	}
	if p.ID != "alice" {
		t.Fatalf("expected trimmed id, got %q", p.ID)
	}
	if p.Recipient != "age1key" {
		t.Fatalf("expected trimmed recipient, got %q", p.Recipient)
	}
}

func TestDecodeShareTokenWithWhitespace(t *testing.T) {
	token, _ := encodeShareToken("bob", "age1x", "pub1")
	// Add surrounding whitespace
	p, err := decodeShareToken("  " + token + "  ")
	if err != nil {
		t.Fatalf("decodeShareToken with whitespace: %v", err)
	}
	if p.ID != "bob" {
		t.Fatalf("id mismatch: got %s", p.ID)
	}
}
