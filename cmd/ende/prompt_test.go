package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestReadEnvelopeInteractive(t *testing.T) {
	envelope := strings.Join([]string{
		"-----BEGIN ENDE ENVELOPE-----",
		"dGVzdGRhdGE=",
		"-----END ENDE ENVELOPE-----",
	}, "\n") + "\n"

	in := strings.NewReader(envelope)
	var errBuf bytes.Buffer

	got, err := readEnvelopeInteractive(in, &errBuf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if string(got) != envelope {
		t.Errorf("got %q, want %q", string(got), envelope)
	}

	if !strings.Contains(errBuf.String(), "Paste encrypted envelope") {
		t.Error("expected prompt message on stderr")
	}
}

func TestReadEnvelopeInteractive_StopsAtEndMarker(t *testing.T) {
	input := strings.Join([]string{
		"-----BEGIN ENDE ENVELOPE-----",
		"dGVzdGRhdGE=",
		"-----END ENDE ENVELOPE-----",
		"this line should not be included",
	}, "\n") + "\n"

	in := strings.NewReader(input)
	var errBuf bytes.Buffer

	got, err := readEnvelopeInteractive(in, &errBuf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if strings.Contains(string(got), "this line should not be included") {
		t.Error("reader should stop at END marker")
	}
}

func TestReadEnvelopeInteractive_EmptyInput(t *testing.T) {
	in := strings.NewReader("")
	var errBuf bytes.Buffer

	_, err := readEnvelopeInteractive(in, &errBuf)
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}
