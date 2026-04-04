package main

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

type fakeTTYReader struct {
	io.Reader
	fd uintptr
}

func (f fakeTTYReader) Fd() uintptr {
	return f.fd
}

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

func TestReadPromptSecret_PipedInput(t *testing.T) {
	var errBuf bytes.Buffer

	got, err := readPromptSecret(strings.NewReader("super-secret\n"), &errBuf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != "super-secret" {
		t.Fatalf("got %q, want %q", string(got), "super-secret")
	}
	if !strings.Contains(errBuf.String(), "secret> ") {
		t.Error("expected prompt message on stderr")
	}
}

func TestReadPromptSecret_RejectsEmptyInput(t *testing.T) {
	var errBuf bytes.Buffer

	_, err := readPromptSecret(strings.NewReader("\n"), &errBuf)
	if err == nil {
		t.Fatal("expected error for empty input")
	}
	if !strings.Contains(err.Error(), "secret is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReadPromptSecret_TTYUsesMaskedInput(t *testing.T) {
	oldIsTerminal := isTerminal
	oldReadPassword := readPassword
	t.Cleanup(func() {
		isTerminal = oldIsTerminal
		readPassword = oldReadPassword
	})

	isTerminal = func(fd int) bool {
		return fd == 42
	}
	readPassword = func(fd int) ([]byte, error) {
		if fd != 42 {
			t.Fatalf("readPassword fd = %d, want 42", fd)
		}
		return []byte("masked-secret"), nil
	}

	var errBuf bytes.Buffer
	in := fakeTTYReader{Reader: strings.NewReader("ignored\n"), fd: 42}

	got, err := readPromptSecret(in, &errBuf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != "masked-secret" {
		t.Fatalf("got %q, want %q", string(got), "masked-secret")
	}
	if !strings.Contains(errBuf.String(), "secret> ") {
		t.Error("expected prompt message on stderr")
	}
}
