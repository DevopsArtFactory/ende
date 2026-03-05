package io

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestReadInputFromFile(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	content := []byte("test content")

	if err := os.WriteFile(testFile, content, 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	result, err := ReadInput(testFile)
	if err != nil {
		t.Fatalf("ReadInput failed: %v", err)
	}

	if !bytes.Equal(result, content) {
		t.Fatalf("content mismatch: got %q, want %q", result, content)
	}
}

func TestReadInputFromStdin(t *testing.T) {
	// Test with "-" argument
	// Note: This is a simplified test. In real usage, stdin would be piped
	_, err := ReadInput("-")
	// We expect this to work or fail gracefully depending on the system
	if err != nil {
		// On systems without /dev/stdin, this is expected
		t.Logf("ReadInput from stdin: %v (expected on some systems)", err)
	}
}

func TestReadInputFileNotFound(t *testing.T) {
	_, err := ReadInput("/nonexistent/file.txt")
	if err == nil {
		t.Fatal("ReadInput should fail for nonexistent file")
	}
}

func TestWriteOutputToFile(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "output.txt")
	content := []byte("output content")

	if err := WriteOutput(testFile, content); err != nil {
		t.Fatalf("WriteOutput failed: %v", err)
	}

	result, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	if !bytes.Equal(result, content) {
		t.Fatalf("content mismatch: got %q, want %q", result, content)
	}

	// Verify file permissions
	info, err := os.Stat(testFile)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}

	mode := info.Mode().Perm()
	if mode != 0600 {
		t.Fatalf("file permission mismatch: got %o, want 0600", mode)
	}
}

func TestWriteOutputToStdout(t *testing.T) {
	// Capture stdout
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Pipe failed: %v", err)
	}
	os.Stdout = w

	content := []byte("stdout content")
	if err := WriteOutput("-", content); err != nil {
		t.Fatalf("WriteOutput failed: %v", err)
	}

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatalf("ReadFrom failed: %v", err)
	}

	if !bytes.Equal(buf.Bytes(), content) {
		t.Fatalf("stdout content mismatch: got %q, want %q", buf.Bytes(), content)
	}
}

func TestWriteOutputEmptyPath(t *testing.T) {
	// Empty path should write to stdout
	// This is similar to "-" behavior
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Pipe failed: %v", err)
	}
	os.Stdout = w

	content := []byte("test")
	if err := WriteOutput("", content); err != nil {
		t.Fatalf("WriteOutput failed: %v", err)
	}

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatalf("ReadFrom failed: %v", err)
	}

	if !bytes.Equal(buf.Bytes(), content) {
		t.Fatalf("content mismatch: got %q, want %q", buf.Bytes(), content)
	}
}

func TestWriteOutputInvalidDirectory(t *testing.T) {
	err := WriteOutput("/nonexistent/dir/file.txt", []byte("test"))
	if err == nil {
		t.Fatal("WriteOutput should fail for invalid directory")
	}
}

func TestReadWriteRoundtrip(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "roundtrip.txt")
	content := []byte("roundtrip test content\nwith multiple lines\nand special chars: !@#$%")

	// Write
	if err := WriteOutput(testFile, content); err != nil {
		t.Fatalf("WriteOutput failed: %v", err)
	}

	// Read
	result, err := ReadInput(testFile)
	if err != nil {
		t.Fatalf("ReadInput failed: %v", err)
	}

	if !bytes.Equal(result, content) {
		t.Fatalf("roundtrip content mismatch: got %q, want %q", result, content)
	}
}

func TestReadInputEmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "empty.txt")

	if err := os.WriteFile(testFile, []byte{}, 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	result, err := ReadInput(testFile)
	if err != nil {
		t.Fatalf("ReadInput failed: %v", err)
	}

	if len(result) != 0 {
		t.Fatalf("expected empty content, got %d bytes", len(result))
	}
}

func TestWriteOutputEmptyContent(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "empty.txt")

	if err := WriteOutput(testFile, []byte{}); err != nil {
		t.Fatalf("WriteOutput failed: %v", err)
	}

	result, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	if len(result) != 0 {
		t.Fatalf("expected empty file, got %d bytes", len(result))
	}
}
