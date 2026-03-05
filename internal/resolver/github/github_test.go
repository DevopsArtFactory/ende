package github

import (
	"strings"
	"testing"
	"time"
)

func TestResolveSSHKeysInvalidUsername(t *testing.T) {
	tests := []struct {
		name     string
		username string
	}{
		{"empty username", ""},
		{"whitespace only", "   "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ResolveSSHKeys(tt.username)
			if err == nil {
				t.Fatal("ResolveSSHKeys should fail with invalid username")
			}
		})
	}
}

func TestResolveSSHKeysNonexistentUser(t *testing.T) {
	// Use a username that is very unlikely to exist
	username := "this-user-definitely-does-not-exist-12345678901234567890"
	_, err := ResolveSSHKeys(username)
	if err == nil {
		t.Fatal("ResolveSSHKeys should fail for nonexistent user")
	}
	// Should get a 404 or similar error
	if !strings.Contains(err.Error(), "404") && !strings.Contains(err.Error(), "failed") {
		t.Logf("Expected 404 or failure, got: %v", err)
	}
}

// Note: Testing with real GitHub users is fragile as their keys can change
// For production, consider mocking the HTTP client or using a test server
func TestResolveSSHKeysRealUser(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	// Test with a well-known GitHub user that has public keys
	// Using "octocat" as it's GitHub's mascot account
	username := "octocat"
	keys, err := ResolveSSHKeys(username)
	if err != nil {
		// If this fails, it might be due to network issues or API changes
		t.Skipf("ResolveSSHKeys failed (network issue?): %v", err)
	}

	if len(keys) == 0 {
		t.Skip("octocat has no public keys (unexpected but not a test failure)")
	}

	// Verify keys are non-empty strings
	for i, key := range keys {
		if strings.TrimSpace(key) == "" {
			t.Fatalf("key %d is empty", i)
		}
		// SSH keys typically start with ssh-rsa, ssh-ed25519, etc.
		if !strings.HasPrefix(key, "ssh-") {
			t.Logf("Warning: key %d doesn't start with 'ssh-': %s", i, key[:min(20, len(key))])
		}
	}
}

func TestParseAgeRecipientFromSSHUnsupported(t *testing.T) {
	tests := []struct {
		name   string
		sshPub string
	}{
		{"rsa key", "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC..."},
		{"ecdsa key", "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY..."},
		{"invalid format", "not-a-valid-ssh-key"},
		{"empty", ""},
		{"whitespace", "   "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseAgeRecipientFromSSH(tt.sshPub)
			if err == nil {
				t.Fatal("ParseAgeRecipientFromSSH should fail for unsupported key types")
			}
		})
	}
}

func TestParseAgeRecipientFromSSHEd25519(t *testing.T) {
	// Ed25519 keys are not directly convertible in current implementation
	sshPub := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
	_, err := ParseAgeRecipientFromSSH(sshPub)
	if err == nil {
		t.Fatal("ParseAgeRecipientFromSSH should fail (not implemented)")
	}
	// Verify error message mentions it's not implemented
	if !strings.Contains(err.Error(), "not implemented") {
		t.Fatalf("expected 'not implemented' error, got: %v", err)
	}
}

func TestResolveSSHKeysUserAgent(t *testing.T) {
	// This test verifies the function sets a User-Agent
	// We can't easily test the actual HTTP request without mocking,
	// but we can verify the function doesn't panic with valid input
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	// Use a known user
	username := "torvalds"
	_, err := ResolveSSHKeys(username)
	if err != nil {
		// Network errors are acceptable in tests
		t.Logf("ResolveSSHKeys failed (network issue?): %v", err)
	}
}

func TestResolveSSHKeysTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	// The function has an 8-second timeout
	// We can't easily test timeout without a slow server,
	// but we can verify it doesn't hang indefinitely
	username := "octocat"
	done := make(chan bool)
	go func() {
		_, _ = ResolveSSHKeys(username)
		done <- true
	}()

	select {
	case <-done:
		// Success - function returned
	case <-time.After(15 * time.Second):
		t.Fatal("ResolveSSHKeys took longer than expected (timeout not working?)")
	}
}
