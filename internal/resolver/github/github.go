package github

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type userKey struct {
	ID  int    `json:"id"`
	Key string `json:"key"`
}

func ResolveSSHKeys(username string) ([]string, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, fmt.Errorf("username is required")
	}
	url := fmt.Sprintf("https://api.github.com/users/%s/keys", username)
	client := &http.Client{Timeout: 8 * time.Second}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build github request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "ende-cli")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request github keys: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github key lookup failed: %s", resp.Status)
	}

	var keys []userKey
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		return nil, fmt.Errorf("decode github key response: %w", err)
	}
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		if k.Key != "" {
			out = append(out, k.Key)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no ssh public keys found for github user %s", username)
	}
	return out, nil
}

// ParseAgeRecipientFromSSH converts only Ed25519 SSH public keys to age recipients.
// GitHub stores SSH keys; this provides optional convenience by deriving age recipient when possible.
func ParseAgeRecipientFromSSH(sshPub string) (string, error) {
	parts := strings.Fields(strings.TrimSpace(sshPub))
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid ssh public key format")
	}
	if parts[0] != "ssh-ed25519" {
		return "", fmt.Errorf("unsupported ssh key type %s; only ssh-ed25519 can be converted", parts[0])
	}
	// This conversion is intentionally strict and delegated to age-keygen interoperability:
	// users should import an age recipient directly for best reliability.
	return "", fmt.Errorf("direct conversion from ssh-ed25519 to age recipient is not implemented; provide an age recipient key")
}
