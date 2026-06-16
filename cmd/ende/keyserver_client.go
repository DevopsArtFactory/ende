package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/kuma/ende/internal/keyring"
	"github.com/kuma/ende/internal/sign"
)

const (
	keyserverSource          = "keyserver"
	keyserverURLEnv          = "ENDE_KEYSERVER_URL"
	keyserverTokenEnv        = "ENDE_KEYSERVER_TOKEN"
	keyserverInsecureHTTPEnv = "ENDE_KEYSERVER_INSECURE_HTTP"
)

var keyserverClient = &http.Client{Timeout: 10 * time.Second}

type keyserverProfile struct {
	ID            string `json:"id"`
	Recipient     string `json:"recipient"`
	SigningPublic string `json:"signing_public"`
	DisplayName   string `json:"display_name,omitempty"`
}

type keyserverShareResponse struct {
	ShareCode string `json:"share_code"`
}

type keyserverAuthResponse struct {
	Token    string `json:"token"`
	PeerID   string `json:"peer_id"`
	Provider string `json:"provider"`
	Subject  string `json:"subject"`
}

type keyserverTokenFile struct {
	Tokens map[string]string `json:"tokens"`
}

func keyserverURL(flagValue string, allowInsecureHTTP ...bool) (string, error) {
	raw := strings.TrimSpace(flagValue)
	if raw == "" {
		raw = strings.TrimSpace(os.Getenv(keyserverURLEnv))
	}
	if raw == "" {
		return "", fmt.Errorf("--keyserver is required (or set %s)", keyserverURLEnv)
	}
	parsed, err := url.ParseRequestURI(raw)
	if err != nil {
		return "", fmt.Errorf("invalid keyserver URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("keyserver URL must start with http:// or https://")
	}
	allowInsecure := len(allowInsecureHTTP) > 0 && allowInsecureHTTP[0]
	if parsed.Scheme == "http" && !allowInsecure && !envEnabled(keyserverInsecureHTTPEnv) && !isLoopbackHost(parsed.Hostname()) {
		return "", fmt.Errorf("remote keyserver URL must use https:// (use --insecure-http only for test environments)")
	}
	return strings.TrimRight(raw, "/"), nil
}

func envEnabled(name string) bool {
	return strings.TrimSpace(strings.ToLower(os.Getenv(name))) == "1" ||
		strings.TrimSpace(strings.ToLower(os.Getenv(name))) == "true" ||
		strings.TrimSpace(strings.ToLower(os.Getenv(name))) == "yes" ||
		strings.TrimSpace(strings.ToLower(os.Getenv(name))) == "on"
}

func isLoopbackHost(host string) bool {
	normalized := strings.TrimSpace(strings.ToLower(host))
	if normalized == "localhost" {
		return true
	}
	ip := net.ParseIP(normalized)
	return ip != nil && ip.IsLoopback()
}

func keyserverToken(baseURL, flagValue string) string {
	if strings.TrimSpace(flagValue) != "" {
		return strings.TrimSpace(flagValue)
	}
	if token := strings.TrimSpace(os.Getenv(keyserverTokenEnv)); token != "" {
		return token
	}
	token, _ := loadStoredKeyserverToken(baseURL)
	return token
}

func keyserverHTTPClient() *http.Client {
	return keyserverClient
}

func localKeyserverProfile(name string) (*keyserverProfile, string, error) {
	store, err := keyring.Load()
	if err != nil {
		return nil, "", err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = store.DefaultSigner()
	}
	if name == "" {
		return nil, "", fmt.Errorf("--name is required because no default signer is configured")
	}
	entry, ok := store.Key(name)
	if !ok {
		return nil, "", fmt.Errorf("unknown local key: %s", name)
	}
	share, err := tutorialShareFromEntry(entry)
	if err != nil {
		return nil, "", err
	}
	payload, err := decodeShareToken(share)
	if err != nil {
		return nil, "", err
	}
	return &keyserverProfile{
		ID:            payload.ID,
		Recipient:     payload.Recipient,
		SigningPublic: payload.SigningPublic,
		DisplayName:   payload.ID,
	}, share, nil
}

func publishKeyserverProfile(baseURL, token string, profile *keyserverProfile) error {
	body, err := json.Marshal(profile)
	if err != nil {
		return fmt.Errorf("encode keyserver profile: %w", err)
	}
	req, err := http.NewRequest(http.MethodPut, baseURL+"/v1/peers/"+url.PathEscape(profile.ID), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := keyserverHTTPClient().Do(req)
	if err != nil {
		return fmt.Errorf("publish profile: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("publish profile failed: %s: %s", resp.Status, readErrorBody(resp.Body))
	}
	return nil
}

func exchangeProviderToken(baseURL, provider, accessToken, peerID string) (*keyserverAuthResponse, error) {
	body, err := json.Marshal(map[string]string{
		"access_token": accessToken,
		"peer_id":      peerID,
	})
	if err != nil {
		return nil, fmt.Errorf("encode auth request: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, baseURL+"/v1/auth/"+url.PathEscape(provider), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := keyserverHTTPClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("exchange SSO token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("exchange SSO token failed: %s: %s", resp.Status, readErrorBody(resp.Body))
	}
	var auth keyserverAuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&auth); err != nil {
		return nil, fmt.Errorf("parse auth response: %w", err)
	}
	if strings.TrimSpace(auth.Token) == "" {
		return nil, fmt.Errorf("keyserver auth response did not include a token")
	}
	return &auth, nil
}

func fetchKeyserverShare(baseURL, peerID string) (string, *sharePayload, error) {
	peerID = strings.TrimSpace(peerID)
	if peerID == "" {
		return "", nil, fmt.Errorf("peer id is required")
	}
	resp, err := keyserverHTTPClient().Get(baseURL + "/v1/share/" + url.PathEscape(peerID))
	if err != nil {
		return "", nil, fmt.Errorf("fetch peer from keyserver: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", nil, fmt.Errorf("fetch peer failed: %s: %s", resp.Status, readErrorBody(resp.Body))
	}
	var body keyserverShareResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", nil, fmt.Errorf("parse keyserver response: %w", err)
	}
	payload, err := decodeShareToken(body.ShareCode)
	if err != nil {
		return "", nil, err
	}
	if _, err := age.ParseX25519Recipient(payload.Recipient); err != nil {
		return "", nil, fmt.Errorf("invalid recipient in keyserver share code: %w", err)
	}
	if _, err := sign.ParsePublicKey(payload.SigningPublic); err != nil {
		return "", nil, fmt.Errorf("invalid signing public key in keyserver share code: %w", err)
	}
	return body.ShareCode, payload, nil
}

func addPeerFromSharePayload(store *keyring.Store, alias string, payload *sharePayload, force bool) error {
	if strings.TrimSpace(alias) == "" {
		alias = payload.ID
	}
	if strings.TrimSpace(alias) == "" {
		return fmt.Errorf("alias is required")
	}
	if err := store.AddRecipient(alias, payload.Recipient, keyserverSource, payload.ID, force); err != nil {
		return err
	}
	if err := store.AddSender(alias, payload.SigningPublic, keyserverSource, payload.ID, force); err != nil {
		return err
	}
	return store.Save()
}

func readErrorBody(r io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(r, 4096))
	msg := strings.TrimSpace(string(b))
	if msg == "" {
		return "empty response body"
	}
	return msg
}

func storeKeyserverToken(baseURL, token string) error {
	path, err := keyserverTokenPath()
	if err != nil {
		return err
	}
	tf := keyserverTokenFile{Tokens: map[string]string{}}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &tf)
	}
	if tf.Tokens == nil {
		tf.Tokens = map[string]string{}
	}
	tf.Tokens[baseURL] = token
	b, err := json.MarshalIndent(tf, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

func loadStoredKeyserverToken(baseURL string) (string, error) {
	path, err := keyserverTokenPath()
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var tf keyserverTokenFile
	if err := json.Unmarshal(b, &tf); err != nil {
		return "", err
	}
	return strings.TrimSpace(tf.Tokens[baseURL]), nil
}

func keyserverTokenPath() (string, error) {
	configDir, _, _, err := keyring.DefaultPaths()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, "keyserver-tokens.json"), nil
}
