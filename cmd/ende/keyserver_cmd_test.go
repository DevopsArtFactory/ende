package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/kuma/ende/internal/keyring"
	"github.com/kuma/ende/internal/sign"
)

func TestKeyserverPublishCommandPublishesLocalProfile(t *testing.T) {
	t.Setenv("ENDE_CONFIG_DIR", t.TempDir())
	if _, err := tutorialKeygen("alice"); err != nil {
		t.Fatalf("keygen: %v", err)
	}

	var gotAuth string
	var gotProfile keyserverProfile
	withKeyserverTransport(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPut {
			t.Fatalf("expected PUT, got %s", r.Method)
		}
		if r.URL.String() != "https://keys.example.test/v1/peers/alice" {
			t.Fatalf("unexpected URL: %s", r.URL.String())
		}
		gotAuth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotProfile); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		return jsonResponse(http.StatusOK, `{}`)
	}))

	cmd := newKeyserverPublishCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--name", "alice", "--keyserver", "https://keys.example.test", "--token", "secret"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("publish failed: %v", err)
	}
	if gotAuth != "Bearer secret" {
		t.Fatalf("unexpected auth header: %q", gotAuth)
	}
	if gotProfile.ID != "alice" || gotProfile.Recipient == "" || gotProfile.SigningPublic == "" {
		t.Fatalf("unexpected published profile: %+v", gotProfile)
	}
	if !strings.Contains(out.String(), "published alice") {
		t.Fatalf("expected publish output, got:\n%s", out.String())
	}
}

func TestPeerFetchCommandPinsKeyserverPeer(t *testing.T) {
	t.Setenv("ENDE_CONFIG_DIR", t.TempDir())
	share := testShareToken(t, "bob")
	withKeyserverTransport(t, shareTransport(t, &share))

	cmd := newPeerFetchCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"bob", "--keyserver", "https://keys.example.test"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("fetch failed: %v", err)
	}

	store, err := keyring.Load()
	if err != nil {
		t.Fatalf("load keyring: %v", err)
	}
	if _, ok := store.Recipient("bob"); !ok {
		t.Fatal("expected bob recipient")
	}
	if _, ok := store.Sender("bob"); !ok {
		t.Fatal("expected bob trusted sender")
	}
	if !strings.Contains(out.String(), "fetched and pinned peer bob") {
		t.Fatalf("expected fetch output, got:\n%s", out.String())
	}
}

func TestPeerRefreshCommandRequiresYesBeforeUpdatingChangedPin(t *testing.T) {
	t.Setenv("ENDE_CONFIG_DIR", t.TempDir())
	share := testShareToken(t, "bob")
	withKeyserverTransport(t, shareTransport(t, &share))

	fetch := newPeerFetchCommand()
	fetch.SetArgs([]string{"bob", "--keyserver", "https://keys.example.test"})
	if err := fetch.Execute(); err != nil {
		t.Fatalf("fetch failed: %v", err)
	}

	share = testShareToken(t, "bob")

	refresh := newPeerRefreshCommand()
	refresh.SetArgs([]string{"bob", "--keyserver", "https://keys.example.test"})
	if err := refresh.Execute(); err == nil {
		t.Fatal("expected refresh without --yes to refuse changed pin")
	}

	refresh = newPeerRefreshCommand()
	var out bytes.Buffer
	refresh.SetOut(&out)
	refresh.SetArgs([]string{"bob", "--keyserver", "https://keys.example.test", "--yes"})
	if err := refresh.Execute(); err != nil {
		t.Fatalf("refresh with --yes failed: %v", err)
	}
	if !strings.Contains(out.String(), "refreshed pinned peer bob") {
		t.Fatalf("expected refresh output, got:\n%s", out.String())
	}
}

func TestKeyserverLoginCommandStoresPerUserToken(t *testing.T) {
	t.Setenv("ENDE_CONFIG_DIR", t.TempDir())
	withKeyserverTransport(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodGet && r.URL.String() == "https://keys.example.test/v1/auth/config" {
			return jsonResponse(http.StatusOK, `{"default_provider":"github","providers":{"github":{"client_id":"configured-client"}}}`)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.String() != "https://keys.example.test/v1/auth/github" {
			t.Fatalf("unexpected URL: %s", r.URL.String())
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode login request: %v", err)
		}
		if body["access_token"] != "provider-token" || body["peer_id"] != "alice" {
			t.Fatalf("unexpected login body: %+v", body)
		}
		return jsonResponse(http.StatusOK, `{"token":"ende_ks_user","peer_id":"alice","provider":"github","subject":"alice"}`)
	}))

	cmd := newKeyserverLoginCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{
		"--name", "alice",
		"--keyserver", "https://keys.example.test",
		"--access-token", "provider-token",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("login failed: %v", err)
	}
	token, err := loadStoredKeyserverToken("https://keys.example.test")
	if err != nil {
		t.Fatalf("load stored token: %v", err)
	}
	if token != "ende_ks_user" {
		t.Fatalf("unexpected stored token: %q", token)
	}
	if !strings.Contains(out.String(), "logged in to https://keys.example.test as alice via github") {
		t.Fatalf("unexpected login output:\n%s", out.String())
	}
}

func TestKeyserverLoginUsesAuthConfigForDeviceFlow(t *testing.T) {
	t.Setenv("ENDE_CONFIG_DIR", t.TempDir())
	requests := []string{}
	withKeyserverTransport(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests = append(requests, r.URL.String())
		switch r.URL.String() {
		case "https://keys.example.test/v1/auth/config":
			return jsonResponse(http.StatusOK, `{"default_provider":"github","providers":{"github":{"client_id":"configured-client"}}}`)
		case "https://github.com/login/device/code":
			if err := r.ParseForm(); err != nil {
				t.Fatalf("parse device form: %v", err)
			}
			if r.Form.Get("client_id") != "configured-client" {
				t.Fatalf("expected configured client id, got %q", r.Form.Get("client_id"))
			}
			return jsonResponse(http.StatusOK, `{"device_code":"device","user_code":"ABCD","verification_uri":"https://github.com/login/device","interval":0,"expires_in":10}`)
		case "https://github.com/login/oauth/access_token":
			return jsonResponse(http.StatusOK, `{"access_token":"provider-token"}`)
		case "https://keys.example.test/v1/auth/github":
			return jsonResponse(http.StatusOK, `{"token":"ende_ks_user","peer_id":"alice","provider":"github","subject":"alice"}`)
		default:
			t.Fatalf("unexpected request: %s", r.URL.String())
		}
		return nil, nil
	}))

	cmd := newKeyserverLoginCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--name", "alice", "--keyserver", "https://keys.example.test"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("login failed: %v; requests=%v", err, requests)
	}
	if !strings.Contains(out.String(), "Open: https://github.com/login/device") {
		t.Fatalf("expected device instructions, got:\n%s", out.String())
	}
}

func TestDeviceFlowConfigRejectsUnsafeOktaIssuers(t *testing.T) {
	tests := []string{
		"http://okta.example.test/oauth2/default",
		"https://127.0.0.1/oauth2/default",
		"https://10.0.0.5/oauth2/default",
		"https://okta.example.test/oauth2/default?next=https://evil.example.test",
	}
	for _, issuer := range tests {
		t.Run(issuer, func(t *testing.T) {
			_, _, _, err := deviceFlowConfig("okta", "client", issuer)
			if err == nil {
				t.Fatal("expected unsafe issuer to be rejected")
			}
		})
	}
}

func TestDeviceFlowConfigAcceptsHTTPSOktaIssuer(t *testing.T) {
	deviceEndpoint, tokenEndpoint, scope, err := deviceFlowConfig("okta", "client", "https://okta.example.test/oauth2/default/")
	if err != nil {
		t.Fatalf("expected valid issuer: %v", err)
	}
	if deviceEndpoint != "https://okta.example.test/oauth2/default/v1/device/authorize" {
		t.Fatalf("unexpected device endpoint: %s", deviceEndpoint)
	}
	if tokenEndpoint != "https://okta.example.test/oauth2/default/v1/token" {
		t.Fatalf("unexpected token endpoint: %s", tokenEndpoint)
	}
	if scope != "openid profile email" {
		t.Fatalf("unexpected scope: %s", scope)
	}
}

func testShareToken(t *testing.T, id string) string {
	t.Helper()
	xid, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate age identity: %v", err)
	}
	signPub, _, err := sign.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	share, err := encodeShareToken(id, xid.Recipient().String(), signPub)
	if err != nil {
		t.Fatalf("encode share token: %v", err)
	}
	return share
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return fn(r)
}

func withKeyserverTransport(t *testing.T, transport http.RoundTripper) {
	t.Helper()
	original := keyserverClient
	keyserverClient = &http.Client{Transport: transport}
	t.Cleanup(func() {
		keyserverClient = original
	})
}

func shareTransport(t *testing.T, share *string) http.RoundTripper {
	t.Helper()
	return roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET, got %s", r.Method)
		}
		if r.URL.String() != "https://keys.example.test/v1/share/bob" {
			t.Fatalf("unexpected URL: %s", r.URL.String())
		}
		return jsonResponse(http.StatusOK, `{"share_code":"`+*share+`"}`)
	})
}

func jsonResponse(status int, body string) (*http.Response, error) {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}, nil
}
