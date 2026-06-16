package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kuma/ende/internal/keyring"
	"github.com/spf13/cobra"
)

type deviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	Interval                int    `json:"interval"`
	ExpiresIn               int    `json:"expires_in"`
}

type deviceTokenResponse struct {
	AccessToken string `json:"access_token"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

type keyserverAuthConfig struct {
	DefaultProvider string                             `json:"default_provider"`
	Providers       map[string]keyserverProviderConfig `json:"providers"`
}

type keyserverProviderConfig struct {
	ClientID string `json:"client_id"`
	Issuer   string `json:"issuer"`
}

func newKeyserverLoginCommand() *cobra.Command {
	var provider string
	var serverURL string
	var name string
	var clientID string
	var issuer string
	var accessToken string
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Login with GitHub or Okta and store a per-user publish token",
		RunE: func(cmd *cobra.Command, args []string) error {
			baseURL, err := keyserverURL(serverURL)
			if err != nil {
				return err
			}
			cfg, _ := fetchKeyserverAuthConfig(baseURL)
			provider = strings.ToLower(strings.TrimSpace(provider))
			if provider == "" && cfg != nil {
				provider = cfg.DefaultProvider
			}
			if provider == "" {
				provider = "github"
			}
			if cfg != nil {
				if p, ok := cfg.Providers[provider]; ok {
					if strings.TrimSpace(clientID) == "" {
						clientID = p.ClientID
					}
					if strings.TrimSpace(issuer) == "" {
						issuer = p.Issuer
					}
				}
			}
			if strings.TrimSpace(name) == "" {
				store, err := keyring.Load()
				if err != nil {
					return err
				}
				name = store.DefaultSigner()
			}
			if strings.TrimSpace(name) == "" {
				return fmt.Errorf("--name is required because no default signer is configured")
			}

			if strings.TrimSpace(accessToken) == "" {
				token, err := runDeviceLogin(cmd.OutOrStdout(), provider, clientID, issuer)
				if err != nil {
					return err
				}
				accessToken = token
			}
			auth, err := exchangeProviderToken(baseURL, provider, accessToken, name)
			if err != nil {
				return err
			}
			if err := storeKeyserverToken(baseURL, auth.Token); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "logged in to %s as %s via %s\n", baseURL, auth.PeerID, auth.Provider)
			fmt.Fprintf(cmd.OutOrStdout(), "stored publish token for %s\n", baseURL)
			return nil
		},
	}
	cmd.Flags().StringVar(&provider, "provider", "", "SSO provider: github or okta (defaults to keyserver config)")
	cmd.Flags().StringVar(&serverURL, "keyserver", "", "keyserver base URL (or ENDE_KEYSERVER_URL)")
	cmd.Flags().StringVar(&name, "name", "", "local peer id to bind to the publish token")
	cmd.Flags().StringVar(&clientID, "client-id", "", "OAuth device-flow client id")
	cmd.Flags().StringVar(&issuer, "issuer", "", "Okta issuer URL, e.g. https://example.okta.com/oauth2/default")
	cmd.Flags().StringVar(&accessToken, "access-token", "", "provider access token for non-interactive login/testing")
	return cmd
}

func runDeviceLogin(out interface{ Write([]byte) (int, error) }, provider, clientID, issuer string) (string, error) {
	deviceEndpoint, tokenEndpoint, scope, err := deviceFlowConfig(provider, clientID, issuer)
	if err != nil {
		return "", err
	}
	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("scope", scope)
	device, err := postFormJSON[deviceCodeResponse](deviceEndpoint, form)
	if err != nil {
		return "", err
	}
	if device.Interval <= 0 {
		device.Interval = 5
	}
	verification := device.VerificationURIComplete
	if verification == "" {
		verification = device.VerificationURI
	}
	fmt.Fprintf(out, "Open: %s\n", verification)
	if device.UserCode != "" {
		fmt.Fprintf(out, "Code: %s\n", device.UserCode)
	}

	deadline := time.Now().Add(time.Duration(device.ExpiresIn) * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(time.Duration(device.Interval) * time.Second)
		form = url.Values{}
		form.Set("client_id", clientID)
		form.Set("device_code", device.DeviceCode)
		form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
		token, err := postFormJSON[deviceTokenResponse](tokenEndpoint, form)
		if err != nil {
			return "", err
		}
		if token.AccessToken != "" {
			return token.AccessToken, nil
		}
		if token.Error == "authorization_pending" {
			continue
		}
		if token.Error == "slow_down" {
			device.Interval++
			continue
		}
		if token.Error != "" {
			if token.ErrorDesc != "" {
				return "", fmt.Errorf("%s: %s", token.Error, token.ErrorDesc)
			}
			return "", errors.New(token.Error)
		}
	}
	return "", fmt.Errorf("device login expired")
}

func fetchKeyserverAuthConfig(baseURL string) (*keyserverAuthConfig, error) {
	resp, err := keyserverHTTPClient().Get(baseURL + "/v1/auth/config")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("fetch auth config failed: %s", resp.Status)
	}
	var cfg keyserverAuthConfig
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return nil, err
	}
	if cfg.Providers == nil {
		cfg.Providers = map[string]keyserverProviderConfig{}
	}
	return &cfg, nil
}

func deviceFlowConfig(provider, clientID, issuer string) (deviceEndpoint, tokenEndpoint, scope string, err error) {
	switch provider {
	case "github":
		if clientID == "" {
			return "", "", "", fmt.Errorf("--client-id is required for GitHub login")
		}
		return "https://github.com/login/device/code", "https://github.com/login/oauth/access_token", "read:user user:email", nil
	case "okta":
		if clientID == "" {
			return "", "", "", fmt.Errorf("--client-id is required for Okta login")
		}
		issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
		if issuer == "" {
			return "", "", "", fmt.Errorf("--issuer is required for Okta login")
		}
		return issuer + "/v1/device/authorize", issuer + "/v1/token", "openid profile email", nil
	default:
		return "", "", "", fmt.Errorf("unsupported provider: %s", provider)
	}
}

func postFormJSON[T any](endpoint string, form url.Values) (*T, error) {
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := keyserverHTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out T
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}
