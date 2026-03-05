package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

const sharePrefix = "ENDE-PUB-1:"

type sharePayload struct {
	Version       int    `json:"version"`
	ID            string `json:"id"`
	Recipient     string `json:"recipient"`
	SigningPublic string `json:"signing_public"`
}

func encodeShareToken(id, recipient, signingPublic string) (string, error) {
	p := sharePayload{
		Version:       1,
		ID:            strings.TrimSpace(id),
		Recipient:     strings.TrimSpace(recipient),
		SigningPublic: strings.TrimSpace(signingPublic),
	}
	b, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("encode share token: %w", err)
	}
	return sharePrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

func decodeShareToken(token string) (*sharePayload, error) {
	t := strings.TrimSpace(token)
	if !strings.HasPrefix(t, sharePrefix) {
		return nil, fmt.Errorf("invalid share token prefix")
	}
	raw := strings.TrimPrefix(t, sharePrefix)
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("decode share token: %w", err)
	}
	var p sharePayload
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("parse share token payload: %w", err)
	}
	if p.Version != 1 {
		return nil, fmt.Errorf("unsupported share token version: %d", p.Version)
	}
	return &p, nil
}
