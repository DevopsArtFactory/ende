package sign

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

func GenerateKeyPair() (publicKey string, privateKey string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate ed25519 keypair: %w", err)
	}
	return base64.StdEncoding.EncodeToString(pub), base64.StdEncoding.EncodeToString(priv), nil
}

func ParsePublicKey(b64 string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid ed25519 public key length: %d", len(b))
	}
	return ed25519.PublicKey(b), nil
}

func ParsePrivateKey(b64 string) (ed25519.PrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	if len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid ed25519 private key length: %d", len(b))
	}
	return ed25519.PrivateKey(b), nil
}

func Sign(payload []byte, privateKeyB64 string) (string, error) {
	priv, err := ParsePrivateKey(privateKeyB64)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, payload)
	return base64.StdEncoding.EncodeToString(sig), nil
}

func Verify(payload []byte, publicKeyB64, signatureB64 string) error {
	pub, err := ParsePublicKey(publicKeyB64)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("invalid ed25519 signature length: %d", len(sig))
	}
	if !ed25519.Verify(pub, payload, sig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}
