package sign

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	if pub == "" || priv == "" {
		t.Fatal("generated keys should not be empty")
	}

	// Verify keys are valid base64
	if _, err := base64.StdEncoding.DecodeString(pub); err != nil {
		t.Fatalf("public key is not valid base64: %v", err)
	}
	if _, err := base64.StdEncoding.DecodeString(priv); err != nil {
		t.Fatalf("private key is not valid base64: %v", err)
	}

	// Verify key lengths
	pubKey, err := ParsePublicKey(pub)
	if err != nil {
		t.Fatalf("ParsePublicKey failed: %v", err)
	}
	if len(pubKey) != ed25519.PublicKeySize {
		t.Fatalf("public key length mismatch: got %d, want %d", len(pubKey), ed25519.PublicKeySize)
	}

	privKey, err := ParsePrivateKey(priv)
	if err != nil {
		t.Fatalf("ParsePrivateKey failed: %v", err)
	}
	if len(privKey) != ed25519.PrivateKeySize {
		t.Fatalf("private key length mismatch: got %d, want %d", len(privKey), ed25519.PrivateKeySize)
	}
}

func TestSignAndVerify(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	payload := []byte("test message")
	sig, err := Sign(payload, priv)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if sig == "" {
		t.Fatal("signature should not be empty")
	}

	// Verify signature
	if err := Verify(payload, pub, sig); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	// Verify with wrong payload should fail
	wrongPayload := []byte("wrong message")
	if err := Verify(wrongPayload, pub, sig); err == nil {
		t.Fatal("Verify should fail with wrong payload")
	}

	// Verify with wrong public key should fail
	otherPub, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	if err := Verify(payload, otherPub, sig); err == nil {
		t.Fatal("Verify should fail with wrong public key")
	}
}

func TestParsePublicKeyInvalid(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"invalid base64", "not-base64!@#"},
		{"wrong length", base64.StdEncoding.EncodeToString([]byte("short"))},
		{"empty", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParsePublicKey(tt.input); err == nil {
				t.Fatal("ParsePublicKey should fail with invalid input")
			}
		})
	}
}

func TestParsePrivateKeyInvalid(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"invalid base64", "not-base64!@#"},
		{"wrong length", base64.StdEncoding.EncodeToString([]byte("short"))},
		{"empty", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParsePrivateKey(tt.input); err == nil {
				t.Fatal("ParsePrivateKey should fail with invalid input")
			}
		})
	}
}

func TestSignInvalidPrivateKey(t *testing.T) {
	payload := []byte("test")
	invalidKey := base64.StdEncoding.EncodeToString([]byte("invalid"))
	if _, err := Sign(payload, invalidKey); err == nil {
		t.Fatal("Sign should fail with invalid private key")
	}
}

func TestVerifyInvalidSignature(t *testing.T) {
	pub, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	payload := []byte("test")

	// Invalid base64 signature
	if err := Verify(payload, pub, "not-base64!@#"); err == nil {
		t.Fatal("Verify should fail with invalid base64 signature")
	}

	// Wrong length signature
	shortSig := base64.StdEncoding.EncodeToString([]byte("short"))
	if err := Verify(payload, pub, shortSig); err == nil {
		t.Fatal("Verify should fail with wrong length signature")
	}
}

func TestSignatureUniqueness(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	payload := []byte("test message")
	sig1, err := Sign(payload, priv)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	sig2, err := Sign(payload, priv)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Ed25519 signatures are deterministic
	if sig1 != sig2 {
		t.Fatal("Ed25519 signatures should be deterministic")
	}

	// Both signatures should verify
	if err := Verify(payload, pub, sig1); err != nil {
		t.Fatalf("Verify sig1 failed: %v", err)
	}
	if err := Verify(payload, pub, sig2); err != nil {
		t.Fatalf("Verify sig2 failed: %v", err)
	}
}
