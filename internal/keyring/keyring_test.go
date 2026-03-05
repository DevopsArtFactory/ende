package keyring

import "testing"

func TestFingerprintAgePublicKeyStable(t *testing.T) {
	k := "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
	if FingerprintAgePublicKey(k) != FingerprintAgePublicKey(k+"\n") {
		t.Fatal("fingerprint should ignore surrounding whitespace")
	}
}

func TestDefaultSigner(t *testing.T) {
	st := &Store{
		Data: File{
			Keys: map[string]KeyEntry{
				"alice": {ID: "alice"},
			},
		},
	}
	if err := st.SetDefaultSigner("alice"); err != nil {
		t.Fatalf("set default signer: %v", err)
	}
	if got := st.DefaultSigner(); got != "alice" {
		t.Fatalf("default signer mismatch: %s", got)
	}
	if err := st.SetDefaultSigner("missing"); err == nil {
		t.Fatal("expected error for unknown key id")
	}
}
