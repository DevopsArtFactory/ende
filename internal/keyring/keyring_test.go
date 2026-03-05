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

func TestAddRecipientForce(t *testing.T) {
	st := &Store{Data: File{Recipients: map[string]RecipientEntry{}}}
	if err := st.AddRecipient("bob", "age1abc", "local", "", false); err != nil {
		t.Fatalf("first add recipient: %v", err)
	}
	if err := st.AddRecipient("bob", "age1def", "local", "", false); err == nil {
		t.Fatal("expected duplicate add to fail without force")
	}
	if err := st.AddRecipient("bob", "age1def", "local", "", true); err != nil {
		t.Fatalf("force add recipient: %v", err)
	}
	if got := st.Data.Recipients["bob"].AgePublic; got != "age1def" {
		t.Fatalf("unexpected recipient key after force overwrite: %s", got)
	}
}

func TestAddSenderForce(t *testing.T) {
	st := &Store{Data: File{Senders: map[string]SenderEntry{}}}
	if err := st.AddSender("alice", "pub-1", "manual", "", false); err != nil {
		t.Fatalf("first add sender: %v", err)
	}
	if err := st.AddSender("alice", "pub-2", "manual", "", false); err == nil {
		t.Fatal("expected duplicate sender add to fail without force")
	}
	if err := st.AddSender("alice", "pub-2", "manual", "", true); err != nil {
		t.Fatalf("force add sender: %v", err)
	}
	s, ok := st.Sender("alice")
	if !ok || s.SignPublic != "pub-2" {
		t.Fatal("sender overwrite did not persist")
	}
}
