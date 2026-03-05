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

func TestRemoveRecipient(t *testing.T) {
	st := &Store{Data: File{Recipients: map[string]RecipientEntry{}}}
	_ = st.AddRecipient("bob", "age1abc", "local", "", false)

	if !st.RemoveRecipient("bob") {
		t.Fatal("RemoveRecipient should return true for existing alias")
	}
	if _, ok := st.Recipient("bob"); ok {
		t.Fatal("recipient should be removed")
	}
	if st.RemoveRecipient("bob") {
		t.Fatal("RemoveRecipient should return false for missing alias")
	}
}

func TestRemoveSender(t *testing.T) {
	st := &Store{Data: File{Senders: map[string]SenderEntry{}}}
	_ = st.AddSender("alice", "pub-1", "manual", "", false)

	if !st.RemoveSender("alice") {
		t.Fatal("RemoveSender should return true for existing id")
	}
	if _, ok := st.Sender("alice"); ok {
		t.Fatal("sender should be removed")
	}
	if st.RemoveSender("alice") {
		t.Fatal("RemoveSender should return false for missing id")
	}
}

func TestAddRecipientEmptyAlias(t *testing.T) {
	st := &Store{Data: File{Recipients: map[string]RecipientEntry{}}}
	if err := st.AddRecipient("", "age1abc", "local", "", false); err == nil {
		t.Fatal("expected error for empty alias")
	}
	if err := st.AddRecipient("   ", "age1abc", "local", "", false); err == nil {
		t.Fatal("expected error for whitespace-only alias")
	}
}

func TestAddSenderEmptyID(t *testing.T) {
	st := &Store{Data: File{Senders: map[string]SenderEntry{}}}
	if err := st.AddSender("", "pub-1", "manual", "", false); err == nil {
		t.Fatal("expected error for empty sender id")
	}
	if err := st.AddSender("   ", "pub-1", "manual", "", false); err == nil {
		t.Fatal("expected error for whitespace-only sender id")
	}
}

func TestAllRecipientAliasesSorted(t *testing.T) {
	st := &Store{Data: File{Recipients: map[string]RecipientEntry{}}}
	_ = st.AddRecipient("charlie", "age1c", "local", "", false)
	_ = st.AddRecipient("alice", "age1a", "local", "", false)
	_ = st.AddRecipient("bob", "age1b", "local", "", false)

	aliases := st.AllRecipientAliases()
	if len(aliases) != 3 {
		t.Fatalf("expected 3 aliases, got %d", len(aliases))
	}
	if aliases[0] != "alice" || aliases[1] != "bob" || aliases[2] != "charlie" {
		t.Fatalf("aliases not sorted: %v", aliases)
	}
}

func TestAllKeyIDsSorted(t *testing.T) {
	st := &Store{Data: File{Keys: map[string]KeyEntry{}}}
	st.AddKey(KeyEntry{ID: "zeta"})
	st.AddKey(KeyEntry{ID: "alpha"})
	st.AddKey(KeyEntry{ID: "mid"})

	ids := st.AllKeyIDs()
	if len(ids) != 3 {
		t.Fatalf("expected 3 ids, got %d", len(ids))
	}
	if ids[0] != "alpha" || ids[1] != "mid" || ids[2] != "zeta" {
		t.Fatalf("ids not sorted: %v", ids)
	}
}

func TestAllSenderIDsSorted(t *testing.T) {
	st := &Store{Data: File{Senders: map[string]SenderEntry{}}}
	_ = st.AddSender("zeta", "pub-z", "manual", "", false)
	_ = st.AddSender("alpha", "pub-a", "manual", "", false)

	ids := st.AllSenderIDs()
	if len(ids) != 2 {
		t.Fatalf("expected 2 ids, got %d", len(ids))
	}
	if ids[0] != "alpha" || ids[1] != "zeta" {
		t.Fatalf("ids not sorted: %v", ids)
	}
}

func TestFingerprintSignPublicKeyStable(t *testing.T) {
	k := "test-signing-public-key"
	if FingerprintSignPublicKey(k) != FingerprintSignPublicKey(k+"\n") {
		t.Fatal("fingerprint should ignore surrounding whitespace")
	}
	if FingerprintSignPublicKey(k) != FingerprintSignPublicKey(k) {
		t.Fatal("fingerprint should be deterministic")
	}
}

func TestAddSenderNilSendersMap(t *testing.T) {
	st := &Store{Data: File{Senders: nil}}
	if err := st.AddSender("alice", "pub-1", "manual", "", false); err != nil {
		t.Fatalf("AddSender with nil map: %v", err)
	}
	if st.Data.Senders == nil {
		t.Fatal("Senders map should be initialized")
	}
	s, ok := st.Sender("alice")
	if !ok || s.SignPublic != "pub-1" {
		t.Fatal("sender not added correctly")
	}
}
