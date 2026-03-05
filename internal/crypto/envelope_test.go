package crypto

import (
	"encoding/base64"
	"testing"

	"filippo.io/age"
	"github.com/kuma/ende/internal/sign"
)

func mustIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id
}

func mustSignKeys(t *testing.T) (string, string) {
	t.Helper()
	pub, priv, err := sign.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate sign keys: %v", err)
	}
	return pub, priv
}

func TestSealAndOpen(t *testing.T) {
	idB := mustIdentity(t)
	signPub, signPriv := mustSignKeys(t)
	plain := []byte("token=super-secret")
	env, err := Seal(plain, []age.Recipient{idB.Recipient()}, "alice", signPub, signPriv, []string{"bob"})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	decoded, out, err := Open(env, []age.Identity{idB}, true)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if string(out) != string(plain) {
		t.Fatalf("plaintext mismatch: got %q", out)
	}
	if decoded.Metadata.Version != EnvelopeVersion {
		t.Fatalf("version mismatch: %s", decoded.Metadata.Version)
	}
}

func TestThirdPartyCannotDecrypt(t *testing.T) {
	idB := mustIdentity(t)
	idC := mustIdentity(t)
	signPub, signPriv := mustSignKeys(t)
	env, err := Seal([]byte("pw=abc"), []age.Recipient{idB.Recipient()}, "alice", signPub, signPriv, nil)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, _, err := Open(env, []age.Identity{idC}, true); err == nil {
		t.Fatal("expected decrypt failure for third party")
	}
}

func TestTamperDetected(t *testing.T) {
	id := mustIdentity(t)
	signPub, signPriv := mustSignKeys(t)
	env, err := Seal([]byte("abc"), []age.Recipient{id.Recipient()}, "alice", signPub, signPriv, nil)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	env[len(env)-1] ^= 0x01
	if _, _, err := VerifyEnvelope(env); err == nil {
		t.Fatal("expected verification failure after tampering")
	}
}

func TestSignerSpoofDetected(t *testing.T) {
	id := mustIdentity(t)
	signPub, signPriv := mustSignKeys(t)
	env, err := Seal([]byte("abc"), []age.Recipient{id.Recipient()}, "alice", signPub, signPriv, nil)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	decoded, ct, err := DecodeEnvelope(env)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	otherPub, _, err := sign.GenerateKeyPair()
	if err != nil {
		t.Fatalf("other key: %v", err)
	}
	decoded.SignerPublic = otherPub
	encoded, err := signPayload(decoded.Metadata, decoded.SignerPublic, ct)
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	if err := sign.Verify(encoded, decoded.SignerPublic, decoded.Signature); err == nil {
		t.Fatal("expected verification to fail with spoofed signer public key")
	}
}

func TestMultiRecipient(t *testing.T) {
	idB := mustIdentity(t)
	idD := mustIdentity(t)
	idC := mustIdentity(t)
	signPub, signPriv := mustSignKeys(t)
	env, err := Seal([]byte("multi"), []age.Recipient{idB.Recipient(), idD.Recipient()}, "alice", signPub, signPriv, []string{"bob", "diana"})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, out, err := Open(env, []age.Identity{idB}, true); err != nil || string(out) != "multi" {
		t.Fatalf("recipient B failed: %v", err)
	}
	if _, out, err := Open(env, []age.Identity{idD}, true); err != nil || string(out) != "multi" {
		t.Fatalf("recipient D failed: %v", err)
	}
	if _, _, err := Open(env, []age.Identity{idC}, true); err == nil {
		t.Fatal("recipient C should not decrypt")
	}
}

func TestDecodeEnvelopeFromBase64(t *testing.T) {
	id := mustIdentity(t)
	signPub, signPriv := mustSignKeys(t)
	env, err := Seal([]byte("base64-ok"), []age.Recipient{id.Recipient()}, "alice", signPub, signPriv, nil)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	b64 := []byte(base64.StdEncoding.EncodeToString(env))
	if _, out, err := Open(b64, []age.Identity{id}, true); err != nil || string(out) != "base64-ok" {
		t.Fatalf("open base64 envelope failed: %v", err)
	}
}

func TestDecodeEnvelopeFromArmor(t *testing.T) {
	id := mustIdentity(t)
	signPub, signPriv := mustSignKeys(t)
	env, err := Seal([]byte("armor-ok"), []age.Recipient{id.Recipient()}, "alice", signPub, signPriv, nil)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	armored := EncodeTextEnvelope(env)
	if _, out, err := Open(armored, []age.Identity{id}, true); err != nil || string(out) != "armor-ok" {
		t.Fatalf("open armored envelope failed: %v", err)
	}
}
