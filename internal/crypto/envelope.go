package crypto

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"time"

	"filippo.io/age"
	"github.com/fxamacker/cbor/v2"
	"github.com/kuma/ende/internal/sign"
)

const EnvelopeVersion = "ende-envelope-v1"

type Metadata struct {
	Version        string   `cbor:"version" json:"version"`
	SenderKeyID    string   `cbor:"sender_key_id" json:"sender_key_id"`
	CreatedAt      string   `cbor:"created_at" json:"created_at"`
	RecipientHints []string `cbor:"recipient_hints,omitempty" json:"recipient_hints,omitempty"`
}

type Envelope struct {
	Metadata     Metadata `cbor:"metadata" json:"metadata"`
	SignerPublic string   `cbor:"signer_public" json:"signer_public"`
	Signature    string   `cbor:"signature" json:"signature"`
	Ciphertext   string   `cbor:"ciphertext" json:"ciphertext"`
}

type signData struct {
	Metadata     Metadata `cbor:"metadata"`
	SignerPublic string   `cbor:"signer_public"`
	Ciphertext   []byte   `cbor:"ciphertext"`
}

func canonicalEncMode() (cbor.EncMode, error) {
	opts := cbor.CanonicalEncOptions()
	return opts.EncMode()
}

func signPayload(meta Metadata, signerPublic string, ciphertext []byte) ([]byte, error) {
	enc, err := canonicalEncMode()
	if err != nil {
		return nil, fmt.Errorf("canonical cbor mode: %w", err)
	}
	payload, err := enc.Marshal(signData{Metadata: meta, SignerPublic: signerPublic, Ciphertext: ciphertext})
	if err != nil {
		return nil, fmt.Errorf("marshal signature payload: %w", err)
	}
	return payload, nil
}

func Seal(plaintext []byte, recipients []age.Recipient, senderKeyID, signerPublicB64, signerPrivateB64 string, recipientHints []string) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, fmt.Errorf("at least one recipient is required")
	}
	if signerPublicB64 == "" || signerPrivateB64 == "" {
		return nil, fmt.Errorf("signing keys are required")
	}

	var ctBuf bytes.Buffer
	w, err := age.Encrypt(&ctBuf, recipients...)
	if err != nil {
		return nil, fmt.Errorf("create age encrypt writer: %w", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("encrypt payload: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("finalize age encryption: %w", err)
	}
	ciphertext := ctBuf.Bytes()

	meta := Metadata{
		Version:        EnvelopeVersion,
		SenderKeyID:    senderKeyID,
		CreatedAt:      time.Now().UTC().Format(time.RFC3339),
		RecipientHints: recipientHints,
	}
	payload, err := signPayload(meta, signerPublicB64, ciphertext)
	if err != nil {
		return nil, err
	}
	sig, err := sign.Sign(payload, signerPrivateB64)
	if err != nil {
		return nil, fmt.Errorf("sign envelope: %w", err)
	}
	env := Envelope{
		Metadata:     meta,
		SignerPublic: signerPublicB64,
		Signature:    sig,
		Ciphertext:   base64.StdEncoding.EncodeToString(ciphertext),
	}

	enc, err := canonicalEncMode()
	if err != nil {
		return nil, fmt.Errorf("canonical cbor mode: %w", err)
	}
	out, err := enc.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("marshal envelope: %w", err)
	}
	return out, nil
}

func DecodeEnvelope(envelopeBytes []byte) (*Envelope, []byte, error) {
	var env Envelope
	if err := cbor.Unmarshal(envelopeBytes, &env); err != nil {
		return nil, nil, fmt.Errorf("decode envelope: %w", err)
	}
	if env.Metadata.Version != EnvelopeVersion {
		return nil, nil, fmt.Errorf("unsupported envelope version: %s", env.Metadata.Version)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	return &env, ciphertext, nil
}

func VerifyEnvelope(envelopeBytes []byte) (*Envelope, []byte, error) {
	env, ciphertext, err := DecodeEnvelope(envelopeBytes)
	if err != nil {
		return nil, nil, err
	}
	payload, err := signPayload(env.Metadata, env.SignerPublic, ciphertext)
	if err != nil {
		return nil, nil, err
	}
	if err := sign.Verify(payload, env.SignerPublic, env.Signature); err != nil {
		return nil, nil, fmt.Errorf("verify envelope signature: %w", err)
	}
	return env, ciphertext, nil
}

func Open(envelopeBytes []byte, identities []age.Identity, verifyRequired bool) (*Envelope, []byte, error) {
	var env *Envelope
	var ciphertext []byte
	var err error
	if verifyRequired {
		env, ciphertext, err = VerifyEnvelope(envelopeBytes)
		if err != nil {
			return nil, nil, err
		}
	} else {
		env, ciphertext, err = DecodeEnvelope(envelopeBytes)
		if err != nil {
			return nil, nil, err
		}
	}

	r, err := age.Decrypt(bytes.NewReader(ciphertext), identities...)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt payload: %w", err)
	}
	pt := new(bytes.Buffer)
	if _, err := pt.ReadFrom(r); err != nil {
		return nil, nil, fmt.Errorf("read decrypted payload: %w", err)
	}
	return env, pt.Bytes(), nil
}
