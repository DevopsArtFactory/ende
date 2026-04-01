package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"filippo.io/age"
	"github.com/kuma/ende/internal/crypto"
	endeio "github.com/kuma/ende/internal/io"
	"github.com/kuma/ende/internal/keyring"
	"github.com/kuma/ende/internal/policy"
	"github.com/spf13/cobra"
)

func newEncryptCommand() *cobra.Command {
	var tos []string
	var signAs, in, out, fileInput string
	var textOut bool
	var binaryOut bool
	var prompt bool
	cmd := &cobra.Command{
		Use:   "encrypt",
		Short: "Encrypt and sign secret payload",
		Aliases: []string{
			"enc",
		},
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if textOut && binaryOut {
				return fmt.Errorf("--text and --binary cannot be used together")
			}
			if binaryOut {
				textOut = false
			}
			if fileInput != "" {
				if in != "-" {
					return fmt.Errorf("--file and --in cannot be used together")
				}
				in = fileInput
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(tos) == 0 {
				return fmt.Errorf("at least one --to is required")
			}
			store, err := keyring.Load()
			if err != nil {
				return err
			}
			if signAs == "" {
				signAs = store.DefaultSigner()
			}
			if signAs == "" {
				return fmt.Errorf("--sign-as is required (or set default via `ende key use --name <id>`)")
			}
			keyEntry, ok := store.Key(signAs)
			if !ok {
				return fmt.Errorf("unknown signer key id: %s", signAs)
			}
			if err := policy.EnsurePrivateFile(keyEntry.SignPrivate); err != nil {
				return err
			}
			signPrivBytes, err := os.ReadFile(keyEntry.SignPrivate)
			if err != nil {
				return err
			}
			signPriv := strings.TrimSpace(string(signPrivBytes))

			recipients := make([]age.Recipient, 0, len(tos))
			hints := make([]string, 0, len(tos))
			for _, to := range tos {
				r, hint, err := resolveRecipient(store, to)
				if err != nil {
					return err
				}
				recipients = append(recipients, r)
				hints = append(hints, hint)
			}
			var plaintext []byte
			if prompt {
				if in != "-" {
					return fmt.Errorf("--prompt cannot be used with --in")
				}
				p, err := readPromptSecret(cmd.InOrStdin(), cmd.ErrOrStderr())
				if err != nil {
					return err
				}
				plaintext = p
			} else {
				plaintext, err = endeio.ReadInput(in)
				if err != nil {
					return err
				}
			}
			envelope, err := crypto.Seal(plaintext, recipients, signAs, keyEntry.SignPublic, signPriv, hints)
			if err != nil {
				return err
			}
			if textOut {
				envelope = crypto.EncodeTextEnvelope(envelope)
			}
			if err := endeio.WriteOutput(out, envelope); err != nil {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringSliceVarP(&tos, "to", "t", nil, "recipient alias, github:user, or age1... public key")
	cmd.Flags().StringVarP(&signAs, "sign-as", "s", "", "local signing key id (optional if default signer is set)")
	cmd.Flags().StringVarP(&in, "in", "i", "-", "input path or -")
	cmd.Flags().StringVarP(&fileInput, "file", "f", "", "input file path (alias of --in)")
	cmd.Flags().StringVarP(&out, "out", "o", "-", "output path or -")
	cmd.Flags().BoolVar(&textOut, "text", true, "output ASCII-armored envelope for copy/paste transport (default true)")
	cmd.Flags().BoolVar(&binaryOut, "binary", false, "output raw binary envelope")
	cmd.Flags().BoolVar(&prompt, "prompt", false, "prompt for secret value interactively")
	return cmd
}

func newDecryptCommand() *cobra.Command {
	var in, out string
	var verifyRequired bool
	var textOut bool
	cmd := &cobra.Command{
		Use:   "decrypt",
		Short: "Verify and decrypt envelope",
		Aliases: []string{
			"dec",
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := policy.EnsurePlaintextOutputAllowed(out); err != nil {
				return err
			}
			store, err := keyring.Load()
			if err != nil {
				return err
			}
			identities, err := loadIdentities(store)
			if err != nil {
				return err
			}
			var envelopeBytes []byte
			if in == "-" {
				if stat, _ := os.Stdin.Stat(); stat.Mode()&os.ModeCharDevice != 0 {
					envelopeBytes, err = readEnvelopeInteractive(cmd.InOrStdin(), cmd.ErrOrStderr())
				} else {
					envelopeBytes, err = endeio.ReadInput(in)
				}
			} else {
				envelopeBytes, err = endeio.ReadInput(in)
			}
			if err != nil {
				return err
			}
			env, plaintext, err := crypto.Open(envelopeBytes, identities, verifyRequired)
			if err != nil {
				return err
			}
			if verifyRequired {
				trusted, ok := store.Sender(env.Metadata.SenderKeyID)
				if !ok {
					return fmt.Errorf("untrusted sender id %s: register with `ende sender add`", env.Metadata.SenderKeyID)
				}
				if trusted.SignPublic != env.SignerPublic {
					return fmt.Errorf("trusted sender mismatch for %s", env.Metadata.SenderKeyID)
				}
			}
			if err := endeio.WriteOutput(out, plaintext); err != nil {
				return err
			}
			return nil
		},
	}
	cmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		if textOut {
			if out != "" && out != "-" {
				return fmt.Errorf("--text-out cannot be used with file output")
			}
			out = "-"
		}
		return nil
	}
	cmd.Flags().StringVarP(&in, "in", "i", "-", "input path or -")
	cmd.Flags().StringVarP(&out, "out", "o", "", "output plaintext path or - (explicit)")
	cmd.Flags().BoolVar(&verifyRequired, "verify-required", true, "require signature verification")
	cmd.Flags().BoolVar(&textOut, "text-out", false, "print decrypted plaintext to stdout")
	return cmd
}

func newVerifyCommand() *cobra.Command {
	var in string
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify signature without decrypting",
		Aliases: []string{
			"v",
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			b, err := endeio.ReadInput(in)
			if err != nil {
				return err
			}
			env, _, err := crypto.VerifyEnvelope(b)
			if err != nil {
				return err
			}
			store, err := keyring.Load()
			if err != nil {
				return err
			}
			trustedState := "untrusted"
			if sender, ok := store.Sender(env.Metadata.SenderKeyID); ok && sender.SignPublic == env.SignerPublic {
				trustedState = "trusted"
			}
			fmt.Fprintf(cmd.OutOrStdout(), "verified\ntrust: %s\nversion: %s\nsender_key_id: %s\ncreated_at: %s\nsigner_fingerprint: %s\n", trustedState, env.Metadata.Version, env.Metadata.SenderKeyID, env.Metadata.CreatedAt, short(sha256Hex(env.SignerPublic)))
			return nil
		},
	}
	cmd.Flags().StringVarP(&in, "in", "i", "-", "input path or -")
	return cmd
}

func resolveRecipient(store *keyring.Store, target string) (age.Recipient, string, error) {
	if strings.HasPrefix(target, "age1") {
		r, err := age.ParseX25519Recipient(target)
		if err != nil {
			return nil, "", err
		}
		return r, "direct:" + target, nil
	}
	if strings.HasPrefix(target, "github:") {
		if r, ok := store.Recipient(target); ok {
			rec, err := age.ParseX25519Recipient(r.AgePublic)
			if err != nil {
				return nil, "", err
			}
			return rec, target, nil
		}
		return nil, "", fmt.Errorf("github recipient %s not pinned in local keyring; run recipient add --github first", target)
	}
	r, ok := store.Recipient(target)
	if !ok {
		return nil, "", fmt.Errorf("recipient alias not found: %s", target)
	}
	rec, err := age.ParseX25519Recipient(r.AgePublic)
	if err != nil {
		return nil, "", fmt.Errorf("invalid recipient key for alias %s: %w", target, err)
	}
	return rec, target, nil
}

func loadIdentities(store *keyring.Store) ([]age.Identity, error) {
	ids := make([]age.Identity, 0, len(store.Data.Keys))
	for _, id := range store.AllKeyIDs() {
		k, _ := store.Key(id)
		if err := policy.EnsurePrivateFile(k.AgeIdentity); err != nil {
			return nil, err
		}
		b, err := os.ReadFile(k.AgeIdentity)
		if err != nil {
			return nil, err
		}
		i, err := age.ParseX25519Identity(strings.TrimSpace(string(b)))
		if err != nil {
			return nil, fmt.Errorf("parse age identity for %s: %w", id, err)
		}
		ids = append(ids, i)
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("no local identities found")
	}
	return ids, nil
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func short(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12]
}
