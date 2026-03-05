package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"github.com/kuma/ende/internal/crypto"
	endeio "github.com/kuma/ende/internal/io"
	"github.com/kuma/ende/internal/keyring"
	"github.com/kuma/ende/internal/policy"
	ghresolver "github.com/kuma/ende/internal/resolver/github"
	"github.com/kuma/ende/internal/sign"
	"github.com/spf13/cobra"
)

func main() {
	root := &cobra.Command{
		Use:   "ende",
		Short: "Ende securely encrypts secrets between developers",
	}
	root.AddCommand(newKeyCommand(), newRecipientCommand(), newSenderCommand(), newEncryptCommand(), newDecryptCommand(), newVerifyCommand())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newKeyCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "key", Short: "Manage local keys", Aliases: []string{"k"}}
	cmd.AddCommand(newKeygenCommand(), newKeyExportCommand(), newKeyImportCommand(), newKeyListCommand(), newKeyUseCommand())
	return cmd
}

func newKeygenCommand() *cobra.Command {
	var name string
	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate X25519 recipient and Ed25519 signing key pair",
		Aliases: []string{
			"kg",
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(name) == "" {
				return fmt.Errorf("--name is required")
			}
			store, err := keyring.Load()
			if err != nil {
				return err
			}
			if _, exists := store.Key(name); exists {
				return fmt.Errorf("key %s already exists", name)
			}
			_, _, keysDir, err := keyring.DefaultPaths()
			if err != nil {
				return err
			}

			xid, err := age.GenerateX25519Identity()
			if err != nil {
				return fmt.Errorf("generate age identity: %w", err)
			}
			signPub, signPriv, err := sign.GenerateKeyPair()
			if err != nil {
				return err
			}

			agePath := filepath.Join(keysDir, name+".agekey")
			signPath := filepath.Join(keysDir, name+".signkey")
			if err := os.WriteFile(agePath, []byte(xid.String()+"\n"), 0o600); err != nil {
				return fmt.Errorf("write age identity: %w", err)
			}
			if err := os.WriteFile(signPath, []byte(signPriv+"\n"), 0o600); err != nil {
				return fmt.Errorf("write signing private key: %w", err)
			}

			store.AddKey(keyring.KeyEntry{
				ID:          name,
				AgeIdentity: agePath,
				SignPrivate: signPath,
				SignPublic:  signPub,
			})
			// Local keys are always trusted senders for self-verification use cases.
			if err := store.AddSender(name, signPub, "local-key", "", true); err != nil {
				return err
			}
			if err := store.Save(); err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "generated key %s\nrecipient: %s\nsigning-public: %s\n", name, xid.Recipient().String(), signPub)
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "key id")
	return cmd
}

func newKeyExportCommand() *cobra.Command {
	var name, typ string
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export public key material",
		RunE: func(cmd *cobra.Command, args []string) error {
			if name == "" || typ == "" {
				return fmt.Errorf("--name and --type are required")
			}
			store, err := keyring.Load()
			if err != nil {
				return err
			}
			entry, ok := store.Key(name)
			if !ok {
				return fmt.Errorf("unknown key id: %s", name)
			}

			switch typ {
			case "recipient":
				if err := policy.EnsurePrivateFile(entry.AgeIdentity); err != nil {
					return err
				}
				b, err := os.ReadFile(entry.AgeIdentity)
				if err != nil {
					return err
				}
				id, err := age.ParseX25519Identity(strings.TrimSpace(string(b)))
				if err != nil {
					return fmt.Errorf("parse age identity: %w", err)
				}
				fmt.Fprintln(cmd.OutOrStdout(), id.Recipient().String())
			case "signing-public":
				fmt.Fprintln(cmd.OutOrStdout(), entry.SignPublic)
			default:
				return fmt.Errorf("unsupported export type: %s", typ)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "key id")
	cmd.Flags().StringVar(&typ, "type", "", "recipient|signing-public")
	return cmd
}

func newKeyImportCommand() *cobra.Command {
	var name, file string
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Import age recipient public key into recipient aliases",
		RunE: func(cmd *cobra.Command, args []string) error {
			if name == "" || file == "" {
				return fmt.Errorf("--name and --file are required")
			}
			b, err := os.ReadFile(file)
			if err != nil {
				return err
			}
			pub := strings.TrimSpace(string(b))
			if _, err := age.ParseX25519Recipient(pub); err != nil {
				return fmt.Errorf("invalid age recipient: %w", err)
			}
			store, err := keyring.Load()
			if err != nil {
				return err
			}
			if err := store.AddRecipient(name, pub, "import", "", false); err != nil {
				return err
			}
			if err := store.Save(); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "imported recipient %s\n", name)
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "recipient alias")
	cmd.Flags().StringVar(&file, "file", "", "file with age recipient")
	return cmd
}

func newSenderCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "sender", Short: "Manage trusted sender signing keys", Aliases: []string{"snd"}}
	cmd.AddCommand(newSenderAddCommand(), newSenderShowCommand(), newSenderRotateCommand(), newSenderListCommand())
	return cmd
}

func newSenderAddCommand() *cobra.Command {
	var id, signingPublic, githubUser string
	var force bool
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add trusted sender signing public key",
		RunE: func(cmd *cobra.Command, args []string) error {
			if id == "" || signingPublic == "" {
				return fmt.Errorf("--id and --signing-public are required")
			}
			if _, err := sign.ParsePublicKey(signingPublic); err != nil {
				return fmt.Errorf("invalid signing public key: %w", err)
			}
			store, err := keyring.Load()
			if err != nil {
				return err
			}
			source := "manual"
			if githubUser != "" {
				source = "github"
			}
			if err := store.AddSender(id, signingPublic, source, githubUser, force); err != nil {
				return err
			}
			if err := store.Save(); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "added trusted sender %s (fp=%s)\n", id, short(keyring.FingerprintSignPublicKey(signingPublic)))
			return nil
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "sender id to trust")
	cmd.Flags().StringVar(&signingPublic, "signing-public", "", "sender Ed25519 public key (base64)")
	cmd.Flags().StringVar(&githubUser, "github", "", "optional github username metadata")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite existing sender entry")
	return cmd
}

func newKeyListCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List local keys and recipients",
		Aliases: []string{
			"ls",
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := keyring.Load()
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "[keys]")
			for _, id := range store.AllKeyIDs() {
				k, _ := store.Key(id)
				fmt.Fprintf(cmd.OutOrStdout(), "- %s (sign=%s)\n", id, short(k.SignPublic))
			}
			if def := store.DefaultSigner(); def != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "default-signer: %s\n", def)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "[recipients]")
			for _, alias := range store.AllRecipientAliases() {
				r, _ := store.Recipient(alias)
				fmt.Fprintf(cmd.OutOrStdout(), "- %s (%s fp=%s)\n", alias, r.Source, short(r.Fingerprint))
			}
			fmt.Fprintln(cmd.OutOrStdout(), "[trusted-senders]")
			for _, id := range store.AllSenderIDs() {
				s, _ := store.Sender(id)
				fmt.Fprintf(cmd.OutOrStdout(), "- %s (%s fp=%s)\n", id, s.Source, short(s.Fingerprint))
			}
			return nil
		},
	}
	return cmd
}

func newKeyUseCommand() *cobra.Command {
	var name string
	cmd := &cobra.Command{
		Use:   "use",
		Short: "Set default signer key ID for encrypt",
		RunE: func(cmd *cobra.Command, args []string) error {
			if name == "" && len(args) == 1 {
				name = args[0]
			}
			if strings.TrimSpace(name) == "" {
				return fmt.Errorf("provide key id via --name or positional arg")
			}
			store, err := keyring.Load()
			if err != nil {
				return err
			}
			if err := store.SetDefaultSigner(name); err != nil {
				return err
			}
			if err := store.Save(); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "default signer set to %s\n", name)
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "key id")
	return cmd
}

func newRecipientCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "recipient", Short: "Manage recipient aliases", Aliases: []string{"rcpt"}}
	cmd.AddCommand(newRecipientAddCommand(), newRecipientShowCommand(), newRecipientRotateCommand())
	return cmd
}

func newRecipientAddCommand() *cobra.Command {
	var alias, key, githubUser string
	var keyIndex int
	var force bool
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add recipient by alias or GitHub username",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := keyring.Load()
			if err != nil {
				return err
			}

			if githubUser != "" {
				if alias == "" {
					alias = "github:" + githubUser
				}
				if key == "" {
					return fmt.Errorf("--key (age recipient) is required for github recipients")
				}
				if _, err := age.ParseX25519Recipient(key); err != nil {
					return fmt.Errorf("invalid age recipient: %w", err)
				}
				sshKeys, err := ghresolver.ResolveSSHKeys(githubUser)
				if err != nil {
					return fmt.Errorf("resolve github user keys: %w", err)
				}
				if keyIndex < 0 || keyIndex >= len(sshKeys) {
					return fmt.Errorf("--key-index out of range; github returned %d keys", len(sshKeys))
				}
				sshPin := sha256Hex(sshKeys[keyIndex])

				if existing, ok := store.Recipient(alias); ok {
					if existing.Source == "github" && existing.GitHubSSHPin != "" && existing.GitHubSSHPin != sshPin {
						return fmt.Errorf("github key pin mismatch for %s: expected %s got %s", githubUser, existing.GitHubSSHPin, sshPin)
					}
				}
				if err := store.AddRecipient(alias, key, "github", githubUser, force); err != nil {
					return err
				}
				r := store.Data.Recipients[alias]
				r.GitHubSSHPin = sshPin
				store.Data.Recipients[alias] = r
				if err := store.Save(); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "added github recipient %s with pin %s\n", alias, short(sshPin))
				return nil
			}

			if alias == "" || key == "" {
				return fmt.Errorf("--alias and --key are required")
			}
			if _, err := age.ParseX25519Recipient(key); err != nil {
				return fmt.Errorf("invalid age recipient: %w", err)
			}
			if err := store.AddRecipient(alias, key, "local", "", force); err != nil {
				return err
			}
			if err := store.Save(); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "added recipient %s\n", alias)
			return nil
		},
	}
	cmd.Flags().StringVar(&alias, "alias", "", "recipient alias")
	cmd.Flags().StringVar(&key, "key", "", "age recipient public key")
	cmd.Flags().StringVar(&githubUser, "github", "", "github username (optional resolver)")
	cmd.Flags().IntVar(&keyIndex, "key-index", 0, "github ssh key index for pinning")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite existing recipient alias")
	return cmd
}

func newSenderListCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List trusted senders",
		Aliases: []string{
			"ls",
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := keyring.Load()
			if err != nil {
				return err
			}
			for _, id := range store.AllSenderIDs() {
				s, _ := store.Sender(id)
				fmt.Fprintf(cmd.OutOrStdout(), "- %s source=%s fp=%s\n", id, s.Source, short(s.Fingerprint))
			}
			return nil
		},
	}
	return cmd
}

func newSenderShowCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show <id>",
		Short: "Show trusted sender details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := keyring.Load()
			if err != nil {
				return err
			}
			s, ok := store.Sender(args[0])
			if !ok {
				return fmt.Errorf("trusted sender not found: %s", args[0])
			}
			fmt.Fprintf(cmd.OutOrStdout(), "id: %s\nsource: %s\nusername: %s\nsign_public: %s\nfingerprint: %s\n", s.ID, s.Source, s.Username, s.SignPublic, s.Fingerprint)
			return nil
		},
	}
	return cmd
}

func newSenderRotateCommand() *cobra.Command {
	var signingPublic string
	cmd := &cobra.Command{
		Use:   "rotate <id>",
		Short: "Rotate trusted sender signing public key",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if signingPublic == "" {
				return fmt.Errorf("--signing-public is required")
			}
			if _, err := sign.ParsePublicKey(signingPublic); err != nil {
				return fmt.Errorf("invalid signing public key: %w", err)
			}
			store, err := keyring.Load()
			if err != nil {
				return err
			}
			prev, ok := store.Sender(args[0])
			if !ok {
				return fmt.Errorf("trusted sender not found: %s", args[0])
			}
			if err := store.AddSender(args[0], signingPublic, prev.Source, prev.Username, true); err != nil {
				return err
			}
			if err := store.Save(); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "rotated trusted sender %s (fp=%s)\n", args[0], short(keyring.FingerprintSignPublicKey(signingPublic)))
			return nil
		},
	}
	cmd.Flags().StringVar(&signingPublic, "signing-public", "", "new sender Ed25519 public key (base64)")
	return cmd
}

func newRecipientShowCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show <alias>",
		Short: "Show recipient details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := keyring.Load()
			if err != nil {
				return err
			}
			r, ok := store.Recipient(args[0])
			if !ok {
				return fmt.Errorf("recipient alias not found: %s", args[0])
			}
			fmt.Fprintf(cmd.OutOrStdout(), "alias: %s\nsource: %s\nusername: %s\nage_public: %s\nfingerprint: %s\ngithub_ssh_pin: %s\n", r.Alias, r.Source, r.Username, r.AgePublic, r.Fingerprint, r.GitHubSSHPin)
			return nil
		},
	}
	return cmd
}

func newRecipientRotateCommand() *cobra.Command {
	var key string
	cmd := &cobra.Command{
		Use:   "rotate <alias>",
		Short: "Rotate recipient public key",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if key == "" {
				return fmt.Errorf("--key is required")
			}
			if _, err := age.ParseX25519Recipient(key); err != nil {
				return fmt.Errorf("invalid age recipient: %w", err)
			}
			store, err := keyring.Load()
			if err != nil {
				return err
			}
			r, ok := store.Recipient(args[0])
			if !ok {
				return fmt.Errorf("recipient alias not found: %s", args[0])
			}
			r.AgePublic = key
			r.Fingerprint = keyring.FingerprintAgePublicKey(key)
			store.Data.Recipients[args[0]] = r
			if err := store.Save(); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "rotated recipient %s\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&key, "key", "", "new age recipient public key")
	return cmd
}

func newEncryptCommand() *cobra.Command {
	var tos []string
	var signAs, in, out string
	var textOut bool
	cmd := &cobra.Command{
		Use:   "encrypt",
		Short: "Encrypt and sign secret payload",
		Aliases: []string{
			"enc",
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
			plaintext, err := endeio.ReadInput(in)
			if err != nil {
				return err
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
	cmd.Flags().StringVarP(&out, "out", "o", "-", "output path or -")
	cmd.Flags().BoolVar(&textOut, "text", false, "output ASCII-armored envelope for copy/paste transport")
	return cmd
}

func newDecryptCommand() *cobra.Command {
	var in, out string
	var verifyRequired bool
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
			envelopeBytes, err := endeio.ReadInput(in)
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
	cmd.Flags().StringVarP(&in, "in", "i", "-", "input path or -")
	cmd.Flags().StringVarP(&out, "out", "o", "", "output plaintext path or - (explicit)")
	cmd.Flags().BoolVar(&verifyRequired, "verify-required", true, "require signature verification")
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
