package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"github.com/kuma/ende/internal/crypto"
	"github.com/kuma/ende/internal/diag"
	endeio "github.com/kuma/ende/internal/io"
	"github.com/kuma/ende/internal/keyring"
	"github.com/kuma/ende/internal/policy"
	ghresolver "github.com/kuma/ende/internal/resolver/github"
	"github.com/kuma/ende/internal/sign"
	"github.com/spf13/cobra"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	var debug bool
	root := &cobra.Command{
		Use:   "ende",
		Short: "Ende securely encrypts secrets between developers",
		Version: version,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if debug {
				diag.SetEnabled(true)
			}
		},
	}
	root.SetVersionTemplate("{{.Use}} version {{.Version}}\ncommit: " + commit + "\nbuilt: " + date + "\n")
	root.Flags().BoolP("version", "V", false, "print version information")
	root.PersistentFlags().BoolVar(&debug, "debug", false, "enable diagnostic logs to stderr")
	root.AddCommand(newVersionCommand(), newKeyCommand(), newRecipientCommand(), newSenderCommand(), newRegisterCommand(), newEncryptCommand(), newDecryptCommand(), newVerifyCommand())

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

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintf(cmd.OutOrStdout(), "ende version %s\ncommit: %s\nbuilt: %s\n", version, commit, date)
			return nil
		},
	}
}

func newKeygenCommand() *cobra.Command {
	var name string
	var setDefault bool
	var exportPublic bool
	var exportDir string
	var exportPrefix string
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
			diag.Debugf("keygen: start name=%s set_default=%v export_public=%v export_dir=%s", name, setDefault, exportPublic, exportDir)
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
			if setDefault {
				if err := store.SetDefaultSigner(name); err != nil {
					return err
				}
			}
			if err := store.Save(); err != nil {
				return err
			}

			recipientPub := xid.Recipient().String()
			shareToken, err := encodeShareToken(name, recipientPub, signPub)
			if err != nil {
				return err
			}
			if exportPublic {
				prefix := strings.TrimSpace(exportPrefix)
				if prefix == "" {
					prefix = name
				}
				if err := os.MkdirAll(exportDir, 0o755); err != nil {
					return fmt.Errorf("create export dir: %w", err)
				}
				recipientOut := filepath.Join(exportDir, prefix+".recipient.pub")
				signingOut := filepath.Join(exportDir, prefix+".signing.pub")
				if err := os.WriteFile(recipientOut, []byte(recipientPub+"\n"), 0o644); err != nil {
					return fmt.Errorf("write recipient export: %w", err)
				}
				if err := os.WriteFile(signingOut, []byte(signPub+"\n"), 0o644); err != nil {
					return fmt.Errorf("write signing export: %w", err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "exported recipient to %s\nexported signing-public to %s\n", recipientOut, signingOut)
			}

			diag.Debugf("keygen: completed name=%s", name)
			fmt.Fprintf(cmd.OutOrStdout(), "generated key %s\nrecipient: %s\nsigning-public: %s\nshare: %s\n", name, xid.Recipient().String(), signPub, shareToken)
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "key id")
	cmd.Flags().BoolVar(&setDefault, "set-default", true, "set generated key as default signer")
	cmd.Flags().BoolVar(&exportPublic, "export-public", false, "export public keys to files")
	cmd.Flags().StringVar(&exportDir, "export-dir", ".", "directory for exported public key files")
	cmd.Flags().StringVar(&exportPrefix, "export-prefix", "", "filename prefix for exported files (defaults to --name)")
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

func newRegisterCommand() *cobra.Command {
	var alias, recipientKey, signingPublic, share string
	var force bool
	cmd := &cobra.Command{
		Use:     "register",
		Short:   "Register recipient and trusted sender in one step",
		Aliases: []string{"reg"},
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := keyring.Load()
			if err != nil {
				return err
			}
			if alias == "" && recipientKey == "" && signingPublic == "" && share == "" {
				// Share-first interactive flow: paste token, optional alias override.
				s, a, err := promptShareRegisterInput(cmd.InOrStdin(), cmd.ErrOrStderr())
				if err != nil {
					return err
				}
				share = s
				if alias == "" {
					alias = a
				}
			}
			if share == "" && strings.HasPrefix(strings.TrimSpace(recipientKey), sharePrefix) {
				share = recipientKey
				recipientKey = ""
			}
			if share != "" {
				p, err := decodeShareToken(share)
				if err != nil {
					return err
				}
				if alias == "" {
					alias = p.ID
				}
				if alias == "" {
					return fmt.Errorf("alias is required")
				}
				if _, err := age.ParseX25519Recipient(p.Recipient); err != nil {
					return fmt.Errorf("invalid recipient in share token: %w", err)
				}
				if _, err := sign.ParsePublicKey(p.SigningPublic); err != nil {
					return fmt.Errorf("invalid signing public key in share token: %w", err)
				}
				if err := store.AddRecipient(alias, p.Recipient, "register", p.ID, force); err != nil {
					return err
				}
				if err := store.AddSender(alias, p.SigningPublic, "register", p.ID, force); err != nil {
					return err
				}
				if err := store.Save(); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "registered alias %s (recipient+trusted-sender)\n", alias)
				return nil
			}
			if alias == "" || recipientKey == "" || signingPublic == "" {
				return fmt.Errorf("--alias, --recipient-key, and --signing-public are required (or provide --share / interactive input)")
			}
			if _, err := age.ParseX25519Recipient(recipientKey); err != nil {
				return fmt.Errorf("invalid recipient key: %w", err)
			}
			if _, err := sign.ParsePublicKey(signingPublic); err != nil {
				return fmt.Errorf("invalid signing public key: %w", err)
			}
			if err := store.AddRecipient(alias, recipientKey, "register", "", force); err != nil {
				return err
			}
			if err := store.AddSender(alias, signingPublic, "register", "", force); err != nil {
				return err
			}
			if err := store.Save(); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "registered alias %s (recipient+trusted-sender)\n", alias)
			return nil
		},
	}
	cmd.Flags().StringVar(&alias, "alias", "", "alias to register")
	cmd.Flags().StringVar(&recipientKey, "recipient-key", "", "age recipient public key")
	cmd.Flags().StringVar(&signingPublic, "signing-public", "", "Ed25519 signing public key (base64)")
	cmd.Flags().StringVar(&share, "share", "", "share token from keygen output")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite existing recipient/sender entries")
	return cmd
}

func newRecipientAddCommand() *cobra.Command {
	var alias, key, githubUser, share string
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

			if alias == "" && key == "" && share == "" {
				// Interactive mode for simpler onboarding.
				var err error
				alias, key, err = promptRecipientInput(cmd.InOrStdin(), cmd.ErrOrStderr())
				if err != nil {
					return err
				}
			}

			if share == "" && strings.HasPrefix(strings.TrimSpace(key), sharePrefix) {
				share = key
				key = ""
			}
			if share != "" {
				p, err := decodeShareToken(share)
				if err != nil {
					return err
				}
				if alias == "" {
					alias = p.ID
				}
				if alias == "" {
					return fmt.Errorf("alias is required")
				}
				if _, err := age.ParseX25519Recipient(p.Recipient); err != nil {
					return fmt.Errorf("invalid recipient in share token: %w", err)
				}
				if _, err := sign.ParsePublicKey(p.SigningPublic); err != nil {
					return fmt.Errorf("invalid signing public key in share token: %w", err)
				}
				if err := store.AddRecipient(alias, p.Recipient, "share", p.ID, force); err != nil {
					return err
				}
				if err := store.AddSender(alias, p.SigningPublic, "share", p.ID, force); err != nil {
					return err
				}
				if err := store.Save(); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "added recipient+trusted-sender alias %s via share token\n", alias)
				return nil
			}

			if alias == "" || key == "" {
				return fmt.Errorf("--alias and --key are required (or provide --share / interactive input)")
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
	cmd.Flags().StringVar(&share, "share", "", "share token from keygen output")
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

func promptRecipientInput(in io.Reader, errw io.Writer) (alias string, keyOrShare string, err error) {
	r := bufio.NewReader(in)
	fmt.Fprint(errw, "alias: ")
	alias, err = r.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", "", fmt.Errorf("read alias: %w", err)
	}
	fmt.Fprint(errw, "key/share: ")
	keyOrShare, err = r.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", "", fmt.Errorf("read key/share: %w", err)
	}
	return strings.TrimSpace(alias), strings.TrimSpace(keyOrShare), nil
}

func readPromptSecret(in io.Reader, errw io.Writer) ([]byte, error) {
	r := bufio.NewReader(in)
	fmt.Fprint(errw, "secret> ")
	v, err := r.ReadString('\n')
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("read prompt value: %w", err)
	}
	return []byte(strings.TrimRight(v, "\r\n")), nil
}

func promptRegisterInput(in io.Reader, errw io.Writer) (alias string, recipientOrShare string, signingPublic string, err error) {
	r := bufio.NewReader(in)
	fmt.Fprint(errw, "alias: ")
	alias, err = r.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", "", "", fmt.Errorf("read alias: %w", err)
	}
	fmt.Fprint(errw, "recipient key or share token: ")
	recipientOrShare, err = r.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", "", "", fmt.Errorf("read recipient/share: %w", err)
	}
	trimmed := strings.TrimSpace(recipientOrShare)
	if strings.HasPrefix(trimmed, sharePrefix) {
		return strings.TrimSpace(alias), trimmed, "", nil
	}
	fmt.Fprint(errw, "signing public key: ")
	signingPublic, err = r.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", "", "", fmt.Errorf("read signing public: %w", err)
	}
	return strings.TrimSpace(alias), trimmed, strings.TrimSpace(signingPublic), nil
}

func promptShareRegisterInput(in io.Reader, errw io.Writer) (share string, aliasOverride string, err error) {
	r := bufio.NewReader(in)
	fmt.Fprint(errw, "share token (ENDE-PUB-1:...): ")
	share, err = r.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", "", fmt.Errorf("read share token: %w", err)
	}
	share = strings.TrimSpace(share)
	if share == "" {
		return "", "", fmt.Errorf("share token is required")
	}
	fmt.Fprint(errw, "alias override (optional, Enter to use token id): ")
	aliasOverride, err = r.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", "", fmt.Errorf("read alias override: %w", err)
	}
	return share, strings.TrimSpace(aliasOverride), nil
}
