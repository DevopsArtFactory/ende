package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"github.com/kuma/ende/internal/diag"
	"github.com/kuma/ende/internal/keyring"
	"github.com/kuma/ende/internal/policy"
	"github.com/kuma/ende/internal/sign"
	"github.com/spf13/cobra"
)

func newKeyCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "key", Short: "Manage local keys", Aliases: []string{"k"}}
	cmd.AddCommand(newKeygenCommand(), newKeyExportCommand(), newKeyImportCommand(), newKeyListCommand(), newKeyUseCommand(), newKeyShareCommand())
	return cmd
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
			return runKeygen(name, setDefault, exportPublic, exportDir, exportPrefix, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "key id")
	cmd.Flags().BoolVar(&setDefault, "set-default", true, "set generated key as default signer")
	cmd.Flags().BoolVar(&exportPublic, "export-public", false, "export public keys to files")
	cmd.Flags().StringVar(&exportDir, "export-dir", ".", "directory for exported public key files")
	cmd.Flags().StringVar(&exportPrefix, "export-prefix", "", "filename prefix for exported files (defaults to --name)")
	return cmd
}

func runKeygen(name string, setDefault bool, exportPublic bool, exportDir, exportPrefix string, out io.Writer) error {
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
		fmt.Fprintf(out, "exported recipient to %s\nexported signing-public to %s\n", recipientOut, signingOut)
	}

	diag.Debugf("keygen: completed name=%s", name)
	fmt.Fprintf(out, "generated key %s\nrecipient: %s\nsigning-public: %s\nshare: %s\n", name, xid.Recipient().String(), signPub, shareToken)
	return nil
}

func newSetupCommand() *cobra.Command {
	var name string
	var exportPublic bool
	var exportDir string
	var exportPrefix string
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Set up your local key and print a share token for a peer",
		Long:  "Set up your local key with a task-oriented command that creates your default sender key and prints a share token for peer onboarding.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(name) == "" {
				fmt.Fprint(cmd.ErrOrStderr(), "your name / key id: ")
				reader := bufio.NewReader(cmd.InOrStdin())
				line, err := reader.ReadString('\n')
				if err != nil && err != io.EOF {
					return fmt.Errorf("read setup name: %w", err)
				}
				name = strings.TrimSpace(line)
			}
			if err := runKeygen(name, true, exportPublic, exportDir, exportPrefix, cmd.OutOrStdout()); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "")
			fmt.Fprintln(cmd.OutOrStdout(), "Next steps:")
			fmt.Fprintln(cmd.OutOrStdout(), "- Share the `share:` token with your peer.")
			fmt.Fprintln(cmd.OutOrStdout(), "- Ask them to run `ende add-peer` or `ende register` with that token.")
			fmt.Fprintln(cmd.OutOrStdout(), "- Then send a secret with `ende send -t <peer>`.")
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "your local key id")
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

func newKeyShareCommand() *cobra.Command {
	var name string
	cmd := &cobra.Command{
		Use:   "share",
		Short: "Print share token for an existing local key",
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
			entry, ok := store.Key(name)
			if !ok {
				return fmt.Errorf("unknown key id: %s", name)
			}
			if err := policy.EnsurePrivateFile(entry.AgeIdentity); err != nil {
				return err
			}
			b, err := os.ReadFile(entry.AgeIdentity)
			if err != nil {
				return fmt.Errorf("read age identity: %w", err)
			}
			id, err := age.ParseX25519Identity(strings.TrimSpace(string(b)))
			if err != nil {
				return fmt.Errorf("parse age identity: %w", err)
			}
			token, err := encodeShareToken(name, id.Recipient().String(), entry.SignPublic)
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), token)
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "key id")
	return cmd
}
