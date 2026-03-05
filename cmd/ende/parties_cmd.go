package main

import (
	"fmt"
	"strings"

	"filippo.io/age"
	"github.com/kuma/ende/internal/keyring"
	ghresolver "github.com/kuma/ende/internal/resolver/github"
	"github.com/kuma/ende/internal/sign"
	"github.com/spf13/cobra"
)

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

func newUnregisterCommand() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:     "unregister <alias>",
		Short:   "Remove recipient and trusted sender registration for an alias",
		Aliases: []string{"unreg"},
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			alias := strings.TrimSpace(args[0])
			if alias == "" {
				return fmt.Errorf("alias is required")
			}
			store, err := keyring.Load()
			if err != nil {
				return err
			}
			removedRecipient := store.RemoveRecipient(alias)
			removedSender := store.RemoveSender(alias)
			if !removedRecipient && !removedSender && !force {
				return fmt.Errorf("alias %s is not registered (use --force to ignore)", alias)
			}
			if err := store.Save(); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "unregistered alias %s (recipient_removed=%t sender_removed=%t)\n", alias, removedRecipient, removedSender)
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "ignore if alias is not registered")
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
