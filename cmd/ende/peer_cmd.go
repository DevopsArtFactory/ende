package main

import (
	"fmt"
	"strings"

	"github.com/kuma/ende/internal/keyring"
	"github.com/spf13/cobra"
)

func newPeerCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "peer",
		Short:   "Manage peers",
		Aliases: []string{"p"},
	}
	cmd.AddCommand(newPeerFetchCommand(), newPeerRefreshCommand())
	return cmd
}

func newPeerFetchCommand() *cobra.Command {
	var serverURL string
	var alias string
	var force bool
	var insecureHTTP bool
	cmd := &cobra.Command{
		Use:   "fetch <peer-id>",
		Short: "Fetch and pin a peer from a keyserver",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			baseURL, err := keyserverURL(serverURL, insecureHTTP)
			if err != nil {
				return err
			}
			_, payload, err := fetchKeyserverShare(baseURL, args[0])
			if err != nil {
				return err
			}
			if strings.TrimSpace(alias) == "" {
				alias = payload.ID
			}
			store, err := keyring.Load()
			if err != nil {
				return err
			}
			if err := addPeerFromSharePayload(store, alias, payload, force); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "fetched and pinned peer %s from %s\n", alias, baseURL)
			fmt.Fprintf(cmd.OutOrStdout(), "recipient fingerprint: %s\n", short(keyring.FingerprintAgePublicKey(payload.Recipient)))
			fmt.Fprintf(cmd.OutOrStdout(), "signing fingerprint: %s\n", short(keyring.FingerprintSignPublicKey(payload.SigningPublic)))
			return nil
		},
	}
	cmd.Flags().StringVar(&serverURL, "keyserver", "", "keyserver base URL (or ENDE_KEYSERVER_URL)")
	cmd.Flags().StringVar(&alias, "alias", "", "local peer alias (defaults to fetched peer id)")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing peer alias")
	cmd.Flags().BoolVar(&insecureHTTP, "insecure-http", false, "allow non-local HTTP keyserver URLs for testing")
	return cmd
}

func newPeerRefreshCommand() *cobra.Command {
	var serverURL string
	var remoteID string
	var yes bool
	var insecureHTTP bool
	cmd := &cobra.Command{
		Use:   "refresh <alias>",
		Short: "Compare a pinned peer with the keyserver and update with --yes",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			alias := strings.TrimSpace(args[0])
			baseURL, err := keyserverURL(serverURL, insecureHTTP)
			if err != nil {
				return err
			}
			store, err := keyring.Load()
			if err != nil {
				return err
			}
			currentRecipient, ok := store.Recipient(alias)
			if !ok {
				return fmt.Errorf("peer %s is not pinned locally; use `ende peer fetch %s` first", alias, alias)
			}
			currentSender, ok := store.Sender(alias)
			if !ok {
				return fmt.Errorf("peer %s has no trusted signing key; use `ende peer fetch %s --force` to repair it", alias, alias)
			}
			if strings.TrimSpace(remoteID) == "" {
				remoteID = currentRecipient.Username
			}
			if strings.TrimSpace(remoteID) == "" {
				remoteID = alias
			}
			_, payload, err := fetchKeyserverShare(baseURL, remoteID)
			if err != nil {
				return err
			}
			sameRecipient := strings.TrimSpace(currentRecipient.AgePublic) == strings.TrimSpace(payload.Recipient)
			sameSigning := strings.TrimSpace(currentSender.SignPublic) == strings.TrimSpace(payload.SigningPublic)
			if sameRecipient && sameSigning {
				fmt.Fprintf(cmd.OutOrStdout(), "peer %s is up to date\n", alias)
				return nil
			}

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "peer %s differs from keyserver profile %s\n", alias, payload.ID)
			fmt.Fprintf(out, "recipient: %s -> %s\n", short(currentRecipient.Fingerprint), short(keyring.FingerprintAgePublicKey(payload.Recipient)))
			fmt.Fprintf(out, "signing: %s -> %s\n", short(currentSender.Fingerprint), short(keyring.FingerprintSignPublicKey(payload.SigningPublic)))
			if !yes {
				return fmt.Errorf("refusing to update pinned peer without --yes")
			}
			if err := addPeerFromSharePayload(store, alias, payload, true); err != nil {
				return err
			}
			fmt.Fprintf(out, "refreshed pinned peer %s from %s\n", alias, baseURL)
			return nil
		},
	}
	cmd.Flags().StringVar(&serverURL, "keyserver", "", "keyserver base URL (or ENDE_KEYSERVER_URL)")
	cmd.Flags().StringVar(&remoteID, "id", "", "keyserver peer id (defaults to the pinned source id or alias)")
	cmd.Flags().BoolVar(&yes, "yes", false, "update the local pinned peer when keyserver values differ")
	cmd.Flags().BoolVar(&insecureHTTP, "insecure-http", false, "allow non-local HTTP keyserver URLs for testing")
	return cmd
}
