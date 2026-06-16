package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newKeyserverCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "keyserver",
		Short: "Publish local public keys to an optional keyserver",
	}
	cmd.AddCommand(newKeyserverLoginCommand(), newKeyserverPublishCommand())
	return cmd
}

func newKeyserverPublishCommand() *cobra.Command {
	var name string
	var serverURL string
	var token string
	var insecureHTTP bool
	cmd := &cobra.Command{
		Use:   "publish",
		Short: "Publish your public profile to a keyserver",
		RunE: func(cmd *cobra.Command, args []string) error {
			baseURL, err := keyserverURL(serverURL, insecureHTTP)
			if err != nil {
				return err
			}
			profile, share, err := localKeyserverProfile(name)
			if err != nil {
				return err
			}
			if err := publishKeyserverProfile(baseURL, keyserverToken(baseURL, token), profile); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "published %s to %s\n", profile.ID, baseURL)
			fmt.Fprintf(cmd.OutOrStdout(), "share: %s\n", share)
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "local key id (defaults to the default signer)")
	cmd.Flags().StringVar(&serverURL, "keyserver", "", "keyserver base URL (or ENDE_KEYSERVER_URL)")
	cmd.Flags().StringVar(&token, "token", "", "bearer token for keyserver writes (or ENDE_KEYSERVER_TOKEN)")
	cmd.Flags().BoolVar(&insecureHTTP, "insecure-http", false, "allow non-local HTTP keyserver URLs for testing")
	return cmd
}
