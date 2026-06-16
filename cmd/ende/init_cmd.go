package main

import (
	"fmt"
	"net/url"
	"os/user"
	"regexp"
	"strings"

	"github.com/kuma/ende/internal/keyring"
	"github.com/spf13/cobra"
)

var initNameSanitizer = regexp.MustCompile(`[^A-Za-z0-9._:@-]+`)

func newInitCommand() *cobra.Command {
	var name string
	var keyserverURL string
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Set up Ende for first-time use",
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(name) == "" {
				name = defaultInitName()
			}
			name = sanitizeInitName(name)
			if name == "" {
				return fmt.Errorf("--name is required")
			}
			if strings.TrimSpace(keyserverURL) != "" {
				if _, err := url.ParseRequestURI(keyserverURL); err != nil {
					return fmt.Errorf("invalid --keyserver URL: %w", err)
				}
			}

			share, created, err := ensureInitKey(name)
			if err != nil {
				return err
			}
			if err := ensureDefaultSigner(name); err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if created {
				fmt.Fprintf(out, "created local key %s\n", name)
			} else {
				fmt.Fprintf(out, "using existing local key %s\n", name)
			}
			fmt.Fprintln(out, "")
			fmt.Fprintln(out, "Your share code:")
			fmt.Fprintf(out, "%s\n", share)
			fmt.Fprintln(out, "")
			fmt.Fprintln(out, "Next steps:")
			fmt.Fprintln(out, "1. Send this share code to a peer, or publish the public profile through your team's keyserver.")
			fmt.Fprintln(out, "2. Add a peer with `ende add-peer` when they send you their share code.")
			fmt.Fprintf(out, "3. Send a secret with `ende send -t <peer>`.\n")
			if strings.TrimSpace(keyserverURL) != "" {
				fmt.Fprintln(out, "")
				fmt.Fprintln(out, "Keyserver:")
				fmt.Fprintf(out, "- publish this public profile to %s/v1/peers/%s\n", strings.TrimRight(keyserverURL, "/"), name)
				fmt.Fprintf(out, "- peers can fetch your share code from %s/v1/share/%s\n", strings.TrimRight(keyserverURL, "/"), name)
				fmt.Fprintln(out, "- the keyserver is a public directory; peers should still pin your key in their local keyring.")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "local key id (defaults to the OS username)")
	cmd.Flags().StringVar(&keyserverURL, "keyserver", "", "optional keyserver base URL for onboarding guidance")
	return cmd
}

func ensureInitKey(name string) (share string, created bool, err error) {
	store, err := keyring.Load()
	if err != nil {
		return "", false, err
	}
	if entry, ok := store.Key(name); ok {
		share, err := tutorialShareFromEntry(entry)
		return share, false, err
	}
	share, err = tutorialKeygen(name)
	return share, true, err
}

func ensureDefaultSigner(name string) error {
	store, err := keyring.Load()
	if err != nil {
		return err
	}
	if store.DefaultSigner() == name {
		return nil
	}
	if err := store.SetDefaultSigner(name); err != nil {
		return err
	}
	return store.Save()
}

func defaultInitName() string {
	current, err := user.Current()
	if err == nil {
		if name := sanitizeInitName(current.Username); name != "" {
			return name
		}
	}
	return "me"
}

func sanitizeInitName(name string) string {
	name = strings.TrimSpace(name)
	if i := strings.LastIndexAny(name, `\/`); i >= 0 {
		name = name[i+1:]
	}
	name = initNameSanitizer.ReplaceAllString(name, "-")
	name = strings.Trim(name, "-")
	if len(name) > 128 {
		name = name[:128]
	}
	return name
}
