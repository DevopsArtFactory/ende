package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/kuma/ende/internal/keyring"
	"github.com/spf13/cobra"
)

type doctorStatus string

const (
	doctorStatusOK   doctorStatus = "ok"
	doctorStatusWarn doctorStatus = "warn"
	doctorStatusFail doctorStatus = "fail"
)

type doctorCheck struct {
	Name    string
	Status  doctorStatus
	Message string
}

func newDoctorCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Run local trust and configuration health checks",
		RunE: func(cmd *cobra.Command, args []string) error {
			checks, err := runDoctorChecks()
			if err != nil {
				return err
			}
			printDoctorReport(cmd.OutOrStdout(), checks)

			failures := countDoctorChecks(checks, doctorStatusFail)
			if failures > 0 {
				return fmt.Errorf("doctor found %d failing check(s)", failures)
			}
			return nil
		},
	}
}

func runDoctorChecks() ([]doctorCheck, error) {
	store, err := keyring.Load()
	if err != nil {
		return nil, err
	}
	_, ringPath, _, err := keyring.DefaultPaths()
	if err != nil {
		return nil, err
	}

	checks := []doctorCheck{checkKeyringFile(ringPath), checkDefaultSigner(store)}

	for _, id := range store.AllKeyIDs() {
	for _, id := range store.AllKeyIDs() {
		keyEntry, ok := store.Key(id)
		if !ok {
			checks = append(checks, doctorCheck{
				Name:    fmt.Sprintf("key[%s]", id),
				Status:  doctorStatusFail,
				Message: fmt.Sprintf("key %q is listed but not found in store", id),
			})
			continue
		}
		checks = append(checks,
			checkPrivatePath(fmt.Sprintf("key[%s].age_identity", id), keyEntry.AgeIdentity),
			checkPrivatePath(fmt.Sprintf("key[%s].sign_private", id), keyEntry.SignPrivate),
	for _, id := range store.AllKeyIDs() {
		keyEntry, ok := store.Key(id)
		if !ok {
			checks = append(checks, doctorCheck{
				Name:    fmt.Sprintf("key[%s]", id),
				Status:  doctorStatusFail,
				Message: fmt.Sprintf("key %q is listed but not found in store", id),
			})
			continue
		}
		checks = append(checks,
			checkPrivatePath(fmt.Sprintf("key[%s].age_identity", id), keyEntry.AgeIdentity),
			checkPrivatePath(fmt.Sprintf("key[%s].sign_private", id), keyEntry.SignPrivate),
		)
	}

	checks = append(checks, checkRegisteredAliases(store)...)
	return checks, nil
}

func checkKeyringFile(path string) doctorCheck {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return doctorCheck{
				Name:    "keyring_file",
				Status:  doctorStatusWarn,
				Message: fmt.Sprintf("%s does not exist yet", path),
			}
		}
		return doctorCheck{
			Name:    "keyring_file",
			Status:  doctorStatusFail,
			Message: fmt.Sprintf("stat failed for %s: %v", path, err),
		}
	}
	mode := info.Mode().Perm()
	if mode != 0o600 {
		return doctorCheck{
			Name:    "keyring_file",
			Status:  doctorStatusWarn,
			Message: fmt.Sprintf("%s should have 0600 permissions, got %o", path, mode),
		}
	}
	return doctorCheck{
		Name:    "keyring_file",
		Status:  doctorStatusOK,
		Message: fmt.Sprintf("%s permissions are %o", path, mode),
	}
}

func checkDefaultSigner(store *keyring.Store) doctorCheck {
	defaultSigner := store.DefaultSigner()
	if defaultSigner == "" {
		if len(store.AllKeyIDs()) == 0 {
			return doctorCheck{
				Name:    "default_signer",
				Status:  doctorStatusWarn,
				Message: "no local keys found; generate a key before encrypting",
			}
		}
		return doctorCheck{
			Name:    "default_signer",
			Status:  doctorStatusWarn,
			Message: "no default signer configured; use `ende key use --name <id>` or pass --sign-as",
		}
	}
	if _, ok := store.Key(defaultSigner); !ok {
		return doctorCheck{
			Name:    "default_signer",
			Status:  doctorStatusFail,
			Message: fmt.Sprintf("default signer %q is configured but missing from the local key store", defaultSigner),
		}
	}
	return doctorCheck{
		Name:    "default_signer",
		Status:  doctorStatusOK,
		Message: fmt.Sprintf("default signer is %s", defaultSigner),
	}
}

func checkPrivatePath(name, path string) doctorCheck {
	path = strings.TrimSpace(path)
	if path == "" {
		return doctorCheck{
			Name:    name,
			Status:  doctorStatusFail,
			Message: "path is empty",
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		return doctorCheck{
			Name:    name,
			Status:  doctorStatusFail,
			Message: fmt.Sprintf("stat failed for %s: %v", path, err),
		}
	}
	mode := info.Mode().Perm()
	if mode != 0o600 {
		return doctorCheck{
			Name:    name,
			Status:  doctorStatusFail,
			Message: fmt.Sprintf("%s should have 0600 permissions, got %o", path, mode),
		}
	}
	return doctorCheck{
		Name:    name,
		Status:  doctorStatusOK,
		Message: fmt.Sprintf("%s permissions are %o", path, mode),
	}
}

func checkRegisteredAliases(store *keyring.Store) []doctorCheck {
	var checks []doctorCheck
	for _, alias := range store.AllRecipientAliases() {
		if _, ok := store.Sender(alias); ok {
			checks = append(checks, doctorCheck{
				Name:    fmt.Sprintf("alias[%s]", alias),
				Status:  doctorStatusOK,
				Message: "recipient and trusted sender are both registered",
			})
			continue
		}
		checks = append(checks, doctorCheck{
			Name:    fmt.Sprintf("alias[%s]", alias),
			Status:  doctorStatusWarn,
			Message: "recipient exists without a matching trusted sender entry",
		})
	}
	return checks
}

func printDoctorReport(w io.Writer, checks []doctorCheck) {
	for _, check := range checks {
		fmt.Fprintf(w, "[%s] %s: %s\n", check.Status, check.Name, check.Message)
	}
	fmt.Fprintf(w,
		"summary: ok=%d warn=%d fail=%d\n",
		countDoctorChecks(checks, doctorStatusOK),
		countDoctorChecks(checks, doctorStatusWarn),
		countDoctorChecks(checks, doctorStatusFail),
	)
}

func countDoctorChecks(checks []doctorCheck, status doctorStatus) int {
	count := 0
	for _, check := range checks {
		if check.Status == status {
			count++
		}
	}
	return count
}
