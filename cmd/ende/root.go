package main

import (
	"fmt"
	"os"

	"github.com/kuma/ende/internal/diag"
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
		Use:     "ende",
		Short:   "Ende securely encrypts secrets between developers",
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
	root.AddCommand(newVersionCommand(), newSetupCommand(), newKeyCommand(), newRecipientCommand(), newSenderCommand(), newRegisterCommand(), newUnregisterCommand(), newEncryptCommand(), newDecryptCommand(), newVerifyCommand(), newTutorialCommand(), newDoctorCommand())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
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
