package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/harshmaur/audr/internal/selfupdate"
	"github.com/spf13/cobra"
)

func newUpdateCmd() *cobra.Command {
	var (
		flagCheck       bool
		flagYes         bool
		flagVersion     string
		flagInstallPath string
	)
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update the AUDR binary from signed GitHub Releases",
		Long: `Update the AUDR binary in place.

The updater downloads the platform release artifact, verifies it against
SHA256SUMS, verifies the cosign signature when cosign is available, extracts
the new audr binary, and atomically replaces the installed binary. Use
--check to only report whether an update is available.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), 2*time.Minute)
			defer cancel()
			installPath := flagInstallPath
			if installPath == "" {
				p, err := os.Executable()
				if err != nil {
					return fmt.Errorf("resolve current executable: %w", err)
				}
				installPath = p
			}
			opts := selfupdate.Options{
				CurrentVersion: Version,
				Version:        flagVersion,
				InstallPath:    installPath,
			}
			latest, newer, err := selfupdate.Check(ctx, opts)
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "audr update: current=%s latest=%s\n", Version, latest.Version)
			if latest.URL != "" {
				fmt.Fprintf(w, "release: %s\n", latest.URL)
			}
			if flagCheck {
				if newer {
					fmt.Fprintln(w, "status: update available")
				} else {
					fmt.Fprintln(w, "status: already current")
				}
				return nil
			}
			if !newer && (flagVersion == "" || flagVersion == "latest") {
				fmt.Fprintln(w, "audr update: already current")
				return nil
			}
			if !flagYes {
				ok, err := confirmUpdate(cmd.InOrStdin(), cmd.ErrOrStderr(), latest.Version, installPath)
				if err != nil {
					return err
				}
				if !ok {
					fmt.Fprintln(w, "audr update: cancelled")
					return nil
				}
			}
			res, err := selfupdate.Apply(ctx, opts)
			if err != nil {
				return err
			}
			if res.AlreadyCurrent {
				fmt.Fprintln(w, "audr update: already current")
				return nil
			}
			printVerifyResult(w, res.Verify)
			fmt.Fprintf(w, "\naudr update: installed %s -> %s\n", res.TargetVersion, res.InstallPath)
			if res.BackupPath != "" {
				fmt.Fprintf(w, "backup: %s\n", res.BackupPath)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&flagCheck, "check", false, "check for a newer release without installing")
	cmd.Flags().BoolVar(&flagYes, "yes", false, "install without prompting")
	cmd.Flags().StringVar(&flagVersion, "version", "latest", "release tag to install (default: latest)")
	cmd.Flags().StringVar(&flagInstallPath, "install-path", "", "path to replace (default: current executable)")
	return cmd
}

func confirmUpdate(in io.Reader, errW io.Writer, version, path string) (bool, error) {
	fmt.Fprintf(errW, "Install AUDR %s to %s? [y/N] ", version, path)
	r := bufio.NewReader(in)
	line, err := r.ReadString('\n')
	if err != nil && len(line) == 0 {
		return false, err
	}
	ans := strings.ToLower(strings.TrimSpace(line))
	return ans == "y" || ans == "yes", nil
}
