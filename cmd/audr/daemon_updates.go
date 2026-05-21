package main

import (
	"fmt"

	"github.com/harshmaur/audr/internal/daemon"
	"github.com/harshmaur/audr/internal/selfupdate"
	"github.com/spf13/cobra"
)

func newDaemonUpdatesCmd() *cobra.Command {
	var on, off, status bool
	cmd := &cobra.Command{
		Use:   "updates",
		Short: "Configure automatic AUDR binary updates",
		Long: `Configure whether the AUDR daemon automatically installs verified AUDR
binary updates from stable GitHub Releases. Auto-update is off by default; when
enabled, release artifacts must pass the same SHA256SUMS/cosign verification as
manual installs before the daemon replaces the binary.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			actions := 0
			for _, b := range []bool{on, off, status} {
				if b {
					actions++
				}
			}
			if actions == 0 {
				status = true
				actions = 1
			}
			if actions > 1 {
				return fmt.Errorf("choose only one of --on, --off, or --status")
			}
			paths, err := daemon.Resolve()
			if err != nil {
				return fmt.Errorf("resolve daemon paths: %w", err)
			}
			if err := paths.Ensure(); err != nil {
				return fmt.Errorf("ensure daemon paths: %w", err)
			}
			cfg, err := selfupdate.LoadConfig(paths.State)
			if err != nil {
				return fmt.Errorf("read update config: %w", err)
			}
			if on {
				cfg.AutoUpdate = true
			}
			if off {
				cfg.AutoUpdate = false
			}
			if on || off {
				if err := selfupdate.SaveConfig(paths.State, cfg); err != nil {
					return fmt.Errorf("save update config: %w", err)
				}
			}
			state := "off"
			if cfg.AutoUpdate {
				state = "on"
			}
			fmt.Fprintf(cmd.OutOrStdout(), "audr daemon auto-update: %s\n", state)
			fmt.Fprintf(cmd.OutOrStdout(), "config: %s\n", selfupdate.ConfigPath(paths.State))
			if !cfg.AutoUpdate {
				fmt.Fprintln(cmd.OutOrStdout(), "tip: enable with `audr daemon updates --on` to receive verified daily binary releases automatically")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&on, "on", false, "enable automatic verified binary updates")
	cmd.Flags().BoolVar(&off, "off", false, "disable automatic binary updates")
	cmd.Flags().BoolVar(&status, "status", false, "print current automatic update setting")
	return cmd
}
