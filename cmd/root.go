// Package cmd implements the CLI interface for netwatch.
package cmd

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	// Version is set at build time.
	Version = "dev"

	// Global flags
	verbose bool
	workers int
	timeout int
)

// Banner prints the netwatch ASCII art banner.
func Banner() string {
	return color.CyanString(`
  _   _      _               _       _
 | \ | | ___| |___      ____| |_ ___| |__
 |  \| |/ _ \ __\ \ /\ / / _` + "`" + ` |/ __| '_ \
 | |\  |  __/ |_ \ V  V / (_| | (__| | | |
 |_| \_|\___|\__| \_/\_/ \__,_|\___|_| |_|
`) + color.HiBlackString("  Network Security Monitor & Vulnerability Scanner\n")
}

var rootCmd = &cobra.Command{
	Use:   "netwatch",
	Short: "Network security monitor and vulnerability scanner",
	Long: Banner() + `
Netwatch is a network security monitoring and vulnerability scanning tool
designed for authorized penetration testing and security audits.

IMPORTANT: Only use this tool on systems you own or have explicit written
permission to test. Unauthorized scanning is illegal.`,
	SilenceUsage: true,
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose output")
	rootCmd.PersistentFlags().IntVarP(&workers, "workers", "w", 100, "number of concurrent workers")
	rootCmd.PersistentFlags().IntVarP(&timeout, "timeout", "t", 3, "connection timeout in seconds")

	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("netwatch %s\n", Version)
	},
}
