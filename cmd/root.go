package cmd

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
	"github.com/sud0x0/bsau/internal/config"
	"github.com/sud0x0/bsau/internal/ui"
)

var (
	cfgFile string
	verbose bool
	cfg     *config.Config
	logger  *slog.Logger
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:               "bsau",
	Short:             "Brew Scan and Update - Security-focused Homebrew package manager",
	CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
	Long: `bsau is a security-focused Homebrew package manager wrapper.

It scans, audits, and safely updates Homebrew packages on macOS by combining:
  - Vulnerability lookup via OSV.dev and NIST NVD
  - Static analysis via Semgrep
  - LLM-based code analysis via Ollama (local)

All scanning is read-only. No packages are modified without explicit user approval.

Commands:
  bsau run         Full scan and update workflow
  bsau inspect     Scan current installation without upgrading
  bsau init        Generate default config file
  bsau version     Print version information`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Skip config loading for version, help, and init commands
		if cmd.Name() == "version" || cmd.Name() == "help" || cmd.Name() == "init" {
			return nil
		}

		// Auto-generate config on first run if it doesn't exist
		if !config.ConfigExists() {
			configPath, err := config.GenerateConfigFile()
			if err != nil {
				return fmt.Errorf("generating config: %w", err)
			}
			ui.PrintInfo(fmt.Sprintf("Generated default config: %s", configPath))
			ui.PrintInfo("Edit this file to customize settings (e.g., enable Ollama)")
		}

		// Load configuration
		var err error
		cfg, err = config.Load()
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		// Apply CLI flag overrides
		cfg.Verbose = verbose

		// Setup logger
		logLevel := slog.LevelInfo
		if verbose {
			logLevel = slog.LevelDebug
		}
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: logLevel,
		}))

		// Validate configuration
		if err := cfg.Validate(); err != nil {
			return err
		}

		return nil
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ./settings.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose output")

	// Add subcommands
	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(inspectCmd)
	rootCmd.AddCommand(versionCmd)
}

// GetConfig returns the loaded configuration
func GetConfig() *config.Config {
	return cfg
}

// GetLogger returns the configured logger
func GetLogger() *slog.Logger {
	return logger
}
