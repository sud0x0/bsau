package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/sud0x0/bsau/internal/config"
	"github.com/sud0x0/bsau/internal/ui"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Generate a default configuration file",
	Long: `Generate a default settings.yaml configuration file in the same
directory as the bsau binary.

This command creates a new config file with default settings. You can then
edit it to enable features like Ollama analysis or VirusTotal fallback.

The config file location is determined by where the bsau binary is installed.`,
	RunE: runInit,
}

func init() {
	rootCmd.AddCommand(initCmd)
}

func runInit(cmd *cobra.Command, args []string) error {
	// Check if config already exists
	if config.ConfigExists() {
		configPath, _ := config.GetConfigPath()
		return fmt.Errorf("config file already exists at %s", configPath)
	}

	// Generate config file
	configPath, err := config.GenerateConfigFile()
	if err != nil {
		return err
	}

	ui.PrintSuccess(fmt.Sprintf("Config file created at: %s", configPath))
	fmt.Println()
	fmt.Println("Edit this file to enable optional features:")
	fmt.Println("  - Set 'features.ollama_scan: true' (requires Ollama running: ollama serve)")

	return nil
}
