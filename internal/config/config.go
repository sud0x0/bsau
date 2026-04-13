package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

const (
	// ConfigFileName is the config file name
	ConfigFileName = "settings.yaml"
)

// Config holds all configuration for bsau
type Config struct {
	HomebrewPath string `mapstructure:"homebrew_path"`

	Features    FeaturesConfig    `mapstructure:"features"`
	BlockPolicy BlockPolicyConfig `mapstructure:"block_policy"`

	OllamaURL          string `mapstructure:"ollama_url"`
	OllamaModel        string `mapstructure:"ollama_model"`
	OllamaMaxFileBytes int    `mapstructure:"ollama_max_file_bytes"`

	// Runtime overrides (set via CLI flags)
	NoOllama  bool `mapstructure:"-"`
	NoSemgrep bool `mapstructure:"-"`
	DryRun    bool `mapstructure:"-"`
	Verbose   bool `mapstructure:"-"`
}

type FeaturesConfig struct {
	OllamaScan bool `mapstructure:"ollama_scan"`
}

type BlockPolicyConfig struct {
	OllamaFormulaHold bool `mapstructure:"ollama_formula_hold"`
	OllamaCodeHold    bool `mapstructure:"ollama_code_hold"`
}

// GetBinaryDir returns the directory where the bsau binary is located
func GetBinaryDir() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("getting executable path: %w", err)
	}
	// Resolve symlinks to get the real path
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return "", fmt.Errorf("resolving symlinks: %w", err)
	}
	return filepath.Dir(exe), nil
}

// GetConfigPath returns the full path to the config file
func GetConfigPath() (string, error) {
	dir, err := GetBinaryDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, ConfigFileName), nil
}

// Load reads configuration from settings.yaml and environment variables
func Load() (*Config, error) {
	v := viper.New()

	// Set defaults
	v.SetDefault("homebrew_path", "/opt/homebrew")
	v.SetDefault("features.ollama_scan", false)
	v.SetDefault("block_policy.ollama_formula_hold", true)
	v.SetDefault("block_policy.ollama_code_hold", true)
	v.SetDefault("ollama_url", "http://localhost:11434")
	v.SetDefault("ollama_model", "") // Must be set in settings.yaml when ollama_scan is enabled
	v.SetDefault("ollama_max_file_bytes", 12000)

	// Check for config override via env
	configPath := os.Getenv("BSAU_CONFIG")
	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		// Look for settings.yaml in binary directory first, then current directory
		v.SetConfigName("settings")
		v.SetConfigType("yaml")

		// Binary directory takes precedence
		binDir, err := GetBinaryDir()
		if err == nil {
			v.AddConfigPath(binDir)
		}
		v.AddConfigPath(".")
	}

	// Read config file
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("reading config: %w", err)
		}
		// Config file not found is OK, use defaults
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshaling config: %w", err)
	}

	return &cfg, nil
}

// Validate checks configuration validity
func (c *Config) Validate() error {
	// If Ollama is enabled, model must be set
	if c.Features.OllamaScan && c.OllamaModel == "" {
		return fmt.Errorf("ollama_model must be set in settings.yaml when features.ollama_scan is enabled")
	}
	return nil
}

// IsOllamaEnabled returns true if Ollama scanning is enabled and not overridden
func (c *Config) IsOllamaEnabled() bool {
	return c.Features.OllamaScan && !c.NoOllama
}

// CellarPath returns the path to the Homebrew Cellar
func (c *Config) CellarPath() string {
	return filepath.Join(c.HomebrewPath, "Cellar")
}

// DefaultConfigContent returns the default config file content
const DefaultConfigContent = `# bsau configuration file
# Place this file in the same directory as the bsau binary

# Path to Homebrew installation. Defaults to /opt/homebrew (Apple Silicon).
# Override for Intel Macs: /usr/local
homebrew_path: /opt/homebrew

# Feature flags - enable optional scanning features
features:
  # Enable local LLM analysis (requires Ollama running locally)
  # Install: brew install ollama && ollama pull <model>
  ollama_scan: false

# Ollama server URL (default: http://localhost:11434)
ollama_url: http://localhost:11434

# LLM model to use for analysis (required when ollama_scan is enabled)
# Examples: gemma3, llama3, mistral, codellama, etc.
# Run 'ollama list' to see available models
ollama_model: ""

# Maximum formula file size in bytes sent to LLM
ollama_max_file_bytes: 12000

# Blocking policy - which signals block an upgrade
block_policy:
  ollama_formula_hold: true   # Block if LLM formula analysis returns HOLD
  ollama_code_hold: true      # Block if LLM code analysis returns HOLD
`

// GenerateConfigFile creates a default config file in the binary directory
func GenerateConfigFile() (string, error) {
	configPath, err := GetConfigPath()
	if err != nil {
		return "", err
	}

	// Check if file already exists
	if _, err := os.Stat(configPath); err == nil {
		return configPath, fmt.Errorf("config file already exists at %s", configPath)
	}

	// Write default config
	if err := os.WriteFile(configPath, []byte(DefaultConfigContent), 0644); err != nil {
		return "", fmt.Errorf("writing config file: %w", err)
	}

	return configPath, nil
}

// ConfigExists checks if a config file exists in the binary directory
func ConfigExists() bool {
	configPath, err := GetConfigPath()
	if err != nil {
		return false
	}
	_, err = os.Stat(configPath)
	return err == nil
}
