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

// LLM provider constants
const (
	ProviderOllama    = "ollama"
	ProviderAnthropic = "anthropic"
)

// Config holds all configuration for bsau
type Config struct {
	HomebrewPath string `mapstructure:"homebrew_path"`

	Features    FeaturesConfig    `mapstructure:"features"`
	BlockPolicy BlockPolicyConfig `mapstructure:"block_policy"`

	LLMURL          string `mapstructure:"llm_url"`
	LLMModel        string `mapstructure:"llm_model"`
	LLMMaxFileBytes int    `mapstructure:"llm_max_file_bytes"`

	YaraRulesDir string `mapstructure:"yara_rules_dir"`

	// Runtime overrides (set via CLI flags)
	NoLLM   bool `mapstructure:"-"`
	NoYara  bool `mapstructure:"-"`
	DryRun  bool `mapstructure:"-"`
	Verbose bool `mapstructure:"-"`
}

type FeaturesConfig struct {
	LLMScan     bool   `mapstructure:"llm_scan"`
	LLMProvider string `mapstructure:"llm_provider"`
}

type BlockPolicyConfig struct {
	LLMFormulaHold bool `mapstructure:"llm_formula_hold"`
	LLMCodeHold    bool `mapstructure:"llm_code_hold"`
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
	v.SetDefault("features.llm_scan", false)
	v.SetDefault("features.llm_provider", ProviderOllama)
	v.SetDefault("block_policy.llm_formula_hold", true)
	v.SetDefault("block_policy.llm_code_hold", true)
	v.SetDefault("llm_url", "http://localhost:11434")
	v.SetDefault("llm_model", "") // Must be set in settings.yaml when llm_scan is enabled
	v.SetDefault("llm_max_file_bytes", 12000)
	v.SetDefault("yara_rules_dir", "")

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
	// If LLM is enabled, validate provider-specific requirements
	if c.Features.LLMScan {
		switch c.Features.LLMProvider {
		case ProviderOllama:
			if c.LLMModel == "" {
				return fmt.Errorf("llm_model must be set in settings.yaml when features.llm_scan is enabled with ollama provider")
			}
		case ProviderAnthropic:
			if os.Getenv("ANTHROPIC_API_KEY") == "" {
				return fmt.Errorf("ANTHROPIC_API_KEY environment variable must be set when using anthropic provider")
			}
			// Model is optional for Anthropic (has default)
		default:
			return fmt.Errorf("invalid llm_provider: %s (must be 'ollama' or 'anthropic')", c.Features.LLMProvider)
		}
	}
	return nil
}

// IsLLMEnabled returns true if LLM scanning is enabled and not overridden
func (c *Config) IsLLMEnabled() bool {
	return c.Features.LLMScan && !c.NoLLM
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
  # Enable LLM-based code analysis
  # Requires either Ollama running locally OR ANTHROPIC_API_KEY set
  llm_scan: false

  # LLM provider to use: "ollama" or "anthropic"
  # - ollama: Local LLM via Ollama (free, requires ollama running)
  # - anthropic: Claude API (requires ANTHROPIC_API_KEY env var)
  llm_provider: ollama

# LLM URL (only used for Ollama provider)
llm_url: http://localhost:11434

# LLM model to use for analysis
# For Ollama: required (e.g., gemma3, llama3, mistral)
# For Anthropic: optional (defaults to claude-sonnet-4-6)
llm_model: ""

# Maximum formula file size in bytes sent to LLM
llm_max_file_bytes: 12000

# Blocking policy - which signals block an upgrade
block_policy:
  llm_formula_hold: true   # Block if LLM formula analysis returns HOLD
  llm_code_hold: true      # Block if LLM code analysis returns HOLD
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
