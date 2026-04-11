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

	HashCheck   HashCheckConfig   `mapstructure:"hash_check"`
	Features    FeaturesConfig    `mapstructure:"features"`
	BlockPolicy BlockPolicyConfig `mapstructure:"block_policy"`

	ClaudeModel        string `mapstructure:"claude_model"`
	ClaudeMaxFileBytes int    `mapstructure:"claude_max_file_bytes"`

	VTRateLimitPerMinute int `mapstructure:"vt_rate_limit_per_minute"`
	VTDailyLimit         int `mapstructure:"vt_daily_limit"`

	// Runtime overrides (set via CLI flags)
	NoClaude bool `mapstructure:"-"`
	NoVT     bool `mapstructure:"-"`
	DryRun   bool `mapstructure:"-"`
	Verbose  bool `mapstructure:"-"`
}

type HashCheckConfig struct {
	CIRCLURL string `mapstructure:"circl_url"`
}

type FeaturesConfig struct {
	ClaudeScan bool `mapstructure:"claude_scan"`
	VTFallback bool `mapstructure:"vt_fallback"`
}

type BlockPolicyConfig struct {
	ClaudeFormulaHold bool `mapstructure:"claude_formula_hold"`
	VTConfirmed       bool `mapstructure:"vt_confirmed"`
	ClaudeCodeHold    bool `mapstructure:"claude_code_hold"`
	RequireBoth       bool `mapstructure:"require_both"`
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
	v.SetDefault("hash_check.circl_url", "https://hashlookup.circl.lu")
	v.SetDefault("features.claude_scan", false)
	v.SetDefault("features.vt_fallback", false)
	v.SetDefault("block_policy.claude_formula_hold", true)
	v.SetDefault("block_policy.vt_confirmed", true)
	v.SetDefault("block_policy.claude_code_hold", true)
	v.SetDefault("block_policy.require_both", false)
	v.SetDefault("claude_model", "claude-sonnet-4-6")
	v.SetDefault("claude_max_file_bytes", 12000)
	v.SetDefault("vt_rate_limit_per_minute", 4)
	v.SetDefault("vt_daily_limit", 500)

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

// Validate checks that required environment variables are set for enabled features
func (c *Config) Validate() error {
	if c.Features.ClaudeScan && !c.NoClaude {
		if os.Getenv("ANTHROPIC_API_KEY") == "" {
			return fmt.Errorf("features.claude_scan is enabled in settings.yaml but ANTHROPIC_API_KEY is not set.\n" +
				"Either export ANTHROPIC_API_KEY or set `claude_scan: false` in settings.yaml")
		}
	}

	if c.Features.VTFallback && !c.NoVT {
		if os.Getenv("VIRUSTOTAL_API_KEY") == "" {
			return fmt.Errorf("features.vt_fallback is enabled in settings.yaml but VIRUSTOTAL_API_KEY is not set.\n" +
				"Either export VIRUSTOTAL_API_KEY or set `vt_fallback: false` in settings.yaml")
		}
	}

	return nil
}

// IsClaudeEnabled returns true if Claude scanning is enabled and not overridden
func (c *Config) IsClaudeEnabled() bool {
	return c.Features.ClaudeScan && !c.NoClaude
}

// IsVTEnabled returns true if VirusTotal fallback is enabled and not overridden
func (c *Config) IsVTEnabled() bool {
	return c.Features.VTFallback && !c.NoVT
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
  # Enable Claude formula analysis (requires ANTHROPIC_API_KEY env var)
  claude_scan: false
  # Enable VirusTotal fallback for --circl-full (requires VIRUSTOTAL_API_KEY env var)
  vt_fallback: false

# Claude model to use for analysis
claude_model: claude-sonnet-4-6

# Maximum formula file size in bytes sent to Claude
claude_max_file_bytes: 12000

# Blocking policy - which signals block an upgrade
block_policy:
  claude_formula_hold: true   # Block if Claude formula analysis returns HOLD
  vt_confirmed: true          # Block if CIRCL flags AND VT confirms malicious
  claude_code_hold: true      # Block if Claude code analysis returns HOLD
  require_both: false         # If true, BOTH pre and post signals must fire to block

# Hash verification settings (used with --circl-full flag)
hash_check:
  circl_url: https://hashlookup.circl.lu

# VirusTotal rate limiting (free tier: 4/min, 500/day)
vt_rate_limit_per_minute: 4
vt_daily_limit: 500
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
