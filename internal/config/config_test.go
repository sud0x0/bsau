package config

import (
	"os"
	"testing"
)

func TestConfig_IsClaudeEnabled(t *testing.T) {
	tests := []struct {
		name       string
		claudeScan bool
		noClaude   bool
		expected   bool
	}{
		{"enabled and not overridden", true, false, true},
		{"enabled but overridden", true, true, false},
		{"disabled", false, false, false},
		{"disabled and overridden", false, true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Features: FeaturesConfig{ClaudeScan: tt.claudeScan},
				NoClaude: tt.noClaude,
			}
			if got := cfg.IsClaudeEnabled(); got != tt.expected {
				t.Errorf("IsClaudeEnabled() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

func TestConfig_IsVTEnabled(t *testing.T) {
	tests := []struct {
		name       string
		vtFallback bool
		noVT       bool
		expected   bool
	}{
		{"enabled and not overridden", true, false, true},
		{"enabled but overridden", true, true, false},
		{"disabled", false, false, false},
		{"disabled and overridden", false, true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Features: FeaturesConfig{VTFallback: tt.vtFallback},
				NoVT:     tt.noVT,
			}
			if got := cfg.IsVTEnabled(); got != tt.expected {
				t.Errorf("IsVTEnabled() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

func TestConfig_CellarPath(t *testing.T) {
	cfg := &Config{HomebrewPath: "/opt/homebrew"}
	expected := "/opt/homebrew/Cellar"
	if got := cfg.CellarPath(); got != expected {
		t.Errorf("CellarPath() = %v, expected %v", got, expected)
	}
}

func TestConfig_Validate_ClaudeEnabled(t *testing.T) {
	// Save and restore env
	origKey := os.Getenv("ANTHROPIC_API_KEY")
	defer func() { _ = os.Setenv("ANTHROPIC_API_KEY", origKey) }()

	cfg := &Config{
		Features: FeaturesConfig{ClaudeScan: true},
	}

	// Without API key
	_ = os.Unsetenv("ANTHROPIC_API_KEY")
	if err := cfg.Validate(); err == nil {
		t.Error("expected error when ANTHROPIC_API_KEY is not set")
	}

	// With API key
	_ = os.Setenv("ANTHROPIC_API_KEY", "test-key")
	if err := cfg.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestConfig_Validate_VTEnabled(t *testing.T) {
	// Save and restore env
	origKey := os.Getenv("VIRUSTOTAL_API_KEY")
	defer func() { _ = os.Setenv("VIRUSTOTAL_API_KEY", origKey) }()

	cfg := &Config{
		Features: FeaturesConfig{VTFallback: true},
	}

	// Without API key
	_ = os.Unsetenv("VIRUSTOTAL_API_KEY")
	if err := cfg.Validate(); err == nil {
		t.Error("expected error when VIRUSTOTAL_API_KEY is not set")
	}

	// With API key
	_ = os.Setenv("VIRUSTOTAL_API_KEY", "test-key")
	if err := cfg.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestConfig_Validate_Overridden(t *testing.T) {
	cfg := &Config{
		Features: FeaturesConfig{
			ClaudeScan: true,
			VTFallback: true,
		},
		NoClaude: true,
		NoVT:     true,
	}

	// Should not require API keys when features are overridden
	if err := cfg.Validate(); err != nil {
		t.Errorf("unexpected error when features are overridden: %v", err)
	}
}
