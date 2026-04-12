package config

import (
	"testing"
)

func TestConfig_IsOllamaEnabled(t *testing.T) {
	tests := []struct {
		name       string
		ollamaScan bool
		noOllama   bool
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
				Features: FeaturesConfig{OllamaScan: tt.ollamaScan},
				NoOllama: tt.noOllama,
			}
			if got := cfg.IsOllamaEnabled(); got != tt.expected {
				t.Errorf("IsOllamaEnabled() = %v, expected %v", got, tt.expected)
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

func TestConfig_Validate(t *testing.T) {
	// Ollama runs locally, no API key needed
	cfg := &Config{
		Features: FeaturesConfig{OllamaScan: true},
	}

	// Should not return error for Ollama - it's local
	if err := cfg.Validate(); err != nil {
		t.Errorf("unexpected error for Ollama (no API key needed): %v", err)
	}
}

func TestConfig_Defaults(t *testing.T) {
	// Test that defaults are properly set
	cfg := &Config{}

	// HomebrewPath should be empty by default (Load sets the default)
	if cfg.HomebrewPath != "" {
		t.Errorf("expected empty HomebrewPath, got %s", cfg.HomebrewPath)
	}

	// Features should be disabled by default
	if cfg.Features.OllamaScan {
		t.Error("expected OllamaScan to be false by default")
	}
}

func TestConfig_BlockPolicy(t *testing.T) {
	cfg := &Config{
		BlockPolicy: BlockPolicyConfig{
			OllamaFormulaHold: true,
			OllamaCodeHold:    true,
		},
	}

	if !cfg.BlockPolicy.OllamaFormulaHold {
		t.Error("expected OllamaFormulaHold to be true")
	}
	if !cfg.BlockPolicy.OllamaCodeHold {
		t.Error("expected OllamaCodeHold to be true")
	}
}
