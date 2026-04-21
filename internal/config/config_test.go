package config

import (
	"os"
	"testing"
)

func TestConfig_IsLLMEnabled(t *testing.T) {
	tests := []struct {
		name     string
		llmScan  bool
		noLLM    bool
		expected bool
	}{
		{"enabled and not overridden", true, false, true},
		{"enabled but overridden", true, true, false},
		{"disabled", false, false, false},
		{"disabled and overridden", false, true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Features: FeaturesConfig{LLMScan: tt.llmScan},
				NoLLM:    tt.noLLM,
			}
			if got := cfg.IsLLMEnabled(); got != tt.expected {
				t.Errorf("IsLLMEnabled() = %v, expected %v", got, tt.expected)
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
	tests := []struct {
		name        string
		llmScan     bool
		llmProvider string
		llmModel    string
		setAPIKey   bool
		wantErr     bool
	}{
		{"llm disabled, no model", false, ProviderOllama, "", false, false},
		{"llm disabled, with model", false, ProviderOllama, "gemma3", false, false},
		{"ollama enabled, with model", true, ProviderOllama, "gemma3", false, false},
		{"ollama enabled, no model", true, ProviderOllama, "", false, true},
		{"anthropic enabled, with api key", true, ProviderAnthropic, "", true, false},
		{"anthropic enabled, no api key", true, ProviderAnthropic, "", false, true},
		{"invalid provider", true, "invalid", "", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set or unset API key as needed
			if tt.setAPIKey {
				_ = os.Setenv("ANTHROPIC_API_KEY", "test-key")
				defer func() { _ = os.Unsetenv("ANTHROPIC_API_KEY") }()
			} else {
				_ = os.Unsetenv("ANTHROPIC_API_KEY")
			}

			cfg := &Config{
				Features: FeaturesConfig{
					LLMScan:     tt.llmScan,
					LLMProvider: tt.llmProvider,
				},
				LLMModel: tt.llmModel,
			}
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
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
	if cfg.Features.LLMScan {
		t.Error("expected LLMScan to be false by default")
	}
}

func TestConfig_BlockPolicy(t *testing.T) {
	cfg := &Config{
		BlockPolicy: BlockPolicyConfig{
			LLMFormulaHold: true,
			LLMCodeHold:    true,
		},
	}

	if !cfg.BlockPolicy.LLMFormulaHold {
		t.Error("expected LLMFormulaHold to be true")
	}
	if !cfg.BlockPolicy.LLMCodeHold {
		t.Error("expected LLMCodeHold to be true")
	}
}
