package llm

import (
	"fmt"
	"os"
)

// Provider defines the interface for LLM backends (Ollama, Anthropic, etc.)
type Provider interface {
	// CheckAvailability verifies the LLM service is reachable and configured
	CheckAvailability() error

	// AnalyzeFormula analyzes formula versions for security issues (Step 3)
	AnalyzeFormula(pkg string, versions []FormulaVersion) (*FormulaAnalysisResult, error)

	// AnalyzeCode analyzes post-install code diff and YARA findings (Step 6)
	AnalyzeCode(pkg, oldVersion, newVersion, diff, yaraFindings string) (*CodeAnalysisResult, error)

	// AnalyzeFiles analyzes file contents using chunking (for inspect command)
	AnalyzeFiles(pkg string, files map[string]string, yaraFindings string) (*CodeAnalysisResult, error)
}

// Verdict represents the LLM's security assessment
type Verdict string

const (
	VerdictSafe   Verdict = "SAFE"
	VerdictReview Verdict = "REVIEW"
	VerdictHold   Verdict = "HOLD"
)

// Confidence represents the LLM's confidence level
type Confidence string

const (
	ConfidenceHigh   Confidence = "HIGH"
	ConfidenceMedium Confidence = "MEDIUM"
	ConfidenceLow    Confidence = "LOW"
)

// FormulaAnalysisResult contains the result of formula analysis
type FormulaAnalysisResult struct {
	Package     string
	Verdict     Verdict
	Confidence  Confidence
	Findings    []Finding
	RawResponse string
	Truncated   bool
	Error       error
}

// CodeAnalysisResult contains the result of post-install code analysis
type CodeAnalysisResult struct {
	Package     string
	OldVersion  string
	NewVersion  string
	Verdict     Verdict
	Confidence  Confidence
	Findings    []Finding
	RawResponse string
	Error       error
}

// Finding represents a specific security finding
type Finding struct {
	File        string
	LineNumber  int
	Description string
	Version     string // For formula analysis: CURRENT, PREVIOUS, TWO_VERSIONS_AGO
}

// FormulaVersion represents a version of a formula from git history
type FormulaVersion struct {
	Label   string // CURRENT, PREVIOUS, TWO_VERSIONS_AGO
	SHA     string
	Content string
}

// verdictPriority returns the priority level for verdict comparison
func verdictPriority(v Verdict) int {
	switch v {
	case VerdictHold:
		return 3
	case VerdictReview:
		return 2
	case VerdictSafe:
		return 1
	default:
		return 0
	}
}

// New creates a Provider based on the provider name from config.
// Supported values: "ollama", "anthropic".
// For "anthropic", reads ANTHROPIC_API_KEY from the environment.
func New(providerName, model, baseURL string, maxFileBytes int) (Provider, error) {
	switch providerName {
	case "ollama":
		return newOllamaProvider(baseURL, model, maxFileBytes), nil
	case "anthropic":
		apiKey := os.Getenv("ANTHROPIC_API_KEY")
		if apiKey == "" {
			return nil, fmt.Errorf("ANTHROPIC_API_KEY environment variable is not set (required for anthropic provider)")
		}
		return newAnthropicProvider(apiKey, model, maxFileBytes), nil
	default:
		return nil, fmt.Errorf("unknown LLM provider %q: supported values are \"ollama\" and \"anthropic\"", providerName)
	}
}
