package ollama

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Client handles Ollama API interactions
type Client struct {
	baseURL      string
	model        string
	maxFileBytes int
	httpClient   *http.Client
}

// Verdict represents Ollama's security assessment
type Verdict string

const (
	VerdictSafe   Verdict = "SAFE"
	VerdictReview Verdict = "REVIEW"
	VerdictHold   Verdict = "HOLD"
)

// Confidence represents Ollama's confidence level
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

// UsageEstimate contains estimated API usage for a step
// Simplified for Ollama since it's local and has no rate limits
type UsageEstimate struct {
	OllamaPackages []string // Packages that will use Ollama
	VTRequests     int      // Total VT API requests needed
	VTHashes       int      // Total hashes flagged by CIRCL as malicious
	CIRCLMalicious []string // File paths flagged as malicious by CIRCL
}

// NewClient creates a new Ollama API client
// baseURL should be the Ollama server URL from settings (e.g., http://localhost:11434)
func NewClient(baseURL, model string, maxFileBytes int) *Client {
	// Ensure the URL includes the API path
	apiURL := strings.TrimSuffix(baseURL, "/") + "/api/generate"

	return &Client{
		baseURL:      apiURL,
		model:        model,
		maxFileBytes: maxFileBytes,
		httpClient: &http.Client{
			Timeout: 300 * time.Second, // Local LLM can take longer
		},
	}
}

// CheckAvailability verifies that Ollama is running and the model is available
func (c *Client) CheckAvailability() error {
	// Try a simple request to check if Ollama is running
	req, err := http.NewRequest(http.MethodPost, c.baseURL, bytes.NewReader([]byte(`{"model":"`+c.model+`","prompt":"test","stream":false}`)))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("ollama not reachable at %s: %w", c.baseURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("ollama error (%d): %s", resp.StatusCode, string(body))
	}

	return nil
}

// AnalyzeFormula analyzes formula versions for security issues (Step 3)
func (c *Client) AnalyzeFormula(pkg string, versions []FormulaVersion) (*FormulaAnalysisResult, error) {
	result := &FormulaAnalysisResult{Package: pkg}

	if len(versions) == 0 {
		result.Error = fmt.Errorf("no formula versions provided")
		return result, nil
	}

	prompt := c.buildFormulaPrompt(pkg, versions)
	if len(prompt) > c.maxFileBytes {
		prompt = prompt[:c.maxFileBytes]
		result.Truncated = true
	}

	response, err := c.sendRequest(prompt)
	if err != nil {
		result.Error = err
		result.Verdict = VerdictReview // Fail-safe: mark as REVIEW on error
		return result, nil
	}

	result.RawResponse = response
	c.parseResponse(response, result)

	return result, nil
}

// AnalyzeCode analyzes post-install code diff and Semgrep findings (Step 6a)
func (c *Client) AnalyzeCode(pkg, oldVersion, newVersion, diff, semgrepFindings string) (*CodeAnalysisResult, error) {
	result := &CodeAnalysisResult{
		Package:    pkg,
		OldVersion: oldVersion,
		NewVersion: newVersion,
	}

	if diff == "" {
		// No text files changed - skip analysis
		result.Verdict = VerdictSafe
		return result, nil
	}

	prompt := c.buildCodeAnalysisPrompt(pkg, oldVersion, newVersion, diff, semgrepFindings)

	response, err := c.sendRequest(prompt)
	if err != nil {
		result.Error = err
		result.Verdict = VerdictReview
		return result, nil
	}

	result.RawResponse = response
	c.parseCodeResponse(response, result)

	return result, nil
}

// AnalyzeFiles analyzes raw file contents for inspect command (no diff available)
func (c *Client) AnalyzeFiles(pkg string, files map[string]string, semgrepFindings string) (*CodeAnalysisResult, error) {
	result := &CodeAnalysisResult{Package: pkg}

	if len(files) == 0 {
		result.Verdict = VerdictSafe
		return result, nil
	}

	prompt := c.buildFileAnalysisPrompt(pkg, files, semgrepFindings)

	response, err := c.sendRequest(prompt)
	if err != nil {
		result.Error = err
		result.Verdict = VerdictReview
		return result, nil
	}

	result.RawResponse = response
	c.parseCodeResponse(response, result)

	return result, nil
}

func (c *Client) buildFormulaPrompt(pkg string, versions []FormulaVersion) string {
	var sb strings.Builder

	sb.WriteString(`You are performing a pre-install security audit of a Homebrew formula.
Analyze the formula versions below with particular focus on what changed between them.
Any pattern present in CURRENT but absent from prior versions is higher suspicion.

Package: `)
	sb.WriteString(pkg)
	sb.WriteString("\n\n")

	for _, v := range versions {
		fmt.Fprintf(&sb, "=== %s ===\n", v.Label)
		if v.SHA != "" {
			fmt.Fprintf(&sb, "Git SHA: %s\n", v.SHA)
		}
		sb.WriteString("```ruby\n")
		sb.WriteString(v.Content)
		sb.WriteString("\n```\n\n")
	}

	sb.WriteString(`Look for:
- New or changed download URLs pointing to unexpected or non-canonical domains
- Newly added or modified shell hooks (postinstall, preinstall, caveats)
- Obfuscated shell commands or base64+eval patterns
- curl | bash or wget | sh without checksum verification
- Credential harvesting from environment variables
- Persistence mechanisms (LaunchAgent/LaunchDaemon writes)
- Exfiltration endpoints (hardcoded IPs, unusual domains)

Respond with EXACTLY this format:
VERDICT: SAFE | REVIEW | HOLD
CONFIDENCE: HIGH | MEDIUM | LOW
FINDINGS:
- [version label, line number, what changed, why suspicious]
`)

	return sb.String()
}

func (c *Client) buildCodeAnalysisPrompt(pkg, oldVersion, newVersion, diff, semgrepFindings string) string {
	var sb strings.Builder

	sb.WriteString(`You are performing a post-install security audit of a Homebrew package
that has just been upgraded on a macOS developer machine.

Package: `)
	sb.WriteString(pkg)
	fmt.Fprintf(&sb, "\nUpgraded: %s → %s\n", oldVersion, newVersion)
	fmt.Fprintf(&sb, "Installed path: /opt/homebrew/Cellar/%s/%s/\n\n", pkg, newVersion)

	sb.WriteString("Semgrep findings (malicious code rule sets only):\n")
	if semgrepFindings == "" || semgrepFindings == "None" {
		sb.WriteString("None\n\n")
	} else {
		sb.WriteString(semgrepFindings)
		sb.WriteString("\n\n")
	}

	sb.WriteString("Unified diff of changed files (text-readable files only):\n")
	sb.WriteString("```diff\n")
	sb.WriteString(diff)
	sb.WriteString("\n```\n\n")

	sb.WriteString(`Analyse the diff for malicious patterns introduced in this version.
Focus on what is NEW or CHANGED — patterns present in the old version
that remain unchanged are lower priority than newly introduced patterns.

Look for:
- Exfiltration of credentials, environment variables, or files to remote endpoints
- Encoded or obfuscated payloads being decoded and executed
- Unexpected network calls (curl, wget, requests, http) in non-networking code
- Persistence mechanisms (LaunchAgent/LaunchDaemon, cron, startup items)
- Privilege escalation or unexpected sudo usage
- Reverse shell or command-and-control patterns
- Anything Semgrep flagged — reason about whether it is a genuine threat
  or a false positive, with explanation

Respond with EXACTLY this format:
VERDICT: SAFE | REVIEW | HOLD
CONFIDENCE: HIGH | MEDIUM | LOW
FINDINGS:
- [file path, line number, what changed, why it is suspicious]
`)

	return sb.String()
}

func (c *Client) buildFileAnalysisPrompt(pkg string, files map[string]string, semgrepFindings string) string {
	var sb strings.Builder

	sb.WriteString(`You are performing a security audit of installed files from a Homebrew package.
This is a standalone inspection (not an upgrade diff).

Package: `)
	sb.WriteString(pkg)
	sb.WriteString("\n\n")

	sb.WriteString("Semgrep findings (malicious code rule sets only):\n")
	if semgrepFindings == "" {
		sb.WriteString("None\n\n")
	} else {
		sb.WriteString(semgrepFindings)
		sb.WriteString("\n\n")
	}

	sb.WriteString("Files flagged by Semgrep:\n")
	for path, content := range files {
		fmt.Fprintf(&sb, "\n=== %s ===\n```\n%s\n```\n", path, content)
	}

	sb.WriteString(`
Analyze these files for malicious patterns:
- Exfiltration of credentials or files to remote endpoints
- Encoded or obfuscated payloads
- Unexpected network calls
- Persistence mechanisms
- Privilege escalation
- Reverse shell patterns

Respond with EXACTLY this format:
VERDICT: SAFE | REVIEW | HOLD
CONFIDENCE: HIGH | MEDIUM | LOW
FINDINGS:
- [file path, line number, what is suspicious, why]
`)

	return sb.String()
}

func (c *Client) sendRequest(prompt string) (string, error) {
	requestBody := map[string]interface{}{
		"model":  c.model,
		"prompt": prompt,
		"stream": false,
	}

	body, err := json.Marshal(requestBody)
	if err != nil {
		return "", fmt.Errorf("marshaling request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, c.baseURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("ollama request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("ollama error (%d): %s", resp.StatusCode, string(errBody))
	}

	var response struct {
		Model    string `json:"model"`
		Response string `json:"response"`
		Done     bool   `json:"done"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return "", fmt.Errorf("decoding response: %w", err)
	}

	if response.Response == "" {
		return "", fmt.Errorf("empty response from ollama")
	}

	return response.Response, nil
}

func (c *Client) parseResponse(response string, result *FormulaAnalysisResult) {
	// Parse VERDICT
	verdictRegex := regexp.MustCompile(`VERDICT:\s*(SAFE|REVIEW|HOLD)`)
	if match := verdictRegex.FindStringSubmatch(response); len(match) > 1 {
		result.Verdict = Verdict(match[1])
	} else {
		result.Verdict = VerdictReview // Default to REVIEW if not parseable
	}

	// Parse CONFIDENCE
	confRegex := regexp.MustCompile(`CONFIDENCE:\s*(HIGH|MEDIUM|LOW)`)
	if match := confRegex.FindStringSubmatch(response); len(match) > 1 {
		result.Confidence = Confidence(match[1])
	} else {
		result.Confidence = ConfidenceMedium
	}

	// Parse FINDINGS (simplified)
	findingsRegex := regexp.MustCompile(`(?m)^-\s*\[([^\]]+)\]`)
	matches := findingsRegex.FindAllStringSubmatch(response, -1)
	for _, match := range matches {
		if len(match) > 1 {
			result.Findings = append(result.Findings, Finding{
				Description: match[1],
			})
		}
	}
}

func (c *Client) parseCodeResponse(response string, result *CodeAnalysisResult) {
	// Parse VERDICT
	verdictRegex := regexp.MustCompile(`VERDICT:\s*(SAFE|REVIEW|HOLD)`)
	if match := verdictRegex.FindStringSubmatch(response); len(match) > 1 {
		result.Verdict = Verdict(match[1])
	} else {
		result.Verdict = VerdictReview
	}

	// Parse CONFIDENCE
	confRegex := regexp.MustCompile(`CONFIDENCE:\s*(HIGH|MEDIUM|LOW)`)
	if match := confRegex.FindStringSubmatch(response); len(match) > 1 {
		result.Confidence = Confidence(match[1])
	} else {
		result.Confidence = ConfidenceMedium
	}

	// Parse FINDINGS
	findingsRegex := regexp.MustCompile(`(?m)^-\s*\[([^\]]+)\]`)
	matches := findingsRegex.FindAllStringSubmatch(response, -1)
	for _, match := range matches {
		if len(match) > 1 {
			result.Findings = append(result.Findings, Finding{
				Description: match[1],
			})
		}
	}
}
