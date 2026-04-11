package claude

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	anthropicAPIURL         = "https://api.anthropic.com/v1/messages"
	anthropicCountTokensURL = "https://api.anthropic.com/v1/messages/count_tokens"
)

// Client handles Anthropic API interactions
type Client struct {
	apiKey        string
	model         string
	maxFileBytes  int
	httpClient    *http.Client
	maxRetries    int // Max retries for rate limit/overload errors
	baseBackoffMs int // Base backoff in milliseconds
}

// Verdict represents Claude's security assessment
type Verdict string

const (
	VerdictSafe   Verdict = "SAFE"
	VerdictReview Verdict = "REVIEW"
	VerdictHold   Verdict = "HOLD"
)

// Confidence represents Claude's confidence level
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

// TokenCountResult contains the result of token counting
type TokenCountResult struct {
	InputTokens int   `json:"input_tokens"`
	Error       error `json:"-"`
}

// UsageEstimate contains estimated API usage for a step
type UsageEstimate struct {
	ClaudeTokens   int      // Total tokens needed for Claude API
	ClaudePackages []string // Packages that will use Claude
	VTRequests     int      // Total VT API requests needed
	VTHashes       int      // Total hashes flagged by CIRCL as malicious
	CIRCLMalicious []string // File paths flagged as malicious by CIRCL
}

// RateLimitInfo contains rate limit information from API response headers
type RateLimitInfo struct {
	RequestsLimit     int   // Max requests allowed in period
	RequestsRemaining int   // Requests remaining in period
	RequestsReset     int64 // Unix timestamp when limit resets
	TokensLimit       int   // Max tokens allowed in period
	TokensRemaining   int   // Tokens remaining in period
	TokensReset       int64 // Unix timestamp when token limit resets
	Error             error
}

// NewClient creates a new Claude API client
func NewClient(model string, maxFileBytes int) (*Client, error) {
	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("ANTHROPIC_API_KEY not set")
	}

	return &Client{
		apiKey:       apiKey,
		model:        model,
		maxFileBytes: maxFileBytes,
		httpClient: &http.Client{
			Timeout: 120 * time.Second, // Claude can take a while
		},
		maxRetries:    3,
		baseBackoffMs: 1000, // 1 second base backoff
	}, nil
}

// CheckRateLimits makes a lightweight API call to retrieve current rate limit status
// This uses the count_tokens endpoint which is fast and low-cost
func (c *Client) CheckRateLimits() (*RateLimitInfo, error) {
	info := &RateLimitInfo{}

	// Make a minimal count_tokens request to get rate limit headers
	requestBody := map[string]interface{}{
		"model": c.model,
		"messages": []map[string]string{
			{"role": "user", "content": "test"},
		},
	}

	body, err := json.Marshal(requestBody)
	if err != nil {
		info.Error = fmt.Errorf("marshaling request: %w", err)
		return info, nil
	}

	req, err := http.NewRequest(http.MethodPost, anthropicCountTokensURL, bytes.NewReader(body))
	if err != nil {
		info.Error = fmt.Errorf("creating request: %w", err)
		return info, nil
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		info.Error = fmt.Errorf("making request: %w", err)
		return info, nil
	}
	defer func() { _ = resp.Body.Close() }()

	// Parse rate limit headers
	c.parseRateLimitHeaders(resp, info)

	if resp.StatusCode == http.StatusUnauthorized {
		info.Error = fmt.Errorf("API key invalid or expired")
	} else if resp.StatusCode != http.StatusOK {
		errMsg := c.parseErrorResponse(resp.Body)
		info.Error = fmt.Errorf("API error (%d): %s", resp.StatusCode, errMsg)
	}

	return info, nil
}

// parseRateLimitHeaders extracts rate limit info from response headers
func (c *Client) parseRateLimitHeaders(resp *http.Response, info *RateLimitInfo) {
	// Anthropic rate limit headers:
	// anthropic-ratelimit-requests-limit
	// anthropic-ratelimit-requests-remaining
	// anthropic-ratelimit-requests-reset
	// anthropic-ratelimit-tokens-limit
	// anthropic-ratelimit-tokens-remaining
	// anthropic-ratelimit-tokens-reset

	if v := resp.Header.Get("anthropic-ratelimit-requests-limit"); v != "" {
		_, _ = fmt.Sscanf(v, "%d", &info.RequestsLimit)
	}
	if v := resp.Header.Get("anthropic-ratelimit-requests-remaining"); v != "" {
		_, _ = fmt.Sscanf(v, "%d", &info.RequestsRemaining)
	}
	if v := resp.Header.Get("anthropic-ratelimit-requests-reset"); v != "" {
		// Parse ISO8601 timestamp
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			info.RequestsReset = t.Unix()
		}
	}
	if v := resp.Header.Get("anthropic-ratelimit-tokens-limit"); v != "" {
		_, _ = fmt.Sscanf(v, "%d", &info.TokensLimit)
	}
	if v := resp.Header.Get("anthropic-ratelimit-tokens-remaining"); v != "" {
		_, _ = fmt.Sscanf(v, "%d", &info.TokensRemaining)
	}
	if v := resp.Header.Get("anthropic-ratelimit-tokens-reset"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			info.TokensReset = t.Unix()
		}
	}
}

// CountTokens counts the tokens required for a prompt using Anthropic's API
func (c *Client) CountTokens(prompt string) (*TokenCountResult, error) {
	result := &TokenCountResult{}

	requestBody := map[string]interface{}{
		"model": c.model,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	}

	body, err := json.Marshal(requestBody)
	if err != nil {
		result.Error = fmt.Errorf("marshaling request: %w", err)
		return result, nil
	}

	req, err := http.NewRequest(http.MethodPost, anthropicCountTokensURL, bytes.NewReader(body))
	if err != nil {
		result.Error = fmt.Errorf("creating request: %w", err)
		return result, nil
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		result.Error = fmt.Errorf("making request: %w", err)
		return result, nil
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		errMsg := c.parseErrorResponse(resp.Body)
		result.Error = fmt.Errorf("count tokens API error (%d): %s", resp.StatusCode, errMsg)
		return result, nil
	}

	if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
		result.Error = fmt.Errorf("decoding response: %w", err)
		return result, nil
	}

	return result, nil
}

// CountFormulaTokens counts tokens for formula analysis without making the actual API call
func (c *Client) CountFormulaTokens(pkg string, versions []FormulaVersion) (*TokenCountResult, error) {
	if len(versions) == 0 {
		return &TokenCountResult{InputTokens: 0}, nil
	}

	prompt := c.buildFormulaPrompt(pkg, versions)
	if len(prompt) > c.maxFileBytes {
		prompt = prompt[:c.maxFileBytes]
	}

	return c.CountTokens(prompt)
}

// CountCodeAnalysisTokens counts tokens for code analysis without making the actual API call
func (c *Client) CountCodeAnalysisTokens(pkg, oldVersion, newVersion, diff, semgrepFindings string) (*TokenCountResult, error) {
	if diff == "" {
		return &TokenCountResult{InputTokens: 0}, nil
	}

	prompt := c.buildCodeAnalysisPrompt(pkg, oldVersion, newVersion, diff, semgrepFindings)
	return c.CountTokens(prompt)
}

// CountFileAnalysisTokens counts tokens for file analysis without making the actual API call
func (c *Client) CountFileAnalysisTokens(pkg string, files map[string]string, semgrepFindings string) (*TokenCountResult, error) {
	if len(files) == 0 {
		return &TokenCountResult{InputTokens: 0}, nil
	}

	prompt := c.buildFileAnalysisPrompt(pkg, files, semgrepFindings)
	return c.CountTokens(prompt)
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
		// No text files changed - skip Claude call
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

Respond with:
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

VERDICT: SAFE | REVIEW | HOLD
CONFIDENCE: HIGH | MEDIUM | LOW
FINDINGS:
- [file path, line number, what changed, why it is suspicious]
`)

	return sb.String()
}

func (c *Client) sendRequest(prompt string) (string, error) {
	return c.sendRequestWithRetry(prompt, 0)
}

// sendRequestWithRetry performs the API request with exponential backoff for retryable errors
func (c *Client) sendRequestWithRetry(prompt string, attempt int) (string, error) {
	requestBody := map[string]interface{}{
		"model":      c.model,
		"max_tokens": 4096,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	}

	body, err := json.Marshal(requestBody)
	if err != nil {
		return "", fmt.Errorf("marshaling request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, anthropicAPIURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("making request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Handle different status codes
	switch resp.StatusCode {
	case http.StatusOK:
		// Success - parse response
		var response struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			return "", fmt.Errorf("decoding response: %w", err)
		}

		if len(response.Content) == 0 {
			return "", fmt.Errorf("empty response from Claude")
		}

		return response.Content[0].Text, nil

	case http.StatusTooManyRequests: // 429 - Rate limited
		if attempt < c.maxRetries {
			backoffMs := c.baseBackoffMs * (1 << attempt) // 1s, 2s, 4s
			fmt.Printf("claude rate limited (429), backing off %dms (attempt %d/%d)\n",
				backoffMs, attempt+1, c.maxRetries)
			time.Sleep(time.Duration(backoffMs) * time.Millisecond)
			return c.sendRequestWithRetry(prompt, attempt+1)
		}
		return "", fmt.Errorf("claude rate limit exceeded (429) after %d retries", c.maxRetries)

	case 529: // Overloaded
		if attempt < c.maxRetries {
			backoffMs := c.baseBackoffMs * (1 << attempt) // 1s, 2s, 4s
			fmt.Printf("claude API overloaded (529), backing off %dms (attempt %d/%d)\n",
				backoffMs, attempt+1, c.maxRetries)
			time.Sleep(time.Duration(backoffMs) * time.Millisecond)
			return c.sendRequestWithRetry(prompt, attempt+1)
		}
		return "", fmt.Errorf("claude API overloaded (529) after %d retries", c.maxRetries)

	case http.StatusUnauthorized: // 401
		return "", fmt.Errorf("claude API key invalid or expired (401)")

	case http.StatusBadRequest: // 400
		errMsg := c.parseErrorResponse(resp.Body)
		if strings.Contains(errMsg, "token") || strings.Contains(errMsg, "length") {
			return "", fmt.Errorf("claude request too large - token limit exceeded: %s", errMsg)
		}
		return "", fmt.Errorf("claude bad request (400): %s", errMsg)

	case http.StatusForbidden: // 403
		return "", fmt.Errorf("claude API access forbidden (403) - check API key permissions")

	case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable: // 500, 502, 503
		if attempt < c.maxRetries {
			backoffMs := c.baseBackoffMs * (1 << attempt)
			fmt.Printf("claude server error (%d), backing off %dms (attempt %d/%d)\n",
				resp.StatusCode, backoffMs, attempt+1, c.maxRetries)
			time.Sleep(time.Duration(backoffMs) * time.Millisecond)
			return c.sendRequestWithRetry(prompt, attempt+1)
		}
		return "", fmt.Errorf("claude server error (%d) after %d retries", resp.StatusCode, c.maxRetries)

	default:
		errMsg := c.parseErrorResponse(resp.Body)
		return "", fmt.Errorf("claude API error (%d): %s", resp.StatusCode, errMsg)
	}
}

// parseErrorResponse extracts error message from API error response
func (c *Client) parseErrorResponse(body io.Reader) string {
	var errResp struct {
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}

	data, err := io.ReadAll(body)
	if err != nil {
		return "unable to read error response"
	}

	if err := json.Unmarshal(data, &errResp); err != nil {
		// Return raw body if not JSON
		if len(data) > 200 {
			return string(data[:200]) + "..."
		}
		return string(data)
	}

	if errResp.Error.Message != "" {
		return errResp.Error.Message
	}
	if errResp.Error.Type != "" {
		return errResp.Error.Type
	}
	return "unknown error"
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

VERDICT: SAFE | REVIEW | HOLD
CONFIDENCE: HIGH | MEDIUM | LOW
FINDINGS:
- [file path, line number, what is suspicious, why]
`)

	return sb.String()
}
