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

	"github.com/sud0x0/bsau/internal/logger"
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

// chatMessage represents a message in the chat API
type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// chatRequest represents a request to the chat API
type chatRequest struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
	Stream   bool          `json:"stream"`
}

// chatResponse represents a response from the chat API
type chatResponse struct {
	Model   string `json:"model"`
	Message struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"message"`
	Done bool `json:"done"`
}

// NewClient creates a new Ollama API client
func NewClient(baseURL, model string, maxFileBytes int) *Client {
	// Use the chat API endpoint
	apiURL := strings.TrimSuffix(baseURL, "/") + "/api/chat"

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
	req := chatRequest{
		Model: c.model,
		Messages: []chatMessage{
			{Role: "user", Content: "test"},
		},
		Stream: false,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	httpReq, err := http.NewRequest(http.MethodPost, c.baseURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("ollama not reachable at %s: %w", c.baseURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("ollama error (%d): %s", resp.StatusCode, string(respBody))
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

	// Build the content with all formula versions
	var content strings.Builder
	fmt.Fprintf(&content, "Package: %s\n\n", pkg)

	for _, v := range versions {
		fmt.Fprintf(&content, "=== %s ===\n", v.Label)
		if v.SHA != "" {
			fmt.Fprintf(&content, "Git SHA: %s\n", v.SHA)
		}
		content.WriteString("```ruby\n")
		content.WriteString(v.Content)
		content.WriteString("\n```\n\n")
	}

	userPrompt := UserPromptFormulaAnalysis + "\n\n" + content.String()

	response, err := c.sendChatRequest(SystemPrompt, userPrompt)
	if err != nil {
		result.Error = err
		result.Verdict = VerdictReview
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
		result.Verdict = VerdictSafe
		return result, nil
	}

	// Build user content
	var content strings.Builder
	fmt.Fprintf(&content, "Package: %s\n", pkg)
	fmt.Fprintf(&content, "Upgraded: %s → %s\n", oldVersion, newVersion)
	fmt.Fprintf(&content, "Installed path: /opt/homebrew/Cellar/%s/%s/\n\n", pkg, newVersion)

	if semgrepFindings != "" && semgrepFindings != "None" {
		content.WriteString("Semgrep findings:\n")
		content.WriteString(semgrepFindings)
		content.WriteString("\n\n")
	}

	content.WriteString("Diff:\n```diff\n")
	content.WriteString(diff)
	content.WriteString("\n```")

	userPrompt := UserPromptDiffAnalysis + "\n\n" + content.String()

	response, err := c.sendChatRequest(SystemPrompt, userPrompt)
	if err != nil {
		result.Error = err
		result.Verdict = VerdictReview
		return result, nil
	}

	result.RawResponse = response
	c.parseCodeResponse(response, result)

	return result, nil
}

// AnalyzeFiles analyzes file contents using chunking (for inspect command)
// This scans all provided files in chunks, similar to the test script
func (c *Client) AnalyzeFiles(pkg string, files map[string]string, semgrepFindings string) (*CodeAnalysisResult, error) {
	result := &CodeAnalysisResult{Package: pkg}

	if len(files) == 0 {
		result.Verdict = VerdictSafe
		return result, nil
	}

	// Collect all chunk results
	var allFindings []Finding
	worstVerdict := VerdictSafe
	var allResponses strings.Builder

	// Process each file
	for filePath, content := range files {
		chunks := chunkContent(content)

		for i, chunk := range chunks {
			startLine := i*(ChunkSize-ChunkOverlap) + 1
			endLine := startLine + len(strings.Split(chunk, "\n")) - 1

			// Build user content for this chunk
			var userContent strings.Builder
			fmt.Fprintf(&userContent, "Package: %s\n", pkg)

			if semgrepFindings != "" {
				userContent.WriteString("Semgrep findings:\n")
				userContent.WriteString(semgrepFindings)
				userContent.WriteString("\n\n")
			}

			fmt.Fprintf(&userContent, "File: %s (lines %d-%d):\n```\n%s\n```",
				filePath, startLine, endLine, chunk)

			userPrompt := UserPromptFileAnalysis + "\n\n" + userContent.String()

			response, err := c.sendChatRequest(SystemPrompt, userPrompt)
			if err != nil {
				// Continue with other chunks on error
				continue
			}

			fmt.Fprintf(&allResponses, "--- %s (lines %d-%d) ---\n", filePath, startLine, endLine)
			allResponses.WriteString(response)
			allResponses.WriteString("\n\n")

			// Parse this chunk's response
			chunkResult := &CodeAnalysisResult{}
			c.parseCodeResponse(response, chunkResult)

			// Aggregate results
			allFindings = append(allFindings, chunkResult.Findings...)

			// Keep worst verdict
			if verdictPriority(chunkResult.Verdict) > verdictPriority(worstVerdict) {
				worstVerdict = chunkResult.Verdict
			}
		}
	}

	result.Verdict = worstVerdict
	result.Findings = allFindings
	result.RawResponse = allResponses.String()

	return result, nil
}

// chunkContent splits content into chunks of ChunkSize lines with ChunkOverlap overlap
func chunkContent(content string) []string {
	lines := strings.Split(content, "\n")
	totalLines := len(lines)

	if totalLines <= ChunkSize {
		return []string{content}
	}

	var chunks []string
	start := 0

	for start < totalLines {
		end := start + ChunkSize
		if end > totalLines {
			end = totalLines
		}

		chunk := strings.Join(lines[start:end], "\n")
		chunks = append(chunks, chunk)

		if end >= totalLines {
			break
		}

		start = end - ChunkOverlap
	}

	return chunks
}

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

func (c *Client) sendChatRequest(systemPrompt, userPrompt string) (string, error) {
	req := chatRequest{
		Model: c.model,
		Messages: []chatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt},
		},
		Stream: false,
	}

	// Log request
	logger.OllamaRequest(c.model, systemPrompt, userPrompt)

	body, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("marshaling request: %w", err)
	}

	httpReq, err := http.NewRequest(http.MethodPost, c.baseURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	startTime := time.Now()

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		logger.OllamaError(err)
		return "", fmt.Errorf("ollama request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	elapsed := time.Since(startTime)

	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(resp.Body)
		logger.OllamaError(fmt.Errorf("status %d: %s", resp.StatusCode, string(errBody)))
		return "", fmt.Errorf("ollama error (%d): %s", resp.StatusCode, string(errBody))
	}

	var response chatResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return "", fmt.Errorf("decoding response: %w", err)
	}

	if response.Message.Content == "" {
		logger.OllamaError(fmt.Errorf("empty response"))
		return "", fmt.Errorf("empty response from ollama")
	}

	// Log response
	logger.OllamaResponse(elapsed, response.Message.Content)

	return response.Message.Content, nil
}

func (c *Client) parseResponse(response string, result *FormulaAnalysisResult) {
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
