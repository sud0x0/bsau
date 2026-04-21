package llm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/sud0x0/bsau/internal/logger"
)

const (
	// AnthropicAPIURL is the Anthropic Messages API endpoint
	AnthropicAPIURL = "https://api.anthropic.com/v1/messages"

	// AnthropicAPIVersion is the required API version header
	AnthropicAPIVersion = "2023-06-01"

	// DefaultAnthropicModel is the default Claude model to use
	DefaultAnthropicModel = "claude-sonnet-4-6"
)

// anthropicProvider implements the Provider interface for Anthropic Claude
type anthropicProvider struct {
	apiKey       string
	model        string
	maxFileBytes int
	httpClient   *http.Client
}

// anthropicMessage represents a message in the Anthropic Messages API
type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// anthropicRequest represents a request to the Anthropic Messages API
type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	System    string             `json:"system,omitempty"`
	Messages  []anthropicMessage `json:"messages"`
}

// anthropicResponse represents a response from the Anthropic Messages API
type anthropicResponse struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Role    string `json:"role"`
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	StopReason string `json:"stop_reason"`
	Usage      struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

// anthropicError represents an error response from the Anthropic API
type anthropicError struct {
	Type  string `json:"type"`
	Error struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

// newAnthropicProvider creates a new Anthropic Claude API provider
func newAnthropicProvider(apiKey, model string, maxFileBytes int) *anthropicProvider {
	if model == "" {
		model = DefaultAnthropicModel
	}

	return &anthropicProvider{
		apiKey:       apiKey,
		model:        model,
		maxFileBytes: maxFileBytes,
		httpClient: &http.Client{
			Timeout: 120 * time.Second,
		},
	}
}

// CheckAvailability verifies that the Anthropic API is reachable and the API key is valid
func (p *anthropicProvider) CheckAvailability() error {
	// Send a minimal request to verify API key
	req := anthropicRequest{
		Model:     p.model,
		MaxTokens: 10,
		Messages: []anthropicMessage{
			{Role: "user", Content: "test"},
		},
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	httpReq, err := http.NewRequest(http.MethodPost, AnthropicAPIURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", p.apiKey)
	httpReq.Header.Set("anthropic-version", AnthropicAPIVersion)

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("anthropic API not reachable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("invalid ANTHROPIC_API_KEY")
	}

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		var errResp anthropicError
		if json.Unmarshal(respBody, &errResp) == nil && errResp.Error.Message != "" {
			return fmt.Errorf("anthropic error: %s", errResp.Error.Message)
		}
		return fmt.Errorf("anthropic error (%d): %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// AnalyzeFormula analyzes formula versions for security issues (Step 3)
func (p *anthropicProvider) AnalyzeFormula(pkg string, versions []FormulaVersion) (*FormulaAnalysisResult, error) {
	result := &FormulaAnalysisResult{Package: pkg}

	if len(versions) == 0 {
		result.Error = fmt.Errorf("no formula versions provided")
		return result, nil
	}

	// If only one version, we can't diff - just note it's new
	if len(versions) == 1 {
		var content strings.Builder
		fmt.Fprintf(&content, "Package: %s\n", pkg)
		fmt.Fprintf(&content, "Note: This is a new formula with no previous version to compare.\n\n")
		content.WriteString("```ruby\n")
		content.WriteString(versions[0].Content)
		content.WriteString("\n```\n")

		userPrompt := UserPromptFormulaAnalysis + "\n\n" + content.String()

		response, err := p.sendRequest(FormulaSystemPrompt, userPrompt)
		if err != nil {
			result.Error = err
			result.Verdict = VerdictReview
			return result, nil
		}

		result.RawResponse = response
		parseFormulaResponse(response, result)
		return result, nil
	}

	// Generate diff between CURRENT (index 0) and PREVIOUS (index 1)
	diff, err := generateFormulaDiff(versions[1].Content, versions[0].Content, pkg)
	if err != nil {
		result.Error = fmt.Errorf("generating diff: %w", err)
		result.Verdict = VerdictReview
		return result, nil
	}

	// If no diff, formula hasn't changed
	if diff == "" {
		result.Verdict = VerdictSafe
		result.RawResponse = "No changes detected between versions"
		return result, nil
	}

	// Build the content with the diff
	var content strings.Builder
	fmt.Fprintf(&content, "Package: %s\n", pkg)
	if versions[1].SHA != "" && versions[0].SHA != "" {
		fmt.Fprintf(&content, "Comparing: %s (PREVIOUS) → %s (CURRENT)\n\n", versions[1].SHA, versions[0].SHA)
	}
	content.WriteString("```diff\n")
	content.WriteString(diff)
	content.WriteString("\n```\n")

	userPrompt := UserPromptFormulaAnalysis + "\n\n" + content.String()

	response, err := p.sendRequest(FormulaSystemPrompt, userPrompt)
	if err != nil {
		result.Error = err
		result.Verdict = VerdictReview
		return result, nil
	}

	result.RawResponse = response
	parseFormulaResponse(response, result)

	return result, nil
}

// AnalyzeCode analyzes post-install code diff and YARA findings (Step 6)
func (p *anthropicProvider) AnalyzeCode(pkg, oldVersion, newVersion, diff, yaraFindings string) (*CodeAnalysisResult, error) {
	result := &CodeAnalysisResult{
		Package:    pkg,
		OldVersion: oldVersion,
		NewVersion: newVersion,
	}

	if diff == "" {
		result.Verdict = VerdictSafe
		return result, nil
	}

	// Change 3: Truncate diff if over 20,000 lines
	diffLines := strings.Split(diff, "\n")
	diffTruncated := false
	if len(diffLines) > MaxDiffLines {
		fmt.Printf("\033[33m[WARN]\033[0m Diff for %s has %d lines, truncating to %d lines for LLM analysis\n", pkg, len(diffLines), MaxDiffLines)
		diffLines = diffLines[:MaxDiffLines]
		diff = strings.Join(diffLines, "\n")
		diffTruncated = true
	}

	// Chunk large diffs to prevent context overflow
	if len(diffLines) <= DiffChunkSize {
		// Single chunk - include YARA findings
		return p.analyzeDiffChunk(pkg, oldVersion, newVersion, diff, yaraFindings, 0, len(diffLines), true, 1, 1, diffTruncated, result)
	}

	// Large diff - chunk and aggregate results
	var allFindings []Finding
	worstVerdict := VerdictSafe
	var allResponses strings.Builder
	consecutiveErrors := 0
	skippedChunks := 0

	chunks := chunkDiff(diff)
	totalChunks := len(chunks)
	currentLine := 1
	for i, chunk := range chunks {
		// Change 2: Stop if 15+ consecutive failures
		if consecutiveErrors >= MaxConsecutiveChunkErrors {
			skippedChunks = totalChunks - i
			fmt.Printf("\033[33m[WARN]\033[0m Stopping LLM analysis for %s: %d consecutive chunk failures. %d chunks skipped. Manual review recommended.\n", pkg, consecutiveErrors, skippedChunks)
			logger.Warn("LLM analysis stopped for %s: %d consecutive errors, %d chunks skipped", pkg, consecutiveErrors, skippedChunks)
			worstVerdict = VerdictReview
			break
		}

		chunkLines := len(strings.Split(chunk, "\n"))
		startLine := currentLine
		endLine := startLine + chunkLines - 1
		currentLine = endLine + 1

		chunkResult := &CodeAnalysisResult{
			Package:    pkg,
			OldVersion: oldVersion,
			NewVersion: newVersion,
		}

		// Only include YARA findings in the first chunk to reduce token cost
		// Also include truncation note in first chunk if diff was truncated
		includeYara := i == 0
		_, err := p.analyzeDiffChunk(pkg, oldVersion, newVersion, chunk, yaraFindings, startLine, endLine, includeYara, i+1, totalChunks, diffTruncated && i == 0, chunkResult)
		if err != nil {
			// Chunk failed after all retries - count as consecutive error
			consecutiveErrors++
			continue
		}

		// Success - reset consecutive error counter
		consecutiveErrors = 0

		fmt.Fprintf(&allResponses, "--- Chunk %d (lines %d-%d) ---\n", i+1, startLine, endLine)
		allResponses.WriteString(chunkResult.RawResponse)
		allResponses.WriteString("\n\n")

		allFindings = append(allFindings, chunkResult.Findings...)

		if verdictPriority(chunkResult.Verdict) > verdictPriority(worstVerdict) {
			worstVerdict = chunkResult.Verdict
		}
	}

	result.Verdict = worstVerdict
	result.Findings = allFindings
	result.RawResponse = allResponses.String()

	return result, nil
}

// analyzeDiffChunk analyzes a single chunk of diff
// includeYara controls whether YARA findings are included (only in first chunk to reduce tokens)
// chunkNum and totalChunks are used for verbose logging
// noteTruncation adds a truncation notice to the prompt if true
func (p *anthropicProvider) analyzeDiffChunk(pkg, oldVersion, newVersion, diffChunk, yaraFindings string, startLine, endLine int, includeYara bool, chunkNum, totalChunks int, noteTruncation bool, result *CodeAnalysisResult) (*CodeAnalysisResult, error) {
	var content strings.Builder
	fmt.Fprintf(&content, "Package: %s\n", pkg)
	fmt.Fprintf(&content, "Upgraded: %s → %s\n", oldVersion, newVersion)
	fmt.Fprintf(&content, "Installed path: /opt/homebrew/Cellar/%s/%s/\n\n", pkg, newVersion)

	if startLine > 1 || endLine > DiffChunkSize {
		fmt.Fprintf(&content, "Diff chunk (lines %d-%d of larger diff):\n", startLine, endLine)
	}

	if includeYara && yaraFindings != "" && yaraFindings != "None" {
		content.WriteString("YARA findings:\n")
		content.WriteString(yaraFindings)
		content.WriteString("\n\n")
	}

	// Change 3: Note truncation in prompt if diff was truncated
	if noteTruncation {
		fmt.Fprintf(&content, "[NOTE: diff truncated to %d lines due to size]\n\n", MaxDiffLines)
	}

	content.WriteString("Diff:\n```diff\n")
	content.WriteString(diffChunk)
	content.WriteString("\n```")

	userPrompt := UserPromptDiffAnalysis + "\n\n" + content.String()

	// Log LLM request
	logger.VerboseLLMRequest(pkg, chunkNum, totalChunks, DiffSystemPrompt, userPrompt)

	// Change 2 & 4: Retry logic with rate limit detection
	var response string
	var lastErr error
	startTime := time.Now()

	for attempt := 1; attempt <= MaxRetries; attempt++ {
		response, lastErr = p.sendRequest(DiffSystemPrompt, userPrompt)
		if lastErr == nil {
			break
		}

		// Change 4: Detect rate limit errors specifically
		isRateLimit := strings.Contains(lastErr.Error(), "rate_limit_error")

		if attempt < MaxRetries {
			if isRateLimit {
				// Rate limit - specific warning, doesn't count toward consecutive errors
				fmt.Printf("\033[33m[WARN]\033[0m Rate limit hit on chunk %d/%d, waiting %ds before retry (attempt %d/%d)...\n",
					chunkNum, totalChunks, RetryWaitSeconds, attempt, MaxRetries)
				logger.Warn("Rate limit hit chunk=%d/%d attempt=%d/%d", chunkNum, totalChunks, attempt, MaxRetries)
			} else {
				// Generic API error
				fmt.Printf("\033[33m[WARN]\033[0m LLM request failed (attempt %d/%d), retrying in %ds: %v\n",
					attempt, MaxRetries, RetryWaitSeconds, lastErr)
				logger.Warn("LLM request failed attempt=%d/%d: %v", attempt, MaxRetries, lastErr)
			}
			time.Sleep(time.Duration(RetryWaitSeconds) * time.Second)
		}
	}

	elapsed := time.Since(startTime)

	if lastErr != nil {
		result.Error = lastErr
		result.Verdict = VerdictReview
		logger.VerboseLLMResponse(pkg, chunkNum, totalChunks, elapsed, "ERROR", "")
		return result, lastErr
	}

	result.RawResponse = response
	parseCodeResponse(response, result)

	// Log LLM response with verdict
	logger.VerboseLLMResponse(pkg, chunkNum, totalChunks, elapsed, string(result.Verdict), response)

	return result, nil
}

// AnalyzeFiles analyzes file contents using chunking (for inspect command)
func (p *anthropicProvider) AnalyzeFiles(pkg string, files map[string]string, yaraFindings string) (*CodeAnalysisResult, error) {
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

			if yaraFindings != "" {
				userContent.WriteString("YARA findings:\n")
				userContent.WriteString(yaraFindings)
				userContent.WriteString("\n\n")
			}

			fmt.Fprintf(&userContent, "File: %s (lines %d-%d):\n```\n%s\n```",
				filePath, startLine, endLine, chunk)

			userPrompt := UserPromptFileAnalysis + "\n\n" + userContent.String()

			response, err := p.sendRequest(SystemPrompt, userPrompt)
			if err != nil {
				// Continue with other chunks on error
				continue
			}

			fmt.Fprintf(&allResponses, "--- %s (lines %d-%d) ---\n", filePath, startLine, endLine)
			allResponses.WriteString(response)
			allResponses.WriteString("\n\n")

			// Parse this chunk's response
			chunkResult := &CodeAnalysisResult{}
			parseCodeResponse(response, chunkResult)

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

func (p *anthropicProvider) sendRequest(systemPrompt, userPrompt string) (string, error) {
	req := anthropicRequest{
		Model:     p.model,
		MaxTokens: 1024,
		System:    systemPrompt,
		Messages: []anthropicMessage{
			{Role: "user", Content: userPrompt},
		},
	}

	// Log request
	logger.LLMRequest("anthropic", p.model, systemPrompt, userPrompt)

	body, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("marshaling request: %w", err)
	}

	httpReq, err := http.NewRequest(http.MethodPost, AnthropicAPIURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", p.apiKey)
	httpReq.Header.Set("anthropic-version", AnthropicAPIVersion)

	startTime := time.Now()

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		logger.LLMError("anthropic", err)
		return "", fmt.Errorf("anthropic request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	elapsed := time.Since(startTime)

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp anthropicError
		if json.Unmarshal(respBody, &errResp) == nil && errResp.Error.Message != "" {
			logger.LLMError("anthropic", fmt.Errorf("%s: %s", errResp.Error.Type, errResp.Error.Message))
			return "", fmt.Errorf("anthropic error: %s", errResp.Error.Message)
		}
		logger.LLMError("anthropic", fmt.Errorf("status %d: %s", resp.StatusCode, string(respBody)))
		return "", fmt.Errorf("anthropic error (%d): %s", resp.StatusCode, string(respBody))
	}

	var response anthropicResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		return "", fmt.Errorf("decoding response: %w", err)
	}

	if len(response.Content) == 0 || response.Content[0].Text == "" {
		logger.LLMError("anthropic", fmt.Errorf("empty response"))
		return "", fmt.Errorf("empty response from anthropic")
	}

	content := response.Content[0].Text

	// Log response
	logger.LLMResponse("anthropic", elapsed, content)

	return content, nil
}
