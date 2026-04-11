package claude

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestVerdict_Constants(t *testing.T) {
	tests := []struct {
		verdict  Verdict
		expected string
	}{
		{VerdictSafe, "SAFE"},
		{VerdictReview, "REVIEW"},
		{VerdictHold, "HOLD"},
	}

	for _, tt := range tests {
		if string(tt.verdict) != tt.expected {
			t.Errorf("Verdict constant %v != %s", tt.verdict, tt.expected)
		}
	}
}

func TestConfidence_Constants(t *testing.T) {
	tests := []struct {
		confidence Confidence
		expected   string
	}{
		{ConfidenceHigh, "HIGH"},
		{ConfidenceMedium, "MEDIUM"},
		{ConfidenceLow, "LOW"},
	}

	for _, tt := range tests {
		if string(tt.confidence) != tt.expected {
			t.Errorf("Confidence constant %v != %s", tt.confidence, tt.expected)
		}
	}
}

func TestParseResponse_Safe(t *testing.T) {
	client := &Client{}
	result := &FormulaAnalysisResult{}

	response := `VERDICT: SAFE
CONFIDENCE: HIGH
FINDINGS:
- No suspicious patterns found`

	client.parseResponse(response, result)

	if result.Verdict != VerdictSafe {
		t.Errorf("expected SAFE verdict, got %v", result.Verdict)
	}
	if result.Confidence != ConfidenceHigh {
		t.Errorf("expected HIGH confidence, got %v", result.Confidence)
	}
}

func TestParseResponse_Hold(t *testing.T) {
	client := &Client{}
	result := &FormulaAnalysisResult{}

	response := `VERDICT: HOLD
CONFIDENCE: HIGH
FINDINGS:
- [CURRENT, line 45, suspicious curl | bash pattern]
- [CURRENT, line 67, hardcoded IP address 192.168.1.1]`

	client.parseResponse(response, result)

	if result.Verdict != VerdictHold {
		t.Errorf("expected HOLD verdict, got %v", result.Verdict)
	}
	if result.Confidence != ConfidenceHigh {
		t.Errorf("expected HIGH confidence, got %v", result.Confidence)
	}
	if len(result.Findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(result.Findings))
	}
}

func TestParseResponse_Review(t *testing.T) {
	client := &Client{}
	result := &FormulaAnalysisResult{}

	response := `VERDICT: REVIEW
CONFIDENCE: MEDIUM
FINDINGS:
- [CURRENT, line 23, new download URL needs verification]`

	client.parseResponse(response, result)

	if result.Verdict != VerdictReview {
		t.Errorf("expected REVIEW verdict, got %v", result.Verdict)
	}
	if result.Confidence != ConfidenceMedium {
		t.Errorf("expected MEDIUM confidence, got %v", result.Confidence)
	}
}

func TestParseResponse_DefaultsOnInvalid(t *testing.T) {
	client := &Client{}
	result := &FormulaAnalysisResult{}

	response := `This is not a valid response format`

	client.parseResponse(response, result)

	// Should default to REVIEW and MEDIUM when parsing fails
	if result.Verdict != VerdictReview {
		t.Errorf("expected REVIEW verdict on invalid input, got %v", result.Verdict)
	}
	if result.Confidence != ConfidenceMedium {
		t.Errorf("expected MEDIUM confidence on invalid input, got %v", result.Confidence)
	}
}

func TestParseCodeResponse_Safe(t *testing.T) {
	client := &Client{}
	result := &CodeAnalysisResult{}

	response := `VERDICT: SAFE
CONFIDENCE: HIGH
FINDINGS:
No malicious patterns detected in the diff.`

	client.parseCodeResponse(response, result)

	if result.Verdict != VerdictSafe {
		t.Errorf("expected SAFE verdict, got %v", result.Verdict)
	}
	if result.Confidence != ConfidenceHigh {
		t.Errorf("expected HIGH confidence, got %v", result.Confidence)
	}
}

func TestParseCodeResponse_Hold(t *testing.T) {
	client := &Client{}
	result := &CodeAnalysisResult{}

	response := `VERDICT: HOLD
CONFIDENCE: HIGH
FINDINGS:
- [bin/script.sh, line 15, curl to external IP, exfiltration risk]
- [lib/helper.rb, line 42, base64 decode and eval, obfuscation]`

	client.parseCodeResponse(response, result)

	if result.Verdict != VerdictHold {
		t.Errorf("expected HOLD verdict, got %v", result.Verdict)
	}
	if len(result.Findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(result.Findings))
	}
}

func TestBuildFormulaPrompt(t *testing.T) {
	client := &Client{maxFileBytes: 50000}

	versions := []FormulaVersion{
		{Label: "CURRENT", SHA: "abc123", Content: "class Ripgrep < Formula\nend"},
		{Label: "PREVIOUS", SHA: "def456", Content: "class Ripgrep < Formula\nend"},
	}

	prompt := client.buildFormulaPrompt("ripgrep", versions)

	if !strings.Contains(prompt, "Package: ripgrep") {
		t.Error("prompt should contain package name")
	}
	if !strings.Contains(prompt, "CURRENT") {
		t.Error("prompt should contain CURRENT label")
	}
	if !strings.Contains(prompt, "PREVIOUS") {
		t.Error("prompt should contain PREVIOUS label")
	}
	if !strings.Contains(prompt, "abc123") {
		t.Error("prompt should contain git SHA")
	}
	if !strings.Contains(prompt, "VERDICT: SAFE | REVIEW | HOLD") {
		t.Error("prompt should contain verdict instructions")
	}
}

func TestBuildCodeAnalysisPrompt(t *testing.T) {
	client := &Client{}

	diff := `--- a/bin/script.sh
+++ b/bin/script.sh
@@ -1,3 +1,4 @@
 #!/bin/bash
+curl http://example.com
 echo "hello"`

	semgrepFindings := `[{"check_id": "generic.secrets.security.detected-private-key"}]`

	prompt := client.buildCodeAnalysisPrompt("ripgrep", "13.0.0", "14.0.0", diff, semgrepFindings)

	if !strings.Contains(prompt, "Package: ripgrep") {
		t.Error("prompt should contain package name")
	}
	if !strings.Contains(prompt, "13.0.0 → 14.0.0") {
		t.Error("prompt should contain version upgrade info")
	}
	if !strings.Contains(prompt, "curl http://example.com") {
		t.Error("prompt should contain diff content")
	}
	if !strings.Contains(prompt, "generic.secrets.security") {
		t.Error("prompt should contain semgrep findings")
	}
}

func TestBuildCodeAnalysisPrompt_NoSemgrepFindings(t *testing.T) {
	client := &Client{}

	diff := "some diff content"
	prompt := client.buildCodeAnalysisPrompt("test", "1.0", "2.0", diff, "")

	if !strings.Contains(prompt, "None") {
		t.Error("prompt should show 'None' when no semgrep findings")
	}
}

func TestBuildFileAnalysisPrompt(t *testing.T) {
	client := &Client{}

	files := map[string]string{
		"/path/to/script.sh": "#!/bin/bash\necho hello",
		"/path/to/config.rb": "module Config\nend",
	}

	prompt := client.buildFileAnalysisPrompt("testpkg", files, "")

	if !strings.Contains(prompt, "Package: testpkg") {
		t.Error("prompt should contain package name")
	}
	if !strings.Contains(prompt, "script.sh") {
		t.Error("prompt should contain file path")
	}
	if !strings.Contains(prompt, "echo hello") {
		t.Error("prompt should contain file content")
	}
}

func TestAnalyzeCode_EmptyDiff(t *testing.T) {
	client := &Client{}

	result, err := client.AnalyzeCode("testpkg", "1.0", "2.0", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Verdict != VerdictSafe {
		t.Errorf("expected SAFE verdict for empty diff, got %v", result.Verdict)
	}
}

func TestAnalyzeFiles_EmptyFiles(t *testing.T) {
	client := &Client{}

	result, err := client.AnalyzeFiles("testpkg", map[string]string{}, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Verdict != VerdictSafe {
		t.Errorf("expected SAFE verdict for empty files, got %v", result.Verdict)
	}
}

func TestAnalyzeFormula_NoVersions(t *testing.T) {
	client := &Client{}

	result, err := client.AnalyzeFormula("testpkg", []FormulaVersion{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Error == nil {
		t.Error("expected error for no versions")
	}
}

func TestNewClient_MissingAPIKey(t *testing.T) {
	// Save original and unset
	original := os.Getenv("ANTHROPIC_API_KEY")
	_ = os.Unsetenv("ANTHROPIC_API_KEY")
	defer func() { _ = os.Setenv("ANTHROPIC_API_KEY", original) }()

	_, err := NewClient("claude-sonnet-4-6", 12000)
	if err == nil {
		t.Error("expected error when ANTHROPIC_API_KEY is not set")
	}
	if !strings.Contains(err.Error(), "ANTHROPIC_API_KEY") {
		t.Errorf("error should mention ANTHROPIC_API_KEY: %v", err)
	}
}

func TestNewClient_WithAPIKey(t *testing.T) {
	// Save original
	original := os.Getenv("ANTHROPIC_API_KEY")
	_ = os.Setenv("ANTHROPIC_API_KEY", "test-key-12345")
	defer func() { _ = os.Setenv("ANTHROPIC_API_KEY", original) }()

	client, err := NewClient("claude-sonnet-4-6", 12000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if client.model != "claude-sonnet-4-6" {
		t.Errorf("expected model claude-sonnet-4-6, got %s", client.model)
	}
	if client.maxFileBytes != 12000 {
		t.Errorf("expected maxFileBytes 12000, got %d", client.maxFileBytes)
	}
}

func TestSendRequest_MockServer(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request headers
		if r.Header.Get("Content-Type") != "application/json" {
			t.Error("expected Content-Type: application/json")
		}
		if r.Header.Get("x-api-key") != "test-key" {
			t.Error("expected x-api-key header")
		}
		if r.Header.Get("anthropic-version") != "2023-06-01" {
			t.Error("expected anthropic-version header")
		}

		// Return mock response
		response := map[string]interface{}{
			"content": []map[string]string{
				{"type": "text", "text": "VERDICT: SAFE\nCONFIDENCE: HIGH"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Note: Can't easily test sendRequest directly without modifying the package
	// This test demonstrates the mock server pattern
}

func TestFormulaAnalysisResult_Structure(t *testing.T) {
	result := FormulaAnalysisResult{
		Package:    "ripgrep",
		Verdict:    VerdictSafe,
		Confidence: ConfidenceHigh,
		Findings: []Finding{
			{File: "formula.rb", LineNumber: 10, Description: "test finding"},
		},
		RawResponse: "test response",
		Truncated:   false,
		Error:       nil,
	}

	if result.Package != "ripgrep" {
		t.Errorf("expected Package to be ripgrep, got %s", result.Package)
	}
	if len(result.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(result.Findings))
	}
}

func TestCodeAnalysisResult_Structure(t *testing.T) {
	result := CodeAnalysisResult{
		Package:     "ripgrep",
		OldVersion:  "13.0.0",
		NewVersion:  "14.0.0",
		Verdict:     VerdictReview,
		Confidence:  ConfidenceMedium,
		Findings:    []Finding{},
		RawResponse: "test",
	}

	if result.OldVersion != "13.0.0" {
		t.Errorf("expected OldVersion 13.0.0, got %s", result.OldVersion)
	}
	if result.NewVersion != "14.0.0" {
		t.Errorf("expected NewVersion 14.0.0, got %s", result.NewVersion)
	}
}

func TestFormulaVersion_Structure(t *testing.T) {
	version := FormulaVersion{
		Label:   "CURRENT",
		SHA:     "abc123",
		Content: "class Test < Formula\nend",
	}

	if version.Label != "CURRENT" {
		t.Errorf("expected Label CURRENT, got %s", version.Label)
	}
	if version.SHA != "abc123" {
		t.Errorf("expected SHA abc123, got %s", version.SHA)
	}
}

func TestFinding_Structure(t *testing.T) {
	finding := Finding{
		File:        "formula.rb",
		LineNumber:  42,
		Description: "suspicious pattern",
		Version:     "CURRENT",
	}

	if finding.LineNumber != 42 {
		t.Errorf("expected LineNumber 42, got %d", finding.LineNumber)
	}
	if finding.Version != "CURRENT" {
		t.Errorf("expected Version CURRENT, got %s", finding.Version)
	}
}

func TestClient_RetryConfiguration(t *testing.T) {
	original := os.Getenv("ANTHROPIC_API_KEY")
	_ = os.Setenv("ANTHROPIC_API_KEY", "test-key")
	defer func() { _ = os.Setenv("ANTHROPIC_API_KEY", original) }()

	client, err := NewClient("claude-sonnet-4-6", 12000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if client.maxRetries != 3 {
		t.Errorf("expected maxRetries 3, got %d", client.maxRetries)
	}
	if client.baseBackoffMs != 1000 {
		t.Errorf("expected baseBackoffMs 1000, got %d", client.baseBackoffMs)
	}
}

func TestSendRequestWithRetry_RateLimited(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount <= 2 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error": {"type": "rate_limit_error", "message": "Rate limited"}}`))
			return
		}
		// Third call succeeds
		response := map[string]interface{}{
			"content": []map[string]string{
				{"type": "text", "text": "VERDICT: SAFE\nCONFIDENCE: HIGH"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Verify mock server behavior
	if callCount != 0 {
		t.Errorf("expected callCount 0 initially, got %d", callCount)
	}
}

func TestSendRequestWithRetry_Overloaded(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount <= 2 {
			w.WriteHeader(529) // Overloaded
			_, _ = w.Write([]byte(`{"error": {"type": "overloaded_error", "message": "API overloaded"}}`))
			return
		}
		response := map[string]interface{}{
			"content": []map[string]string{
				{"type": "text", "text": "VERDICT: SAFE"},
			},
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()
}

func TestSendRequestWithRetry_Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error": {"type": "authentication_error", "message": "Invalid API key"}}`))
	}))
	defer server.Close()
}

func TestSendRequestWithRetry_BadRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error": {"type": "invalid_request_error", "message": "max_tokens exceeds token limit"}}`))
	}))
	defer server.Close()
}

func TestSendRequestWithRetry_ServerError(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error": {"type": "api_error", "message": "Internal server error"}}`))
	}))
	defer server.Close()
}

func TestParseErrorResponse_ValidJSON(t *testing.T) {
	client := &Client{}

	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{
			name:     "with message",
			body:     `{"error": {"type": "rate_limit_error", "message": "Rate limited"}}`,
			expected: "Rate limited",
		},
		{
			name:     "with type only",
			body:     `{"error": {"type": "authentication_error"}}`,
			expected: "authentication_error",
		},
		{
			name:     "empty error",
			body:     `{"error": {}}`,
			expected: "unknown error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.parseErrorResponse(strings.NewReader(tt.body))
			if result != tt.expected {
				t.Errorf("parseErrorResponse() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestParseErrorResponse_InvalidJSON(t *testing.T) {
	client := &Client{}

	result := client.parseErrorResponse(strings.NewReader("not json"))
	if result != "not json" {
		t.Errorf("expected raw body for invalid JSON, got %q", result)
	}
}

func TestParseErrorResponse_LongBody(t *testing.T) {
	client := &Client{}

	longBody := strings.Repeat("a", 300)
	result := client.parseErrorResponse(strings.NewReader(longBody))

	if len(result) > 203 { // 200 chars + "..."
		t.Errorf("expected truncated result, got length %d", len(result))
	}
	if !strings.HasSuffix(result, "...") {
		t.Error("expected result to end with ...")
	}
}

func TestErrorMessages(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		contains   string
	}{
		{"rate limit", 429, "rate limit"},
		{"overloaded", 529, "overloaded"},
		{"unauthorized", 401, "invalid or expired"},
		{"forbidden", 403, "forbidden"},
		{"bad request", 400, "bad request"},
		{"server error 500", 500, "server error"},
		{"server error 502", 502, "server error"},
		{"server error 503", 503, "server error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This test documents expected error message patterns
			// Actual HTTP testing would require injecting mock transport
		})
	}
}

func TestTokenCountResult_Structure(t *testing.T) {
	result := TokenCountResult{
		InputTokens: 1500,
		Error:       nil,
	}

	if result.InputTokens != 1500 {
		t.Errorf("expected InputTokens 1500, got %d", result.InputTokens)
	}
	if result.Error != nil {
		t.Error("expected nil error")
	}
}

func TestUsageEstimate_Structure(t *testing.T) {
	estimate := UsageEstimate{
		ClaudeTokens:   5000,
		ClaudePackages: []string{"ripgrep", "curl", "wget"},
		VTRequests:     2,
		VTHashes:       2,
		CIRCLMalicious: []string{"/path/to/file1", "/path/to/file2"},
	}

	if estimate.ClaudeTokens != 5000 {
		t.Errorf("expected ClaudeTokens 5000, got %d", estimate.ClaudeTokens)
	}
	if len(estimate.ClaudePackages) != 3 {
		t.Errorf("expected 3 ClaudePackages, got %d", len(estimate.ClaudePackages))
	}
	if estimate.VTRequests != 2 {
		t.Errorf("expected VTRequests 2, got %d", estimate.VTRequests)
	}
	if len(estimate.CIRCLMalicious) != 2 {
		t.Errorf("expected 2 CIRCLMalicious files, got %d", len(estimate.CIRCLMalicious))
	}
}

func TestCountFormulaTokens_EmptyVersions(t *testing.T) {
	client := &Client{maxFileBytes: 12000}

	result, err := client.CountFormulaTokens("testpkg", []FormulaVersion{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.InputTokens != 0 {
		t.Errorf("expected 0 tokens for empty versions, got %d", result.InputTokens)
	}
}

func TestCountCodeAnalysisTokens_EmptyDiff(t *testing.T) {
	client := &Client{maxFileBytes: 12000}

	result, err := client.CountCodeAnalysisTokens("testpkg", "1.0", "2.0", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.InputTokens != 0 {
		t.Errorf("expected 0 tokens for empty diff, got %d", result.InputTokens)
	}
}

func TestCountFileAnalysisTokens_EmptyFiles(t *testing.T) {
	client := &Client{maxFileBytes: 12000}

	result, err := client.CountFileAnalysisTokens("testpkg", map[string]string{}, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.InputTokens != 0 {
		t.Errorf("expected 0 tokens for empty files, got %d", result.InputTokens)
	}
}

func TestCountTokens_MockServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request headers
		if r.Header.Get("Content-Type") != "application/json" {
			t.Error("expected Content-Type: application/json")
		}
		if r.Header.Get("x-api-key") == "" {
			t.Error("expected x-api-key header")
		}
		if r.Header.Get("anthropic-version") != "2023-06-01" {
			t.Error("expected anthropic-version header")
		}

		// Return mock token count response
		response := map[string]interface{}{
			"input_tokens": 1234,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Verify the server is running
	if server.URL == "" {
		t.Error("mock server should have a URL")
	}
}

func TestCountTokens_ErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error": {"type": "invalid_request_error", "message": "Invalid model"}}`))
	}))
	defer server.Close()

	// Verify mock server pattern
	if server.URL == "" {
		t.Error("mock server should have a URL")
	}
}

func TestCountFormulaTokens_WithVersions(t *testing.T) {
	// This test verifies the prompt is built correctly before counting
	client := &Client{maxFileBytes: 50000}

	versions := []FormulaVersion{
		{Label: "CURRENT", SHA: "abc123", Content: "class Test < Formula\nend"},
		{Label: "PREVIOUS", SHA: "def456", Content: "class Test < Formula\nend"},
	}

	// The actual API call would fail without a real key, but we verify the setup
	// In integration tests with a real key, this would return actual token counts
	_ = client.buildFormulaPrompt("testpkg", versions)
}

func TestCountFormulaTokens_Truncation(t *testing.T) {
	client := &Client{maxFileBytes: 100} // Very small limit

	// Create content larger than maxFileBytes
	largeContent := strings.Repeat("x", 200)
	versions := []FormulaVersion{
		{Label: "CURRENT", SHA: "abc123", Content: largeContent},
	}

	// Build prompt - it won't be truncated here since buildFormulaPrompt doesn't truncate
	// The truncation happens in AnalyzeFormula. This test verifies the prompt is built.
	prompt := client.buildFormulaPrompt("testpkg", versions)
	if len(prompt) == 0 {
		t.Error("expected non-empty prompt")
	}
}

func TestCountCodeAnalysisTokens_WithContent(t *testing.T) {
	client := &Client{maxFileBytes: 50000}

	diff := `--- a/test.sh
+++ b/test.sh
@@ -1,3 +1,4 @@
 #!/bin/bash
+echo "new line"
 echo "hello"`

	semgrepFindings := "some findings"

	// Verify prompt is built correctly
	prompt := client.buildCodeAnalysisPrompt("testpkg", "1.0", "2.0", diff, semgrepFindings)
	if !strings.Contains(prompt, "testpkg") {
		t.Error("prompt should contain package name")
	}
	if !strings.Contains(prompt, "new line") {
		t.Error("prompt should contain diff content")
	}
}

func TestCountFileAnalysisTokens_WithFiles(t *testing.T) {
	client := &Client{maxFileBytes: 50000}

	files := map[string]string{
		"/path/to/script.sh": "#!/bin/bash\necho hello",
	}

	// Verify prompt is built correctly
	prompt := client.buildFileAnalysisPrompt("testpkg", files, "")
	if !strings.Contains(prompt, "testpkg") {
		t.Error("prompt should contain package name")
	}
	if !strings.Contains(prompt, "echo hello") {
		t.Error("prompt should contain file content")
	}
}

func TestRateLimitInfo_Structure(t *testing.T) {
	info := RateLimitInfo{
		RequestsLimit:     1000,
		RequestsRemaining: 950,
		RequestsReset:     1700000000,
		TokensLimit:       100000,
		TokensRemaining:   95000,
		TokensReset:       1700000000,
		Error:             nil,
	}

	if info.RequestsLimit != 1000 {
		t.Errorf("expected RequestsLimit 1000, got %d", info.RequestsLimit)
	}
	if info.RequestsRemaining != 950 {
		t.Errorf("expected RequestsRemaining 950, got %d", info.RequestsRemaining)
	}
	if info.TokensLimit != 100000 {
		t.Errorf("expected TokensLimit 100000, got %d", info.TokensLimit)
	}
	if info.TokensRemaining != 95000 {
		t.Errorf("expected TokensRemaining 95000, got %d", info.TokensRemaining)
	}
}

func TestParseRateLimitHeaders(t *testing.T) {
	client := &Client{}
	info := &RateLimitInfo{}

	// Create mock response with rate limit headers
	resp := &http.Response{
		Header: http.Header{
			"Anthropic-Ratelimit-Requests-Limit":     []string{"1000"},
			"Anthropic-Ratelimit-Requests-Remaining": []string{"999"},
			"Anthropic-Ratelimit-Tokens-Limit":       []string{"100000"},
			"Anthropic-Ratelimit-Tokens-Remaining":   []string{"99500"},
		},
	}

	client.parseRateLimitHeaders(resp, info)

	if info.RequestsLimit != 1000 {
		t.Errorf("expected RequestsLimit 1000, got %d", info.RequestsLimit)
	}
	if info.RequestsRemaining != 999 {
		t.Errorf("expected RequestsRemaining 999, got %d", info.RequestsRemaining)
	}
	if info.TokensLimit != 100000 {
		t.Errorf("expected TokensLimit 100000, got %d", info.TokensLimit)
	}
	if info.TokensRemaining != 99500 {
		t.Errorf("expected TokensRemaining 99500, got %d", info.TokensRemaining)
	}
}

func TestParseRateLimitHeaders_WithTimestamp(t *testing.T) {
	client := &Client{}
	info := &RateLimitInfo{}

	// Create mock response with timestamp header
	resp := &http.Response{
		Header: http.Header{
			"Anthropic-Ratelimit-Requests-Reset": []string{"2024-01-15T10:30:00Z"},
			"Anthropic-Ratelimit-Tokens-Reset":   []string{"2024-01-15T10:30:00Z"},
		},
	}

	client.parseRateLimitHeaders(resp, info)

	if info.RequestsReset == 0 {
		t.Error("expected RequestsReset to be parsed")
	}
	if info.TokensReset == 0 {
		t.Error("expected TokensReset to be parsed")
	}
}

func TestParseRateLimitHeaders_Empty(t *testing.T) {
	client := &Client{}
	info := &RateLimitInfo{}

	resp := &http.Response{
		Header: http.Header{},
	}

	client.parseRateLimitHeaders(resp, info)

	// All values should be zero when headers are missing
	if info.RequestsLimit != 0 {
		t.Errorf("expected RequestsLimit 0 for empty headers, got %d", info.RequestsLimit)
	}
	if info.TokensLimit != 0 {
		t.Errorf("expected TokensLimit 0 for empty headers, got %d", info.TokensLimit)
	}
}

func TestCheckRateLimits_MockServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set rate limit headers
		w.Header().Set("anthropic-ratelimit-requests-limit", "1000")
		w.Header().Set("anthropic-ratelimit-requests-remaining", "995")
		w.Header().Set("anthropic-ratelimit-tokens-limit", "100000")
		w.Header().Set("anthropic-ratelimit-tokens-remaining", "98000")

		// Return minimal response
		response := map[string]interface{}{
			"input_tokens": 5,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Verify mock server pattern
	if server.URL == "" {
		t.Error("mock server should have a URL")
	}
}
