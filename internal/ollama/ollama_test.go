package ollama

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewClient(t *testing.T) {
	client := NewClient("http://localhost:11434", "gemma3", 12000)

	if client.baseURL != "http://localhost:11434/api/generate" {
		t.Errorf("expected baseURL to include /api/generate, got %s", client.baseURL)
	}
	if client.model != "gemma3" {
		t.Errorf("expected model 'gemma3', got %s", client.model)
	}
	if client.maxFileBytes != 12000 {
		t.Errorf("expected maxFileBytes 12000, got %d", client.maxFileBytes)
	}
}

func TestNewClient_TrailingSlash(t *testing.T) {
	client := NewClient("http://localhost:11434/", "llama3", 8000)

	if client.baseURL != "http://localhost:11434/api/generate" {
		t.Errorf("expected trailing slash to be trimmed, got %s", client.baseURL)
	}
}

func TestParseResponse_Safe(t *testing.T) {
	client := NewClient("http://localhost:11434", "gemma3", 12000)
	result := &FormulaAnalysisResult{}

	response := `Based on my analysis of the formula versions:

VERDICT: SAFE
CONFIDENCE: HIGH
FINDINGS:
- [No suspicious patterns detected]`

	client.parseResponse(response, result)

	if result.Verdict != VerdictSafe {
		t.Errorf("expected SAFE verdict, got %s", result.Verdict)
	}
	if result.Confidence != ConfidenceHigh {
		t.Errorf("expected HIGH confidence, got %s", result.Confidence)
	}
}

func TestParseResponse_Hold(t *testing.T) {
	client := NewClient("http://localhost:11434", "gemma3", 12000)
	result := &FormulaAnalysisResult{}

	response := `This formula contains malicious patterns:

VERDICT: HOLD
CONFIDENCE: HIGH
FINDINGS:
- [CURRENT, line 25, base64 decode piped to shell, obfuscated code execution]
- [CURRENT, line 30, hardcoded IP address 192.168.1.1, potential C2 server]`

	client.parseResponse(response, result)

	if result.Verdict != VerdictHold {
		t.Errorf("expected HOLD verdict, got %s", result.Verdict)
	}
	if len(result.Findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(result.Findings))
	}
}

func TestParseResponse_Review(t *testing.T) {
	client := NewClient("http://localhost:11434", "gemma3", 12000)
	result := &FormulaAnalysisResult{}

	response := `Some patterns require human review:

VERDICT: REVIEW
CONFIDENCE: MEDIUM
FINDINGS:
- [CURRENT, line 15, new domain in URL, may be legitimate mirror]`

	client.parseResponse(response, result)

	if result.Verdict != VerdictReview {
		t.Errorf("expected REVIEW verdict, got %s", result.Verdict)
	}
	if result.Confidence != ConfidenceMedium {
		t.Errorf("expected MEDIUM confidence, got %s", result.Confidence)
	}
}

func TestParseResponse_DefaultsOnInvalid(t *testing.T) {
	client := NewClient("http://localhost:11434", "gemma3", 12000)
	result := &FormulaAnalysisResult{}

	response := `I cannot determine the verdict clearly.`

	client.parseResponse(response, result)

	if result.Verdict != VerdictReview {
		t.Errorf("expected default REVIEW verdict, got %s", result.Verdict)
	}
	if result.Confidence != ConfidenceMedium {
		t.Errorf("expected default MEDIUM confidence, got %s", result.Confidence)
	}
}

func TestParseCodeResponse_Safe(t *testing.T) {
	client := NewClient("http://localhost:11434", "gemma3", 12000)
	result := &CodeAnalysisResult{}

	response := `The code changes appear safe:

VERDICT: SAFE
CONFIDENCE: HIGH
FINDINGS:
- [No malicious patterns detected in diff]`

	client.parseCodeResponse(response, result)

	if result.Verdict != VerdictSafe {
		t.Errorf("expected SAFE verdict, got %s", result.Verdict)
	}
}

func TestParseCodeResponse_Hold(t *testing.T) {
	client := NewClient("http://localhost:11434", "gemma3", 12000)
	result := &CodeAnalysisResult{}

	response := `CRITICAL: Malicious code detected:

VERDICT: HOLD
CONFIDENCE: HIGH
FINDINGS:
- [src/main.py, line 42, reverse shell to 10.0.0.1:443, command execution]
- [src/install.sh, line 10, credential harvesting from ~/.ssh, exfiltration]`

	client.parseCodeResponse(response, result)

	if result.Verdict != VerdictHold {
		t.Errorf("expected HOLD verdict, got %s", result.Verdict)
	}
	if len(result.Findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(result.Findings))
	}
}

func TestAnalyzeFormula_NoVersions(t *testing.T) {
	client := NewClient("http://localhost:11434", "gemma3", 12000)

	result, err := client.AnalyzeFormula("test-pkg", []FormulaVersion{})

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result.Error == nil {
		t.Error("expected error for empty versions")
	}
}

func TestAnalyzeCode_EmptyDiff(t *testing.T) {
	client := NewClient("http://localhost:11434", "gemma3", 12000)

	result, err := client.AnalyzeCode("test-pkg", "1.0.0", "1.0.1", "", "")

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result.Verdict != VerdictSafe {
		t.Errorf("expected SAFE verdict for empty diff, got %s", result.Verdict)
	}
}

func TestAnalyzeFiles_Empty(t *testing.T) {
	client := NewClient("http://localhost:11434", "gemma3", 12000)

	result, err := client.AnalyzeFiles("test-pkg", map[string]string{}, "")

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result.Verdict != VerdictSafe {
		t.Errorf("expected SAFE verdict for empty files, got %s", result.Verdict)
	}
}

func TestBuildFormulaPrompt(t *testing.T) {
	client := NewClient("http://localhost:11434", "gemma3", 12000)

	versions := []FormulaVersion{
		{Label: "CURRENT", SHA: "abc123", Content: "class Test < Formula\nend"},
		{Label: "PREVIOUS", SHA: "def456", Content: "class Test < Formula\nend"},
	}

	prompt := client.buildFormulaPrompt("test-pkg", versions)

	if prompt == "" {
		t.Error("expected non-empty prompt")
	}
	// Check key elements are in the prompt
	if !contains(prompt, "test-pkg") {
		t.Error("expected package name in prompt")
	}
	if !contains(prompt, "CURRENT") {
		t.Error("expected CURRENT label in prompt")
	}
	if !contains(prompt, "PREVIOUS") {
		t.Error("expected PREVIOUS label in prompt")
	}
	if !contains(prompt, "VERDICT") {
		t.Error("expected VERDICT instruction in prompt")
	}
}

func TestBuildCodeAnalysisPrompt(t *testing.T) {
	client := NewClient("http://localhost:11434", "gemma3", 12000)

	prompt := client.buildCodeAnalysisPrompt("test-pkg", "1.0.0", "1.0.1", "+ new line", "")

	if prompt == "" {
		t.Error("expected non-empty prompt")
	}
	if !contains(prompt, "test-pkg") {
		t.Error("expected package name in prompt")
	}
	if !contains(prompt, "1.0.0 → 1.0.1") {
		t.Error("expected version info in prompt")
	}
	if !contains(prompt, "+ new line") {
		t.Error("expected diff in prompt")
	}
}

func TestBuildFileAnalysisPrompt(t *testing.T) {
	client := NewClient("http://localhost:11434", "gemma3", 12000)

	files := map[string]string{
		"/path/to/file.py": "import os\nos.system('ls')",
	}

	prompt := client.buildFileAnalysisPrompt("test-pkg", files, "Semgrep found secrets")

	if prompt == "" {
		t.Error("expected non-empty prompt")
	}
	if !contains(prompt, "test-pkg") {
		t.Error("expected package name in prompt")
	}
	if !contains(prompt, "/path/to/file.py") {
		t.Error("expected file path in prompt")
	}
	if !contains(prompt, "Semgrep found secrets") {
		t.Error("expected semgrep findings in prompt")
	}
}

func TestCheckAvailability_Success(t *testing.T) {
	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		response := map[string]interface{}{
			"model":    "gemma3",
			"response": "test",
			"done":     true,
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL, "gemma3", 12000)
	err := client.CheckAvailability()

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestCheckAvailability_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("model not found"))
	}))
	defer server.Close()

	client := NewClient(server.URL, "nonexistent", 12000)
	err := client.CheckAvailability()

	if err == nil {
		t.Error("expected error for server error response")
	}
}

func TestSendRequest_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		response := map[string]interface{}{
			"model":    "gemma3",
			"response": "VERDICT: SAFE\nCONFIDENCE: HIGH",
			"done":     true,
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL, "gemma3", 12000)
	response, err := client.sendRequest("test prompt")

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if response == "" {
		t.Error("expected non-empty response")
	}
}

func TestSendRequest_EmptyResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		response := map[string]interface{}{
			"model":    "gemma3",
			"response": "",
			"done":     true,
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL, "gemma3", 12000)
	_, err := client.sendRequest("test prompt")

	if err == nil {
		t.Error("expected error for empty response")
	}
}

func TestAnalyzeFormula_WithMockServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		response := map[string]interface{}{
			"model":    "gemma3",
			"response": "VERDICT: SAFE\nCONFIDENCE: HIGH\nFINDINGS:\n- [No issues found]",
			"done":     true,
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL, "gemma3", 12000)

	versions := []FormulaVersion{
		{Label: "CURRENT", Content: "class Test < Formula\nend"},
	}

	result, err := client.AnalyzeFormula("test-pkg", versions)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result.Verdict != VerdictSafe {
		t.Errorf("expected SAFE verdict, got %s", result.Verdict)
	}
}

func TestAnalyzeFormula_Truncation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		response := map[string]interface{}{
			"model":    "gemma3",
			"response": "VERDICT: SAFE\nCONFIDENCE: HIGH",
			"done":     true,
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	// Create client with small maxFileBytes
	client := NewClient(server.URL, "gemma3", 100)

	// Create a large formula content
	largeContent := ""
	for i := 0; i < 200; i++ {
		largeContent += "x"
	}

	versions := []FormulaVersion{
		{Label: "CURRENT", Content: largeContent},
	}

	result, err := client.AnalyzeFormula("test-pkg", versions)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !result.Truncated {
		t.Error("expected truncation flag to be set")
	}
}

func TestVerdictConstants(t *testing.T) {
	if VerdictSafe != "SAFE" {
		t.Errorf("expected SAFE, got %s", VerdictSafe)
	}
	if VerdictReview != "REVIEW" {
		t.Errorf("expected REVIEW, got %s", VerdictReview)
	}
	if VerdictHold != "HOLD" {
		t.Errorf("expected HOLD, got %s", VerdictHold)
	}
}

func TestConfidenceConstants(t *testing.T) {
	if ConfidenceHigh != "HIGH" {
		t.Errorf("expected HIGH, got %s", ConfidenceHigh)
	}
	if ConfidenceMedium != "MEDIUM" {
		t.Errorf("expected MEDIUM, got %s", ConfidenceMedium)
	}
	if ConfidenceLow != "LOW" {
		t.Errorf("expected LOW, got %s", ConfidenceLow)
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
