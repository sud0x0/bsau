package ollama

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewClient(t *testing.T) {
	client := NewClient("http://localhost:11434", "gemma3", 12000)

	if client.baseURL != "http://localhost:11434/api/chat" {
		t.Errorf("expected baseURL to include /api/chat, got %s", client.baseURL)
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

	if client.baseURL != "http://localhost:11434/api/chat" {
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

func TestCheckAvailability_Success(t *testing.T) {
	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		response := chatResponse{
			Model: "gemma3",
			Done:  true,
		}
		response.Message.Role = "assistant"
		response.Message.Content = "test"
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

func TestSendChatRequest_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		response := chatResponse{
			Model: "gemma3",
			Done:  true,
		}
		response.Message.Role = "assistant"
		response.Message.Content = "VERDICT: SAFE\nCONFIDENCE: HIGH"
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL, "gemma3", 12000)
	response, err := client.sendChatRequest("system prompt", "user prompt")

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if response == "" {
		t.Error("expected non-empty response")
	}
}

func TestSendChatRequest_EmptyResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		response := chatResponse{
			Model: "gemma3",
			Done:  true,
		}
		response.Message.Role = "assistant"
		response.Message.Content = ""
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL, "gemma3", 12000)
	_, err := client.sendChatRequest("system prompt", "user prompt")

	if err == nil {
		t.Error("expected error for empty response")
	}
}

func TestAnalyzeFormula_WithMockServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		response := chatResponse{
			Model: "gemma3",
			Done:  true,
		}
		response.Message.Role = "assistant"
		response.Message.Content = "VERDICT: SAFE\nCONFIDENCE: HIGH\nFINDINGS:\n- [No issues found]"
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

func TestChunkContent(t *testing.T) {
	// Test small content (under ChunkSize lines)
	smallContent := "line1\nline2\nline3"
	chunks := chunkContent(smallContent)
	if len(chunks) != 1 {
		t.Errorf("expected 1 chunk for small content, got %d", len(chunks))
	}
	if chunks[0] != smallContent {
		t.Error("expected small content to be returned unchanged")
	}

	// Test large content (over ChunkSize lines)
	var lines []string
	for i := 0; i < 100; i++ {
		lines = append(lines, "line")
	}
	largeContent := ""
	for i, line := range lines {
		if i > 0 {
			largeContent += "\n"
		}
		largeContent += line
	}

	chunks = chunkContent(largeContent)
	if len(chunks) < 2 {
		t.Errorf("expected multiple chunks for large content, got %d", len(chunks))
	}
}

func TestVerdictPriority(t *testing.T) {
	if verdictPriority(VerdictSafe) != 1 {
		t.Error("SAFE should have priority 1")
	}
	if verdictPriority(VerdictReview) != 2 {
		t.Error("REVIEW should have priority 2")
	}
	if verdictPriority(VerdictHold) != 3 {
		t.Error("HOLD should have priority 3")
	}
	if verdictPriority("UNKNOWN") != 0 {
		t.Error("Unknown verdict should have priority 0")
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

func TestPromptConstants(t *testing.T) {
	// Verify prompts are defined and non-empty
	if SystemPrompt == "" {
		t.Error("SystemPrompt should not be empty")
	}
	if UserPromptFileAnalysis == "" {
		t.Error("UserPromptFileAnalysis should not be empty")
	}
	if UserPromptFormulaAnalysis == "" {
		t.Error("UserPromptFormulaAnalysis should not be empty")
	}
	if UserPromptDiffAnalysis == "" {
		t.Error("UserPromptDiffAnalysis should not be empty")
	}
	if ChunkSize <= 0 {
		t.Error("ChunkSize should be positive")
	}
	if ChunkOverlap < 0 {
		t.Error("ChunkOverlap should not be negative")
	}
}
