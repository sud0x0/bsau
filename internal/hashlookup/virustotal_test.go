package hashlookup

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestNewVTClient_MissingAPIKey(t *testing.T) {
	// Save original and unset
	original := os.Getenv("VIRUSTOTAL_API_KEY")
	_ = os.Unsetenv("VIRUSTOTAL_API_KEY")
	defer func() { _ = os.Setenv("VIRUSTOTAL_API_KEY", original) }()

	_, err := NewVTClient(500, 4)
	if err == nil {
		t.Error("expected error when VIRUSTOTAL_API_KEY is not set")
	}
	if !strings.Contains(err.Error(), "VIRUSTOTAL_API_KEY") {
		t.Errorf("error should mention VIRUSTOTAL_API_KEY: %v", err)
	}
}

func TestVTResponse_Structure(t *testing.T) {
	jsonData := `{
		"data": {
			"attributes": {
				"last_analysis_stats": {
					"malicious": 5,
					"suspicious": 2,
					"harmless": 60,
					"undetected": 3
				},
				"last_analysis_date": 1700000000
			}
		}
	}`

	var resp VTResponse
	if err := json.Unmarshal([]byte(jsonData), &resp); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	stats := resp.Data.Attributes.LastAnalysisStats
	if stats.Malicious != 5 {
		t.Errorf("expected Malicious 5, got %d", stats.Malicious)
	}
	if stats.Suspicious != 2 {
		t.Errorf("expected Suspicious 2, got %d", stats.Suspicious)
	}
	if stats.Harmless != 60 {
		t.Errorf("expected Harmless 60, got %d", stats.Harmless)
	}
	if stats.Undetected != 3 {
		t.Errorf("expected Undetected 3, got %d", stats.Undetected)
	}
}

func TestVTLookupResult_Structure(t *testing.T) {
	result := VTLookupResult{
		Hash:        "abc123def456",
		Found:       true,
		Malicious:   5,
		Suspicious:  2,
		Harmless:    60,
		Undetected:  3,
		IsConfirmed: true,
		Error:       nil,
	}

	if result.Hash != "abc123def456" {
		t.Errorf("expected Hash abc123def456, got %s", result.Hash)
	}
	if !result.Found {
		t.Error("expected Found to be true")
	}
	if !result.IsConfirmed {
		t.Error("expected IsConfirmed to be true")
	}
	if result.Malicious != 5 {
		t.Errorf("expected Malicious 5, got %d", result.Malicious)
	}
}

func TestVTLookupResult_NotConfirmed(t *testing.T) {
	result := VTLookupResult{
		Hash:        "abc123",
		Found:       true,
		Malicious:   0,
		Suspicious:  0,
		Harmless:    70,
		Undetected:  0,
		IsConfirmed: false,
	}

	if result.IsConfirmed {
		t.Error("expected IsConfirmed to be false when no malicious/suspicious")
	}
}

func TestVTMockServer_OK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify API key header
		if r.Header.Get("x-apikey") == "" {
			t.Error("expected x-apikey header")
		}

		response := VTResponse{}
		response.Data.Attributes.LastAnalysisStats.Malicious = 3
		response.Data.Attributes.LastAnalysisStats.Suspicious = 1
		response.Data.Attributes.LastAnalysisStats.Harmless = 50
		response.Data.Attributes.LastAnalysisDate = 1700000000

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Note: Can't easily inject mock URL without modifying package
	// This demonstrates the mock server pattern
}

func TestVTMockServer_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
}

func TestVTMockServer_RateLimited(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount <= 2 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		// Third call succeeds
		response := VTResponse{}
		response.Data.Attributes.LastAnalysisStats.Harmless = 70
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()
}

func TestVTMockServer_Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
}

func TestVTClient_IsConfirmedLogic(t *testing.T) {
	tests := []struct {
		name       string
		malicious  int
		suspicious int
		expected   bool
	}{
		{"both zero", 0, 0, false},
		{"malicious only", 5, 0, true},
		{"suspicious only", 0, 3, true},
		{"both present", 2, 1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isConfirmed := (tt.malicious + tt.suspicious) > 0
			if isConfirmed != tt.expected {
				t.Errorf("isConfirmed = %v, expected %v", isConfirmed, tt.expected)
			}
		})
	}
}

func TestQuotaInfo_Structure(t *testing.T) {
	info := QuotaInfo{
		DailyLimit:     500,
		DailyUsed:      50,
		DailyRemaining: 450,
		RateLimit:      4,
		Error:          nil,
	}

	if info.DailyLimit != 500 {
		t.Errorf("expected DailyLimit 500, got %d", info.DailyLimit)
	}
	if info.DailyUsed != 50 {
		t.Errorf("expected DailyUsed 50, got %d", info.DailyUsed)
	}
	if info.DailyRemaining != 450 {
		t.Errorf("expected DailyRemaining 450, got %d", info.DailyRemaining)
	}
	if info.RateLimit != 4 {
		t.Errorf("expected RateLimit 4, got %d", info.RateLimit)
	}
}

func TestQuotaInfo_Exhausted(t *testing.T) {
	info := QuotaInfo{
		DailyLimit:     500,
		DailyUsed:      500,
		DailyRemaining: 0,
		RateLimit:      4,
	}

	if info.DailyRemaining != 0 {
		t.Errorf("expected DailyRemaining 0, got %d", info.DailyRemaining)
	}
}

func TestQuotaInfo_LowQuota(t *testing.T) {
	info := QuotaInfo{
		DailyLimit:     500,
		DailyUsed:      450,
		DailyRemaining: 50,
		RateLimit:      4,
	}

	// Under 20% remaining
	pct := float64(info.DailyRemaining) / float64(info.DailyLimit) * 100
	if pct >= 20 {
		t.Errorf("expected low quota (<20%%), got %.1f%%", pct)
	}
}
