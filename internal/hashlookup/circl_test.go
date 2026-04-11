package hashlookup

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewCIRCLClient(t *testing.T) {
	tests := []struct {
		name     string
		baseURL  string
		expected string
	}{
		{
			name:     "empty URL uses default",
			baseURL:  "",
			expected: "https://hashlookup.circl.lu",
		},
		{
			name:     "custom URL is used",
			baseURL:  "https://custom.example.com",
			expected: "https://custom.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewCIRCLClient(tt.baseURL)
			if client.baseURL != tt.expected {
				t.Errorf("expected baseURL %q, got %q", tt.expected, client.baseURL)
			}
		})
	}
}

func TestLookupSHA256_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewCIRCLClient(server.URL)
	result := client.LookupSHA256("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

	if result.Found {
		t.Error("expected Found to be false for 404 response")
	}
	if result.Malicious {
		t.Error("expected Malicious to be false for 404 response")
	}
	if result.Error != nil {
		t.Errorf("expected no error, got %v", result.Error)
	}
}

func TestLookupSHA256_FoundNotMalicious(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := CIRCLResponse{
			SHA256:         "abc123",
			KnownMalicious: false,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewCIRCLClient(server.URL)
	result := client.LookupSHA256("abc123")

	if !result.Found {
		t.Error("expected Found to be true")
	}
	if result.Malicious {
		t.Error("expected Malicious to be false")
	}
	if result.Error != nil {
		t.Errorf("expected no error, got %v", result.Error)
	}
}

func TestLookupSHA256_FoundMalicious(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := CIRCLResponse{
			SHA256:         "malicious123",
			KnownMalicious: true,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewCIRCLClient(server.URL)
	result := client.LookupSHA256("malicious123")

	if !result.Found {
		t.Error("expected Found to be true")
	}
	if !result.Malicious {
		t.Error("expected Malicious to be true")
	}
}

func TestLookupSHA256_RateLimited(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	client := NewCIRCLClient(server.URL)
	result := client.LookupSHA256("abc123")

	if result.Error == nil {
		t.Error("expected error for rate limited response")
	}
}

func TestBulkLookup(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewCIRCLClient(server.URL)
	hashes := []string{"hash1", "hash2", "hash3"}
	results := client.BulkLookup(hashes)

	if len(results) != 3 {
		t.Errorf("expected 3 results, got %d", len(results))
	}
	if callCount != 3 {
		t.Errorf("expected 3 API calls, got %d", callCount)
	}
}
