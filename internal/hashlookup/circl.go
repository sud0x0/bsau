package hashlookup

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// CIRCLClient provides access to the CIRCL hashlookup service
type CIRCLClient struct {
	baseURL    string
	httpClient *http.Client
}

// CIRCLResponse represents the response from CIRCL hashlookup
type CIRCLResponse struct {
	SHA256         string `json:"SHA-256"`
	SHA1           string `json:"SHA-1"`
	MD5            string `json:"MD5"`
	FileName       string `json:"FileName"`
	FileSize       int64  `json:"FileSize"`
	ProductCode    string `json:"ProductCode"`
	OpSystemCode   string `json:"OpSystemCode"`
	KnownMalicious bool   `json:"KnownMalicious"`
}

// NewCIRCLClient creates a new CIRCL hashlookup client
func NewCIRCLClient(baseURL string) *CIRCLClient {
	if baseURL == "" {
		baseURL = "https://hashlookup.circl.lu"
	}

	return &CIRCLClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// CIRCLLookupResult represents the outcome of a CIRCL lookup
type CIRCLLookupResult struct {
	Hash      string
	Found     bool
	Malicious bool
	Response  *CIRCLResponse
	Error     error
}

// LookupSHA256 queries CIRCL for a SHA256 hash
// Returns:
// - Found=false: NOT_IN_CIRCL (404)
// - Found=true, Malicious=false: NOT_FLAGGED_BY_CIRCL
// - Found=true, Malicious=true: CIRCL_MALICIOUS (should escalate to VT)
func (c *CIRCLClient) LookupSHA256(hash string) *CIRCLLookupResult {
	result := &CIRCLLookupResult{Hash: hash}

	url := fmt.Sprintf("%s/lookup/sha256/%s", c.baseURL, hash)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		result.Error = fmt.Errorf("creating request: %w", err)
		return result
	}

	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		result.Error = fmt.Errorf("making request to CIRCL: %w", err)
		return result
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		var circlResp CIRCLResponse
		if err := json.NewDecoder(resp.Body).Decode(&circlResp); err != nil {
			result.Error = fmt.Errorf("decoding CIRCL response: %w", err)
			return result
		}
		result.Found = true
		result.Malicious = circlResp.KnownMalicious
		result.Response = &circlResp
		return result

	case http.StatusNotFound:
		// Hash not in CIRCL database - this is expected for most Homebrew binaries
		// NOT_IN_CIRCL - VT is never called for this case
		result.Found = false
		return result

	case http.StatusTooManyRequests:
		result.Error = fmt.Errorf("CIRCL rate limit exceeded")
		return result

	default:
		result.Error = fmt.Errorf("unexpected CIRCL response: %d", resp.StatusCode)
		return result
	}
}

// BulkLookup looks up multiple hashes
func (c *CIRCLClient) BulkLookup(hashes []string) []*CIRCLLookupResult {
	results := make([]*CIRCLLookupResult, 0, len(hashes))
	for _, hash := range hashes {
		results = append(results, c.LookupSHA256(hash))
	}
	return results
}
