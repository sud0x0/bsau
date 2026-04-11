package hashlookup

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/sud0x0/bsau/internal/state"
)

// VTClient provides access to the VirusTotal API
type VTClient struct {
	apiKey        string
	httpClient    *http.Client
	vtDaily       *state.VTDailyManager
	dailyLimit    int
	rateLimit     int // per minute
	rateMu        sync.Mutex
	lastRequest   time.Time
	requestCount  int
	warned80Pct   bool // Track if we've warned about 80% usage
	maxRetries    int  // Max retries for 429 errors
	baseBackoffMs int  // Base backoff in milliseconds
}

// VTResponse represents the VirusTotal API response
type VTResponse struct {
	Data struct {
		Attributes struct {
			LastAnalysisStats struct {
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Harmless   int `json:"harmless"`
				Undetected int `json:"undetected"`
			} `json:"last_analysis_stats"`
			LastAnalysisDate int64 `json:"last_analysis_date"`
		} `json:"attributes"`
	} `json:"data"`
}

// VTLookupResult represents the outcome of a VT lookup
type VTLookupResult struct {
	Hash        string
	Found       bool
	Malicious   int
	Suspicious  int
	Harmless    int
	Undetected  int
	IsConfirmed bool // True if malicious+suspicious > 0
	Error       error
}

// NewVTClient creates a new VirusTotal client
func NewVTClient(dailyLimit, rateLimit int) (*VTClient, error) {
	apiKey := os.Getenv("VIRUSTOTAL_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("VIRUSTOTAL_API_KEY not set")
	}

	vtDaily, err := state.NewVTDailyManager()
	if err != nil {
		return nil, fmt.Errorf("initializing VT daily manager: %w", err)
	}

	return &VTClient{
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		vtDaily:       vtDaily,
		dailyLimit:    dailyLimit,
		rateLimit:     rateLimit,
		warned80Pct:   false,
		maxRetries:    3,
		baseBackoffMs: 1000, // 1 second base backoff
	}, nil
}

// LookupSHA256 queries VirusTotal for a SHA256 hash
// This should ONLY be called for hashes that CIRCL flagged as malicious
func (c *VTClient) LookupSHA256(hash string) *VTLookupResult {
	result := &VTLookupResult{Hash: hash}

	// Check daily limit
	canSubmit, err := c.vtDaily.CanSubmit(c.dailyLimit)
	if err != nil {
		result.Error = fmt.Errorf("checking VT daily limit: %w", err)
		return result
	}
	if !canSubmit {
		result.Error = fmt.Errorf("VT daily limit (%d) reached", c.dailyLimit)
		return result
	}

	// Check for 80% warning
	if !c.warned80Pct {
		usagePct, err := c.vtDaily.UsagePercent(c.dailyLimit)
		if err == nil && usagePct >= 80.0 {
			c.warned80Pct = true
			fmt.Printf("WARNING: VirusTotal API usage at %.0f%% of daily limit (%d/%d)\n",
				usagePct, int(float64(c.dailyLimit)*usagePct/100), c.dailyLimit)
		}
	}

	// Rate limiting - 4 requests per minute for free tier
	c.rateMu.Lock()
	now := time.Now()
	if now.Sub(c.lastRequest) < time.Minute {
		if c.requestCount >= c.rateLimit {
			waitTime := time.Minute - now.Sub(c.lastRequest)
			c.rateMu.Unlock()
			time.Sleep(waitTime)
			c.rateMu.Lock()
			c.requestCount = 0
		}
	} else {
		c.requestCount = 0
	}
	c.lastRequest = now
	c.requestCount++
	c.rateMu.Unlock()

	// Execute request with exponential backoff for 429 errors
	return c.executeWithRetry(hash, 0)
}

// executeWithRetry performs the VT API request with exponential backoff
func (c *VTClient) executeWithRetry(hash string, attempt int) *VTLookupResult {
	result := &VTLookupResult{Hash: hash}

	url := fmt.Sprintf("https://www.virustotal.com/api/v3/files/%s", hash)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		result.Error = fmt.Errorf("creating request: %w", err)
		return result
	}

	req.Header.Set("x-apikey", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		result.Error = fmt.Errorf("making request to VT: %w", err)
		return result
	}
	defer func() { _ = resp.Body.Close() }()

	// Increment daily count (non-fatal if it fails)
	_ = c.vtDaily.Increment()

	switch resp.StatusCode {
	case http.StatusOK:
		var vtResp VTResponse
		if err := json.NewDecoder(resp.Body).Decode(&vtResp); err != nil {
			result.Error = fmt.Errorf("decoding VT response: %w", err)
			return result
		}

		stats := vtResp.Data.Attributes.LastAnalysisStats
		result.Found = true
		result.Malicious = stats.Malicious
		result.Suspicious = stats.Suspicious
		result.Harmless = stats.Harmless
		result.Undetected = stats.Undetected
		result.IsConfirmed = (stats.Malicious + stats.Suspicious) > 0
		return result

	case http.StatusNotFound:
		// Hash not in VT database
		result.Found = false
		return result

	case http.StatusTooManyRequests:
		// Exponential backoff for 429 errors
		if attempt < c.maxRetries {
			backoffMs := c.baseBackoffMs * (1 << attempt) // 1s, 2s, 4s
			fmt.Printf("VT rate limited (429), backing off %dms (attempt %d/%d)\n",
				backoffMs, attempt+1, c.maxRetries)
			time.Sleep(time.Duration(backoffMs) * time.Millisecond)
			return c.executeWithRetry(hash, attempt+1)
		}
		result.Error = fmt.Errorf("VT rate limit exceeded (429) after %d retries", c.maxRetries)
		return result

	case http.StatusUnauthorized:
		result.Error = fmt.Errorf("VT API key invalid or expired")
		return result

	default:
		result.Error = fmt.Errorf("unexpected VT response: %d", resp.StatusCode)
		return result
	}
}

// DailyUsagePercent returns the percentage of daily limit used
func (c *VTClient) DailyUsagePercent() (float64, error) {
	return c.vtDaily.UsagePercent(c.dailyLimit)
}

// DailyCount returns the current daily request count
func (c *VTClient) DailyCount() (int, error) {
	return c.vtDaily.CurrentCount()
}

// QuotaInfo contains VirusTotal quota information
type QuotaInfo struct {
	DailyLimit     int
	DailyUsed      int
	DailyRemaining int
	RateLimit      int // per minute
	Error          error
}

// GetQuotaInfo returns the current VT quota status
func (c *VTClient) GetQuotaInfo() *QuotaInfo {
	info := &QuotaInfo{
		DailyLimit: c.dailyLimit,
		RateLimit:  c.rateLimit,
	}

	count, err := c.vtDaily.CurrentCount()
	if err != nil {
		info.Error = err
		return info
	}

	info.DailyUsed = count
	info.DailyRemaining = c.dailyLimit - count
	if info.DailyRemaining < 0 {
		info.DailyRemaining = 0
	}

	return info
}
