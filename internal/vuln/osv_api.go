package vuln

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/goark/go-cvss/v3/metric"
	"github.com/sud0x0/bsau/internal/ui"
)

//go:embed mapped-values.json
var mappedValuesData []byte

// MappedValuesFile is the structure of the embedded mapped-values.json
type MappedValuesFile struct {
	GeneratedAt string                     `json:"generated_at"`
	Mappings    map[string]*PackageMapping `json:"mappings"`
}

// PackageMapping represents a single package mapping entry
type PackageMapping struct {
	BrewName       string `json:"brew_name"`
	OSVEcosystem   string `json:"osv_ecosystem"`
	OSVPackageName string `json:"osv_package_name"`
	CPEVendor      string `json:"cpe_vendor"`
	CPEProduct     string `json:"cpe_product"`
	Confidence     string `json:"confidence"`
}

// packageMappings holds the parsed embedded mappings (populated at init)
var packageMappings map[string]*PackageMapping

func init() {
	var data MappedValuesFile
	if err := json.Unmarshal(mappedValuesData, &data); err != nil {
		return
	}
	packageMappings = data.Mappings
}

const (
	osvBatchURL = "https://api.osv.dev/v1/querybatch"
	osvVulnURL  = "https://api.osv.dev/v1/vulns/"
	nvdCVEURL   = "https://services.nvd.nist.gov/rest/json/cves/2.0"

	maxConcurrentFetches = 5
	perRequestTimeout    = 10 * time.Second
	totalFetchTimeout    = 2 * time.Minute
	nvdRateLimitDelay    = 6 * time.Second // 5 requests per 30 seconds without API key
)

// VulnResult contains vulnerability scan results for a package
type VulnResult struct {
	Package     string
	Version     string
	Vulns       []VulnEntry
	CVECount    int
	MaxSeverity ui.Severity
}

// VulnEntry represents a single vulnerability
type VulnEntry struct {
	ID       string
	Summary  string
	Severity string
}

// OSVAPIClient queries OSV and NIST APIs for vulnerabilities
type OSVAPIClient struct {
	httpClient *http.Client
}

// PackageInfo contains information needed to query for vulnerabilities
type PackageInfo struct {
	Name      string
	Version   string
	SourceURL string // Unused but kept for API compatibility
}

// QueryStats contains statistics about the vulnerability query operation
type QueryStats struct {
	TotalVulns       int
	FetchErrors      int
	PackagesQueried  int
	PackagesSkipped  int
	OSVQueries       int
	NVDQueries       int
	GitQueries       int // Deprecated, always 0
	EcosystemQueries int // Deprecated, same as OSVQueries
}

// OSV API types
type osvQuery struct {
	Package *osvPackage `json:"package,omitempty"`
	Version string      `json:"version,omitempty"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}

type osvBatchResponse struct {
	Results []osvQueryResult `json:"results"`
}

type osvQueryResult struct {
	Vulns []osvBatchVuln `json:"vulns,omitempty"`
}

type osvBatchVuln struct {
	ID       string `json:"id"`
	Modified string `json:"modified,omitempty"`
}

type osvVulnDetail struct {
	ID               string         `json:"id"`
	Summary          string         `json:"summary,omitempty"`
	Details          string         `json:"details,omitempty"`
	Severity         []osvSeverity  `json:"severity,omitempty"`
	DatabaseSpecific map[string]any `json:"database_specific,omitempty"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// NVD API types
type nvdResponse struct {
	ResultsPerPage  int            `json:"resultsPerPage"`
	StartIndex      int            `json:"startIndex"`
	TotalResults    int            `json:"totalResults"`
	Vulnerabilities []nvdVulnEntry `json:"vulnerabilities"`
}

type nvdVulnEntry struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID          string       `json:"id"`
	Description nvdLangValue `json:"descriptions"`
	Metrics     nvdMetrics   `json:"metrics,omitempty"`
}

type nvdLangValue []struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetrics struct {
	CvssMetricV31 []nvdCVSSMetric `json:"cvssMetricV31,omitempty"`
	CvssMetricV30 []nvdCVSSMetric `json:"cvssMetricV30,omitempty"`
	CvssMetricV2  []nvdCVSSMetric `json:"cvssMetricV2,omitempty"`
}

type nvdCVSSMetric struct {
	CvssData nvdCVSSData `json:"cvssData"`
}

type nvdCVSSData struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity,omitempty"`
}

// NewOSVAPIClient creates a new OSV API client
func NewOSVAPIClient() *OSVAPIClient {
	return &OSVAPIClient{
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// GetPackageMapping returns the mapping for a package from embedded mappings
func GetPackageMapping(brewName string) *PackageMapping {
	if packageMappings == nil {
		return nil
	}
	return packageMappings[brewName]
}

// QueryPackages queries OSV and NIST NVD for vulnerabilities affecting packages.
func (c *OSVAPIClient) QueryPackages(packages []PackageInfo) (map[string]*VulnResult, *QueryStats, error) {
	results := make(map[string]*VulnResult)
	stats := &QueryStats{}

	var osvPackages []PackageInfo
	var nvdPackages []PackageInfo
	osvPackageToMapping := make(map[string]*PackageMapping)
	nvdPackageToMapping := make(map[string]*PackageMapping)

	for _, pkg := range packages {
		mapping := GetPackageMapping(pkg.Name)
		if mapping == nil {
			results[pkg.Name] = &VulnResult{
				Package:     pkg.Name,
				Version:     pkg.Version,
				MaxSeverity: ui.SeverityNA,
			}
			stats.PackagesSkipped++
			continue
		}

		if mapping.OSVEcosystem != "" && mapping.OSVPackageName != "" {
			osvPackages = append(osvPackages, pkg)
			osvPackageToMapping[pkg.Name] = mapping
		} else if mapping.CPEVendor != "" && mapping.CPEProduct != "" {
			nvdPackages = append(nvdPackages, pkg)
			nvdPackageToMapping[pkg.Name] = mapping
		} else {
			results[pkg.Name] = &VulnResult{
				Package:     pkg.Name,
				Version:     pkg.Version,
				MaxSeverity: ui.SeverityNA,
			}
			stats.PackagesSkipped++
		}
	}

	if len(osvPackages) > 0 {
		osvResults, osvStats, err := c.queryOSV(osvPackages, osvPackageToMapping)
		if err != nil {
			return nil, stats, fmt.Errorf("OSV query failed: %w", err)
		}
		for name, result := range osvResults {
			results[name] = result
		}
		stats.OSVQueries = osvStats.OSVQueries
		stats.TotalVulns += osvStats.TotalVulns
		stats.FetchErrors += osvStats.FetchErrors
		stats.PackagesQueried += len(osvPackages)
		stats.EcosystemQueries = osvStats.OSVQueries
	}

	if len(nvdPackages) > 0 {
		nvdResults, nvdStats := c.queryNVD(nvdPackages, nvdPackageToMapping)
		for name, result := range nvdResults {
			results[name] = result
		}
		stats.NVDQueries = nvdStats.NVDQueries
		stats.TotalVulns += nvdStats.TotalVulns
		stats.PackagesQueried += len(nvdPackages)
	}

	return results, stats, nil
}

func (c *OSVAPIClient) queryOSV(packages []PackageInfo, mappings map[string]*PackageMapping) (map[string]*VulnResult, *QueryStats, error) {
	results := make(map[string]*VulnResult)
	stats := &QueryStats{}

	var queries []osvQuery
	var queryOrder []string

	for _, pkg := range packages {
		mapping := mappings[pkg.Name]
		if mapping == nil {
			continue
		}
		queries = append(queries, osvQuery{
			Package: &osvPackage{
				Name:      mapping.OSVPackageName,
				Ecosystem: mapping.OSVEcosystem,
			},
			Version: cleanVersion(pkg.Version),
		})
		queryOrder = append(queryOrder, pkg.Name)
		stats.OSVQueries++
	}

	if len(queries) == 0 {
		return results, stats, nil
	}

	reqBody := osvBatchRequest{Queries: queries}
	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, stats, fmt.Errorf("marshaling request: %w", err)
	}

	resp, err := c.httpClient.Post(osvBatchURL, "application/json", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, stats, fmt.Errorf("OSV API request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, stats, fmt.Errorf("OSV API returned HTTP %d", resp.StatusCode)
	}

	var batchResp osvBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&batchResp); err != nil {
		return nil, stats, fmt.Errorf("decoding OSV response: %w", err)
	}

	var vulnIDs []string
	vulnIDSet := make(map[string]bool)
	for _, queryResult := range batchResp.Results {
		for _, vuln := range queryResult.Vulns {
			if !vulnIDSet[vuln.ID] {
				vulnIDSet[vuln.ID] = true
				vulnIDs = append(vulnIDs, vuln.ID)
			}
		}
	}

	stats.TotalVulns = len(vulnIDs)
	vulnDetails, fetchErrors := c.fetchVulnDetailsConcurrent(vulnIDs)
	stats.FetchErrors = fetchErrors

	for i, brewName := range queryOrder {
		pkg := packages[i]
		result := &VulnResult{
			Package: pkg.Name,
			Version: pkg.Version,
		}

		if i >= len(batchResp.Results) {
			result.MaxSeverity = ui.SeverityNA
			results[brewName] = result
			continue
		}

		queryResult := batchResp.Results[i]
		if len(queryResult.Vulns) == 0 {
			result.MaxSeverity = ui.SeverityNone
		} else {
			for _, vuln := range queryResult.Vulns {
				entry := VulnEntry{ID: vuln.ID}
				if detail, ok := vulnDetails[vuln.ID]; ok {
					entry.Summary = detail.Summary
					entry.Severity = extractSeverityFromDetail(detail)
				} else {
					entry.Severity = "UNKNOWN"
				}
				result.Vulns = append(result.Vulns, entry)
			}
			result.CVECount = len(result.Vulns)
			result.MaxSeverity = calculateMaxSeverity(result.Vulns)
		}
		results[brewName] = result
	}

	return results, stats, nil
}

func (c *OSVAPIClient) queryNVD(packages []PackageInfo, mappings map[string]*PackageMapping) (map[string]*VulnResult, *QueryStats) {
	results := make(map[string]*VulnResult)
	stats := &QueryStats{}

	for i, pkg := range packages {
		mapping := mappings[pkg.Name]
		if mapping == nil {
			continue
		}

		if i > 0 {
			time.Sleep(nvdRateLimitDelay)
		}

		vulns, err := c.queryNVDForPackage(pkg, mapping)
		if err != nil {
			fmt.Printf("[WARN] NVD query failed for %s: %v\n", pkg.Name, err)
			results[pkg.Name] = &VulnResult{
				Package:     pkg.Name,
				Version:     pkg.Version,
				MaxSeverity: ui.SeverityNA,
			}
			continue
		}

		result := &VulnResult{
			Package: pkg.Name,
			Version: pkg.Version,
			Vulns:   vulns,
		}

		if len(vulns) == 0 {
			result.MaxSeverity = ui.SeverityNone
		} else {
			result.CVECount = len(vulns)
			result.MaxSeverity = calculateMaxSeverity(vulns)
			stats.TotalVulns += len(vulns)
		}

		results[pkg.Name] = result
		stats.NVDQueries++
	}

	return results, stats
}

func (c *OSVAPIClient) queryNVDForPackage(pkg PackageInfo, mapping *PackageMapping) ([]VulnEntry, error) {
	version := cleanVersion(pkg.Version)
	cpe := fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*",
		mapping.CPEVendor, mapping.CPEProduct, version)

	reqURL := fmt.Sprintf("%s?cpeName=%s", nvdCVEURL, url.QueryEscape(cpe))

	ctx, cancel := context.WithTimeout(context.Background(), perRequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("NVD API request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NVD API returned HTTP %d", resp.StatusCode)
	}

	var nvdResp nvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
		return nil, fmt.Errorf("decoding NVD response: %w", err)
	}

	var vulns []VulnEntry
	for _, entry := range nvdResp.Vulnerabilities {
		vuln := VulnEntry{
			ID:       entry.CVE.ID,
			Severity: extractSeverityFromNVD(entry.CVE.Metrics),
		}
		for _, desc := range entry.CVE.Description {
			if desc.Lang == "en" {
				vuln.Summary = desc.Value
				break
			}
		}
		vulns = append(vulns, vuln)
	}

	return vulns, nil
}

func extractSeverityFromNVD(metrics nvdMetrics) string {
	if len(metrics.CvssMetricV31) > 0 {
		m := metrics.CvssMetricV31[0].CvssData
		if m.BaseSeverity != "" {
			return strings.ToUpper(m.BaseSeverity)
		}
		return scoreToSeverity(m.BaseScore)
	}
	if len(metrics.CvssMetricV30) > 0 {
		m := metrics.CvssMetricV30[0].CvssData
		if m.BaseSeverity != "" {
			return strings.ToUpper(m.BaseSeverity)
		}
		return scoreToSeverity(m.BaseScore)
	}
	if len(metrics.CvssMetricV2) > 0 {
		return scoreToSeverity(metrics.CvssMetricV2[0].CvssData.BaseScore)
	}
	return "UNKNOWN"
}

func (c *OSVAPIClient) fetchVulnDetailsConcurrent(vulnIDs []string) (map[string]*osvVulnDetail, int) {
	results := make(map[string]*osvVulnDetail)
	var mu sync.Mutex
	var wg sync.WaitGroup
	var errorCount int64

	ctx, cancel := context.WithTimeout(context.Background(), totalFetchTimeout)
	defer cancel()

	sem := make(chan struct{}, maxConcurrentFetches)

	for _, vulnID := range vulnIDs {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			detail, err := c.fetchVulnDetailWithContext(ctx, id)
			if err != nil {
				atomic.AddInt64(&errorCount, 1)
				return
			}
			mu.Lock()
			results[id] = detail
			mu.Unlock()
		}(vulnID)
	}

	wg.Wait()
	return results, int(errorCount)
}

func (c *OSVAPIClient) fetchVulnDetailWithContext(ctx context.Context, vulnID string) (*osvVulnDetail, error) {
	reqCtx, cancel := context.WithTimeout(ctx, perRequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, osvVulnURL+vulnID, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request for %s: %w", vulnID, err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching vuln %s: %w", vulnID, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vuln %s returned HTTP %d", vulnID, resp.StatusCode)
	}

	var detail osvVulnDetail
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		return nil, fmt.Errorf("decoding vuln %s: %w", vulnID, err)
	}

	return &detail, nil
}

func extractSeverityFromDetail(detail *osvVulnDetail) string {
	if detail.DatabaseSpecific != nil {
		if sev, ok := detail.DatabaseSpecific["severity"]; ok {
			if sevStr, ok := sev.(string); ok {
				if normalized := normalizeSeverityString(sevStr); normalized != "" {
					return normalized
				}
			}
		}
	}

	for _, sev := range detail.Severity {
		switch sev.Type {
		case "CVSS_V3":
			if severity := parseCVSSv3(sev.Score); severity != "" {
				return severity
			}
		case "CVSS_V2":
			if severity := parseCVSSScore(sev.Score); severity != "" {
				return severity
			}
		}
	}

	return "UNKNOWN"
}

func normalizeSeverityString(sev string) string {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case "CRITICAL":
		return "CRITICAL"
	case "HIGH":
		return "HIGH"
	case "MEDIUM", "MODERATE":
		return "MEDIUM"
	case "LOW":
		return "LOW"
	case "NONE", "INFORMATIONAL", "INFO":
		return "NONE"
	default:
		return ""
	}
}

func parseCVSSv3(cvss string) string {
	cvss = strings.TrimSpace(cvss)
	if cvss == "" {
		return ""
	}

	var score float64
	if _, err := fmt.Sscanf(cvss, "%f", &score); err == nil {
		return scoreToSeverity(score)
	}

	if strings.HasPrefix(cvss, "CVSS:3") {
		if bm, err := metric.NewBase().Decode(cvss); err == nil {
			return scoreToSeverity(bm.Score())
		}
	}

	return ""
}

func parseCVSSScore(cvss string) string {
	cvss = strings.TrimSpace(cvss)
	if cvss == "" {
		return ""
	}
	var score float64
	if _, err := fmt.Sscanf(cvss, "%f", &score); err == nil {
		return scoreToSeverity(score)
	}
	return ""
}

func scoreToSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	default:
		return "NONE"
	}
}

// calculateMaxSeverity determines the highest severity among vulnerabilities
func calculateMaxSeverity(vulns []VulnEntry) ui.Severity {
	if len(vulns) == 0 {
		return ui.SeverityNone
	}

	maxSev := ui.SeverityNone
	for _, v := range vulns {
		sev := parseSeverity(v.Severity)
		if severityPriority(sev) > severityPriority(maxSev) {
			maxSev = sev
		}
	}
	return maxSev
}

// parseSeverity converts a severity string or CVSS score to ui.Severity
func parseSeverity(s string) ui.Severity {
	var numScore float64
	if _, err := fmt.Sscanf(s, "%f", &numScore); err == nil {
		switch {
		case numScore >= 9.0:
			return ui.SeverityCritical
		case numScore >= 7.0:
			return ui.SeverityHigh
		case numScore >= 4.0:
			return ui.SeverityMedium
		case numScore > 0:
			return ui.SeverityLow
		default:
			return ui.SeverityNone
		}
	}

	switch strings.ToUpper(s) {
	case "CRITICAL":
		return ui.SeverityCritical
	case "HIGH":
		return ui.SeverityHigh
	case "MODERATE", "MEDIUM":
		return ui.SeverityMedium
	case "LOW":
		return ui.SeverityLow
	default:
		return ui.SeverityMedium
	}
}

func severityPriority(s ui.Severity) int {
	switch s {
	case ui.SeverityCritical:
		return 5
	case ui.SeverityHigh:
		return 4
	case ui.SeverityMedium:
		return 3
	case ui.SeverityLow:
		return 2
	case ui.SeverityNone:
		return 1
	default:
		return 0
	}
}

func cleanVersion(version string) string {
	if idx := strings.LastIndex(version, "_"); idx != -1 {
		suffix := version[idx+1:]
		allDigits := true
		for _, c := range suffix {
			if c < '0' || c > '9' {
				allDigits = false
				break
			}
		}
		if allDigits && len(suffix) > 0 {
			return version[:idx]
		}
	}
	return version
}
