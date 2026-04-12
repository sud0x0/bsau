package vuln

import (
	"strings"
	"testing"

	"github.com/sud0x0/bsau/internal/ui"
)

func TestParseSeverity_CVSSScores(t *testing.T) {
	tests := []struct {
		score    string
		expected ui.Severity
	}{
		{"9.8", ui.SeverityCritical},
		{"9.0", ui.SeverityCritical},
		{"8.5", ui.SeverityHigh},
		{"7.0", ui.SeverityHigh},
		{"6.5", ui.SeverityMedium},
		{"4.0", ui.SeverityMedium},
		{"3.9", ui.SeverityLow},
		{"1.0", ui.SeverityLow},
		{"0.0", ui.SeverityNone},
	}

	for _, tt := range tests {
		t.Run(tt.score, func(t *testing.T) {
			result := parseSeverity(tt.score)
			if result != tt.expected {
				t.Errorf("parseSeverity(%s) = %v, expected %v", tt.score, result, tt.expected)
			}
		})
	}
}

func TestParseSeverity_Strings(t *testing.T) {
	tests := []struct {
		severity string
		expected ui.Severity
	}{
		{"CRITICAL", ui.SeverityCritical},
		{"critical", ui.SeverityCritical},
		{"HIGH", ui.SeverityHigh},
		{"high", ui.SeverityHigh},
		{"MEDIUM", ui.SeverityMedium},
		{"medium", ui.SeverityMedium},
		{"MODERATE", ui.SeverityMedium},
		{"moderate", ui.SeverityMedium},
		{"LOW", ui.SeverityLow},
		{"low", ui.SeverityLow},
		{"unknown", ui.SeverityMedium}, // defaults to medium
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			result := parseSeverity(tt.severity)
			if result != tt.expected {
				t.Errorf("parseSeverity(%s) = %v, expected %v", tt.severity, result, tt.expected)
			}
		})
	}
}

func TestSeverityPriority(t *testing.T) {
	tests := []struct {
		severity ui.Severity
		expected int
	}{
		{ui.SeverityCritical, 5},
		{ui.SeverityHigh, 4},
		{ui.SeverityMedium, 3},
		{ui.SeverityLow, 2},
		{ui.SeverityNone, 1},
		{ui.SeverityNA, 0},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			result := severityPriority(tt.severity)
			if result != tt.expected {
				t.Errorf("severityPriority(%v) = %d, expected %d", tt.severity, result, tt.expected)
			}
		})
	}
}

func TestSeverityPriority_Ordering(t *testing.T) {
	// Verify that priorities are correctly ordered
	if severityPriority(ui.SeverityCritical) <= severityPriority(ui.SeverityHigh) {
		t.Error("CRITICAL should have higher priority than HIGH")
	}
	if severityPriority(ui.SeverityHigh) <= severityPriority(ui.SeverityMedium) {
		t.Error("HIGH should have higher priority than MEDIUM")
	}
	if severityPriority(ui.SeverityMedium) <= severityPriority(ui.SeverityLow) {
		t.Error("MEDIUM should have higher priority than LOW")
	}
	if severityPriority(ui.SeverityLow) <= severityPriority(ui.SeverityNone) {
		t.Error("LOW should have higher priority than NONE")
	}
}

func TestCalculateMaxSeverity_Empty(t *testing.T) {
	result := calculateMaxSeverity([]VulnEntry{})
	if result != ui.SeverityNone {
		t.Errorf("expected NONE for empty vulns, got %v", result)
	}
}

func TestCalculateMaxSeverity_SingleVuln(t *testing.T) {
	vulns := []VulnEntry{
		{ID: "CVE-2023-1234", Severity: "HIGH"},
	}

	result := calculateMaxSeverity(vulns)
	if result != ui.SeverityHigh {
		t.Errorf("expected HIGH, got %v", result)
	}
}

func TestCalculateMaxSeverity_MultipleVulns(t *testing.T) {
	vulns := []VulnEntry{
		{ID: "CVE-2023-1111", Severity: "LOW"},
		{ID: "CVE-2023-2222", Severity: "CRITICAL"},
		{ID: "CVE-2023-3333", Severity: "MEDIUM"},
	}

	result := calculateMaxSeverity(vulns)
	if result != ui.SeverityCritical {
		t.Errorf("expected CRITICAL (highest), got %v", result)
	}
}

func TestCalculateMaxSeverity_CVSSScores(t *testing.T) {
	vulns := []VulnEntry{
		{ID: "CVE-2023-1111", Severity: "3.5"}, // LOW
		{ID: "CVE-2023-2222", Severity: "7.5"}, // HIGH
		{ID: "CVE-2023-3333", Severity: "5.0"}, // MEDIUM
	}

	result := calculateMaxSeverity(vulns)
	if result != ui.SeverityHigh {
		t.Errorf("expected HIGH (7.5 is highest), got %v", result)
	}
}

func TestVulnEntry_Structure(t *testing.T) {
	entry := VulnEntry{
		ID:       "CVE-2023-12345",
		Summary:  "Test vulnerability description",
		Severity: "HIGH",
	}

	if entry.ID != "CVE-2023-12345" {
		t.Errorf("expected ID CVE-2023-12345, got %s", entry.ID)
	}
	if entry.Summary != "Test vulnerability description" {
		t.Errorf("unexpected summary: %s", entry.Summary)
	}
}

func TestVulnResult_Structure(t *testing.T) {
	result := VulnResult{
		Package:     "openssl",
		Version:     "3.0.0",
		Vulns:       []VulnEntry{{ID: "CVE-2023-1234", Severity: "HIGH"}},
		CVECount:    1,
		MaxSeverity: ui.SeverityHigh,
	}

	if result.Package != "openssl" {
		t.Errorf("expected Package openssl, got %s", result.Package)
	}
	if result.CVECount != 1 {
		t.Errorf("expected CVECount 1, got %d", result.CVECount)
	}
	if len(result.Vulns) != 1 {
		t.Errorf("expected 1 vuln, got %d", len(result.Vulns))
	}
}

func TestCalculateMaxSeverity_AllLow(t *testing.T) {
	vulns := []VulnEntry{
		{ID: "CVE-2023-1111", Severity: "LOW"},
		{ID: "CVE-2023-2222", Severity: "LOW"},
		{ID: "CVE-2023-3333", Severity: "LOW"},
	}

	result := calculateMaxSeverity(vulns)
	if result != ui.SeverityLow {
		t.Errorf("expected LOW, got %v", result)
	}
}

func TestCalculateMaxSeverity_MixedFormats(t *testing.T) {
	vulns := []VulnEntry{
		{ID: "CVE-2023-1111", Severity: "LOW"},
		{ID: "CVE-2023-2222", Severity: "9.1"}, // CVSS Critical
		{ID: "CVE-2023-3333", Severity: "HIGH"},
	}

	result := calculateMaxSeverity(vulns)
	if result != ui.SeverityCritical {
		t.Errorf("expected CRITICAL from CVSS 9.1, got %v", result)
	}
}

func TestParseSeverity_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected ui.Severity
	}{
		{"empty string", "", ui.SeverityMedium},
		{"whitespace", "  ", ui.SeverityMedium},
		{"invalid number", "abc", ui.SeverityMedium},
		{"negative number", "-1.0", ui.SeverityNone},
		{"very high CVSS", "10.0", ui.SeverityCritical},
		{"boundary 7.0", "7.0", ui.SeverityHigh},
		{"boundary 4.0", "4.0", ui.SeverityMedium},
		{"boundary 0.1", "0.1", ui.SeverityLow},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseSeverity(tt.input)
			if result != tt.expected {
				t.Errorf("parseSeverity(%q) = %v, expected %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestCleanVersion(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"1.2.3", "1.2.3"},
		{"1.2.3_1", "1.2.3"},
		{"1.2.3_12", "1.2.3"},
		{"1.2.3_abc", "1.2.3_abc"}, // non-digit suffix kept
		{"1.2.3-1", "1.2.3-1"},     // hyphen suffix kept
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := cleanVersion(tt.input)
			if result != tt.expected {
				t.Errorf("cleanVersion(%s) = %s, expected %s", tt.input, result, tt.expected)
			}
		})
	}
}

func TestGetPackageMapping(t *testing.T) {
	// Test a known package
	mapping := GetPackageMapping("python@3.13")
	if mapping == nil {
		t.Skip("Package mapping not found - mappings may not be loaded")
	}

	if mapping.BrewName != "python@3.13" {
		t.Errorf("expected BrewName python@3.13, got %s", mapping.BrewName)
	}
}

func TestGetPackageMapping_NotFound(t *testing.T) {
	mapping := GetPackageMapping("nonexistent-package-xyz-123")
	if mapping != nil {
		t.Errorf("expected nil for nonexistent package, got %+v", mapping)
	}
}

func TestNewScanner(t *testing.T) {
	client := NewScanner()
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if client.httpClient == nil {
		t.Error("expected non-nil httpClient")
	}
}

func TestGenerateVulnReport_Empty(t *testing.T) {
	results := make(map[string]*VulnResult)
	report := GenerateVulnReport(results)

	if !strings.Contains(report, "VULNERABILITY REPORT") {
		t.Error("expected report to contain header")
	}
	if !strings.Contains(report, "Total Vulnerabilities Found: 0") {
		t.Error("expected report to show 0 vulnerabilities")
	}
}

func TestGenerateVulnReport_WithVulns(t *testing.T) {
	results := map[string]*VulnResult{
		"openssl": {
			Package:     "openssl",
			Version:     "3.0.0",
			CVECount:    2,
			MaxSeverity: ui.SeverityHigh,
			Vulns: []VulnEntry{
				{
					ID:       "CVE-2023-1234",
					Severity: "HIGH",
					Summary:  "Test vulnerability",
				},
				{
					ID:       "GHSA-abcd-1234-efgh",
					Severity: "MEDIUM",
					Summary:  "Another vulnerability",
				},
			},
		},
		"curl": {
			Package:     "curl",
			Version:     "8.0.0",
			CVECount:    0,
			MaxSeverity: ui.SeverityNone,
			Vulns:       []VulnEntry{},
		},
	}

	report := GenerateVulnReport(results)

	// Check header
	if !strings.Contains(report, "VULNERABILITY REPORT") {
		t.Error("expected report to contain header")
	}

	// Check total count
	if !strings.Contains(report, "Total Vulnerabilities Found: 2") {
		t.Error("expected report to show 2 vulnerabilities")
	}

	// Check packages affected
	if !strings.Contains(report, "Packages Affected: 1") {
		t.Error("expected report to show 1 package affected")
	}

	// Check package info
	if !strings.Contains(report, "PACKAGE: openssl") {
		t.Error("expected report to contain openssl package")
	}
	if !strings.Contains(report, "PACKAGE: curl") {
		t.Error("expected report to contain curl package")
	}

	// Check CVE link format
	if !strings.Contains(report, "https://nvd.nist.gov/vuln/detail/CVE-2023-1234") {
		t.Error("expected report to contain NVD link for CVE")
	}

	// Check GHSA link format
	if !strings.Contains(report, "https://github.com/advisories/GHSA-abcd-1234-efgh") {
		t.Error("expected report to contain GitHub advisory link")
	}

	// Check summary
	if !strings.Contains(report, "Test vulnerability") {
		t.Error("expected report to contain vulnerability summary")
	}

	// Check no vulns message
	if !strings.Contains(report, "No known vulnerabilities") {
		t.Error("expected report to show 'No known vulnerabilities' for curl")
	}
}

func TestGenerateVulnReport_NAPackage(t *testing.T) {
	results := map[string]*VulnResult{
		"custom-pkg": {
			Package:     "custom-pkg",
			Version:     "1.0.0",
			CVECount:    0,
			MaxSeverity: ui.SeverityNA,
			Vulns:       []VulnEntry{},
		},
	}

	report := GenerateVulnReport(results)

	if !strings.Contains(report, "No vulnerability data available") {
		t.Error("expected report to show N/A status message")
	}
}
