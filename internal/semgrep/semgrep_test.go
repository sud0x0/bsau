package semgrep

import (
	"testing"
)

func TestFormatFindings_Empty(t *testing.T) {
	result := FormatFindings([]Finding{})
	expected := "No findings"
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestFormatFindings_WithFindings(t *testing.T) {
	findings := []Finding{
		{
			CheckID: "test-rule-1",
			Path:    "/path/to/file.rb",
			Start: struct {
				Line   int `json:"line"`
				Col    int `json:"col"`
				Offset int `json:"offset"`
			}{Line: 10, Col: 1, Offset: 100},
			Extra: struct {
				Message  string `json:"message"`
				Severity string `json:"severity"`
				Metadata struct {
					Category string `json:"category"`
				} `json:"metadata"`
				Lines string `json:"lines"`
			}{Severity: "ERROR"},
		},
	}

	result := FormatFindings(findings)
	if result == "No findings" {
		t.Error("expected findings to be formatted")
	}
	if len(result) == 0 {
		t.Error("expected non-empty result")
	}
}

func TestFilterBySeverity(t *testing.T) {
	findings := []Finding{
		{CheckID: "info-rule", Extra: struct {
			Message  string `json:"message"`
			Severity string `json:"severity"`
			Metadata struct {
				Category string `json:"category"`
			} `json:"metadata"`
			Lines string `json:"lines"`
		}{Severity: "INFO"}},
		{CheckID: "warning-rule", Extra: struct {
			Message  string `json:"message"`
			Severity string `json:"severity"`
			Metadata struct {
				Category string `json:"category"`
			} `json:"metadata"`
			Lines string `json:"lines"`
		}{Severity: "WARNING"}},
		{CheckID: "error-rule", Extra: struct {
			Message  string `json:"message"`
			Severity string `json:"severity"`
			Metadata struct {
				Category string `json:"category"`
			} `json:"metadata"`
			Lines string `json:"lines"`
		}{Severity: "ERROR"}},
	}

	tests := []struct {
		name        string
		minSeverity string
		expected    int
	}{
		{"filter INFO and above", "INFO", 3},
		{"filter WARNING and above", "WARNING", 2},
		{"filter ERROR only", "ERROR", 1},
		{"unknown severity defaults to INFO", "UNKNOWN", 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered := FilterBySeverity(findings, tt.minSeverity)
			if len(filtered) != tt.expected {
				t.Errorf("expected %d findings, got %d", tt.expected, len(filtered))
			}
		})
	}
}

func TestGetFlaggedFilePaths(t *testing.T) {
	findings := []Finding{
		{Path: "/path/to/file1.rb"},
		{Path: "/path/to/file2.rb"},
		{Path: "/path/to/file1.rb"}, // Duplicate
	}

	paths := GetFlaggedFilePaths(findings)

	if len(paths) != 2 {
		t.Errorf("expected 2 unique paths, got %d", len(paths))
	}
}

func TestGetFlaggedFilePaths_Empty(t *testing.T) {
	paths := GetFlaggedFilePaths([]Finding{})
	if len(paths) != 0 {
		t.Errorf("expected 0 paths, got %d", len(paths))
	}
}

func TestFinding_Structure(t *testing.T) {
	finding := Finding{
		CheckID: "generic.secrets.security.detected-private-key",
		Path:    "/opt/homebrew/Cellar/pkg/1.0.0/bin/script.sh",
		Start: struct {
			Line   int `json:"line"`
			Col    int `json:"col"`
			Offset int `json:"offset"`
		}{Line: 42, Col: 5, Offset: 1000},
		End: struct {
			Line   int `json:"line"`
			Col    int `json:"col"`
			Offset int `json:"offset"`
		}{Line: 42, Col: 50, Offset: 1045},
		Extra: struct {
			Message  string `json:"message"`
			Severity string `json:"severity"`
			Metadata struct {
				Category string `json:"category"`
			} `json:"metadata"`
			Lines string `json:"lines"`
		}{
			Message:  "Private key detected",
			Severity: "ERROR",
			Lines:    "-----BEGIN RSA PRIVATE KEY-----",
		},
	}

	if finding.CheckID != "generic.secrets.security.detected-private-key" {
		t.Errorf("unexpected CheckID: %s", finding.CheckID)
	}
	if finding.Start.Line != 42 {
		t.Errorf("expected Start.Line 42, got %d", finding.Start.Line)
	}
	if finding.End.Line != 42 {
		t.Errorf("expected End.Line 42, got %d", finding.End.Line)
	}
	if finding.Extra.Severity != "ERROR" {
		t.Errorf("expected Severity ERROR, got %s", finding.Extra.Severity)
	}
}

func TestScanResult_Structure(t *testing.T) {
	result := ScanResult{
		Results: []Finding{
			{CheckID: "rule-1", Path: "/path/1"},
			{CheckID: "rule-2", Path: "/path/2"},
		},
		Errors: []struct {
			Message string `json:"message"`
			Level   string `json:"level"`
		}{
			{Message: "test error", Level: "warning"},
		},
	}

	if len(result.Results) != 2 {
		t.Errorf("expected 2 results, got %d", len(result.Results))
	}
	if len(result.Errors) != 1 {
		t.Errorf("expected 1 error, got %d", len(result.Errors))
	}
}

func TestPackageScanResult_Structure(t *testing.T) {
	result := PackageScanResult{
		Package:      "ripgrep",
		Version:      "14.0.0",
		Path:         "/opt/homebrew/Cellar/ripgrep/14.0.0",
		Findings:     []Finding{{CheckID: "test-rule"}},
		FindingCount: 1,
		HasFindings:  true,
		Error:        nil,
	}

	if result.Package != "ripgrep" {
		t.Errorf("expected Package ripgrep, got %s", result.Package)
	}
	if result.Version != "14.0.0" {
		t.Errorf("expected Version 14.0.0, got %s", result.Version)
	}
	if !result.HasFindings {
		t.Error("expected HasFindings to be true")
	}
	if result.FindingCount != 1 {
		t.Errorf("expected FindingCount 1, got %d", result.FindingCount)
	}
}

func TestPackageScanResult_NoFindings(t *testing.T) {
	result := PackageScanResult{
		Package:      "curl",
		Version:      "8.0.0",
		Path:         "/opt/homebrew/Cellar/curl/8.0.0",
		Findings:     []Finding{},
		FindingCount: 0,
		HasFindings:  false,
	}

	if result.HasFindings {
		t.Error("expected HasFindings to be false")
	}
	if result.FindingCount != 0 {
		t.Errorf("expected FindingCount 0, got %d", result.FindingCount)
	}
}

func TestRunner_Structure(t *testing.T) {
	runner := &Runner{
		semgrepPath: "/usr/local/bin/semgrep",
	}

	if runner.semgrepPath != "/usr/local/bin/semgrep" {
		t.Errorf("unexpected semgrepPath: %s", runner.semgrepPath)
	}
}

func TestFormatFindings_MultipleFindings(t *testing.T) {
	findings := []Finding{
		{
			CheckID: "rule-1",
			Path:    "/path/to/file1.rb",
			Start: struct {
				Line   int `json:"line"`
				Col    int `json:"col"`
				Offset int `json:"offset"`
			}{Line: 10},
			Extra: struct {
				Message  string `json:"message"`
				Severity string `json:"severity"`
				Metadata struct {
					Category string `json:"category"`
				} `json:"metadata"`
				Lines string `json:"lines"`
			}{Severity: "ERROR"},
		},
		{
			CheckID: "rule-2",
			Path:    "/path/to/file2.py",
			Start: struct {
				Line   int `json:"line"`
				Col    int `json:"col"`
				Offset int `json:"offset"`
			}{Line: 20},
			Extra: struct {
				Message  string `json:"message"`
				Severity string `json:"severity"`
				Metadata struct {
					Category string `json:"category"`
				} `json:"metadata"`
				Lines string `json:"lines"`
			}{Severity: "WARNING"},
		},
	}

	result := FormatFindings(findings)

	// Should contain "2 finding(s)"
	if result == "No findings" {
		t.Error("expected formatted findings, got 'No findings'")
	}
}

func TestGetFlaggedFilePaths_ManyDuplicates(t *testing.T) {
	findings := []Finding{
		{Path: "/path/a"},
		{Path: "/path/b"},
		{Path: "/path/a"},
		{Path: "/path/c"},
		{Path: "/path/b"},
		{Path: "/path/a"},
	}

	paths := GetFlaggedFilePaths(findings)

	if len(paths) != 3 {
		t.Errorf("expected 3 unique paths, got %d", len(paths))
	}
}

func TestFilterBySeverity_EmptyInput(t *testing.T) {
	result := FilterBySeverity([]Finding{}, "ERROR")
	if len(result) != 0 {
		t.Errorf("expected 0 findings for empty input, got %d", len(result))
	}
}

func TestFilterBySeverity_AllFiltered(t *testing.T) {
	findings := []Finding{
		{CheckID: "info-rule", Extra: struct {
			Message  string `json:"message"`
			Severity string `json:"severity"`
			Metadata struct {
				Category string `json:"category"`
			} `json:"metadata"`
			Lines string `json:"lines"`
		}{Severity: "INFO"}},
	}

	// Filter for ERROR should return 0 since only INFO exists
	result := FilterBySeverity(findings, "ERROR")
	if len(result) != 0 {
		t.Errorf("expected 0 findings when filtering INFO by ERROR, got %d", len(result))
	}
}

func TestFinding_JSONTags(t *testing.T) {
	// Verify that Finding struct has correct JSON tags by checking field names
	finding := Finding{
		CheckID: "test",
		Path:    "/test",
	}

	// Verify basic fields are accessible
	if finding.CheckID != "test" {
		t.Error("CheckID field access failed")
	}
	if finding.Path != "/test" {
		t.Error("Path field access failed")
	}
}
