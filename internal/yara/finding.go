package yara

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Finding represents a single YARA rule match in a file or buffer.
type Finding struct {
	RuleID      string
	Path        string
	Severity    string // "ERROR" or "WARNING"
	Message     string
	Offsets     []uint64
	LineNumbers []int // Line numbers corresponding to each offset (1-indexed)
}

// DirScanResult holds the aggregated results of scanning a directory.
type DirScanResult struct {
	Dir          string
	Findings     []Finding
	FindingCount int
	HasFindings  bool
	Errors       []string
}

// FormatFindings returns a human-readable summary of findings for use in LLM prompts.
// Shows full paths. Use FormatFindingsRelative for shorter display paths.
func FormatFindings(findings []Finding) string {
	return formatFindingsInternal(findings, "")
}

// FormatFindingsRelative returns a human-readable summary with paths relative to basePath.
// Useful for display output where full paths would be too long.
func FormatFindingsRelative(findings []Finding, basePath string) string {
	return formatFindingsInternal(findings, basePath)
}

func formatFindingsInternal(findings []Finding, basePath string) string {
	if len(findings) == 0 {
		return "No findings"
	}
	summary := fmt.Sprintf("%d finding(s):\n", len(findings))
	for _, f := range findings {
		// Format line numbers if available
		lineInfo := ""
		if len(f.LineNumbers) > 0 {
			if len(f.LineNumbers) == 1 {
				lineInfo = fmt.Sprintf(":%d", f.LineNumbers[0])
			} else {
				// Show first few line numbers if multiple matches
				lines := f.LineNumbers
				if len(lines) > 3 {
					lineInfo = fmt.Sprintf(":%d,%d,%d...", lines[0], lines[1], lines[2])
				} else {
					nums := make([]string, len(lines))
					for i, n := range lines {
						nums[i] = fmt.Sprintf("%d", n)
					}
					lineInfo = ":" + strings.Join(nums, ",")
				}
			}
		}

		// Use relative path if basePath is provided
		displayPath := f.Path
		if basePath != "" {
			if rel, err := filepath.Rel(basePath, f.Path); err == nil {
				displayPath = rel
			}
		}

		summary += fmt.Sprintf("  - %s%s [%s] %s\n",
			displayPath,
			lineInfo,
			f.Severity,
			f.RuleID,
		)
		if f.Message != "" {
			summary += fmt.Sprintf("    %s\n", f.Message)
		}
	}
	return summary
}
