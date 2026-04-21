package report

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// PackageScanStatus tracks scan results for a single package
type PackageScanStatus struct {
	Name            string
	OldVersion      string
	NewVersion      string
	CVECount        int
	Severity        string
	Updated         bool
	UpdateError     string
	FormulaAnalysis string // "SAFE", "REVIEW", "HOLD", "skipped", "failed", "N/A"
	YaraScan        string // "clean", "X findings", "skipped", "failed", "N/A"
	LLMMalwareScan  string // "SAFE", "REVIEW", "HOLD", "skipped", "failed", "N/A"
}

// YaraFinding represents a single YARA finding for the report
type YaraFinding struct {
	RuleID      string
	Path        string
	Severity    string
	Message     string
	LineNumbers []int
}

// LLMFinding represents a single LLM finding for the report
type LLMFinding struct {
	File        string
	LineNumber  int
	Description string
}

// Report manages the vulnerability and scan report file
type Report struct {
	filePath        string
	startTime       time.Time
	packages        map[string]*PackageScanStatus
	vulnDetails     map[string][]string      // package -> list of CVE details
	yaraFindings    map[string][]YaraFinding // package -> list of YARA findings
	llmFindings     map[string][]LLMFinding  // package -> list of LLM findings
	formulaFindings map[string][]LLMFinding  // package -> list of formula LLM findings
}

// New creates a new report in the specified directory
func New(dir string) (*Report, error) {
	now := time.Now()
	filename := fmt.Sprintf("bsau_report_%s_%d.txt",
		now.Format("2006-01-02"),
		now.Unix())
	filePath := filepath.Join(dir, filename)

	r := &Report{
		filePath:        filePath,
		startTime:       now,
		packages:        make(map[string]*PackageScanStatus),
		vulnDetails:     make(map[string][]string),
		yaraFindings:    make(map[string][]YaraFinding),
		llmFindings:     make(map[string][]LLMFinding),
		formulaFindings: make(map[string][]LLMFinding),
	}

	// Create initial file with header
	f, err := os.Create(filePath)
	if err != nil {
		return nil, fmt.Errorf("creating report file: %w", err)
	}
	defer func() { _ = f.Close() }()

	header := fmt.Sprintf(`================================================================================
BSAU SCAN REPORT
================================================================================
Generated: %s
Unix Timestamp: %d
================================================================================

`, now.Format("2006-01-02 15:04:05 MST"), now.Unix())

	if _, err := f.WriteString(header); err != nil {
		return nil, fmt.Errorf("writing report header: %w", err)
	}

	return r, nil
}

// FilePath returns the path to the report file
func (r *Report) FilePath() string {
	return r.filePath
}

// AddPackage registers a package for tracking
func (r *Report) AddPackage(name, oldVersion, newVersion string, cveCount int, severity string) {
	r.packages[name] = &PackageScanStatus{
		Name:            name,
		OldVersion:      oldVersion,
		NewVersion:      newVersion,
		CVECount:        cveCount,
		Severity:        severity,
		Updated:         false,
		FormulaAnalysis: "N/A",
		YaraScan:        "N/A",
		LLMMalwareScan:  "N/A",
	}
}

// AddVulnDetails adds CVE details for a package
func (r *Report) AddVulnDetails(pkgName string, details []string) {
	r.vulnDetails[pkgName] = details
}

// SetUpdated marks a package as successfully updated
func (r *Report) SetUpdated(name string, success bool, errorMsg string) {
	if pkg, ok := r.packages[name]; ok {
		pkg.Updated = success
		pkg.UpdateError = errorMsg
	}
}

// SetFormulaAnalysis sets the formula analysis result for a package
func (r *Report) SetFormulaAnalysis(name, result string) {
	if pkg, ok := r.packages[name]; ok {
		pkg.FormulaAnalysis = result
	}
}

// SetYaraScan sets the YARA scan result for a package
func (r *Report) SetYaraScan(name, result string) {
	if pkg, ok := r.packages[name]; ok {
		pkg.YaraScan = result
	}
}

// AddYaraFindings adds YARA findings details for a package
func (r *Report) AddYaraFindings(pkgName string, findings []YaraFinding) {
	r.yaraFindings[pkgName] = findings
}

// AddLLMFindings adds LLM code analysis findings for a package
func (r *Report) AddLLMFindings(pkgName string, findings []LLMFinding) {
	r.llmFindings[pkgName] = findings
}

// AddFormulaFindings adds LLM formula analysis findings for a package
func (r *Report) AddFormulaFindings(pkgName string, findings []LLMFinding) {
	r.formulaFindings[pkgName] = findings
}

// SetLLMMalwareScan sets the LLM malware scan result for a package
func (r *Report) SetLLMMalwareScan(name, result string) {
	if pkg, ok := r.packages[name]; ok {
		pkg.LLMMalwareScan = result
	}
}

// WriteVulnSection writes the vulnerability section to the report
func (r *Report) WriteVulnSection() error {
	f, err := os.OpenFile(r.filePath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	var sb strings.Builder
	sb.WriteString("VULNERABILITY SCAN RESULTS\n")
	sb.WriteString("--------------------------------------------------------------------------------\n")
	sb.WriteString("Source: OSV.dev and NIST NVD (other databases may contain additional CVEs)\n\n")

	totalCVEs := 0
	for name, pkg := range r.packages {
		totalCVEs += pkg.CVECount
		fmt.Fprintf(&sb, "Package: %s (%s -> %s)\n", name, pkg.OldVersion, pkg.NewVersion)
		fmt.Fprintf(&sb, "  CVEs: %d, Severity: %s\n", pkg.CVECount, pkg.Severity)
		if details, ok := r.vulnDetails[name]; ok && len(details) > 0 {
			for _, d := range details {
				fmt.Fprintf(&sb, "    - %s\n", d)
			}
		}
		sb.WriteString("\n")
	}

	fmt.Fprintf(&sb, "Total packages: %d, Total CVEs found: %d\n\n", len(r.packages), totalCVEs)

	_, err = f.WriteString(sb.String())
	return err
}

// WriteFinalSummary writes the final summary to the report
func (r *Report) WriteFinalSummary() error {
	f, err := os.OpenFile(r.filePath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	var sb strings.Builder

	// Write findings details FIRST (before final summary)

	// YARA findings details
	if len(r.yaraFindings) > 0 {
		sb.WriteString("YARA FINDINGS DETAILS\n")
		sb.WriteString("--------------------------------------------------------------------------------\n")
		for pkgName, findings := range r.yaraFindings {
			fmt.Fprintf(&sb, "\nPackage: %s (%d findings)\n", pkgName, len(findings))
			for _, f := range findings {
				// Format line numbers if available
				lineInfo := ""
				if len(f.LineNumbers) > 0 {
					if len(f.LineNumbers) == 1 {
						lineInfo = fmt.Sprintf(":%d", f.LineNumbers[0])
					} else if len(f.LineNumbers) <= 3 {
						nums := make([]string, len(f.LineNumbers))
						for i, n := range f.LineNumbers {
							nums[i] = fmt.Sprintf("%d", n)
						}
						lineInfo = ":" + strings.Join(nums, ",")
					} else {
						lineInfo = fmt.Sprintf(":%d,%d,%d...", f.LineNumbers[0], f.LineNumbers[1], f.LineNumbers[2])
					}
				}
				fmt.Fprintf(&sb, "  - %s%s [%s] %s\n", f.Path, lineInfo, f.Severity, f.RuleID)
				if f.Message != "" {
					fmt.Fprintf(&sb, "    %s\n", f.Message)
				}
			}
		}
		sb.WriteString("\n")
	}

	// LLM formula analysis findings details
	if len(r.formulaFindings) > 0 {
		sb.WriteString("LLM FORMULA ANALYSIS FINDINGS\n")
		sb.WriteString("--------------------------------------------------------------------------------\n")
		for pkgName, findings := range r.formulaFindings {
			fmt.Fprintf(&sb, "\nPackage: %s (%d findings)\n", pkgName, len(findings))
			for _, f := range findings {
				if f.LineNumber > 0 {
					fmt.Fprintf(&sb, "  - %s:%d: %s\n", f.File, f.LineNumber, f.Description)
				} else {
					fmt.Fprintf(&sb, "  - %s\n", f.Description)
				}
			}
		}
		sb.WriteString("\n")
	}

	// LLM code analysis findings details
	if len(r.llmFindings) > 0 {
		sb.WriteString("LLM CODE ANALYSIS FINDINGS\n")
		sb.WriteString("--------------------------------------------------------------------------------\n")
		for pkgName, findings := range r.llmFindings {
			fmt.Fprintf(&sb, "\nPackage: %s (%d findings)\n", pkgName, len(findings))
			for _, f := range findings {
				if f.LineNumber > 0 {
					fmt.Fprintf(&sb, "  - %s:%d: %s\n", f.File, f.LineNumber, f.Description)
				} else {
					fmt.Fprintf(&sb, "  - %s\n", f.Description)
				}
			}
		}
		sb.WriteString("\n")
	}

	// Now write the FINAL SUMMARY section
	sb.WriteString("================================================================================\n")
	sb.WriteString("FINAL SUMMARY\n")
	sb.WriteString("================================================================================\n\n")

	// Count stats
	updated := 0
	notUpdated := 0
	totalCVEsUpdated := 0
	totalCVEsNotUpdated := 0
	yaraReviewCount := 0
	totalYaraFindings := 0
	llmReviewCount := 0
	llmHoldCount := 0

	for _, pkg := range r.packages {
		if pkg.Updated {
			updated++
			totalCVEsUpdated += pkg.CVECount
		} else {
			notUpdated++
			totalCVEsNotUpdated += pkg.CVECount
		}

		// Count YARA reviews (packages with findings)
		if strings.Contains(pkg.YaraScan, "findings") {
			yaraReviewCount++
		}

		// Count LLM verdicts
		switch pkg.LLMMalwareScan {
		case "REVIEW":
			llmReviewCount++
		case "HOLD":
			llmHoldCount++
		}
	}

	// Count total YARA findings
	for _, findings := range r.yaraFindings {
		totalYaraFindings += len(findings)
	}

	sb.WriteString("UPDATE STATUS\n")
	sb.WriteString("--------------------------------------------------------------------------------\n")
	fmt.Fprintf(&sb, "Packages updated: %d (had %d CVEs)\n", updated, totalCVEsUpdated)
	fmt.Fprintf(&sb, "Packages not updated: %d (have %d CVEs)\n", notUpdated, totalCVEsNotUpdated)
	fmt.Fprintf(&sb, "YARA scan: %d packages with %d total findings requiring review\n", yaraReviewCount, totalYaraFindings)
	if llmHoldCount > 0 {
		fmt.Fprintf(&sb, "LLM analysis: %d REVIEW, %d HOLD\n\n", llmReviewCount, llmHoldCount)
	} else if llmReviewCount > 0 {
		fmt.Fprintf(&sb, "LLM analysis: %d REVIEW\n\n", llmReviewCount)
	} else {
		sb.WriteString("\n")
	}

	// Per-package scan results
	sb.WriteString("PER-PACKAGE SCAN RESULTS\n")
	sb.WriteString("--------------------------------------------------------------------------------\n")
	fmt.Fprintf(&sb, "%-25s | %-8s | %-12s | %-12s | %-12s\n",
		"Package", "Updated", "Formula LLM", "YARA", "Code LLM")
	sb.WriteString(strings.Repeat("-", 80) + "\n")

	for name, pkg := range r.packages {
		updatedStr := "No"
		if pkg.Updated {
			updatedStr = "Yes"
		}
		fmt.Fprintf(&sb, "%-25s | %-8s | %-12s | %-12s | %-12s\n",
			truncate(name, 25),
			updatedStr,
			truncate(pkg.FormulaAnalysis, 12),
			truncate(pkg.YaraScan, 12),
			truncate(pkg.LLMMalwareScan, 12))
	}

	sb.WriteString("\n")
	fmt.Fprintf(&sb, "Report completed: %s\n", time.Now().Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(&sb, "Duration: %s\n", time.Since(r.startTime).Round(time.Second))

	_, err = f.WriteString(sb.String())
	return err
}

// GetSummary returns a formatted summary for console output
func (r *Report) GetSummary() string {
	var sb strings.Builder

	// Count stats
	updated := 0
	notUpdated := 0
	totalCVEsUpdated := 0
	totalCVEsNotUpdated := 0
	yaraReviewCount := 0
	totalYaraFindings := 0
	llmReviewCount := 0
	llmHoldCount := 0

	for _, pkg := range r.packages {
		if pkg.Updated {
			updated++
			totalCVEsUpdated += pkg.CVECount
		} else {
			notUpdated++
			totalCVEsNotUpdated += pkg.CVECount
		}

		// Count YARA reviews (packages with findings)
		if strings.Contains(pkg.YaraScan, "findings") {
			yaraReviewCount++
		}

		// Count LLM verdicts
		switch pkg.LLMMalwareScan {
		case "REVIEW":
			llmReviewCount++
		case "HOLD":
			llmHoldCount++
		}
	}

	// Count total YARA findings
	for _, findings := range r.yaraFindings {
		totalYaraFindings += len(findings)
	}

	fmt.Fprintf(&sb, "Packages updated: %d (had %d CVEs)\n", updated, totalCVEsUpdated)
	fmt.Fprintf(&sb, "Packages not updated: %d (have %d CVEs)\n", notUpdated, totalCVEsNotUpdated)
	fmt.Fprintf(&sb, "YARA scan: %d packages with %d total findings requiring review\n", yaraReviewCount, totalYaraFindings)
	if llmHoldCount > 0 {
		fmt.Fprintf(&sb, "LLM analysis: %d REVIEW, %d HOLD\n\n", llmReviewCount, llmHoldCount)
	} else if llmReviewCount > 0 {
		fmt.Fprintf(&sb, "LLM analysis: %d REVIEW\n\n", llmReviewCount)
	} else {
		sb.WriteString("\n")
	}

	// Per-package scan results table
	fmt.Fprintf(&sb, "%-25s | %-8s | %-12s | %-12s | %-12s\n",
		"Package", "Updated", "Formula LLM", "YARA", "Code LLM")
	sb.WriteString(strings.Repeat("-", 80) + "\n")

	for name, pkg := range r.packages {
		updatedStr := "No"
		if pkg.Updated {
			updatedStr = "Yes"
		}
		fmt.Fprintf(&sb, "%-25s | %-8s | %-12s | %-12s | %-12s\n",
			truncate(name, 25),
			updatedStr,
			truncate(pkg.FormulaAnalysis, 12),
			truncate(pkg.YaraScan, 12),
			truncate(pkg.LLMMalwareScan, 12))
	}

	return sb.String()
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-2] + ".."
}
