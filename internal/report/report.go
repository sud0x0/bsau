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
	Name              string
	OldVersion        string
	NewVersion        string
	CVECount          int
	Severity          string
	Updated           bool
	UpdateError       string
	FormulaAnalysis   string // "SAFE", "REVIEW", "HOLD", "skipped", "failed", "N/A"
	SemgrepScan       string // "clean", "X findings", "skipped", "failed", "N/A"
	OllamaMalwareScan string // "SAFE", "REVIEW", "HOLD", "skipped", "failed", "N/A"
}

// Report manages the vulnerability and scan report file
type Report struct {
	filePath    string
	startTime   time.Time
	packages    map[string]*PackageScanStatus
	vulnDetails map[string][]string // package -> list of CVE details
}

// New creates a new report in the specified directory
func New(dir string) (*Report, error) {
	now := time.Now()
	filename := fmt.Sprintf("bsau_report_%s_%d.txt",
		now.Format("2006-01-02"),
		now.Unix())
	filePath := filepath.Join(dir, filename)

	r := &Report{
		filePath:    filePath,
		startTime:   now,
		packages:    make(map[string]*PackageScanStatus),
		vulnDetails: make(map[string][]string),
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
		Name:              name,
		OldVersion:        oldVersion,
		NewVersion:        newVersion,
		CVECount:          cveCount,
		Severity:          severity,
		Updated:           false,
		FormulaAnalysis:   "N/A",
		SemgrepScan:       "N/A",
		OllamaMalwareScan: "N/A",
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

// SetSemgrepScan sets the Semgrep scan result for a package
func (r *Report) SetSemgrepScan(name, result string) {
	if pkg, ok := r.packages[name]; ok {
		pkg.SemgrepScan = result
	}
}

// SetOllamaMalwareScan sets the Ollama malware scan result for a package
func (r *Report) SetOllamaMalwareScan(name, result string) {
	if pkg, ok := r.packages[name]; ok {
		pkg.OllamaMalwareScan = result
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
	sb.WriteString("================================================================================\n")
	sb.WriteString("FINAL SUMMARY\n")
	sb.WriteString("================================================================================\n\n")

	// Count stats
	updated := 0
	notUpdated := 0
	totalCVEsUpdated := 0
	totalCVEsNotUpdated := 0

	for _, pkg := range r.packages {
		if pkg.Updated {
			updated++
			totalCVEsUpdated += pkg.CVECount
		} else {
			notUpdated++
			totalCVEsNotUpdated += pkg.CVECount
		}
	}

	sb.WriteString("UPDATE STATUS\n")
	sb.WriteString("--------------------------------------------------------------------------------\n")
	fmt.Fprintf(&sb, "Packages updated: %d (had %d CVEs)\n", updated, totalCVEsUpdated)
	fmt.Fprintf(&sb, "Packages not updated: %d (have %d CVEs)\n\n", notUpdated, totalCVEsNotUpdated)

	// Per-package scan results
	sb.WriteString("PER-PACKAGE SCAN RESULTS\n")
	sb.WriteString("--------------------------------------------------------------------------------\n")
	fmt.Fprintf(&sb, "%-25s | %-8s | %-12s | %-12s | %-12s\n",
		"Package", "Updated", "Formula LLM", "Semgrep", "Code LLM")
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
			truncate(pkg.SemgrepScan, 12),
			truncate(pkg.OllamaMalwareScan, 12))
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

	for _, pkg := range r.packages {
		if pkg.Updated {
			updated++
			totalCVEsUpdated += pkg.CVECount
		} else {
			notUpdated++
			totalCVEsNotUpdated += pkg.CVECount
		}
	}

	fmt.Fprintf(&sb, "Packages updated: %d (had %d CVEs)\n", updated, totalCVEsUpdated)
	fmt.Fprintf(&sb, "Packages not updated: %d (have %d CVEs)\n\n", notUpdated, totalCVEsNotUpdated)

	// Per-package scan results table
	fmt.Fprintf(&sb, "%-25s | %-8s | %-12s | %-12s | %-12s\n",
		"Package", "Updated", "Formula LLM", "Semgrep", "Code LLM")
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
			truncate(pkg.SemgrepScan, 12),
			truncate(pkg.OllamaMalwareScan, 12))
	}

	return sb.String()
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-2] + ".."
}
