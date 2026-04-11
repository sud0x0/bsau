package ui

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/olekukonko/tablewriter"
	"github.com/sud0x0/bsau/internal/claude"
	"github.com/sud0x0/bsau/internal/hashlookup"
)

// Color codes for terminal output
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorCyan   = "\033[36m"
	ColorBold   = "\033[1m"
)

// Severity represents CVE severity levels
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityNone     Severity = "NONE"
	SeverityNA       Severity = "UNKNOWN"
)

// PackageRow represents a row in the package table (Step 2)
type PackageRow struct {
	Package   string
	Current   string
	Available string
	Pinned    bool
	CVECount  int
	Severity  Severity
	Action    string
}

// PreInstallRow represents a row in the pre-install scan table (Step 4)
type PreInstallRow struct {
	Package        string
	CVECount       int
	ClaudeVerdict  claude.Verdict
	Recommendation string
}

// PostInstallRow represents a row in the post-install summary (Step 6)
type PostInstallRow struct {
	Package       string
	CIRCLResult   hashlookup.HashResult
	VTResult      string
	SemgrepCount  int
	ClaudeVerdict claude.Verdict
	Overall       string
}

// RenderPackageTable displays the package status table (Step 2)
func RenderPackageTable(rows []PackageRow) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Package", "Current", "Latest Brew Version", "Pinned", "CVEs", "Severity", "Action"})
	table.SetBorder(true)
	table.SetRowLine(false)
	table.SetAutoWrapText(false)
	table.SetColumnAlignment([]int{
		tablewriter.ALIGN_LEFT,
		tablewriter.ALIGN_LEFT,
		tablewriter.ALIGN_LEFT,
		tablewriter.ALIGN_CENTER,
		tablewriter.ALIGN_RIGHT,
		tablewriter.ALIGN_CENTER,
		tablewriter.ALIGN_LEFT,
	})

	for _, row := range rows {
		pinned := ""
		if row.Pinned {
			pinned = "Yes"
		}

		cves := fmt.Sprintf("%d", row.CVECount)
		if row.Severity == SeverityNA {
			cves = "unknown"
		}

		table.Append([]string{
			row.Package,
			row.Current,
			row.Available,
			pinned,
			cves,
			colorSeverity(row.Severity),
			row.Action,
		})
	}

	table.Render()
}

// RenderPreInstallTable displays pre-install scan results (Step 4)
func RenderPreInstallTable(rows []PreInstallRow, showClaude bool) {
	headers := []string{"Package", "CVEs", "Recommendation"}
	alignments := []int{
		tablewriter.ALIGN_LEFT,
		tablewriter.ALIGN_RIGHT,
		tablewriter.ALIGN_LEFT,
	}

	if showClaude {
		headers = []string{"Package", "CVEs", "Claude Verdict", "Recommendation"}
		alignments = []int{
			tablewriter.ALIGN_LEFT,
			tablewriter.ALIGN_RIGHT,
			tablewriter.ALIGN_CENTER,
			tablewriter.ALIGN_LEFT,
		}
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader(headers)
	table.SetBorder(true)
	table.SetRowLine(false)
	table.SetAutoWrapText(false)
	table.SetColumnAlignment(alignments)

	for _, row := range rows {
		cols := []string{
			row.Package,
			fmt.Sprintf("%d", row.CVECount),
		}

		if showClaude {
			cols = append(cols, colorVerdict(row.ClaudeVerdict))
		}

		cols = append(cols, colorRecommendation(row.Recommendation))
		table.Append(cols)
	}

	table.Render()
}

// RenderPostInstallTable displays post-install summary (Step 6)
func RenderPostInstallTable(rows []PostInstallRow, showVT, showClaude bool) {
	headers := []string{"Package", "CIRCL", "Semgrep", "Overall"}
	alignments := []int{
		tablewriter.ALIGN_LEFT,
		tablewriter.ALIGN_CENTER,
		tablewriter.ALIGN_RIGHT,
		tablewriter.ALIGN_CENTER,
	}

	if showVT {
		headers = insertAt(headers, 2, "VT")
		alignments = insertIntAt(alignments, 2, tablewriter.ALIGN_CENTER)
	}
	if showClaude {
		headers = insertAt(headers, len(headers)-1, "Claude")
		alignments = insertIntAt(alignments, len(alignments)-1, tablewriter.ALIGN_CENTER)
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader(headers)
	table.SetBorder(true)
	table.SetRowLine(false)
	table.SetAutoWrapText(false)
	table.SetColumnAlignment(alignments)

	for _, row := range rows {
		cols := []string{
			row.Package,
			colorHashResult(row.CIRCLResult),
			fmt.Sprintf("%d", row.SemgrepCount),
		}

		if showVT {
			cols = insertAt(cols, 2, row.VTResult)
		}
		if showClaude {
			cols = insertAt(cols, len(cols)-1, colorVerdict(row.ClaudeVerdict))
		}

		cols = append(cols, colorOverall(row.Overall))
		table.Append(cols)
	}

	table.Render()
}

// RenderSummary displays the final summary
func RenderSummary(updated, failed int, cvesResolved, cvesRemaining int) {
	fmt.Println()
	fmt.Printf("%s=== Summary ===%s\n", ColorBold, ColorReset)
	fmt.Printf("Packages updated: %s%d%s\n", ColorGreen, updated, ColorReset)
	if failed > 0 {
		fmt.Printf("Packages failed:  %s%d%s\n", ColorRed, failed, ColorReset)
	}
	fmt.Printf("CVEs resolved:    %s%d%s\n", ColorGreen, cvesResolved, ColorReset)
	if cvesRemaining > 0 {
		fmt.Printf("CVEs remaining:   %s%d%s\n", ColorYellow, cvesRemaining, ColorReset)
	}
	fmt.Println()
}

// PrintWarning prints a warning message
func PrintWarning(msg string) {
	fmt.Printf("%s[WARN]%s %s\n", ColorYellow, ColorReset, msg)
}

// PrintError prints an error message
func PrintError(msg string) {
	fmt.Printf("%s[ERROR]%s %s\n", ColorRed, ColorReset, msg)
}

// PrintInfo prints an info message
func PrintInfo(msg string) {
	fmt.Printf("%s[INFO]%s %s\n", ColorCyan, ColorReset, msg)
}

// PrintSuccess prints a success message
func PrintSuccess(msg string) {
	fmt.Printf("%s[OK]%s %s\n", ColorGreen, ColorReset, msg)
}

// PrintSkipped prints a skipped/not applicable message
func PrintSkipped(msg string) {
	fmt.Printf("%s[SKIPPED]%s %s\n", ColorYellow, ColorReset, msg)
}

// PrintRunDir prints the run directory path
func PrintRunDir(runDir string) {
	fmt.Printf("\n%sbsau run directory:%s %s\n", ColorBold, ColorReset, runDir)
	fmt.Println("  (delete manually if bsau exits unexpectedly)")
	fmt.Println()
}

// PrintStep prints a step header with number and description
func PrintStep(step, total int, title, description string) {
	fmt.Println()
	fmt.Printf("%s══════════════════════════════════════════════════════════════%s\n", ColorCyan, ColorReset)
	fmt.Printf("%s  Step %d of %d: %s%s\n", ColorBold, step, total, title, ColorReset)
	fmt.Printf("%s  %s%s\n", ColorCyan, description, ColorReset)
	fmt.Printf("%s══════════════════════════════════════════════════════════════%s\n", ColorCyan, ColorReset)
	fmt.Println()
}

// Progress provides a simple progress indicator for long-running operations
type Progress struct {
	total   int
	current int
	prefix  string
}

// NewProgress creates a new progress indicator
func NewProgress(prefix string, total int) *Progress {
	return &Progress{
		total:   total,
		current: 0,
		prefix:  prefix,
	}
}

// Update shows progress for the current item
func (p *Progress) Update(item string) {
	p.current++
	// Clear line and print progress
	fmt.Printf("\r%s[%d/%d]%s %s%-40s%s",
		ColorCyan, p.current, p.total, ColorReset,
		ColorYellow, truncate(item, 40), ColorReset)
}

// Done completes the progress and moves to next line
func (p *Progress) Done() {
	fmt.Printf("\r%s[%d/%d]%s %s%-40s%s\n",
		ColorGreen, p.current, p.total, ColorReset,
		ColorGreen, "Done", ColorReset)
}

// Clear clears the progress line
func (p *Progress) Clear() {
	fmt.Printf("\r%-60s\r", "")
}

// truncate shortens a string to maxLen
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// Spinner provides a simple spinning indicator
type Spinner struct {
	frames  []string
	current int
	message string
	done    chan bool
}

// NewSpinner creates a new spinner with a message
func NewSpinner(message string) *Spinner {
	return &Spinner{
		frames:  []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
		current: 0,
		message: message,
		done:    make(chan bool),
	}
}

// Start begins the spinner animation
func (s *Spinner) Start() {
	go func() {
		for {
			select {
			case <-s.done:
				return
			default:
				fmt.Printf("\r%s%s%s %s", ColorCyan, s.frames[s.current], ColorReset, s.message)
				s.current = (s.current + 1) % len(s.frames)
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()
}

// Stop stops the spinner and clears the line
func (s *Spinner) Stop() {
	s.done <- true
	fmt.Printf("\r%-60s\r", "")
}

// StopWithMessage stops the spinner and shows a final message
func (s *Spinner) StopWithMessage(msg string) {
	s.done <- true
	fmt.Printf("\r%s✓%s %s\n", ColorGreen, ColorReset, msg)
}

func colorSeverity(s Severity) string {
	switch s {
	case SeverityCritical:
		return ColorRed + string(s) + ColorReset
	case SeverityHigh:
		return ColorRed + string(s) + ColorReset
	case SeverityMedium:
		return ColorYellow + string(s) + ColorReset
	case SeverityLow:
		return ColorCyan + string(s) + ColorReset
	default:
		return string(s)
	}
}

func colorVerdict(v claude.Verdict) string {
	switch v {
	case claude.VerdictSafe:
		return ColorGreen + string(v) + ColorReset
	case claude.VerdictReview:
		return ColorYellow + string(v) + ColorReset
	case claude.VerdictHold:
		return ColorRed + string(v) + ColorReset
	default:
		return string(v)
	}
}

func colorHashResult(h hashlookup.HashResult) string {
	switch h {
	case hashlookup.HashNotFlaggedByCIRCL:
		return ColorGreen + "CLEAN" + ColorReset
	case hashlookup.HashNotInCIRCL:
		return "NOT_IN_DB"
	case hashlookup.HashCIRCLMalicious:
		return ColorRed + "MALICIOUS" + ColorReset
	case hashlookup.HashVTConfirmed:
		return ColorRed + "VT_CONFIRMED" + ColorReset
	case hashlookup.HashVTClean:
		return ColorYellow + "VT_CLEAN" + ColorReset
	case hashlookup.HashVTNotFound:
		return ColorYellow + "VT_NOT_FOUND" + ColorReset
	default:
		return string(h)
	}
}

func colorRecommendation(r string) string {
	r = strings.ToUpper(r)
	switch r {
	case "SAFE", "UPDATE", "PROCEED":
		return ColorGreen + r + ColorReset
	case "REVIEW":
		return ColorYellow + r + ColorReset
	case "BLOCK", "HOLD":
		return ColorRed + r + ColorReset
	default:
		return r
	}
}

func colorOverall(o string) string {
	o = strings.ToUpper(o)
	switch o {
	case "CLEAN", "OK":
		return ColorGreen + o + ColorReset
	case "REVIEW", "WARNING":
		return ColorYellow + o + ColorReset
	case "BLOCK", "MALICIOUS", "HOLD":
		return ColorRed + o + ColorReset
	default:
		return o
	}
}

func insertAt(slice []string, index int, value string) []string {
	if index >= len(slice) {
		return append(slice, value)
	}
	slice = append(slice[:index+1], slice[index:]...)
	slice[index] = value
	return slice
}

func insertIntAt(slice []int, index int, value int) []int {
	if index >= len(slice) {
		return append(slice, value)
	}
	slice = append(slice[:index+1], slice[index:]...)
	slice[index] = value
	return slice
}

// ScanFailure represents a failure during the workflow
type ScanFailure struct {
	Package string // Package name (empty for non-package-specific failures)
	Step    string // Which step failed (e.g., "OSV Scan", "CIRCL Hash", "Semgrep")
	Error   string // Error message
}

// RenderFailureSummary displays failures at the end of the workflow
func RenderFailureSummary(failures []ScanFailure, totalPackages int) {
	if len(failures) == 0 {
		return
	}

	fmt.Println()
	fmt.Printf("%s=== Failures ===%s\n", ColorBold, ColorReset)

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Package", "Step", "Error"})
	table.SetBorder(true)
	table.SetRowLine(false)
	table.SetAutoWrapText(true)
	table.SetColWidth(50)
	table.SetColumnAlignment([]int{
		tablewriter.ALIGN_LEFT,
		tablewriter.ALIGN_LEFT,
		tablewriter.ALIGN_LEFT,
	})

	for _, f := range failures {
		pkg := f.Package
		if pkg == "" {
			pkg = "-"
		}
		table.Append([]string{pkg, f.Step, f.Error})
	}

	table.Render()

	// Calculate and display pass/fail percentage
	failedPkgs := make(map[string]bool)
	for _, f := range failures {
		if f.Package != "" {
			failedPkgs[f.Package] = true
		}
	}
	failedCount := len(failedPkgs)
	passedCount := totalPackages - failedCount

	if totalPackages > 0 {
		passRate := float64(passedCount) / float64(totalPackages) * 100
		fmt.Printf("\nPackage scan results: %s%d passed%s / %s%d failed%s (%.1f%% success rate)\n",
			ColorGreen, passedCount, ColorReset,
			ColorRed, failedCount, ColorReset,
			passRate)
	}
	fmt.Println()
}
