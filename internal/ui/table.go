package ui

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/olekukonko/tablewriter"
	"github.com/sud0x0/bsau/internal/ollama"
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
	OllamaVerdict  ollama.Verdict
	Recommendation string
}

// PostInstallRow represents a row in the post-install summary (Step 6) and inspect results
type PostInstallRow struct {
	Package       string
	Version       string
	CVECount      int
	Severity      Severity
	SemgrepCount  int
	OllamaVerdict ollama.Verdict
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
func RenderPreInstallTable(rows []PreInstallRow, showOllama bool) {
	headers := []string{"Package", "CVEs", "Recommendation"}
	alignments := []int{
		tablewriter.ALIGN_LEFT,
		tablewriter.ALIGN_RIGHT,
		tablewriter.ALIGN_LEFT,
	}

	if showOllama {
		headers = []string{"Package", "CVEs", "Ollama Verdict", "Recommendation"}
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

		if showOllama {
			cols = append(cols, colorVerdict(row.OllamaVerdict))
		}

		cols = append(cols, colorRecommendation(row.Recommendation))
		table.Append(cols)
	}

	table.Render()
}

// InspectTableOptions controls which columns to show in inspect results
type InspectTableOptions struct {
	ShowVuln    bool
	ShowSemgrep bool
	ShowOllama  bool
}

// RenderPostInstallTable displays post-install summary (Step 6)
func RenderPostInstallTable(rows []PostInstallRow, showOllama bool) {
	RenderInspectTable(rows, InspectTableOptions{
		ShowVuln:    false,
		ShowSemgrep: true,
		ShowOllama:  showOllama,
	})
}

// RenderInspectTable displays inspect results with configurable columns
func RenderInspectTable(rows []PostInstallRow, opts InspectTableOptions) {
	headers := []string{"Package"}
	alignments := []int{tablewriter.ALIGN_LEFT}

	if opts.ShowVuln {
		headers = append(headers, "Version", "CVEs", "Severity")
		alignments = append(alignments, tablewriter.ALIGN_LEFT, tablewriter.ALIGN_RIGHT, tablewriter.ALIGN_CENTER)
	}

	if opts.ShowSemgrep {
		headers = append(headers, "Semgrep")
		alignments = append(alignments, tablewriter.ALIGN_RIGHT)
	}

	if opts.ShowOllama {
		headers = append(headers, "Ollama")
		alignments = append(alignments, tablewriter.ALIGN_CENTER)
	}

	headers = append(headers, "Overall")
	alignments = append(alignments, tablewriter.ALIGN_CENTER)

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader(headers)
	table.SetBorder(true)
	table.SetRowLine(false)
	table.SetAutoWrapText(false)
	table.SetColumnAlignment(alignments)

	for _, row := range rows {
		cols := []string{row.Package}

		if opts.ShowVuln {
			cves := fmt.Sprintf("%d", row.CVECount)
			if row.Severity == SeverityNA {
				cves = "N/A"
			}
			cols = append(cols, row.Version, cves, colorSeverity(row.Severity))
		}

		if opts.ShowSemgrep {
			cols = append(cols, fmt.Sprintf("%d", row.SemgrepCount))
		}

		if opts.ShowOllama {
			cols = append(cols, colorVerdict(row.OllamaVerdict))
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
	skipped int
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

// Skip increments the skipped counter (call when an item fails/is skipped)
func (p *Progress) Skip() {
	p.skipped++
}

// Done completes the progress and moves to next line
func (p *Progress) Done() {
	status := "Done"
	color := ColorGreen
	if p.skipped > 0 {
		status = fmt.Sprintf("Done (%d skipped)", p.skipped)
		color = ColorYellow
	}
	fmt.Printf("\r%s[%d/%d]%s %s%-40s%s\n",
		color, p.current, p.total, ColorReset,
		color, status, ColorReset)
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

func colorVerdict(v ollama.Verdict) string {
	switch v {
	case ollama.VerdictSafe:
		return ColorGreen + string(v) + ColorReset
	case ollama.VerdictReview:
		return ColorYellow + string(v) + ColorReset
	case ollama.VerdictHold:
		return ColorRed + string(v) + ColorReset
	default:
		return string(v)
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

// ScanFailure represents a failure during the workflow
type ScanFailure struct {
	Package string // Package name (empty for non-package-specific failures)
	Step    string // Which step failed (e.g., "OSV Scan", "Semgrep")
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
