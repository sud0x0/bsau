package ui

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/sud0x0/bsau/internal/ollama"
	"golang.org/x/term"
)

// Prompter handles user input
type Prompter struct {
	reader *bufio.Reader
}

// NewPrompter creates a new prompter
func NewPrompter() *Prompter {
	return &Prompter{
		reader: bufio.NewReader(os.Stdin),
	}
}

// Confirm asks a yes/no question and returns the result
func (p *Prompter) Confirm(question string, defaultYes bool) (bool, error) {
	suffix := " [y/N]: "
	if defaultYes {
		suffix = " [Y/n]: "
	}

	fmt.Print(question + suffix)
	input, err := p.reader.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("reading input: %w", err)
	}

	input = strings.TrimSpace(strings.ToLower(input))
	if input == "" {
		return defaultYes, nil
	}

	return input == "y" || input == "yes", nil
}

// Select presents options and returns the selected index
func (p *Prompter) Select(question string, options []string) (int, error) {
	fmt.Println(question)
	for i, opt := range options {
		fmt.Printf("  %d. %s\n", i+1, opt)
	}
	fmt.Print("Enter number: ")

	input, err := p.reader.ReadString('\n')
	if err != nil {
		return -1, fmt.Errorf("reading input: %w", err)
	}

	input = strings.TrimSpace(input)
	choice, err := strconv.Atoi(input)
	if err != nil {
		return -1, fmt.Errorf("invalid selection: %s", input)
	}

	if choice < 1 || choice > len(options) {
		return -1, fmt.Errorf("selection out of range: %d", choice)
	}

	return choice - 1, nil
}

// MultiSelect presents options and returns selected indices
func (p *Prompter) MultiSelect(question string, options []string) ([]int, error) {
	fmt.Println(question)
	for i, opt := range options {
		fmt.Printf("  %d. %s\n", i+1, opt)
	}
	fmt.Print("Enter numbers (comma-separated) or 'all': ")

	input, err := p.reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("reading input: %w", err)
	}

	input = strings.TrimSpace(strings.ToLower(input))
	if input == "all" {
		indices := make([]int, len(options))
		for i := range options {
			indices[i] = i
		}
		return indices, nil
	}

	parts := strings.Split(input, ",")
	indices := make([]int, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		choice, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("invalid number: %s", part)
		}
		if choice < 1 || choice > len(options) {
			return nil, fmt.Errorf("selection out of range: %d", choice)
		}
		indices = append(indices, choice-1)
	}

	return indices, nil
}

// SelectPackagesForUpdate presents the update options menu
func (p *Prompter) SelectPackagesForUpdate(packages []string) ([]string, error) {
	if len(packages) == 0 {
		return nil, nil
	}

	fmt.Println()
	fmt.Println("Select packages to update:")
	fmt.Println("  1. Update all non-pinned packages")
	fmt.Println("  2. Select packages to exclude")
	fmt.Println("  3. Cancel")
	fmt.Print("Enter choice: ")

	input, err := p.reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("reading input: %w", err)
	}

	choice := strings.TrimSpace(input)
	switch choice {
	case "1":
		return packages, nil
	case "2":
		return p.excludePackages(packages)
	case "3":
		return nil, nil
	default:
		return nil, fmt.Errorf("invalid choice: %s", choice)
	}
}

func (p *Prompter) excludePackages(packages []string) ([]string, error) {
	fmt.Println()
	fmt.Println("Select packages to EXCLUDE from update:")
	for i, pkg := range packages {
		fmt.Printf("  %d. %s\n", i+1, pkg)
	}
	fmt.Print("Enter numbers to exclude (comma-separated): ")

	input, err := p.reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("reading input: %w", err)
	}

	input = strings.TrimSpace(input)
	if input == "" {
		return packages, nil
	}

	excludeSet := make(map[int]bool)
	parts := strings.Split(input, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		idx, err := strconv.Atoi(part)
		if err != nil {
			PrintWarning(fmt.Sprintf("Ignoring invalid number: %s", part))
			continue
		}
		if idx >= 1 && idx <= len(packages) {
			excludeSet[idx-1] = true
		}
	}

	selected := make([]string, 0, len(packages)-len(excludeSet))
	for i, pkg := range packages {
		if !excludeSet[i] {
			selected = append(selected, pkg)
		}
	}

	return selected, nil
}

// ConfirmPackageUpgrade asks for confirmation before upgrading a specific package
func (p *Prompter) ConfirmPackageUpgrade(pkg string, verdict ollama.Verdict, reason string) (bool, error) {
	fmt.Println()
	fmt.Printf("Package: %s%s%s\n", ColorBold, pkg, ColorReset)
	fmt.Printf("Verdict: %s\n", colorVerdict(verdict))
	if reason != "" {
		fmt.Printf("Reason:  %s\n", reason)
	}

	return p.Confirm("Proceed with upgrade?", verdict == ollama.VerdictSafe)
}

// WaitForEnter waits for the user to press Enter
func (p *Prompter) WaitForEnter(message string) {
	if message == "" {
		message = "Press Enter to continue..."
	}
	fmt.Print(message)
	_, _ = p.reader.ReadString('\n')
}

// WaitForEnterOrEsc waits for Enter (returns true) or Esc (returns false)
func (p *Prompter) WaitForEnterOrEsc() bool {
	// Switch to raw mode to capture Esc
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		// Fallback to regular read
		_, _ = p.reader.ReadString('\n')
		return true
	}
	defer func() { _ = term.Restore(int(os.Stdin.Fd()), oldState) }()

	buf := make([]byte, 3)
	for {
		n, err := os.Stdin.Read(buf)
		if err != nil {
			return true
		}
		if n > 0 {
			if buf[0] == 13 || buf[0] == 10 { // Enter
				fmt.Print("\r\n")
				return true
			}
			if buf[0] == 27 && n == 1 { // Esc (single byte, not part of escape sequence)
				fmt.Print("\r\n")
				return false
			}
			if buf[0] == 'q' || buf[0] == 'Q' { // Also allow 'q' to cancel
				fmt.Print("\r\n")
				return false
			}
		}
	}
}

// ReadInput reads a line of input from the user
func (p *Prompter) ReadInput(prompt string) (string, error) {
	fmt.Print(prompt)
	input, err := p.reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("reading input: %w", err)
	}
	return strings.TrimSpace(input), nil
}

// APIUsageInfo contains information about API usage for user confirmation
type APIUsageInfo struct {
	StepName       string   // Name of the step (e.g., "Pre-install Ollama scan")
	OllamaPackages []string // Packages that will use Ollama
	VTRequests     int      // Total VT API requests required
	VTFiles        []string // Files that will be checked via VT
}

// ConfirmAPIUsage asks the user to confirm API usage before proceeding
// Returns true if user wants to proceed, false if they want to skip
func (p *Prompter) ConfirmAPIUsage(info APIUsageInfo) (bool, error) {
	fmt.Println()
	fmt.Printf("%s┌─────────────────────────────────────────────────────────────┐%s\n", ColorCyan, ColorReset)
	fmt.Printf("%s│ API Usage Confirmation: %-36s│%s\n", ColorCyan, info.StepName, ColorReset)
	fmt.Printf("%s└─────────────────────────────────────────────────────────────┘%s\n", ColorCyan, ColorReset)
	fmt.Println()

	hasOllamaUsage := len(info.OllamaPackages) > 0
	hasVTUsage := info.VTRequests > 0

	if !hasOllamaUsage && !hasVTUsage {
		fmt.Println("  No API calls required for this step.")
		return true, nil
	}

	if hasOllamaUsage {
		fmt.Printf("  %sOllama (local):%s\n", ColorBold, ColorReset)
		fmt.Printf("    Packages (%d):   ", len(info.OllamaPackages))
		if len(info.OllamaPackages) <= 5 {
			fmt.Printf("%s\n", strings.Join(info.OllamaPackages, ", "))
		} else {
			fmt.Printf("%s, ... (+%d more)\n",
				strings.Join(info.OllamaPackages[:5], ", "),
				len(info.OllamaPackages)-5)
		}
		fmt.Println()
	}

	if hasVTUsage {
		fmt.Printf("  %sVirusTotal API:%s\n", ColorBold, ColorReset)
		fmt.Printf("    Requests required: %s%d%s\n", ColorYellow, info.VTRequests, ColorReset)
		if len(info.VTFiles) > 0 {
			fmt.Printf("    Files flagged by CIRCL as malicious:\n")
			displayCount := len(info.VTFiles)
			if displayCount > 5 {
				displayCount = 5
			}
			for _, f := range info.VTFiles[:displayCount] {
				// Show just filename, not full path
				parts := strings.Split(f, "/")
				filename := parts[len(parts)-1]
				fmt.Printf("      - %s%s%s\n", ColorRed, filename, ColorReset)
			}
			if len(info.VTFiles) > 5 {
				fmt.Printf("      ... +%d more files\n", len(info.VTFiles)-5)
			}
		}
		fmt.Println()
	}

	fmt.Println("  Options:")
	fmt.Printf("    %s[y]%s Proceed with API calls\n", ColorGreen, ColorReset)
	fmt.Printf("    %s[n]%s Skip this step (mark packages as REVIEW)\n", ColorYellow, ColorReset)
	fmt.Println()

	return p.Confirm("Proceed with API calls?", true)
}

// QuotaSufficiency represents whether there's enough API quota for an operation
type QuotaSufficiency struct {
	// Ollama (local - no quota limits, always available if running)
	OllamaPackagesRequired int
	OllamaAvailable        bool

	// VirusTotal
	VTRequestsRequired   int
	VTRequestsAvailable  int
	VTRequestsSufficient bool

	// Overall
	CanProceed      bool   // True if all required APIs have sufficient quota
	PartialPossible bool   // True if at least some work can be done
	Warning         string // Human-readable warning message
}

// CheckQuotaSufficiency compares required usage against available quota
func CheckQuotaSufficiency(
	ollamaPackagesRequired int, ollamaAvailable bool,
	vtRequestsRequired, vtRequestsAvailable int,
) *QuotaSufficiency {
	s := &QuotaSufficiency{
		OllamaPackagesRequired: ollamaPackagesRequired,
		OllamaAvailable:        ollamaAvailable,
		VTRequestsRequired:     vtRequestsRequired,
		VTRequestsAvailable:    vtRequestsAvailable,
	}

	// Check VT requests
	s.VTRequestsSufficient = vtRequestsRequired <= vtRequestsAvailable || vtRequestsRequired == 0

	// Overall assessment - Ollama is local so always available if running
	s.CanProceed = (ollamaPackagesRequired == 0 || ollamaAvailable) && s.VTRequestsSufficient

	// Check if partial work is possible
	if !s.CanProceed {
		s.PartialPossible = vtRequestsAvailable > 0
	}

	// Build warning message
	s.buildWarning()

	return s
}

func (s *QuotaSufficiency) buildWarning() {
	var warnings []string

	if s.OllamaPackagesRequired > 0 && !s.OllamaAvailable {
		warnings = append(warnings, fmt.Sprintf(
			"Ollama not available: %d packages require Ollama scan",
			s.OllamaPackagesRequired))
	}

	if !s.VTRequestsSufficient {
		warnings = append(warnings, fmt.Sprintf(
			"VirusTotal requests: need %d, have %d",
			s.VTRequestsRequired, s.VTRequestsAvailable))
	}

	if len(warnings) > 0 {
		s.Warning = strings.Join(warnings, "; ")
	}
}

// APIQuotaStatus contains quota information for all APIs
type APIQuotaStatus struct {
	// Ollama (local)
	OllamaEnabled   bool
	OllamaAvailable bool
	OllamaModel     string
	OllamaError     error

	// VirusTotal API
	VTEnabled        bool
	VTDailyLimit     int
	VTDailyUsed      int
	VTDailyRemaining int
	VTRateLimit      int // per minute
	VTError          error
}

// DisplayAPIQuota shows the current API quota status to the user
func DisplayAPIQuota(status APIQuotaStatus) {
	fmt.Println()
	fmt.Printf("%s┌─────────────────────────────────────────────────────────────┐%s\n", ColorCyan, ColorReset)
	fmt.Printf("%s│ API Status                                                  │%s\n", ColorCyan, ColorReset)
	fmt.Printf("%s└─────────────────────────────────────────────────────────────┘%s\n", ColorCyan, ColorReset)
	fmt.Println()

	// Ollama status
	if status.OllamaEnabled {
		fmt.Printf("  %sOllama (local):%s\n", ColorBold, ColorReset)
		if status.OllamaError != nil {
			fmt.Printf("    %sError: %s%s\n", ColorRed, status.OllamaError, ColorReset)
		} else if status.OllamaAvailable {
			fmt.Printf("    Status:  %sAvailable%s\n", ColorGreen, ColorReset)
			fmt.Printf("    Model:   %s\n", status.OllamaModel)
		} else {
			fmt.Printf("    Status:  %sNot running%s (start with: ollama serve)\n", ColorRed, ColorReset)
		}
		fmt.Println()
	} else {
		fmt.Printf("  %sOllama:%s %sDisabled%s (set features.ollama_scan: true)\n",
			ColorBold, ColorReset, ColorYellow, ColorReset)
		fmt.Println()
	}

	// VirusTotal API status
	if status.VTEnabled {
		fmt.Printf("  %sVirusTotal API:%s\n", ColorBold, ColorReset)
		if status.VTError != nil {
			fmt.Printf("    %sError: %s%s\n", ColorRed, status.VTError, ColorReset)
		} else {
			// Daily quota
			dailyPct := 0.0
			if status.VTDailyLimit > 0 {
				dailyPct = float64(status.VTDailyRemaining) / float64(status.VTDailyLimit) * 100
			}
			dailyColor := ColorGreen
			if dailyPct < 20 {
				dailyColor = ColorRed
			} else if dailyPct < 50 {
				dailyColor = ColorYellow
			}
			fmt.Printf("    Daily:     %s%d%s / %d remaining (%.0f%%)\n",
				dailyColor, status.VTDailyRemaining, ColorReset, status.VTDailyLimit, dailyPct)
			fmt.Printf("    Rate:      %d requests/minute\n", status.VTRateLimit)
		}
		fmt.Println()
	} else {
		fmt.Printf("  %sVirusTotal API:%s %sDisabled%s (set features.vt_fallback: true)\n",
			ColorBold, ColorReset, ColorYellow, ColorReset)
		fmt.Println()
	}
}

// InsufficientQuotaChoice represents user's choice when quota is insufficient
type InsufficientQuotaChoice int

const (
	QuotaChoiceProceedPartial InsufficientQuotaChoice = iota // Proceed with available quota
	QuotaChoiceSkipAPI                                       // Skip API calls, mark as REVIEW
	QuotaChoiceCancel                                        // Cancel the operation
)

// ConfirmInsufficientQuota warns the user about insufficient quota and gets their choice
func (p *Prompter) ConfirmInsufficientQuota(sufficiency *QuotaSufficiency) (InsufficientQuotaChoice, error) {
	fmt.Println()
	fmt.Printf("%s┌─────────────────────────────────────────────────────────────┐%s\n", ColorRed, ColorReset)
	fmt.Printf("%s│ ⚠ SERVICE UNAVAILABLE                                       │%s\n", ColorRed, ColorReset)
	fmt.Printf("%s└─────────────────────────────────────────────────────────────┘%s\n", ColorRed, ColorReset)
	fmt.Println()

	// Show what's unavailable
	if sufficiency.OllamaPackagesRequired > 0 && !sufficiency.OllamaAvailable {
		fmt.Printf("  %sOllama (local):%s\n", ColorBold, ColorReset)
		fmt.Printf("    Status:    %sNot running%s\n", ColorRed, ColorReset)
		fmt.Printf("    Required:  %s%d%s packages need scanning\n", ColorYellow, sufficiency.OllamaPackagesRequired, ColorReset)
		fmt.Printf("    Start with: ollama serve\n")
		fmt.Println()
	}

	if !sufficiency.VTRequestsSufficient {
		fmt.Printf("  %sVirusTotal Requests:%s\n", ColorBold, ColorReset)
		fmt.Printf("    Required:  %s%d%s\n", ColorYellow, sufficiency.VTRequestsRequired, ColorReset)
		fmt.Printf("    Available: %s%d%s\n", ColorRed, sufficiency.VTRequestsAvailable, ColorReset)
		fmt.Println()
	}

	// Show options
	fmt.Println("  Options:")
	if sufficiency.PartialPossible {
		fmt.Printf("    %s[1]%s Proceed with partial scan (use available services)\n", ColorYellow, ColorReset)
		fmt.Printf("        - Scan as many packages as possible\n")
		fmt.Printf("        - Remaining packages marked as REVIEW\n")
	}
	fmt.Printf("    %s[2]%s Skip scans entirely (mark all as REVIEW)\n", ColorYellow, ColorReset)
	fmt.Printf("    %s[3]%s Cancel operation\n", ColorRed, ColorReset)
	fmt.Println()

	for {
		input, err := p.ReadInput("Enter choice (1-3): ")
		if err != nil {
			return QuotaChoiceCancel, err
		}

		switch strings.TrimSpace(input) {
		case "1":
			if sufficiency.PartialPossible {
				return QuotaChoiceProceedPartial, nil
			}
			fmt.Printf("  %sPartial scan not available - no services available%s\n", ColorRed, ColorReset)
		case "2":
			return QuotaChoiceSkipAPI, nil
		case "3", "":
			return QuotaChoiceCancel, nil
		default:
			fmt.Printf("  %sInvalid choice. Please enter 1, 2, or 3.%s\n", ColorYellow, ColorReset)
		}
	}
}

// DisplayQuotaComparison shows required vs available services before an operation
func DisplayQuotaComparison(sufficiency *QuotaSufficiency, stepName string) {
	fmt.Println()

	statusIcon := "✓"
	statusColor := ColorGreen
	if !sufficiency.CanProceed {
		statusIcon = "⚠"
		statusColor = ColorRed
	}

	fmt.Printf("%s┌─────────────────────────────────────────────────────────────┐%s\n", ColorCyan, ColorReset)
	fmt.Printf("%s│ Service Check: %-45s│%s\n", ColorCyan, stepName, ColorReset)
	fmt.Printf("%s└─────────────────────────────────────────────────────────────┘%s\n", ColorCyan, ColorReset)
	fmt.Println()

	// Ollama section
	if sufficiency.OllamaPackagesRequired > 0 {
		fmt.Printf("  %sOllama (local):%s\n", ColorBold, ColorReset)
		ollamaColor := ColorGreen
		ollamaIcon := "✓"
		if !sufficiency.OllamaAvailable {
			ollamaColor = ColorRed
			ollamaIcon = "✗"
		}
		fmt.Printf("    %s%s%s Status:   %s\n",
			ollamaColor, ollamaIcon, ColorReset,
			func() string {
				if sufficiency.OllamaAvailable {
					return "Available"
				}
				return "Not running"
			}())
		fmt.Printf("    Packages: %d to scan\n", sufficiency.OllamaPackagesRequired)
		fmt.Println()
	}

	// VT section
	if sufficiency.VTRequestsRequired > 0 {
		fmt.Printf("  %sVirusTotal API:%s\n", ColorBold, ColorReset)
		vtColor := ColorGreen
		vtIcon := "✓"
		if !sufficiency.VTRequestsSufficient {
			vtColor = ColorRed
			vtIcon = "✗"
		}
		fmt.Printf("    %s%s%s Requests: %d required / %d available\n",
			vtColor, vtIcon, ColorReset,
			sufficiency.VTRequestsRequired, sufficiency.VTRequestsAvailable)
		fmt.Println()
	}

	// Overall status
	fmt.Printf("  %sStatus: %s%s %s%s\n", ColorBold, statusColor, statusIcon,
		func() string {
			if sufficiency.CanProceed {
				return "All services available"
			}
			return "Some services unavailable"
		}(), ColorReset)
	fmt.Println()
}

// ScanItem represents an item that can be scanned
type ScanItem struct {
	Name            string // Package or file name
	Description     string // Additional info (version, path, etc.)
	EstimatedTokens int    // Estimated tokens for this item (for display purposes)
	Selected        bool
	Priority        int    // Higher = more important (for sorting)
	Category        string // Optional grouping (e.g., "formula", "code", "file")
}

// ScanSelector provides interactive selection with quota tracking
type ScanSelector struct {
	items             []ScanItem
	cursor            int
	done              bool
	canceled          bool
	viewOffset        int
	viewHeight        int
	availableTokens   int
	availableRequests int
	totalSelected     int
	tokensSelected    int
}

// NewScanSelector creates a new scan selector with quota limits
func NewScanSelector(items []ScanItem, availableTokens, availableRequests int) *ScanSelector {
	viewHeight := 15
	if height, err := getTerminalHeight(); err == nil && height > 10 {
		viewHeight = height - 14 // Reserve space for header, footer, progress bar
		if viewHeight < 5 {
			viewHeight = 5
		}
	}

	s := &ScanSelector{
		items:             items,
		cursor:            0,
		viewOffset:        0,
		viewHeight:        viewHeight,
		availableTokens:   availableTokens,
		availableRequests: availableRequests,
	}

	s.recalculateSelection()
	return s
}

func (s *ScanSelector) recalculateSelection() {
	s.totalSelected = 0
	s.tokensSelected = 0
	for _, item := range s.items {
		if item.Selected {
			s.totalSelected++
			s.tokensSelected += item.EstimatedTokens
		}
	}
}

// Run displays the interactive selector and returns selected items
func (s *ScanSelector) Run() ([]ScanItem, error) {
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return nil, fmt.Errorf("failed to set raw mode: %w", err)
	}
	defer func() { _ = term.Restore(int(os.Stdin.Fd()), oldState) }()

	// Alternate screen buffer
	fmt.Print("\033[?1049h")
	defer fmt.Print("\033[?1049l")

	// Hide cursor
	fmt.Print("\033[?25l")
	defer fmt.Print("\033[?25h")

	s.cursor = 0
	s.viewOffset = 0

	fmt.Print("\033[2J\033[H")
	s.render()

	buf := make([]byte, 3)
	for !s.done && !s.canceled {
		n, err := os.Stdin.Read(buf)
		if err != nil {
			return nil, fmt.Errorf("reading input: %w", err)
		}

		s.handleInput(buf[:n])
		s.render()
	}

	if s.canceled {
		return nil, nil
	}

	// Return selected items
	selected := make([]ScanItem, 0)
	for _, item := range s.items {
		if item.Selected {
			selected = append(selected, item)
		}
	}

	return selected, nil
}

func (s *ScanSelector) handleInput(buf []byte) {
	if len(buf) == 0 {
		return
	}

	maxCursor := len(s.items) + 1 // items + Done + Cancel

	// Arrow keys
	if len(buf) == 3 && buf[0] == 27 && buf[1] == 91 {
		switch buf[2] {
		case 65: // Up
			if s.cursor > 0 {
				s.cursor--
				s.adjustViewOffset()
			}
		case 66: // Down
			if s.cursor < maxCursor {
				s.cursor++
				s.adjustViewOffset()
			}
		}
		return
	}

	switch buf[0] {
	case 32: // Space - toggle
		if s.cursor < len(s.items) {
			s.items[s.cursor].Selected = !s.items[s.cursor].Selected
			s.recalculateSelection()
		}
	case 13: // Enter
		if s.cursor == len(s.items) {
			s.done = true
		} else if s.cursor == len(s.items)+1 {
			s.canceled = true
		}
	case 'q', 'Q':
		s.canceled = true
	case 'd', 'D':
		s.done = true
	case 'a', 'A': // Select all that fit in quota
		s.selectAllWithinQuota()
	case 'n', 'N': // Select none
		for i := range s.items {
			s.items[i].Selected = false
		}
		s.recalculateSelection()
	case 'p', 'P': // Select by priority (highest first until quota filled)
		s.selectByPriority()
	}
}

func (s *ScanSelector) selectAllWithinQuota() {
	// Deselect all first
	for i := range s.items {
		s.items[i].Selected = false
	}

	// Select items until quota is reached
	tokensUsed := 0
	requestsUsed := 0
	for i := range s.items {
		if tokensUsed+s.items[i].EstimatedTokens <= s.availableTokens &&
			requestsUsed+1 <= s.availableRequests {
			s.items[i].Selected = true
			tokensUsed += s.items[i].EstimatedTokens
			requestsUsed++
		}
	}
	s.recalculateSelection()
}

func (s *ScanSelector) selectByPriority() {
	// Sort by priority (higher first), then select until quota filled
	// Create a copy of indices sorted by priority
	indices := make([]int, len(s.items))
	for i := range indices {
		indices[i] = i
	}

	// Simple bubble sort by priority (descending)
	for i := 0; i < len(indices)-1; i++ {
		for j := i + 1; j < len(indices); j++ {
			if s.items[indices[j]].Priority > s.items[indices[i]].Priority {
				indices[i], indices[j] = indices[j], indices[i]
			}
		}
	}

	// Deselect all
	for i := range s.items {
		s.items[i].Selected = false
	}

	// Select by priority until quota filled
	tokensUsed := 0
	requestsUsed := 0
	for _, idx := range indices {
		if tokensUsed+s.items[idx].EstimatedTokens <= s.availableTokens &&
			requestsUsed+1 <= s.availableRequests {
			s.items[idx].Selected = true
			tokensUsed += s.items[idx].EstimatedTokens
			requestsUsed++
		}
	}
	s.recalculateSelection()
}

func (s *ScanSelector) adjustViewOffset() {
	if s.cursor < len(s.items) {
		if s.cursor < s.viewOffset {
			s.viewOffset = s.cursor
		}
		if s.cursor >= s.viewOffset+s.viewHeight {
			s.viewOffset = s.cursor - s.viewHeight + 1
		}
	} else {
		if len(s.items) > s.viewHeight {
			s.viewOffset = len(s.items) - s.viewHeight
		}
	}
}

func (s *ScanSelector) render() {
	fmt.Print("\033[H\033[2J")

	// Header
	fmt.Printf("%s╔══════════════════════════════════════════════════════════════════════════════╗%s\r\n", ColorCyan, ColorReset)
	fmt.Printf("%s║%s  %sSelect Items to Scan%s                                                         %s║%s\r\n", ColorCyan, ColorReset, ColorBold, ColorReset, ColorCyan, ColorReset)
	fmt.Printf("%s║%s  ↑/↓ Navigate  Space Toggle  a=Auto-fill  p=Priority  n=None  d=Done  q=Quit %s║%s\r\n", ColorCyan, ColorReset, ColorCyan, ColorReset)
	fmt.Printf("%s╚══════════════════════════════════════════════════════════════════════════════╝%s\r\n", ColorCyan, ColorReset)

	// Quota progress bar
	s.renderQuotaBar()

	// Scroll indicator (top)
	if s.viewOffset > 0 {
		fmt.Printf("  %s↑ %d more above%s\r\n", ColorYellow, s.viewOffset, ColorReset)
	} else {
		fmt.Print("\r\n")
	}

	// Items
	endIdx := s.viewOffset + s.viewHeight
	if endIdx > len(s.items) {
		endIdx = len(s.items)
	}

	for i := s.viewOffset; i < endIdx; i++ {
		item := s.items[i]
		cursor := "  "
		if i == s.cursor {
			cursor = ColorCyan + "> " + ColorReset
		}

		checkbox := "[ ]"
		if item.Selected {
			checkbox = ColorGreen + "[x]" + ColorReset
		}

		// Token cost indicator
		tokenStr := fmt.Sprintf("%d tok", item.EstimatedTokens)
		tokenColor := ColorGreen
		if item.EstimatedTokens > 5000 {
			tokenColor = ColorYellow
		}
		if item.EstimatedTokens > 10000 {
			tokenColor = ColorRed
		}

		// Priority indicator
		priorityStr := ""
		if item.Priority > 0 {
			priorityStr = fmt.Sprintf(" %s★%d%s", ColorYellow, item.Priority, ColorReset)
		}

		name := item.Name
		if len(name) > 25 {
			name = name[:22] + "..."
		}
		desc := item.Description
		if len(desc) > 20 {
			desc = desc[:17] + "..."
		}

		fmt.Printf("%s%s %-25s %-20s %s%6s%s%s\r\n",
			cursor, checkbox, name, desc, tokenColor, tokenStr, ColorReset, priorityStr)
	}

	// Scroll indicator (bottom)
	remaining := len(s.items) - endIdx
	if remaining > 0 {
		fmt.Printf("  %s↓ %d more below%s\r\n", ColorYellow, remaining, ColorReset)
	} else {
		fmt.Print("\r\n")
	}

	fmt.Print("\r\n")

	// Done button
	if s.cursor == len(s.items) {
		fmt.Printf("%s> %s%s[Done]%s - Scan %d item(s) using %d tokens\r\n",
			ColorCyan, ColorReset, ColorGreen, ColorReset, s.totalSelected, s.tokensSelected)
	} else {
		fmt.Printf("  %s[Done]%s - Scan %d item(s) using %d tokens\r\n",
			ColorGreen, ColorReset, s.totalSelected, s.tokensSelected)
	}

	// Cancel button
	if s.cursor == len(s.items)+1 {
		fmt.Printf("%s> %s%s[Cancel]%s - Skip scanning\r\n", ColorCyan, ColorReset, ColorRed, ColorReset)
	} else {
		fmt.Printf("  %s[Cancel]%s - Skip scanning\r\n", ColorRed, ColorReset)
	}
}

func (s *ScanSelector) renderQuotaBar() {
	fmt.Print("\r\n")

	// Calculate usage percentage
	usagePct := 0.0
	if s.availableTokens > 0 {
		usagePct = float64(s.tokensSelected) / float64(s.availableTokens) * 100
	}

	// Determine color based on usage
	barColor := ColorGreen
	if usagePct > 80 {
		barColor = ColorRed
	} else if usagePct > 50 {
		barColor = ColorYellow
	}

	// Over quota indicator
	overQuota := s.tokensSelected > s.availableTokens
	if overQuota {
		barColor = ColorRed
	}

	// Draw the bar
	barWidth := 50
	filledWidth := int(usagePct / 100 * float64(barWidth))
	if filledWidth > barWidth {
		filledWidth = barWidth
	}

	bar := strings.Repeat("█", filledWidth) + strings.Repeat("░", barWidth-filledWidth)

	fmt.Printf("  %sTokens:%s [%s%s%s] ", ColorBold, ColorReset, barColor, bar, ColorReset)

	if overQuota {
		fmt.Printf("%s%d / %d (OVER QUOTA by %d)%s\r\n",
			ColorRed, s.tokensSelected, s.availableTokens, s.tokensSelected-s.availableTokens, ColorReset)
	} else {
		remaining := s.availableTokens - s.tokensSelected
		fmt.Printf("%d / %d (%s%d remaining%s)\r\n",
			s.tokensSelected, s.availableTokens, ColorGreen, remaining, ColorReset)
	}

	// Requests counter
	fmt.Printf("  %sRequests:%s %d / %d selected\r\n",
		ColorBold, ColorReset, s.totalSelected, s.availableRequests)

	fmt.Print("\r\n")
}

// SelectItemsToScan shows the interactive scan selector
func (p *Prompter) SelectItemsToScan(items []ScanItem, availableTokens, availableRequests int) ([]ScanItem, error) {
	selector := NewScanSelector(items, availableTokens, availableRequests)
	return selector.Run()
}

// PackageItem represents a package in the interactive selector
type PackageItem struct {
	Name         string
	Current      string
	Latest       string
	CVECount     int
	Severity     Severity
	Pinned       bool
	Selected     bool
	Dependents   []string // Packages that depend on this one (would break if this is updated without them)
	Dependencies []string // Packages that this one requires (this would break if they're not updated)
	LockedAsDep  bool     // True if this package is auto-selected because a selected package depends on it
}

// InteractiveSelector provides an interactive package selection UI
type InteractiveSelector struct {
	items      []PackageItem
	cursor     int
	done       bool
	canceled   bool
	viewOffset int // For scrolling when list is longer than screen
	viewHeight int // Number of items visible at once
}

// NewInteractiveSelector creates a new interactive selector
// Note: Selection state should already be set on items before calling this
func NewInteractiveSelector(items []PackageItem) *InteractiveSelector {
	// Get terminal height, default to 20 if we can't determine
	viewHeight := 20
	if height, err := getTerminalHeight(); err == nil && height > 10 {
		// Reserve lines for header (6) + footer (4) + some margin (2)
		viewHeight = height - 12
		if viewHeight < 5 {
			viewHeight = 5
		}
	}

	s := &InteractiveSelector{
		items:      items,
		cursor:     0,
		viewOffset: 0,
		viewHeight: viewHeight,
	}

	// Calculate initial locked dependencies
	s.recalculateLockedDeps()

	return s
}

// recalculateLockedDeps marks packages as locked if they are dependencies of selected packages
func (s *InteractiveSelector) recalculateLockedDeps() {
	// Build a map of package name -> index for quick lookup
	pkgIndex := make(map[string]int)
	for i, item := range s.items {
		pkgIndex[item.Name] = i
	}

	// Reset all locked status
	for i := range s.items {
		s.items[i].LockedAsDep = false
	}

	// Method 1: For each selected package, lock its dependencies
	for _, item := range s.items {
		if item.Selected && !item.Pinned && !item.LockedAsDep {
			for _, depName := range item.Dependencies {
				if idx, ok := pkgIndex[depName]; ok {
					s.items[idx].LockedAsDep = true
					s.items[idx].Selected = true
				}
			}
		}
	}

	// Method 2: Use Dependents as reverse check
	// If package A has Dependents containing B, and B is selected, then A should be locked
	// (because B depends on A, so A will be upgraded by brew anyway)
	for i := range s.items {
		item := &s.items[i]
		if item.Pinned || item.LockedAsDep {
			continue
		}
		for _, dependentName := range item.Dependents {
			if idx, ok := pkgIndex[dependentName]; ok {
				if s.items[idx].Selected && !s.items[idx].Pinned {
					// A selected package depends on this one - lock it
					item.LockedAsDep = true
					item.Selected = true
					break
				}
			}
		}
	}
}

// getTerminalHeight returns the terminal height
func getTerminalHeight() (int, error) {
	width, height, err := term.GetSize(int(os.Stdout.Fd()))
	_ = width
	return height, err
}

// Run displays the interactive selector and returns selected package names
func (s *InteractiveSelector) Run() ([]string, error) {
	// Switch to raw mode
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return nil, fmt.Errorf("failed to set raw mode: %w", err)
	}
	defer func() { _ = term.Restore(int(os.Stdin.Fd()), oldState) }()

	// Switch to alternate screen buffer
	fmt.Print("\033[?1049h")
	defer fmt.Print("\033[?1049l")

	// Hide cursor
	fmt.Print("\033[?25l")
	defer fmt.Print("\033[?25h")

	// Ensure we start at the top
	s.cursor = 0
	s.viewOffset = 0

	// Clear the alternate screen and move to top
	fmt.Print("\033[2J\033[H")

	s.render()

	buf := make([]byte, 3)
	for !s.done && !s.canceled {
		n, err := os.Stdin.Read(buf)
		if err != nil {
			return nil, fmt.Errorf("reading input: %w", err)
		}

		s.handleInput(buf[:n])
		s.render()
	}

	if s.canceled {
		return nil, nil
	}

	// Return selected packages
	selected := make([]string, 0)
	for _, item := range s.items {
		if item.Selected && !item.Pinned {
			selected = append(selected, item.Name)
		}
	}

	return selected, nil
}

func (s *InteractiveSelector) handleInput(buf []byte) {
	if len(buf) == 0 {
		return
	}

	maxCursor := len(s.items) + 1 // items + Done + Cancel

	// Handle escape sequences (arrow keys)
	if len(buf) == 3 && buf[0] == 27 && buf[1] == 91 {
		switch buf[2] {
		case 65: // Up arrow
			if s.cursor > 0 {
				s.cursor--
				s.adjustViewOffset()
			}
		case 66: // Down arrow
			if s.cursor < maxCursor {
				s.cursor++
				s.adjustViewOffset()
			}
		}
		return
	}

	// Handle single key presses
	switch buf[0] {
	case 32: // Space - toggle selection
		if s.cursor < len(s.items) {
			item := &s.items[s.cursor]
			if !item.Pinned && !item.LockedAsDep {
				item.Selected = !item.Selected
				s.recalculateLockedDeps()
			}
		}
	case 13: // Enter - select current item
		if s.cursor == len(s.items) { // Done button
			s.done = true
		} else if s.cursor == len(s.items)+1 { // Cancel button
			s.canceled = true
		}
	case 'q', 'Q': // q - cancel
		s.canceled = true
	case 'd', 'D': // d - done
		s.done = true
	case 'a', 'A': // a - select all
		for i := range s.items {
			if !s.items[i].Pinned {
				s.items[i].Selected = true
			}
		}
		s.recalculateLockedDeps()
	case 'n', 'N': // n - select none
		for i := range s.items {
			if !s.items[i].Pinned {
				s.items[i].Selected = false
				s.items[i].LockedAsDep = false
			}
		}
	}
}

// adjustViewOffset ensures the cursor is visible in the viewport
func (s *InteractiveSelector) adjustViewOffset() {
	// If cursor is in the items list
	if s.cursor < len(s.items) {
		// Cursor above viewport
		if s.cursor < s.viewOffset {
			s.viewOffset = s.cursor
		}
		// Cursor below viewport
		if s.cursor >= s.viewOffset+s.viewHeight {
			s.viewOffset = s.cursor - s.viewHeight + 1
		}
	} else {
		// Cursor is on Done/Cancel buttons - show end of list
		if len(s.items) > s.viewHeight {
			s.viewOffset = len(s.items) - s.viewHeight
		}
	}
}

func (s *InteractiveSelector) render() {
	// Move cursor to top-left
	fmt.Print("\033[H")

	// Clear screen
	fmt.Print("\033[2J")

	// Count selected
	selectedCount := 0
	for _, item := range s.items {
		if item.Selected && !item.Pinned {
			selectedCount++
		}
	}

	// Header
	fmt.Printf("%s╔══════════════════════════════════════════════════════════════════════════════╗%s\r\n", ColorCyan, ColorReset)
	fmt.Printf("%s║%s  %sSelect Packages to Update%s                                                    %s║%s\r\n", ColorCyan, ColorReset, ColorBold, ColorReset, ColorCyan, ColorReset)
	fmt.Printf("%s║%s  ↑/↓ Navigate  Space Toggle  a=All  n=None  d=Done  q=Cancel                 %s║%s\r\n", ColorCyan, ColorReset, ColorCyan, ColorReset)
	fmt.Printf("%s║%s  Selected: %-3d / %-3d    %s[x]%s=selected %s[D]%s=dependency %s[P]%s=pinned            %s║%s\r\n",
		ColorCyan, ColorReset, selectedCount, len(s.items),
		ColorGreen, ColorReset, ColorCyan, ColorReset, ColorYellow, ColorReset, ColorCyan, ColorReset)
	fmt.Printf("%s╚══════════════════════════════════════════════════════════════════════════════╝%s\r\n", ColorCyan, ColorReset)

	// Scroll indicator (top)
	if s.viewOffset > 0 {
		fmt.Printf("  %s↑ %d more above%s\r\n", ColorYellow, s.viewOffset, ColorReset)
	} else {
		fmt.Print("\r\n")
	}

	// Calculate visible range
	endIdx := s.viewOffset + s.viewHeight
	if endIdx > len(s.items) {
		endIdx = len(s.items)
	}

	// Package list (only visible portion)
	for i := s.viewOffset; i < endIdx; i++ {
		item := s.items[i]
		cursor := "  "
		if i == s.cursor {
			cursor = ColorCyan + "> " + ColorReset
		}

		var checkbox string
		if item.Pinned {
			checkbox = ColorYellow + "[P]" + ColorReset // Pinned
		} else if item.LockedAsDep {
			checkbox = ColorCyan + "[D]" + ColorReset // Dependency (auto-selected, locked)
		} else if item.Selected {
			checkbox = ColorGreen + "[x]" + ColorReset
		} else {
			checkbox = "[ ]"
		}

		name := item.Name
		if item.Pinned {
			name = ColorYellow + item.Name + " (pinned)" + ColorReset
		} else if item.LockedAsDep {
			name = ColorCyan + item.Name + " (dependency)" + ColorReset
		}

		// Show dependency indicator
		depInfo := ""
		if len(item.Dependents) > 0 {
			depInfo = fmt.Sprintf(" %s[%d dependents]%s", ColorYellow, len(item.Dependents), ColorReset)
		}

		fmt.Printf("%s%s %-28s %12s -> %-12s %d CVEs%s\r\n",
			cursor, checkbox, name, item.Current, item.Latest, item.CVECount, depInfo)
	}

	// Scroll indicator (bottom)
	remaining := len(s.items) - endIdx
	if remaining > 0 {
		fmt.Printf("  %s↓ %d more below%s\r\n", ColorYellow, remaining, ColorReset)
	} else {
		fmt.Print("\r\n")
	}

	// Blank line
	fmt.Print("\r\n")

	// Done button
	if s.cursor == len(s.items) {
		fmt.Printf("%s> %s%s[Done]%s - Update %d package(s)\r\n", ColorCyan, ColorReset, ColorGreen, ColorReset, selectedCount)
	} else {
		fmt.Printf("  %s[Done]%s - Update %d package(s)\r\n", ColorGreen, ColorReset, selectedCount)
	}

	// Cancel button
	if s.cursor == len(s.items)+1 {
		fmt.Printf("%s> %s%s[Cancel]%s - Exit without updating\r\n", ColorCyan, ColorReset, ColorRed, ColorReset)
	} else {
		fmt.Printf("  %s[Cancel]%s - Exit without updating\r\n", ColorRed, ColorReset)
	}

	// Show dependency info for current item
	fmt.Print("\r\n")
	if s.cursor < len(s.items) {
		item := s.items[s.cursor]
		hasInfo := false

		// Show what depends on this package (dependents) - more important, show first
		if len(item.Dependents) > 0 {
			depList := strings.Join(item.Dependents, ", ")
			if len(depList) > 60 {
				depList = depList[:57] + "..."
			}
			fmt.Printf("%sUsed by:%s %s %s(consider upgrading together)%s\r\n", ColorYellow, ColorReset, depList, ColorYellow, ColorReset)
			hasInfo = true
		}

		// Show what this package requires (dependencies) - brew handles these automatically
		if len(item.Dependencies) > 0 {
			depList := strings.Join(item.Dependencies, ", ")
			if len(depList) > 60 {
				depList = depList[:57] + "..."
			}
			fmt.Printf("%sNeeds:%s %s %s(auto-upgraded by brew)%s\r\n", ColorCyan, ColorReset, depList, ColorCyan, ColorReset)
			hasInfo = true
		}

		if !hasInfo {
			fmt.Print("\r\n\r\n") // Empty lines to maintain consistent height
		} else if len(item.Dependencies) == 0 || len(item.Dependents) == 0 {
			fmt.Print("\r\n") // One empty line if only one info line
		}
	} else {
		fmt.Print("\r\n\r\n") // Empty lines to maintain consistent height
	}
}

// SelectPackagesInteractive shows an interactive package selector
func (p *Prompter) SelectPackagesInteractive(items []PackageItem) ([]string, error) {
	selector := NewInteractiveSelector(items)
	return selector.Run()
}
