package ui

import (
	"fmt"
	"testing"

	"github.com/sud0x0/bsau/internal/ollama"
)

func TestSeverity_Constants(t *testing.T) {
	tests := []struct {
		severity Severity
		expected string
	}{
		{SeverityCritical, "CRITICAL"},
		{SeverityHigh, "HIGH"},
		{SeverityMedium, "MEDIUM"},
		{SeverityLow, "LOW"},
		{SeverityNone, "NONE"},
		{SeverityNA, "UNKNOWN"},
	}

	for _, tt := range tests {
		if string(tt.severity) != tt.expected {
			t.Errorf("Severity constant %v != %s", tt.severity, tt.expected)
		}
	}
}

func TestColorSeverity(t *testing.T) {
	tests := []struct {
		severity Severity
		contains string
	}{
		{SeverityCritical, ColorRed},
		{SeverityHigh, ColorRed},
		{SeverityMedium, ColorYellow},
		{SeverityLow, ColorCyan},
		{SeverityNone, "NONE"},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			result := colorSeverity(tt.severity)
			if len(result) == 0 {
				t.Error("expected non-empty result")
			}
		})
	}
}

func TestColorVerdict(t *testing.T) {
	tests := []struct {
		verdict  ollama.Verdict
		contains string
	}{
		{ollama.VerdictSafe, ColorGreen},
		{ollama.VerdictReview, ColorYellow},
		{ollama.VerdictHold, ColorRed},
	}

	for _, tt := range tests {
		t.Run(string(tt.verdict), func(t *testing.T) {
			result := colorVerdict(tt.verdict)
			if len(result) == 0 {
				t.Error("expected non-empty result")
			}
		})
	}
}

func TestColorRecommendation(t *testing.T) {
	tests := []struct {
		input    string
		contains string
	}{
		{"safe", ColorGreen},
		{"SAFE", ColorGreen},
		{"update", ColorGreen},
		{"proceed", ColorGreen},
		{"review", ColorYellow},
		{"REVIEW", ColorYellow},
		{"block", ColorRed},
		{"HOLD", ColorRed},
		{"unknown", "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := colorRecommendation(tt.input)
			if len(result) == 0 {
				t.Error("expected non-empty result")
			}
		})
	}
}

func TestColorOverall(t *testing.T) {
	tests := []struct {
		input    string
		contains string
	}{
		{"clean", ColorGreen},
		{"OK", ColorGreen},
		{"review", ColorYellow},
		{"warning", ColorYellow},
		{"block", ColorRed},
		{"malicious", ColorRed},
		{"hold", ColorRed},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := colorOverall(tt.input)
			if len(result) == 0 {
				t.Error("expected non-empty result")
			}
		})
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input    string
		maxLen   int
		expected string
	}{
		{"hello", 10, "hello"},
		{"hello", 5, "hello"},
		{"hello world", 8, "hello..."},
		{"hello world", 5, "he..."},
		{"", 5, ""},
		{"ab", 3, "ab"},
		{"abc", 3, "abc"},
		{"abcd", 3, "..."},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := truncate(tt.input, tt.maxLen)
			if result != tt.expected {
				t.Errorf("truncate(%q, %d) = %q, expected %q", tt.input, tt.maxLen, result, tt.expected)
			}
		})
	}
}

func TestPackageRow_Structure(t *testing.T) {
	row := PackageRow{
		Package:   "ripgrep",
		Current:   "13.0.0",
		Available: "14.0.0",
		Pinned:    false,
		CVECount:  2,
		Severity:  SeverityHigh,
		Action:    "UPDATE",
	}

	if row.Package != "ripgrep" {
		t.Errorf("expected Package ripgrep, got %s", row.Package)
	}
	if row.CVECount != 2 {
		t.Errorf("expected CVECount 2, got %d", row.CVECount)
	}
}

func TestPreInstallRow_Structure(t *testing.T) {
	row := PreInstallRow{
		Package:        "openssl",
		CVECount:       5,
		OllamaVerdict:  ollama.VerdictReview,
		Recommendation: "REVIEW",
	}

	if row.Package != "openssl" {
		t.Errorf("expected Package openssl, got %s", row.Package)
	}
	if row.OllamaVerdict != ollama.VerdictReview {
		t.Errorf("expected VerdictReview, got %v", row.OllamaVerdict)
	}
}

func TestPostInstallRow_Structure(t *testing.T) {
	row := PostInstallRow{
		Package:       "curl",
		SemgrepCount:  0,
		OllamaVerdict: ollama.VerdictSafe,
		Overall:       "CLEAN",
	}

	if row.Package != "curl" {
		t.Errorf("expected Package curl, got %s", row.Package)
	}
	if row.SemgrepCount != 0 {
		t.Errorf("expected SemgrepCount 0, got %d", row.SemgrepCount)
	}
}

func TestNewProgress(t *testing.T) {
	p := NewProgress("Scanning", 10)

	if p == nil {
		t.Fatal("expected non-nil Progress")
	}
	if p.total != 10 {
		t.Errorf("expected total 10, got %d", p.total)
	}
	if p.current != 0 {
		t.Errorf("expected current 0, got %d", p.current)
	}
	if p.prefix != "Scanning" {
		t.Errorf("expected prefix 'Scanning', got %s", p.prefix)
	}
}

func TestNewSpinner(t *testing.T) {
	s := NewSpinner("Loading")

	if s == nil {
		t.Fatal("expected non-nil Spinner")
	}
	if s.message != "Loading" {
		t.Errorf("expected message 'Loading', got %s", s.message)
	}
	if len(s.frames) == 0 {
		t.Error("expected non-empty frames")
	}
	if s.done == nil {
		t.Error("expected non-nil done channel")
	}
}

func TestColorConstants(t *testing.T) {
	// Verify color escape codes are defined
	colors := []string{
		ColorReset,
		ColorRed,
		ColorGreen,
		ColorYellow,
		ColorBlue,
		ColorCyan,
		ColorBold,
	}

	for _, c := range colors {
		if len(c) == 0 {
			t.Error("expected non-empty color constant")
		}
		if c[0] != '\033' {
			t.Errorf("expected color to start with escape char, got %q", c)
		}
	}
}

func TestProgress_Update(t *testing.T) {
	p := NewProgress("Test", 5)

	p.Update("item1")
	if p.current != 1 {
		t.Errorf("expected current 1 after Update, got %d", p.current)
	}

	p.Update("item2")
	if p.current != 2 {
		t.Errorf("expected current 2 after second Update, got %d", p.current)
	}
}

func TestTruncate_EdgeCases(t *testing.T) {
	// Test with exactly maxLen
	result := truncate("hello", 5)
	if result != "hello" {
		t.Errorf("truncate should not modify string at exact length, got %q", result)
	}

	// Test with larger maxLen
	result = truncate("hi", 10)
	if result != "hi" {
		t.Errorf("truncate should not modify short string, got %q", result)
	}

	// Test truncation with sufficient space for "..."
	result = truncate("hello world", 8)
	if result != "hello..." {
		t.Errorf("truncate should add ellipsis, got %q", result)
	}
}

func TestAPIUsageInfo_Structure(t *testing.T) {
	info := APIUsageInfo{
		StepName:       "Pre-install Ollama scan",
		OllamaPackages: []string{"ripgrep", "curl", "wget"},
	}

	if info.StepName != "Pre-install Ollama scan" {
		t.Errorf("expected StepName 'Pre-install Ollama scan', got %s", info.StepName)
	}
	if len(info.OllamaPackages) != 3 {
		t.Errorf("expected 3 OllamaPackages, got %d", len(info.OllamaPackages))
	}
}

func TestAPIUsageInfo_EmptyUsage(t *testing.T) {
	info := APIUsageInfo{
		StepName:       "Test step",
		OllamaPackages: nil,
	}

	hasOllamaUsage := len(info.OllamaPackages) > 0

	if hasOllamaUsage {
		t.Error("expected no Ollama usage when packages is empty")
	}
}

func TestAPIUsageInfo_OnlyOllama(t *testing.T) {
	info := APIUsageInfo{
		StepName:       "Ollama-only step",
		OllamaPackages: []string{"pkg1"},
	}

	hasOllamaUsage := len(info.OllamaPackages) > 0

	if !hasOllamaUsage {
		t.Error("expected Ollama usage when packages > 0")
	}
}

func TestAPIUsageInfo_ManyPackages(t *testing.T) {
	packages := make([]string, 10)
	for i := 0; i < 10; i++ {
		packages[i] = "package" + string(rune('a'+i))
	}

	info := APIUsageInfo{
		StepName:       "Many packages",
		OllamaPackages: packages,
	}

	// Verify the package list is stored correctly
	if len(info.OllamaPackages) != 10 {
		t.Errorf("expected 10 packages, got %d", len(info.OllamaPackages))
	}
	// When displayed, only first 5 should show with "+X more"
	displayCount := 5
	if len(info.OllamaPackages) > displayCount {
		remaining := len(info.OllamaPackages) - displayCount
		if remaining != 5 {
			t.Errorf("expected 5 remaining packages, got %d", remaining)
		}
	}
}

func TestPackageItem_Structure(t *testing.T) {
	item := PackageItem{
		Name:         "ripgrep",
		Current:      "13.0.0",
		Latest:       "14.0.0",
		CVECount:     2,
		Severity:     SeverityHigh,
		Pinned:       false,
		Selected:     true,
		Dependents:   []string{"fd", "bat"},
		Dependencies: []string{"pcre2"},
		LockedAsDep:  false,
	}

	if item.Name != "ripgrep" {
		t.Errorf("expected Name ripgrep, got %s", item.Name)
	}
	if item.Current != "13.0.0" {
		t.Errorf("expected Current 13.0.0, got %s", item.Current)
	}
	if item.Latest != "14.0.0" {
		t.Errorf("expected Latest 14.0.0, got %s", item.Latest)
	}
	if item.CVECount != 2 {
		t.Errorf("expected CVECount 2, got %d", item.CVECount)
	}
	if !item.Selected {
		t.Error("expected Selected to be true")
	}
	if len(item.Dependents) != 2 {
		t.Errorf("expected 2 Dependents, got %d", len(item.Dependents))
	}
	if len(item.Dependencies) != 1 {
		t.Errorf("expected 1 Dependency, got %d", len(item.Dependencies))
	}
}

func TestInteractiveSelector_Creation(t *testing.T) {
	items := []PackageItem{
		{Name: "pkg1", Current: "1.0", Latest: "2.0", Selected: true},
		{Name: "pkg2", Current: "1.0", Latest: "2.0", Selected: false},
	}

	selector := NewInteractiveSelector(items)

	if selector == nil {
		t.Fatal("expected non-nil selector")
	}
	if len(selector.items) != 2 {
		t.Errorf("expected 2 items, got %d", len(selector.items))
	}
	if selector.cursor != 0 {
		t.Errorf("expected cursor at 0, got %d", selector.cursor)
	}
	if selector.viewHeight < 5 {
		t.Errorf("expected viewHeight >= 5, got %d", selector.viewHeight)
	}
}

func TestInteractiveSelector_RecalculateLockedDeps(t *testing.T) {
	items := []PackageItem{
		{Name: "parent", Current: "1.0", Latest: "2.0", Selected: true, Dependencies: []string{"child"}},
		{Name: "child", Current: "1.0", Latest: "2.0", Selected: false},
	}

	selector := NewInteractiveSelector(items)

	// After creation, child should be locked as dependency
	if !selector.items[1].LockedAsDep {
		t.Error("expected child to be locked as dependency")
	}
	if !selector.items[1].Selected {
		t.Error("expected child to be auto-selected")
	}
}

func TestInteractiveSelector_PinnedNotLocked(t *testing.T) {
	items := []PackageItem{
		{Name: "pinned", Current: "1.0", Latest: "2.0", Pinned: true},
		{Name: "normal", Current: "1.0", Latest: "2.0", Selected: true},
	}

	selector := NewInteractiveSelector(items)

	// Pinned items should not be affected by locking
	if selector.items[0].LockedAsDep {
		t.Error("pinned items should not be locked as dependency")
	}
}

func TestAPIQuotaStatus_Structure(t *testing.T) {
	status := APIQuotaStatus{
		OllamaEnabled:   true,
		OllamaAvailable: true,
		OllamaModel:     "gemma3",
		OllamaError:     nil,
	}

	if !status.OllamaEnabled {
		t.Error("expected OllamaEnabled to be true")
	}
	if !status.OllamaAvailable {
		t.Error("expected OllamaAvailable to be true")
	}
	if status.OllamaModel != "gemma3" {
		t.Errorf("expected OllamaModel gemma3, got %s", status.OllamaModel)
	}
}

func TestAPIQuotaStatus_OllamaUnavailable(t *testing.T) {
	status := APIQuotaStatus{
		OllamaEnabled:   true,
		OllamaAvailable: false, // Ollama not running
		OllamaModel:     "gemma3",
	}

	if !status.OllamaEnabled {
		t.Error("expected OllamaEnabled to be true")
	}
	if status.OllamaAvailable {
		t.Error("expected OllamaAvailable to be false when not running")
	}
}

func TestAPIQuotaStatus_WithError(t *testing.T) {
	status := APIQuotaStatus{
		OllamaEnabled: true,
		OllamaError:   fmt.Errorf("connection refused"),
	}

	if status.OllamaError == nil {
		t.Error("expected OllamaError to be set")
	}
}

func TestCheckQuotaSufficiency_AllSufficient(t *testing.T) {
	s := CheckQuotaSufficiency(
		5, true, // Ollama: 5 packages required, available
		0, 0, // No VT
	)

	if !s.CanProceed {
		t.Error("expected CanProceed to be true when all sufficient")
	}
	if !s.OllamaAvailable {
		t.Error("expected OllamaAvailable to be true")
	}
	if s.Warning != "" {
		t.Errorf("expected no warning, got %s", s.Warning)
	}
}

func TestCheckQuotaSufficiency_OllamaUnavailable(t *testing.T) {
	s := CheckQuotaSufficiency(
		5, false, // Ollama: 5 packages required, NOT available
		0, 0, // No VT
	)

	if s.CanProceed {
		t.Error("expected CanProceed to be false when Ollama unavailable")
	}
	if s.OllamaAvailable {
		t.Error("expected OllamaAvailable to be false")
	}
	if s.Warning == "" {
		t.Error("expected warning message")
	}
}

func TestCheckQuotaSufficiency_ZeroRequired(t *testing.T) {
	s := CheckQuotaSufficiency(
		0, true, // Ollama: none required
		0, 0, // No VT
	)

	if !s.CanProceed {
		t.Error("expected CanProceed to be true when nothing required")
	}
}

func TestQuotaSufficiency_Structure(t *testing.T) {
	s := QuotaSufficiency{
		OllamaPackagesRequired: 5,
		OllamaAvailable:        false,
		CanProceed:             false,
		PartialPossible:        false,
		Warning:                "Ollama not available: 5 packages require Ollama scan",
	}

	if s.OllamaPackagesRequired != 5 {
		t.Errorf("expected OllamaPackagesRequired 5, got %d", s.OllamaPackagesRequired)
	}
	if s.OllamaAvailable {
		t.Error("expected OllamaAvailable to be false")
	}
	if s.CanProceed {
		t.Error("expected CanProceed to be false")
	}
}

func TestInsufficientQuotaChoice_Constants(t *testing.T) {
	if QuotaChoiceProceedPartial != 0 {
		t.Errorf("expected QuotaChoiceProceedPartial to be 0, got %d", QuotaChoiceProceedPartial)
	}
	if QuotaChoiceSkipAPI != 1 {
		t.Errorf("expected QuotaChoiceSkipAPI to be 1, got %d", QuotaChoiceSkipAPI)
	}
	if QuotaChoiceCancel != 2 {
		t.Errorf("expected QuotaChoiceCancel to be 2, got %d", QuotaChoiceCancel)
	}
}

func TestScanItem_Structure(t *testing.T) {
	item := ScanItem{
		Name:            "ripgrep",
		Description:     "13.0.0 → 14.0.0",
		EstimatedTokens: 2500,
		Selected:        true,
		Priority:        3,
		Category:        "formula",
	}

	if item.Name != "ripgrep" {
		t.Errorf("expected Name ripgrep, got %s", item.Name)
	}
	if item.EstimatedTokens != 2500 {
		t.Errorf("expected EstimatedTokens 2500, got %d", item.EstimatedTokens)
	}
	if !item.Selected {
		t.Error("expected Selected to be true")
	}
	if item.Priority != 3 {
		t.Errorf("expected Priority 3, got %d", item.Priority)
	}
	if item.Category != "formula" {
		t.Errorf("expected Category formula, got %s", item.Category)
	}
}

func TestNewScanSelector(t *testing.T) {
	items := []ScanItem{
		{Name: "pkg1", EstimatedTokens: 1000, Selected: false},
		{Name: "pkg2", EstimatedTokens: 2000, Selected: true},
	}

	selector := NewScanSelector(items, 10000, 100)

	if selector == nil {
		t.Fatal("expected non-nil selector")
	}
	if len(selector.items) != 2 {
		t.Errorf("expected 2 items, got %d", len(selector.items))
	}
	if selector.availableTokens != 10000 {
		t.Errorf("expected availableTokens 10000, got %d", selector.availableTokens)
	}
	if selector.availableRequests != 100 {
		t.Errorf("expected availableRequests 100, got %d", selector.availableRequests)
	}
	if selector.totalSelected != 1 {
		t.Errorf("expected totalSelected 1, got %d", selector.totalSelected)
	}
	if selector.tokensSelected != 2000 {
		t.Errorf("expected tokensSelected 2000, got %d", selector.tokensSelected)
	}
}

func TestScanSelector_RecalculateSelection(t *testing.T) {
	items := []ScanItem{
		{Name: "pkg1", EstimatedTokens: 1000, Selected: true},
		{Name: "pkg2", EstimatedTokens: 2000, Selected: true},
		{Name: "pkg3", EstimatedTokens: 3000, Selected: false},
	}

	selector := NewScanSelector(items, 10000, 100)

	if selector.totalSelected != 2 {
		t.Errorf("expected totalSelected 2, got %d", selector.totalSelected)
	}
	if selector.tokensSelected != 3000 {
		t.Errorf("expected tokensSelected 3000, got %d", selector.tokensSelected)
	}
}

func TestScanSelector_SelectAllWithinQuota(t *testing.T) {
	items := []ScanItem{
		{Name: "pkg1", EstimatedTokens: 3000, Selected: false},
		{Name: "pkg2", EstimatedTokens: 3000, Selected: false},
		{Name: "pkg3", EstimatedTokens: 3000, Selected: false},
		{Name: "pkg4", EstimatedTokens: 3000, Selected: false},
	}

	selector := NewScanSelector(items, 7000, 100) // Only room for 2 packages
	selector.selectAllWithinQuota()

	if selector.totalSelected != 2 {
		t.Errorf("expected 2 selected within quota, got %d", selector.totalSelected)
	}
	if selector.tokensSelected != 6000 {
		t.Errorf("expected 6000 tokens selected, got %d", selector.tokensSelected)
	}
}

func TestScanSelector_SelectByPriority(t *testing.T) {
	items := []ScanItem{
		{Name: "low", EstimatedTokens: 1000, Priority: 1},
		{Name: "high", EstimatedTokens: 1000, Priority: 3},
		{Name: "medium", EstimatedTokens: 1000, Priority: 2},
	}

	selector := NewScanSelector(items, 2000, 100) // Room for 2 packages
	selector.selectByPriority()

	if selector.totalSelected != 2 {
		t.Errorf("expected 2 selected, got %d", selector.totalSelected)
	}
}

func TestScanSelector_SelectNone(t *testing.T) {
	items := []ScanItem{
		{Name: "pkg1", EstimatedTokens: 1000, Selected: true},
		{Name: "pkg2", EstimatedTokens: 2000, Selected: true},
	}

	selector := NewScanSelector(items, 10000, 100)

	// Simulate pressing 'n'
	for i := range selector.items {
		selector.items[i].Selected = false
	}
	selector.recalculateSelection()

	if selector.totalSelected != 0 {
		t.Errorf("expected 0 selected after clear, got %d", selector.totalSelected)
	}
	if selector.tokensSelected != 0 {
		t.Errorf("expected 0 tokens after clear, got %d", selector.tokensSelected)
	}
}
