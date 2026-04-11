package ui

import (
	"fmt"
	"testing"

	"github.com/sud0x0/bsau/internal/claude"
	"github.com/sud0x0/bsau/internal/hashlookup"
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
		verdict  claude.Verdict
		contains string
	}{
		{claude.VerdictSafe, ColorGreen},
		{claude.VerdictReview, ColorYellow},
		{claude.VerdictHold, ColorRed},
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

func TestColorHashResult(t *testing.T) {
	tests := []struct {
		result   hashlookup.HashResult
		expected string
	}{
		{hashlookup.HashNotFlaggedByCIRCL, "CLEAN"},
		{hashlookup.HashNotInCIRCL, "NOT_IN_DB"},
		{hashlookup.HashCIRCLMalicious, "MALICIOUS"},
		{hashlookup.HashVTConfirmed, "VT_CONFIRMED"},
		{hashlookup.HashVTClean, "VT_CLEAN"},
		{hashlookup.HashVTNotFound, "VT_NOT_FOUND"},
	}

	for _, tt := range tests {
		t.Run(string(tt.result), func(t *testing.T) {
			result := colorHashResult(tt.result)
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

func TestInsertAt(t *testing.T) {
	tests := []struct {
		name     string
		slice    []string
		index    int
		value    string
		expected []string
	}{
		{"insert at beginning", []string{"b", "c"}, 0, "a", []string{"a", "b", "c"}},
		{"insert in middle", []string{"a", "c"}, 1, "b", []string{"a", "b", "c"}},
		{"insert at end", []string{"a", "b"}, 2, "c", []string{"a", "b", "c"}},
		{"insert beyond end", []string{"a", "b"}, 5, "c", []string{"a", "b", "c"}},
		{"insert into empty", []string{}, 0, "a", []string{"a"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := insertAt(tt.slice, tt.index, tt.value)
			if len(result) != len(tt.expected) {
				t.Errorf("length mismatch: got %d, expected %d", len(result), len(tt.expected))
				return
			}
			for i, v := range result {
				if v != tt.expected[i] {
					t.Errorf("insertAt()[%d] = %s, expected %s", i, v, tt.expected[i])
				}
			}
		})
	}
}

func TestInsertIntAt(t *testing.T) {
	tests := []struct {
		name     string
		slice    []int
		index    int
		value    int
		expected []int
	}{
		{"insert at beginning", []int{2, 3}, 0, 1, []int{1, 2, 3}},
		{"insert in middle", []int{1, 3}, 1, 2, []int{1, 2, 3}},
		{"insert at end", []int{1, 2}, 2, 3, []int{1, 2, 3}},
		{"insert beyond end", []int{1, 2}, 5, 3, []int{1, 2, 3}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := insertIntAt(tt.slice, tt.index, tt.value)
			if len(result) != len(tt.expected) {
				t.Errorf("length mismatch: got %d, expected %d", len(result), len(tt.expected))
				return
			}
			for i, v := range result {
				if v != tt.expected[i] {
					t.Errorf("insertIntAt()[%d] = %d, expected %d", i, v, tt.expected[i])
				}
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
		ClaudeVerdict:  claude.VerdictReview,
		Recommendation: "REVIEW",
	}

	if row.Package != "openssl" {
		t.Errorf("expected Package openssl, got %s", row.Package)
	}
	if row.ClaudeVerdict != claude.VerdictReview {
		t.Errorf("expected VerdictReview, got %v", row.ClaudeVerdict)
	}
}

func TestPostInstallRow_Structure(t *testing.T) {
	row := PostInstallRow{
		Package:       "curl",
		CIRCLResult:   hashlookup.HashNotInCIRCL,
		VTResult:      "N/A",
		SemgrepCount:  0,
		ClaudeVerdict: claude.VerdictSafe,
		Overall:       "CLEAN",
	}

	if row.Package != "curl" {
		t.Errorf("expected Package curl, got %s", row.Package)
	}
	if row.CIRCLResult != hashlookup.HashNotInCIRCL {
		t.Errorf("expected HashNotInCIRCL, got %v", row.CIRCLResult)
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
		StepName:       "Pre-install Claude scan",
		ClaudeTokens:   5000,
		ClaudePackages: []string{"ripgrep", "curl", "wget"},
		VTRequests:     2,
		VTFiles:        []string{"/path/to/file1.exe", "/path/to/file2.dll"},
	}

	if info.StepName != "Pre-install Claude scan" {
		t.Errorf("expected StepName 'Pre-install Claude scan', got %s", info.StepName)
	}
	if info.ClaudeTokens != 5000 {
		t.Errorf("expected ClaudeTokens 5000, got %d", info.ClaudeTokens)
	}
	if len(info.ClaudePackages) != 3 {
		t.Errorf("expected 3 ClaudePackages, got %d", len(info.ClaudePackages))
	}
	if info.VTRequests != 2 {
		t.Errorf("expected VTRequests 2, got %d", info.VTRequests)
	}
	if len(info.VTFiles) != 2 {
		t.Errorf("expected 2 VTFiles, got %d", len(info.VTFiles))
	}
}

func TestAPIUsageInfo_EmptyUsage(t *testing.T) {
	info := APIUsageInfo{
		StepName:       "Test step",
		ClaudeTokens:   0,
		ClaudePackages: nil,
		VTRequests:     0,
		VTFiles:        nil,
	}

	// When both are zero, no API calls are required
	hasClaudeUsage := info.ClaudeTokens > 0
	hasVTUsage := info.VTRequests > 0

	if hasClaudeUsage {
		t.Error("expected no Claude usage when tokens is 0")
	}
	if hasVTUsage {
		t.Error("expected no VT usage when requests is 0")
	}
}

func TestAPIUsageInfo_OnlyClaude(t *testing.T) {
	info := APIUsageInfo{
		StepName:       "Claude-only step",
		ClaudeTokens:   10000,
		ClaudePackages: []string{"pkg1"},
		VTRequests:     0,
		VTFiles:        nil,
	}

	hasClaudeUsage := info.ClaudeTokens > 0
	hasVTUsage := info.VTRequests > 0

	if !hasClaudeUsage {
		t.Error("expected Claude usage when tokens > 0")
	}
	if hasVTUsage {
		t.Error("expected no VT usage when requests is 0")
	}
}

func TestAPIUsageInfo_OnlyVT(t *testing.T) {
	info := APIUsageInfo{
		StepName:       "VT-only step",
		ClaudeTokens:   0,
		ClaudePackages: nil,
		VTRequests:     5,
		VTFiles:        []string{"/a", "/b", "/c", "/d", "/e"},
	}

	hasClaudeUsage := info.ClaudeTokens > 0
	hasVTUsage := info.VTRequests > 0

	if hasClaudeUsage {
		t.Error("expected no Claude usage when tokens is 0")
	}
	if !hasVTUsage {
		t.Error("expected VT usage when requests > 0")
	}
}

func TestAPIUsageInfo_ManyPackages(t *testing.T) {
	packages := make([]string, 10)
	for i := 0; i < 10; i++ {
		packages[i] = "package" + string(rune('a'+i))
	}

	info := APIUsageInfo{
		StepName:       "Many packages",
		ClaudeTokens:   50000,
		ClaudePackages: packages,
		VTRequests:     0,
		VTFiles:        nil,
	}

	// Verify the package list is stored correctly
	if len(info.ClaudePackages) != 10 {
		t.Errorf("expected 10 packages, got %d", len(info.ClaudePackages))
	}
	// When displayed, only first 5 should show with "+X more"
	displayCount := 5
	if len(info.ClaudePackages) > displayCount {
		remaining := len(info.ClaudePackages) - displayCount
		if remaining != 5 {
			t.Errorf("expected 5 remaining packages, got %d", remaining)
		}
	}
}

func TestAPIUsageInfo_ManyVTFiles(t *testing.T) {
	files := make([]string, 8)
	for i := 0; i < 8; i++ {
		files[i] = "/path/to/file" + string(rune('1'+i)) + ".exe"
	}

	info := APIUsageInfo{
		StepName:       "Many VT files",
		ClaudeTokens:   0,
		ClaudePackages: nil,
		VTRequests:     8,
		VTFiles:        files,
	}

	if len(info.VTFiles) != 8 {
		t.Errorf("expected 8 VTFiles, got %d", len(info.VTFiles))
	}
	// When displayed, only first 5 should show
	displayCount := 5
	if len(info.VTFiles) > displayCount {
		remaining := len(info.VTFiles) - displayCount
		if remaining != 3 {
			t.Errorf("expected 3 remaining files, got %d", remaining)
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
		ClaudeEnabled:           true,
		ClaudeRequestsLimit:     1000,
		ClaudeRequestsRemaining: 950,
		ClaudeTokensLimit:       100000,
		ClaudeTokensRemaining:   95000,
		ClaudeError:             nil,
		VTEnabled:               true,
		VTDailyLimit:            500,
		VTDailyUsed:             50,
		VTDailyRemaining:        450,
		VTRateLimit:             4,
		VTError:                 nil,
	}

	if !status.ClaudeEnabled {
		t.Error("expected ClaudeEnabled to be true")
	}
	if status.ClaudeRequestsLimit != 1000 {
		t.Errorf("expected ClaudeRequestsLimit 1000, got %d", status.ClaudeRequestsLimit)
	}
	if status.ClaudeRequestsRemaining != 950 {
		t.Errorf("expected ClaudeRequestsRemaining 950, got %d", status.ClaudeRequestsRemaining)
	}
	if !status.VTEnabled {
		t.Error("expected VTEnabled to be true")
	}
	if status.VTDailyLimit != 500 {
		t.Errorf("expected VTDailyLimit 500, got %d", status.VTDailyLimit)
	}
	if status.VTDailyRemaining != 450 {
		t.Errorf("expected VTDailyRemaining 450, got %d", status.VTDailyRemaining)
	}
}

func TestAPIQuotaStatus_OnlyClaude(t *testing.T) {
	status := APIQuotaStatus{
		ClaudeEnabled:           true,
		ClaudeRequestsLimit:     1000,
		ClaudeRequestsRemaining: 800,
		ClaudeTokensLimit:       100000,
		ClaudeTokensRemaining:   80000,
		VTEnabled:               false,
	}

	if !status.ClaudeEnabled {
		t.Error("expected ClaudeEnabled to be true")
	}
	if status.VTEnabled {
		t.Error("expected VTEnabled to be false")
	}
}

func TestAPIQuotaStatus_OnlyVT(t *testing.T) {
	status := APIQuotaStatus{
		ClaudeEnabled:    false,
		VTEnabled:        true,
		VTDailyLimit:     500,
		VTDailyUsed:      100,
		VTDailyRemaining: 400,
		VTRateLimit:      4,
	}

	if status.ClaudeEnabled {
		t.Error("expected ClaudeEnabled to be false")
	}
	if !status.VTEnabled {
		t.Error("expected VTEnabled to be true")
	}
}

func TestAPIQuotaStatus_BothDisabled(t *testing.T) {
	status := APIQuotaStatus{
		ClaudeEnabled: false,
		VTEnabled:     false,
	}

	if status.ClaudeEnabled {
		t.Error("expected ClaudeEnabled to be false")
	}
	if status.VTEnabled {
		t.Error("expected VTEnabled to be false")
	}
}

func TestAPIQuotaStatus_LowClaudeQuota(t *testing.T) {
	status := APIQuotaStatus{
		ClaudeEnabled:           true,
		ClaudeRequestsLimit:     1000,
		ClaudeRequestsRemaining: 100, // 10% remaining
		ClaudeTokensLimit:       100000,
		ClaudeTokensRemaining:   10000, // 10% remaining
	}

	reqPct := float64(status.ClaudeRequestsRemaining) / float64(status.ClaudeRequestsLimit) * 100
	tokPct := float64(status.ClaudeTokensRemaining) / float64(status.ClaudeTokensLimit) * 100

	if reqPct >= 20 {
		t.Errorf("expected low request quota (<20%%), got %.1f%%", reqPct)
	}
	if tokPct >= 20 {
		t.Errorf("expected low token quota (<20%%), got %.1f%%", tokPct)
	}
}

func TestAPIQuotaStatus_LowVTQuota(t *testing.T) {
	status := APIQuotaStatus{
		VTEnabled:        true,
		VTDailyLimit:     500,
		VTDailyUsed:      450,
		VTDailyRemaining: 50, // 10% remaining
	}

	pct := float64(status.VTDailyRemaining) / float64(status.VTDailyLimit) * 100
	if pct >= 20 {
		t.Errorf("expected low VT quota (<20%%), got %.1f%%", pct)
	}
}

func TestAPIQuotaStatus_WithErrors(t *testing.T) {
	status := APIQuotaStatus{
		ClaudeEnabled: true,
		ClaudeError:   fmt.Errorf("API key invalid"),
		VTEnabled:     true,
		VTError:       fmt.Errorf("rate limit exceeded"),
	}

	if status.ClaudeError == nil {
		t.Error("expected ClaudeError to be set")
	}
	if status.VTError == nil {
		t.Error("expected VTError to be set")
	}
}

func TestCheckQuotaSufficiency_AllSufficient(t *testing.T) {
	s := CheckQuotaSufficiency(
		5000, 10000, // Claude tokens: need 5000, have 10000
		10, 100, // Claude requests: need 10, have 100
		5, 500, // VT requests: need 5, have 500
	)

	if !s.CanProceed {
		t.Error("expected CanProceed to be true when all sufficient")
	}
	if !s.ClaudeTokensSufficient {
		t.Error("expected ClaudeTokensSufficient to be true")
	}
	if !s.ClaudeRequestsSufficient {
		t.Error("expected ClaudeRequestsSufficient to be true")
	}
	if !s.VTRequestsSufficient {
		t.Error("expected VTRequestsSufficient to be true")
	}
	if s.Warning != "" {
		t.Errorf("expected no warning, got %s", s.Warning)
	}
}

func TestCheckQuotaSufficiency_InsufficientTokens(t *testing.T) {
	s := CheckQuotaSufficiency(
		10000, 5000, // Claude tokens: need 10000, have 5000
		10, 100, // Claude requests: sufficient
		5, 500, // VT requests: sufficient
	)

	if s.CanProceed {
		t.Error("expected CanProceed to be false when tokens insufficient")
	}
	if s.ClaudeTokensSufficient {
		t.Error("expected ClaudeTokensSufficient to be false")
	}
	if !s.PartialPossible {
		t.Error("expected PartialPossible to be true when some quota available")
	}
	if s.Warning == "" {
		t.Error("expected warning message")
	}
}

func TestCheckQuotaSufficiency_InsufficientRequests(t *testing.T) {
	s := CheckQuotaSufficiency(
		5000, 10000, // Claude tokens: sufficient
		100, 10, // Claude requests: need 100, have 10
		5, 500, // VT requests: sufficient
	)

	if s.CanProceed {
		t.Error("expected CanProceed to be false when requests insufficient")
	}
	if !s.ClaudeTokensSufficient {
		t.Error("expected ClaudeTokensSufficient to be true")
	}
	if s.ClaudeRequestsSufficient {
		t.Error("expected ClaudeRequestsSufficient to be false")
	}
}

func TestCheckQuotaSufficiency_InsufficientVT(t *testing.T) {
	s := CheckQuotaSufficiency(
		5000, 10000, // Claude tokens: sufficient
		10, 100, // Claude requests: sufficient
		100, 50, // VT requests: need 100, have 50
	)

	if s.CanProceed {
		t.Error("expected CanProceed to be false when VT insufficient")
	}
	if s.VTRequestsSufficient {
		t.Error("expected VTRequestsSufficient to be false")
	}
}

func TestCheckQuotaSufficiency_AllInsufficient(t *testing.T) {
	s := CheckQuotaSufficiency(
		10000, 1000, // Claude tokens: insufficient
		100, 10, // Claude requests: insufficient
		100, 10, // VT requests: insufficient
	)

	if s.CanProceed {
		t.Error("expected CanProceed to be false when all insufficient")
	}
	if s.ClaudeTokensSufficient {
		t.Error("expected ClaudeTokensSufficient to be false")
	}
	if s.ClaudeRequestsSufficient {
		t.Error("expected ClaudeRequestsSufficient to be false")
	}
	if s.VTRequestsSufficient {
		t.Error("expected VTRequestsSufficient to be false")
	}
	if !s.PartialPossible {
		t.Error("expected PartialPossible when some quota remains")
	}
}

func TestCheckQuotaSufficiency_ZeroRequired(t *testing.T) {
	s := CheckQuotaSufficiency(
		0, 10000, // Claude tokens: none required
		0, 100, // Claude requests: none required
		0, 500, // VT requests: none required
	)

	if !s.CanProceed {
		t.Error("expected CanProceed to be true when nothing required")
	}
	if !s.ClaudeTokensSufficient {
		t.Error("expected ClaudeTokensSufficient to be true when none required")
	}
}

func TestCheckQuotaSufficiency_ZeroAvailable(t *testing.T) {
	s := CheckQuotaSufficiency(
		5000, 0, // Claude tokens: need 5000, have 0
		10, 0, // Claude requests: need 10, have 0
		5, 0, // VT requests: need 5, have 0
	)

	if s.CanProceed {
		t.Error("expected CanProceed to be false when no quota available")
	}
	if s.PartialPossible {
		t.Error("expected PartialPossible to be false when no quota at all")
	}
}

func TestCheckQuotaSufficiency_ExactMatch(t *testing.T) {
	s := CheckQuotaSufficiency(
		5000, 5000, // Claude tokens: exact match
		10, 10, // Claude requests: exact match
		5, 5, // VT requests: exact match
	)

	if !s.CanProceed {
		t.Error("expected CanProceed to be true when exact match")
	}
	if !s.ClaudeTokensSufficient {
		t.Error("expected ClaudeTokensSufficient to be true on exact match")
	}
}

func TestQuotaSufficiency_Structure(t *testing.T) {
	s := QuotaSufficiency{
		ClaudeTokensRequired:     10000,
		ClaudeTokensAvailable:    5000,
		ClaudeTokensSufficient:   false,
		ClaudeRequestsRequired:   50,
		ClaudeRequestsAvailable:  100,
		ClaudeRequestsSufficient: true,
		VTRequestsRequired:       10,
		VTRequestsAvailable:      500,
		VTRequestsSufficient:     true,
		CanProceed:               false,
		PartialPossible:          true,
		Warning:                  "Claude tokens: need 10000, have 5000 (50% of required)",
	}

	if s.ClaudeTokensRequired != 10000 {
		t.Errorf("expected ClaudeTokensRequired 10000, got %d", s.ClaudeTokensRequired)
	}
	if s.ClaudeTokensSufficient {
		t.Error("expected ClaudeTokensSufficient to be false")
	}
	if s.CanProceed {
		t.Error("expected CanProceed to be false")
	}
	if !s.PartialPossible {
		t.Error("expected PartialPossible to be true")
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
	// First two should be selected
	if !selector.items[0].Selected {
		t.Error("expected first item to be selected")
	}
	if !selector.items[1].Selected {
		t.Error("expected second item to be selected")
	}
	if selector.items[2].Selected {
		t.Error("expected third item to NOT be selected")
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
	// High and medium priority should be selected
	if selector.items[0].Selected {
		t.Error("expected low priority item to NOT be selected")
	}
	if !selector.items[1].Selected {
		t.Error("expected high priority item to be selected")
	}
	if !selector.items[2].Selected {
		t.Error("expected medium priority item to be selected")
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

func TestScanSelector_OverQuota(t *testing.T) {
	items := []ScanItem{
		{Name: "pkg1", EstimatedTokens: 5000, Selected: true},
		{Name: "pkg2", EstimatedTokens: 5000, Selected: true},
		{Name: "pkg3", EstimatedTokens: 5000, Selected: true},
	}

	selector := NewScanSelector(items, 10000, 100) // 15000 selected, only 10000 available

	if selector.tokensSelected != 15000 {
		t.Errorf("expected tokensSelected 15000, got %d", selector.tokensSelected)
	}
	// Over quota
	overQuota := selector.tokensSelected > selector.availableTokens
	if !overQuota {
		t.Error("expected to be over quota")
	}
}

func TestScanSelector_RequestsLimit(t *testing.T) {
	items := []ScanItem{
		{Name: "pkg1", EstimatedTokens: 100, Selected: false},
		{Name: "pkg2", EstimatedTokens: 100, Selected: false},
		{Name: "pkg3", EstimatedTokens: 100, Selected: false},
	}

	selector := NewScanSelector(items, 10000, 2) // Only 2 requests allowed
	selector.selectAllWithinQuota()

	if selector.totalSelected != 2 {
		t.Errorf("expected 2 selected (limited by requests), got %d", selector.totalSelected)
	}
}

func TestScanSelector_ViewOffset(t *testing.T) {
	items := make([]ScanItem, 50)
	for i := range items {
		items[i] = ScanItem{Name: fmt.Sprintf("pkg%d", i), EstimatedTokens: 100}
	}

	selector := NewScanSelector(items, 10000, 100)
	selector.viewHeight = 10 // Force small view height

	// Move cursor down past view
	selector.cursor = 15
	selector.adjustViewOffset()

	if selector.viewOffset == 0 {
		t.Error("expected viewOffset to be adjusted when cursor below viewport")
	}
}

func TestScanSelector_ZeroTokens(t *testing.T) {
	items := []ScanItem{
		{Name: "pkg1", EstimatedTokens: 0, Selected: true},
	}

	selector := NewScanSelector(items, 10000, 100)

	if selector.tokensSelected != 0 {
		t.Errorf("expected tokensSelected 0, got %d", selector.tokensSelected)
	}
}
