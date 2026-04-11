package hashlookup

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHashResult_Constants(t *testing.T) {
	tests := []struct {
		result   HashResult
		expected string
	}{
		{HashNotInCIRCL, "NOT_IN_CIRCL"},
		{HashNotFlaggedByCIRCL, "NOT_FLAGGED_BY_CIRCL"},
		{HashCIRCLMalicious, "CIRCL_MALICIOUS"},
		{HashVTConfirmed, "VT_CONFIRMED"},
		{HashVTClean, "VT_CLEAN"},
		{HashVTNotFound, "VT_NOT_FOUND"},
		{HashError, "ERROR"},
	}

	for _, tt := range tests {
		if string(tt.result) != tt.expected {
			t.Errorf("HashResult constant %v != %s", tt.result, tt.expected)
		}
	}
}

func TestIsBlockingResult(t *testing.T) {
	tests := []struct {
		result   HashResult
		expected bool
	}{
		{HashVTConfirmed, true},
		{HashCIRCLMalicious, false},
		{HashVTClean, false},
		{HashVTNotFound, false},
		{HashNotInCIRCL, false},
		{HashNotFlaggedByCIRCL, false},
		{HashError, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.result), func(t *testing.T) {
			if got := IsBlockingResult(tt.result); got != tt.expected {
				t.Errorf("IsBlockingResult(%v) = %v, expected %v", tt.result, got, tt.expected)
			}
		})
	}
}

func TestRequiresPrompt(t *testing.T) {
	tests := []struct {
		result   HashResult
		expected bool
	}{
		{HashCIRCLMalicious, true},
		{HashVTClean, true},
		{HashVTNotFound, true},
		{HashVTConfirmed, false},
		{HashNotInCIRCL, false},
		{HashNotFlaggedByCIRCL, false},
		{HashError, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.result), func(t *testing.T) {
			if got := RequiresPrompt(tt.result); got != tt.expected {
				t.Errorf("RequiresPrompt(%v) = %v, expected %v", tt.result, got, tt.expected)
			}
		})
	}
}

func TestComputeSHA256(t *testing.T) {
	// Create temp file with known content
	tmpDir, err := os.MkdirTemp("", "hash-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	testFile := filepath.Join(tmpDir, "test.txt")
	content := []byte("hello world")
	if err := os.WriteFile(testFile, content, 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	hash, err := ComputeSHA256(testFile)
	if err != nil {
		t.Fatalf("ComputeSHA256 failed: %v", err)
	}

	// SHA256 of "hello world" is known
	expected := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
	if hash != expected {
		t.Errorf("ComputeSHA256 = %s, expected %s", hash, expected)
	}
}

func TestComputeSHA256_EmptyFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "hash-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	testFile := filepath.Join(tmpDir, "empty.txt")
	if err := os.WriteFile(testFile, []byte{}, 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	hash, err := ComputeSHA256(testFile)
	if err != nil {
		t.Fatalf("ComputeSHA256 failed: %v", err)
	}

	// SHA256 of empty string
	expected := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if hash != expected {
		t.Errorf("ComputeSHA256 of empty file = %s, expected %s", hash, expected)
	}
}

func TestComputeSHA256_NonExistent(t *testing.T) {
	_, err := ComputeSHA256("/nonexistent/file.txt")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestComputeSHA256_BinaryFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "hash-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	testFile := filepath.Join(tmpDir, "binary.dat")
	content := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD}
	if err := os.WriteFile(testFile, content, 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	hash, err := ComputeSHA256(testFile)
	if err != nil {
		t.Fatalf("ComputeSHA256 failed: %v", err)
	}

	// Just verify it returns a valid 64-char hex string
	if len(hash) != 64 {
		t.Errorf("expected 64-char hash, got %d chars", len(hash))
	}
}

func TestFileHashResult_Structure(t *testing.T) {
	result := FileHashResult{
		FilePath: "/path/to/file.bin",
		Hash:     "abc123",
		Result:   HashNotInCIRCL,
		Error:    nil,
	}

	if result.FilePath != "/path/to/file.bin" {
		t.Errorf("expected FilePath /path/to/file.bin, got %s", result.FilePath)
	}
	if result.Result != HashNotInCIRCL {
		t.Errorf("expected Result NOT_IN_CIRCL, got %v", result.Result)
	}
}

func TestPackageHashResult_Structure(t *testing.T) {
	result := PackageHashResult{
		Package:        "ripgrep",
		Version:        "14.0.0",
		Files:          []FileHashResult{{FilePath: "/test", Result: HashNotInCIRCL}},
		MaliciousCount: 0,
		OverallResult:  HashNotInCIRCL,
	}

	if result.Package != "ripgrep" {
		t.Errorf("expected Package ripgrep, got %s", result.Package)
	}
	if len(result.Files) != 1 {
		t.Errorf("expected 1 file, got %d", len(result.Files))
	}
}

func TestDetermineOverallResult(t *testing.T) {
	checker := &HashChecker{}

	tests := []struct {
		name     string
		files    []FileHashResult
		expected HashResult
	}{
		{
			name:     "empty",
			files:    []FileHashResult{},
			expected: HashNotFlaggedByCIRCL,
		},
		{
			name: "all clean",
			files: []FileHashResult{
				{Result: HashNotFlaggedByCIRCL},
				{Result: HashNotFlaggedByCIRCL},
			},
			expected: HashNotFlaggedByCIRCL,
		},
		{
			name: "all not in CIRCL",
			files: []FileHashResult{
				{Result: HashNotInCIRCL},
				{Result: HashNotInCIRCL},
			},
			expected: HashNotInCIRCL,
		},
		{
			name: "mixed with VT confirmed",
			files: []FileHashResult{
				{Result: HashNotInCIRCL},
				{Result: HashVTConfirmed},
				{Result: HashNotFlaggedByCIRCL},
			},
			expected: HashVTConfirmed,
		},
		{
			name: "mixed with CIRCL malicious",
			files: []FileHashResult{
				{Result: HashNotInCIRCL},
				{Result: HashCIRCLMalicious},
			},
			expected: HashCIRCLMalicious,
		},
		{
			name: "VT clean (still suspicious)",
			files: []FileHashResult{
				{Result: HashNotInCIRCL},
				{Result: HashVTClean},
			},
			expected: HashVTClean,
		},
		{
			name: "VT not found",
			files: []FileHashResult{
				{Result: HashVTNotFound},
				{Result: HashNotInCIRCL},
			},
			expected: HashVTNotFound,
		},
		{
			name: "error case",
			files: []FileHashResult{
				{Result: HashNotInCIRCL},
				{Result: HashError},
			},
			expected: HashError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checker.determineOverallResult(tt.files)
			if result != tt.expected {
				t.Errorf("determineOverallResult() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestNewHashChecker_VTDisabled(t *testing.T) {
	checker, err := NewHashChecker("", false, 0, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if checker.circl == nil {
		t.Error("expected non-nil CIRCL client")
	}
	if checker.vt != nil {
		t.Error("expected nil VT client when disabled")
	}
	if checker.vtEnabled {
		t.Error("expected vtEnabled to be false")
	}
}

func TestNewHashChecker_VTEnabled_NoKey(t *testing.T) {
	// Save and unset VT key
	original := os.Getenv("VIRUSTOTAL_API_KEY")
	_ = os.Unsetenv("VIRUSTOTAL_API_KEY")
	defer func() { _ = os.Setenv("VIRUSTOTAL_API_KEY", original) }()

	_, err := NewHashChecker("", true, 500, 4)
	if err == nil {
		t.Error("expected error when VT enabled but no API key")
	}
}

func TestHashChecker_CheckFile_NonExistent(t *testing.T) {
	checker, _ := NewHashChecker("", false, 0, 0)

	result := checker.CheckFile("/nonexistent/file.bin")

	if result.Result != HashError {
		t.Errorf("expected ERROR result for non-existent file, got %v", result.Result)
	}
	if result.Error == nil {
		t.Error("expected error to be set")
	}
}

func TestHashResultPriority(t *testing.T) {
	// Verify priority ordering is correct
	priority := map[HashResult]int{
		HashNotFlaggedByCIRCL: 0,
		HashNotInCIRCL:        1,
		HashVTClean:           2,
		HashVTNotFound:        3,
		HashCIRCLMalicious:    4,
		HashVTConfirmed:       5,
		HashError:             6,
	}

	// VT_CONFIRMED should be highest priority (most severe)
	if priority[HashVTConfirmed] <= priority[HashCIRCLMalicious] {
		t.Error("VT_CONFIRMED should have higher priority than CIRCL_MALICIOUS")
	}

	// CIRCL_MALICIOUS > VT_NOT_FOUND
	if priority[HashCIRCLMalicious] <= priority[HashVTNotFound] {
		t.Error("CIRCL_MALICIOUS should have higher priority than VT_NOT_FOUND")
	}

	// NOT_FLAGGED_BY_CIRCL should be lowest
	if priority[HashNotFlaggedByCIRCL] != 0 {
		t.Error("NOT_FLAGGED_BY_CIRCL should have lowest priority")
	}
}
