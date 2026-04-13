package semgrep

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// Runner handles Semgrep execution
type Runner struct {
	semgrepPath string
}

// Finding represents a single Semgrep finding
type Finding struct {
	CheckID string `json:"check_id"`
	Path    string `json:"path"`
	Start   struct {
		Line   int `json:"line"`
		Col    int `json:"col"`
		Offset int `json:"offset"`
	} `json:"start"`
	End struct {
		Line   int `json:"line"`
		Col    int `json:"col"`
		Offset int `json:"offset"`
	} `json:"end"`
	Extra struct {
		Message  string `json:"message"`
		Severity string `json:"severity"`
		Metadata struct {
			Category string `json:"category"`
		} `json:"metadata"`
		Lines string `json:"lines"`
	} `json:"extra"`
}

// ScanResult represents the complete Semgrep output
type ScanResult struct {
	Results []Finding `json:"results"`
	Errors  []struct {
		Message string `json:"message"`
		Level   string `json:"level"`
	} `json:"errors"`
}

// PackageScanResult holds scan results for a package
type PackageScanResult struct {
	Package      string
	Version      string
	Path         string
	Findings     []Finding
	FindingCount int
	HasFindings  bool
	Error        error
}

// NewRunner creates a new Semgrep runner
func NewRunner() (*Runner, error) {
	// Find semgrep in PATH
	path, err := exec.LookPath("semgrep")
	if err != nil {
		return nil, fmt.Errorf("semgrep not found in PATH: %w", err)
	}

	return &Runner{
		semgrepPath: path,
	}, nil
}

// Update is a no-op - Semgrep auto-downloads rules when using remote configs
// The --update flag was deprecated in newer Semgrep versions
func (r *Runner) Update() error {
	// Rules are automatically downloaded when scanning with remote configs
	// like p/supply-chain, p/secrets, p/malicious-code
	return nil
}

// ScanDirectory runs Semgrep against a directory using malicious code rule sets only
// Per the spec: p/supply-chain, p/secrets, p/malicious-code - NOT vulnerability rules
func (r *Runner) ScanDirectory(dir string) (*ScanResult, error) {
	// Verify directory exists
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil, fmt.Errorf("directory does not exist: %s", dir)
	}

	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd := exec.Command(r.semgrepPath,
		"--config=p/supply-chain",
		"--config=p/secrets",
		"--config=p/malicious-code",
		"--json",
		"--no-git-ignore", // Scan all files
		dir,
	)

	output, err := cmd.Output()
	if err != nil {
		// Semgrep returns non-zero exit code when findings exist
		// Check if we still got valid JSON output
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Exit code 1 with output means findings found - that's OK
			if len(output) > 0 {
				// Continue to parse output
			} else if len(exitErr.Stderr) > 0 {
				return nil, fmt.Errorf("semgrep error: %s", string(exitErr.Stderr))
			} else {
				return nil, fmt.Errorf("semgrep failed: %w", err)
			}
		} else {
			return nil, fmt.Errorf("running semgrep: %w", err)
		}
	}

	var result ScanResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("parsing semgrep output: %w", err)
	}

	return &result, nil
}

// ScanPackage scans a Homebrew package in the Cellar
func (r *Runner) ScanPackage(cellarPath, pkg, version string) (*PackageScanResult, error) {
	pkgPath := filepath.Join(cellarPath, pkg, version)

	result := &PackageScanResult{
		Package: pkg,
		Version: version,
		Path:    pkgPath,
	}

	scanResult, err := r.ScanDirectory(pkgPath)
	if err != nil {
		result.Error = err
		return result, nil
	}

	result.Findings = scanResult.Results
	result.FindingCount = len(scanResult.Results)
	result.HasFindings = result.FindingCount > 0

	return result, nil
}

// FormatFindings returns a human-readable summary of findings
func FormatFindings(findings []Finding) string {
	if len(findings) == 0 {
		return "No findings"
	}

	summary := fmt.Sprintf("%d finding(s):\n", len(findings))
	for _, f := range findings {
		summary += fmt.Sprintf("  - %s:%d [%s] %s\n",
			filepath.Base(f.Path),
			f.Start.Line,
			f.Extra.Severity,
			f.CheckID,
		)
	}
	return summary
}

// FilterBySeverity returns findings at or above the given severity
func FilterBySeverity(findings []Finding, minSeverity string) []Finding {
	severityRank := map[string]int{
		"INFO":    0,
		"WARNING": 1,
		"ERROR":   2,
	}

	minRank, ok := severityRank[minSeverity]
	if !ok {
		minRank = 0
	}

	filtered := make([]Finding, 0)
	for _, f := range findings {
		rank, ok := severityRank[f.Extra.Severity]
		if !ok {
			rank = 0
		}
		if rank >= minRank {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// GetFlaggedFilePaths returns unique file paths that have findings
func GetFlaggedFilePaths(findings []Finding) []string {
	pathSet := make(map[string]bool)
	for _, f := range findings {
		pathSet[f.Path] = true
	}

	paths := make([]string, 0, len(pathSet))
	for p := range pathSet {
		paths = append(paths, p)
	}
	return paths
}
