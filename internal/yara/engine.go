package yara

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	goyara "github.com/hillu/go-yara/v4"
)

//go:embed rules/*.yar
var embeddedRules embed.FS

// Engine provides YARA scanning using libyara via CGO.
// Requires libyara installed via: brew install yara
type Engine struct {
	rules   *goyara.Rules
	timeout time.Duration
}

// New creates a new Engine by compiling rules from rulesDir or embedded rules.
// If rulesDir is empty, the .yar files embedded in the binary are used.
func New(rulesDir string, timeout time.Duration) (*Engine, error) {
	compiler, err := goyara.NewCompiler()
	if err != nil {
		return nil, fmt.Errorf("creating YARA compiler: %w", err)
	}

	if rulesDir != "" {
		entries, err := os.ReadDir(rulesDir)
		if err != nil {
			return nil, fmt.Errorf("reading rules directory %s: %w", rulesDir, err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yar") {
				continue
			}
			content, err := os.ReadFile(filepath.Join(rulesDir, entry.Name()))
			if err != nil {
				return nil, fmt.Errorf("reading rule file %s: %w", entry.Name(), err)
			}
			if err := compiler.AddString(string(content), ""); err != nil {
				return nil, fmt.Errorf("compiling rule file %s: %w", entry.Name(), err)
			}
		}
	} else {
		err = fs.WalkDir(embeddedRules, "rules", func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".yar") {
				return nil
			}
			content, err := embeddedRules.ReadFile(path)
			if err != nil {
				return fmt.Errorf("reading embedded rule %s: %w", path, err)
			}
			if err := compiler.AddString(string(content), ""); err != nil {
				return fmt.Errorf("compiling embedded rule %s: %w", path, err)
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("loading embedded rules: %w", err)
		}
	}

	rules, err := compiler.GetRules()
	if err != nil {
		return nil, fmt.Errorf("finalising YARA rules: %w", err)
	}

	return &Engine{rules: rules, timeout: timeout}, nil
}

// Close releases libyara resources.
func (e *Engine) Close() error {
	if e.rules != nil {
		e.rules.Destroy()
	}
	return nil
}

// ScanBytes scans in-memory data and returns findings.
func (e *Engine) ScanBytes(name string, data []byte) ([]Finding, error) {
	if len(data) == 0 {
		return nil, nil
	}

	scanner, err := goyara.NewScanner(e.rules)
	if err != nil {
		return nil, fmt.Errorf("creating scanner: %w", err)
	}
	defer scanner.Destroy()

	if e.timeout > 0 {
		scanner.SetTimeout(e.timeout)
	}

	var matches goyara.MatchRules
	scanner.SetCallback(&matches)

	if err := scanner.ScanMem(data); err != nil {
		return nil, fmt.Errorf("scanning: %w", err)
	}

	return matchesToFindings(matches, name, data), nil
}

// ScanFile scans a single file on disk.
func (e *Engine) ScanFile(path string) ([]Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file %s: %w", path, err)
	}
	return e.ScanBytes(path, data)
}

// ScanDir scans all text files in a directory recursively.
func (e *Engine) ScanDir(dir string) (*DirScanResult, error) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil, fmt.Errorf("directory does not exist: %s", dir)
	}

	result := &DirScanResult{Dir: dir}

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("walking %s: %v", path, err))
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !isTextFile(path) {
			return nil
		}
		findings, err := e.ScanFile(path)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("scanning %s: %v", path, err))
			return nil
		}
		result.Findings = append(result.Findings, findings...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking directory: %w", err)
	}

	result.FindingCount = len(result.Findings)
	result.HasFindings = result.FindingCount > 0
	return result, nil
}

// ScanFiles scans a specific list of file paths and returns a combined result.
// Files that are not text files or cannot be read are skipped with errors logged.
// This is more efficient than ScanDir when only a subset of files need scanning.
func (e *Engine) ScanFiles(paths []string) (*DirScanResult, error) {
	result := &DirScanResult{}

	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("stat %s: %v", path, err))
			continue
		}
		if info.IsDir() {
			continue
		}
		if !isTextFile(path) {
			continue
		}
		findings, err := e.ScanFile(path)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("scanning %s: %v", path, err))
			continue
		}
		result.Findings = append(result.Findings, findings...)
	}

	result.FindingCount = len(result.Findings)
	result.HasFindings = result.FindingCount > 0
	return result, nil
}

// matchesToFindings converts go-yara match results to bsau findings.
func matchesToFindings(matches goyara.MatchRules, path string, data []byte) []Finding {
	// Build line offset table for fast offset->line conversion
	lineOffsets := buildLineOffsets(data)

	var findings []Finding
	for _, m := range matches {
		f := Finding{
			RuleID:   m.Rule,
			Path:     path,
			Severity: "WARNING",
		}
		for _, meta := range m.Metas {
			switch meta.Identifier {
			case "id":
				if s, ok := meta.Value.(string); ok {
					f.RuleID = s
				}
			case "severity":
				if s, ok := meta.Value.(string); ok {
					f.Severity = s
				}
			case "message":
				if s, ok := meta.Value.(string); ok {
					f.Message = s
				}
			}
		}
		for _, str := range m.Strings {
			f.Offsets = append(f.Offsets, str.Offset)
			f.LineNumbers = append(f.LineNumbers, offsetToLine(lineOffsets, str.Offset))
		}
		findings = append(findings, f)
	}
	return findings
}

// buildLineOffsets builds a table of byte offsets where each line starts.
// lineOffsets[i] is the byte offset where line i+1 begins (0-indexed internally).
func buildLineOffsets(data []byte) []int {
	offsets := []int{0} // Line 1 starts at offset 0
	for i, b := range data {
		if b == '\n' && i+1 < len(data) {
			offsets = append(offsets, i+1)
		}
	}
	return offsets
}

// offsetToLine converts a byte offset to a 1-indexed line number.
func offsetToLine(lineOffsets []int, offset uint64) int {
	// Binary search for the line containing this offset
	off := int(offset)
	lo, hi := 0, len(lineOffsets)-1
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if lineOffsets[mid] <= off {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return lo + 1 // Convert to 1-indexed
}

// isTextFile returns true if the file is likely a text file.
// Reads up to 512 bytes and returns false if a null byte is found.
func isTextFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, 512)
	n, err := f.Read(buf)
	if err != nil && n == 0 {
		return false
	}
	for _, b := range buf[:n] {
		if b == 0 {
			return false
		}
	}
	return true
}
