package hashlookup

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/sud0x0/bsau/internal/bloom"
)

// BloomResult represents the result of a bloom filter lookup
type BloomResult string

const (
	// BloomKnown - Hash found in bloom filter (known file from NSRL/trusted sources)
	BloomKnown BloomResult = "KNOWN"
	// BloomUnknown - Hash not in bloom filter (unknown file, may need investigation)
	BloomUnknown BloomResult = "UNKNOWN"
	// BloomError - Error computing hash
	BloomError BloomResult = "ERROR"
)

// FileBloomResult represents bloom check result for a single file
type FileBloomResult struct {
	FilePath string
	Hash     string // SHA-1 hash (uppercase)
	Result   BloomResult
	Error    error
}

// PackageBloomResult aggregates bloom results for a package
type PackageBloomResult struct {
	Package      string
	Version      string
	Files        []FileBloomResult
	KnownCount   int
	UnknownCount int
	TotalFiles   int
}

// BloomChecker performs fast local hash checking using bloom filter
type BloomChecker struct {
	filter *bloom.Filter
}

// NewBloomChecker creates a new bloom filter based hash checker
func NewBloomChecker() (*BloomChecker, error) {
	if !bloom.Exists() {
		return nil, fmt.Errorf("bloom filter not found - run download first")
	}

	filter, err := bloom.Load()
	if err != nil {
		return nil, fmt.Errorf("loading bloom filter: %w", err)
	}

	return &BloomChecker{filter: filter}, nil
}

// AgeInfo returns bloom filter age info for display
func (b *BloomChecker) AgeInfo() string {
	age := b.filter.Age()
	days := int(age.Hours() / 24)
	return fmt.Sprintf("%d days old (downloaded: %s)",
		days, b.filter.DownloadedAt().Format("2006-01-02"))
}

// CheckFile checks a single file against the bloom filter
func (b *BloomChecker) CheckFile(filePath string) FileBloomResult {
	result := FileBloomResult{FilePath: filePath}

	// Compute SHA-1 (bloom filter uses SHA-1, uppercase hex)
	hash, err := ComputeSHA1(filePath)
	if err != nil {
		result.Error = err
		result.Result = BloomError
		return result
	}
	result.Hash = hash

	// Check against bloom filter
	if b.filter.Contains(hash) {
		result.Result = BloomKnown
	} else {
		result.Result = BloomUnknown
	}

	return result
}

// CheckPackage checks all files in a package directory
func (b *BloomChecker) CheckPackage(cellarPath, pkg, version string) (*PackageBloomResult, error) {
	return b.CheckPackageWithProgress(cellarPath, pkg, version, nil)
}

// CheckPackageWithProgress checks all files with progress callback
func (b *BloomChecker) CheckPackageWithProgress(cellarPath, pkg, version string, progress ProgressCallback) (*PackageBloomResult, error) {
	pkgPath := filepath.Join(cellarPath, pkg, version)

	result := &PackageBloomResult{
		Package: pkg,
		Version: version,
		Files:   make([]FileBloomResult, 0),
	}

	// First pass: count files
	var filesToCheck []string
	err := filepath.Walk(pkgPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() || !info.Mode().IsRegular() {
			return nil
		}
		filesToCheck = append(filesToCheck, path)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking package directory: %w", err)
	}

	result.TotalFiles = len(filesToCheck)

	// Second pass: check each file
	for i, path := range filesToCheck {
		if progress != nil {
			filename := filepath.Base(path)
			progress(i+1, len(filesToCheck), filename)
		}

		fileResult := b.CheckFile(path)
		result.Files = append(result.Files, fileResult)

		switch fileResult.Result {
		case BloomKnown:
			result.KnownCount++
		case BloomUnknown:
			result.UnknownCount++
		}
	}

	return result, nil
}

// Summary returns a summary string for display
func (r *PackageBloomResult) Summary() string {
	if r.TotalFiles == 0 {
		return "no files"
	}
	knownPct := float64(r.KnownCount) / float64(r.TotalFiles) * 100
	return fmt.Sprintf("%d/%d known (%.0f%%)", r.KnownCount, r.TotalFiles, knownPct)
}
