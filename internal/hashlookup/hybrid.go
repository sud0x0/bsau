package hashlookup

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// HashResult represents the final result taxonomy per the spec
type HashResult string

const (
	// NOT_IN_CIRCL - CIRCL returned 404, hash not in database
	// This is expected for most Homebrew binaries. VT is never called.
	HashNotInCIRCL HashResult = "NOT_IN_CIRCL"

	// NOT_FLAGGED_BY_CIRCL - CIRCL returned 200 but KnownMalicious=false
	// VT is never called for this case.
	HashNotFlaggedByCIRCL HashResult = "NOT_FLAGGED_BY_CIRCL"

	// CIRCL_MALICIOUS - CIRCL returned 200 with KnownMalicious=true
	// VT should be called to confirm if vt_fallback is enabled
	HashCIRCLMalicious HashResult = "CIRCL_MALICIOUS"

	// VT_CONFIRMED - VT confirmed the malicious detection
	// This is a blocking signal
	HashVTConfirmed HashResult = "VT_CONFIRMED"

	// VT_CLEAN - VT says the hash is clean despite CIRCL flagging it
	// Warn user, prompt for confirmation
	HashVTClean HashResult = "VT_CLEAN"

	// VT_NOT_FOUND - VT doesn't have the hash in its database
	// Warn user, prompt for confirmation
	HashVTNotFound HashResult = "VT_NOT_FOUND"

	// ERROR - Something went wrong during lookup
	HashError HashResult = "ERROR"
)

// FileHashResult represents the verification result for a single file
type FileHashResult struct {
	FilePath    string
	Hash        string
	Result      HashResult
	CIRCLResult *CIRCLLookupResult
	VTResult    *VTLookupResult
	Error       error
}

// PackageHashResult aggregates hash results for a package
type PackageHashResult struct {
	Package        string
	Version        string
	Files          []FileHashResult
	MaliciousCount int
	OverallResult  HashResult
}

// HashChecker performs hybrid hash verification
type HashChecker struct {
	circl     *CIRCLClient
	vt        *VTClient
	vtEnabled bool
}

// NewHashChecker creates a new hybrid hash checker
func NewHashChecker(circlURL string, vtEnabled bool, vtDailyLimit, vtRateLimit int) (*HashChecker, error) {
	checker := &HashChecker{
		circl:     NewCIRCLClient(circlURL),
		vtEnabled: vtEnabled,
	}

	if vtEnabled {
		vt, err := NewVTClient(vtDailyLimit, vtRateLimit)
		if err != nil {
			return nil, fmt.Errorf("initializing VT client: %w", err)
		}
		checker.vt = vt
	}

	return checker, nil
}

// CheckFile verifies a single file's hash
func (h *HashChecker) CheckFile(filePath string) FileHashResult {
	result := FileHashResult{FilePath: filePath}

	// Compute SHA256
	hash, err := ComputeSHA256(filePath)
	if err != nil {
		result.Error = err
		result.Result = HashError
		return result
	}
	result.Hash = hash

	// Stage 1: CIRCL lookup
	circlResult := h.circl.LookupSHA256(hash)
	result.CIRCLResult = circlResult

	if circlResult.Error != nil {
		// CIRCL error - treat as NOT_IN_CIRCL per error handling spec
		result.Result = HashNotInCIRCL
		result.Error = circlResult.Error
		return result
	}

	if !circlResult.Found {
		// CIRCL 404 - NOT_IN_CIRCL, VT never called
		result.Result = HashNotInCIRCL
		return result
	}

	if !circlResult.Malicious {
		// CIRCL found it but not malicious
		result.Result = HashNotFlaggedByCIRCL
		return result
	}

	// CIRCL flagged as malicious - Stage 2: VT confirmation
	result.Result = HashCIRCLMalicious

	if !h.vtEnabled || h.vt == nil {
		// VT not enabled, return CIRCL_MALICIOUS
		return result
	}

	// Query VT for confirmation
	vtResult := h.vt.LookupSHA256(hash)
	result.VTResult = vtResult

	if vtResult.Error != nil {
		// VT error - stay at CIRCL_MALICIOUS, warn user
		result.Error = vtResult.Error
		return result
	}

	if !vtResult.Found {
		// VT doesn't have it
		result.Result = HashVTNotFound
		return result
	}

	if vtResult.IsConfirmed {
		// VT confirms malicious
		result.Result = HashVTConfirmed
	} else {
		// VT says clean despite CIRCL flagging
		result.Result = HashVTClean
	}

	return result
}

// ProgressCallback is called during package checking to report progress
type ProgressCallback func(current, total int, filename string)

// CheckPackage verifies all files in a package directory
func (h *HashChecker) CheckPackage(cellarPath, pkg, version string) (*PackageHashResult, error) {
	return h.CheckPackageWithProgress(cellarPath, pkg, version, nil)
}

// CheckPackageWithProgress verifies all files in a package directory with progress reporting
func (h *HashChecker) CheckPackageWithProgress(cellarPath, pkg, version string, progress ProgressCallback) (*PackageHashResult, error) {
	pkgPath := filepath.Join(cellarPath, pkg, version)

	result := &PackageHashResult{
		Package: pkg,
		Version: version,
		Files:   make([]FileHashResult, 0),
	}

	// First pass: count files to check
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

	// Second pass: check each file with progress
	for i, path := range filesToCheck {
		if progress != nil {
			// Extract just the filename for display
			filename := filepath.Base(path)
			progress(i+1, len(filesToCheck), filename)
		}

		fileResult := h.CheckFile(path)
		result.Files = append(result.Files, fileResult)

		// Track malicious findings
		if fileResult.Result == HashCIRCLMalicious ||
			fileResult.Result == HashVTConfirmed {
			result.MaliciousCount++
		}
	}

	// Determine overall result (worst case)
	result.OverallResult = h.determineOverallResult(result.Files)

	return result, nil
}

func (h *HashChecker) determineOverallResult(files []FileHashResult) HashResult {
	// Priority: VT_CONFIRMED > CIRCL_MALICIOUS > VT_NOT_FOUND > VT_CLEAN > NOT_IN_CIRCL > NOT_FLAGGED_BY_CIRCL
	priority := map[HashResult]int{
		HashNotFlaggedByCIRCL: 0,
		HashNotInCIRCL:        1,
		HashVTClean:           2,
		HashVTNotFound:        3,
		HashCIRCLMalicious:    4,
		HashVTConfirmed:       5,
		HashError:             6,
	}

	worst := HashNotFlaggedByCIRCL
	for _, f := range files {
		if priority[f.Result] > priority[worst] {
			worst = f.Result
		}
	}
	return worst
}

// ComputeSHA256 calculates the SHA256 hash of a file
func ComputeSHA256(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("opening file: %w", err)
	}
	defer func() { _ = f.Close() }()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return "", fmt.Errorf("hashing file: %w", err)
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// ComputeSHA1 calculates the SHA1 hash of a file
// Returns uppercase hex string (required by CIRCL bloom filter)
func ComputeSHA1(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("opening file: %w", err)
	}
	defer func() { _ = f.Close() }()

	// SHA-1 is required here because the CIRCL bloom filter contains SHA-1 hashes.
	// This is not used for cryptographic security, only for hash lookups.
	hasher := sha1.New() // nosemgrep: go.lang.security.audit.crypto.use_of_weak_crypto.use-of-sha1
	if _, err := io.Copy(hasher, f); err != nil {
		return "", fmt.Errorf("hashing file: %w", err)
	}

	// CIRCL bloom filter expects uppercase hex
	return strings.ToUpper(hex.EncodeToString(hasher.Sum(nil))), nil
}

// IsBlockingResult returns true if this result should block an upgrade
func IsBlockingResult(r HashResult) bool {
	return r == HashVTConfirmed
}

// RequiresPrompt returns true if this result requires user confirmation
func RequiresPrompt(r HashResult) bool {
	return r == HashCIRCLMalicious || r == HashVTClean || r == HashVTNotFound
}
