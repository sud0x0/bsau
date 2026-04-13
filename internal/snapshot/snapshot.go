package snapshot

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf8"
)

// Manager handles pre-upgrade snapshots
type Manager struct {
	snapshotsDir string
}

// NewManager creates a new snapshot manager
func NewManager(snapshotsDir string) *Manager {
	return &Manager{
		snapshotsDir: snapshotsDir,
	}
}

// DiskSpaceCheck contains disk space analysis
type DiskSpaceCheck struct {
	EstimatedSize  int64
	AvailableSpace int64
	Ratio          float64 // available / estimated
	CanProceed     bool
	NeedsPrompt    bool
	SkipAutomatic  bool
	WarningMessage string
}

// CheckDiskSpace analyzes if there's enough space for the snapshot
func (m *Manager) CheckDiskSpace(srcPath string) (*DiskSpaceCheck, error) {
	// Calculate size of text-readable files
	estimated, err := m.estimateTextFileSize(srcPath)
	if err != nil {
		return nil, fmt.Errorf("estimating size: %w", err)
	}

	// Get available space in /tmp
	available, err := getAvailableSpace(m.snapshotsDir)
	if err != nil {
		return nil, fmt.Errorf("checking available space: %w", err)
	}

	check := &DiskSpaceCheck{
		EstimatedSize:  estimated,
		AvailableSpace: available,
	}

	if estimated == 0 {
		check.Ratio = 999 // No files to snapshot
		check.CanProceed = true
		return check, nil
	}

	check.Ratio = float64(available) / float64(estimated)

	switch {
	case check.Ratio < 1.1:
		// Less than 1.1x - skip automatically
		check.SkipAutomatic = true
		check.CanProceed = false
		check.WarningMessage = fmt.Sprintf(
			"Insufficient disk space: snapshot requires ~%s but only %s available in /tmp",
			formatBytes(estimated), formatBytes(available))

	case check.Ratio < 2.0:
		// Less than 2x - warn and prompt
		check.NeedsPrompt = true
		check.CanProceed = true
		check.WarningMessage = fmt.Sprintf(
			"Low disk space: snapshot requires ~%s, /tmp has %s available",
			formatBytes(estimated), formatBytes(available))

	default:
		// 2x or more - proceed without prompt
		check.CanProceed = true
	}

	return check, nil
}

// estimateTextFileSize calculates the total size of text-readable files
func (m *Manager) estimateTextFileSize(srcPath string) (int64, error) {
	var totalSize int64

	err := filepath.Walk(srcPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip inaccessible files
		}
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}

		if IsTextFile(path) {
			totalSize += info.Size()
		}
		return nil
	})

	return totalSize, err
}

// CreateSnapshot copies text-readable files from src to the snapshot directory
func (m *Manager) CreateSnapshot(srcPath, pkg, version string) (string, error) {
	destPath := filepath.Join(m.snapshotsDir, pkg, version)

	if err := os.MkdirAll(destPath, 0755); err != nil {
		return "", fmt.Errorf("creating snapshot directory: %w", err)
	}

	err := filepath.Walk(srcPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip inaccessible files
		}

		relPath, err := filepath.Rel(srcPath, path)
		if err != nil {
			return nil
		}

		destFilePath := filepath.Join(destPath, relPath)

		if info.IsDir() {
			return os.MkdirAll(destFilePath, info.Mode())
		}

		if !info.Mode().IsRegular() {
			return nil
		}

		// Only copy text-readable files
		if !IsTextFile(path) {
			return nil
		}

		return copyFile(path, destFilePath)
	})

	if err != nil {
		return "", fmt.Errorf("walking source directory: %w", err)
	}

	return destPath, nil
}

// GenerateDiff creates a unified diff between snapshot and new version
func (m *Manager) GenerateDiff(snapshotPath, newPath string) (string, error) {
	cmd := exec.Command("diff", "-ru", snapshotPath, newPath)
	output, err := cmd.Output()

	// diff returns exit code 1 when files differ - that's expected
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 1 {
				// Files differ - return the diff
				return string(output), nil
			}
		}
		// Only return error for unexpected failures
		if len(output) == 0 {
			return "", fmt.Errorf("generating diff: %w", err)
		}
	}

	return string(output), nil
}

// Cleanup removes a package's snapshot directory
func (m *Manager) Cleanup(pkg string) error {
	pkgDir := filepath.Join(m.snapshotsDir, pkg)
	return os.RemoveAll(pkgDir)
}

// IsTextFile checks if a file is text-readable (valid UTF-8)
func IsTextFile(path string) bool {
	// Check extension first for common cases
	ext := strings.ToLower(filepath.Ext(path))
	textExtensions := map[string]bool{
		".rb": true, ".py": true, ".sh": true, ".bash": true, ".zsh": true,
		".pl": true, ".js": true, ".ts": true, ".json": true, ".yaml": true,
		".yml": true, ".toml": true, ".xml": true, ".html": true, ".css": true,
		".md": true, ".txt": true, ".conf": true, ".cfg": true, ".ini": true,
		".c": true, ".h": true, ".cpp": true, ".hpp": true, ".go": true,
		".rs": true, ".java": true, ".kt": true, ".swift": true, ".m": true,
		".lua": true, ".vim": true, ".el": true, ".lisp": true, ".clj": true,
		".sql": true, ".graphql": true, ".proto": true, ".fish": true,
	}

	if textExtensions[ext] {
		return true
	}

	// Check for shebang (script without extension)
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()

	// Read first 512 bytes to check if text
	buf := make([]byte, 512)
	n, err := f.Read(buf)
	if err != nil && err != io.EOF {
		return false
	}
	buf = buf[:n]

	// Check for shebang
	if len(buf) >= 2 && buf[0] == '#' && buf[1] == '!' {
		return true
	}

	// Check if valid UTF-8 and doesn't contain null bytes
	if !utf8.Valid(buf) {
		return false
	}

	for _, b := range buf {
		if b == 0 {
			return false // Binary file (contains null bytes)
		}
	}

	return true
}

// CollectTextFiles returns a map of file paths to their contents for all text files in a directory
func CollectTextFiles(dirPath string, maxFileBytes int) (map[string]string, error) {
	files := make(map[string]string)

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip inaccessible files
		}
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}

		// Skip files larger than maxFileBytes
		if maxFileBytes > 0 && info.Size() > int64(maxFileBytes) {
			return nil
		}

		if IsTextFile(path) {
			content, err := os.ReadFile(path)
			if err != nil {
				return nil // Skip unreadable files
			}
			files[path] = string(content)
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("walking directory: %w", err)
	}

	return files, nil
}

func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = srcFile.Close() }()

	// Ensure destination directory exists
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() { _ = dstFile.Close() }()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return err
	}

	// Copy permissions
	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}
	return os.Chmod(dst, srcInfo.Mode())
}

func getAvailableSpace(path string) (int64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		// If path doesn't exist, check parent
		parent := filepath.Dir(path)
		if err := syscall.Statfs(parent, &stat); err != nil {
			return 0, err
		}
	}
	return int64(stat.Bavail) * int64(stat.Bsize), nil
}

func formatBytes(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)

	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.1fGB", float64(bytes)/GB)
	case bytes >= MB:
		return fmt.Sprintf("%.1fMB", float64(bytes)/MB)
	case bytes >= KB:
		return fmt.Sprintf("%.1fKB", float64(bytes)/KB)
	default:
		return fmt.Sprintf("%dB", bytes)
	}
}
