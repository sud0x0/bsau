package snapshot

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewManager(t *testing.T) {
	m := NewManager("/tmp/test-snapshots")
	if m.snapshotsDir != "/tmp/test-snapshots" {
		t.Errorf("expected snapshotsDir to be /tmp/test-snapshots, got %s", m.snapshotsDir)
	}
}

func TestIsTextFile(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "snapshot-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	tests := []struct {
		name     string
		filename string
		content  []byte
		expected bool
	}{
		{
			name:     "ruby file",
			filename: "test.rb",
			content:  []byte("puts 'hello'"),
			expected: true,
		},
		{
			name:     "python file",
			filename: "test.py",
			content:  []byte("print('hello')"),
			expected: true,
		},
		{
			name:     "shell script with shebang",
			filename: "script",
			content:  []byte("#!/bin/bash\necho hello"),
			expected: true,
		},
		{
			name:     "binary file with null bytes",
			filename: "binary.dat",
			content:  []byte{0x00, 0x01, 0x02, 0x03},
			expected: false,
		},
		{
			name:     "json file",
			filename: "config.json",
			content:  []byte(`{"key": "value"}`),
			expected: true,
		},
		{
			name:     "yaml file",
			filename: "config.yaml",
			content:  []byte("key: value"),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filePath := filepath.Join(tmpDir, tt.filename)
			if err := os.WriteFile(filePath, tt.content, 0644); err != nil {
				t.Fatalf("failed to write test file: %v", err)
			}

			result := IsTextFile(filePath)
			if result != tt.expected {
				t.Errorf("IsTextFile(%s) = %v, expected %v", tt.filename, result, tt.expected)
			}
		})
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		bytes    int64
		expected string
	}{
		{500, "500B"},
		{1024, "1.0KB"},
		{1536, "1.5KB"},
		{1048576, "1.0MB"},
		{1572864, "1.5MB"},
		{1073741824, "1.0GB"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := formatBytes(tt.bytes)
			if result != tt.expected {
				t.Errorf("formatBytes(%d) = %s, expected %s", tt.bytes, result, tt.expected)
			}
		})
	}
}

func TestCreateSnapshot(t *testing.T) {
	// Create source directory with test files
	srcDir, err := os.MkdirTemp("", "snapshot-src")
	if err != nil {
		t.Fatalf("failed to create source dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(srcDir) }()

	// Create destination directory
	destDir, err := os.MkdirTemp("", "snapshot-dest")
	if err != nil {
		t.Fatalf("failed to create dest dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(destDir) }()

	// Create test files in source
	testFile := filepath.Join(srcDir, "test.rb")
	if err := os.WriteFile(testFile, []byte("puts 'hello'"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	m := NewManager(destDir)
	snapshotPath, err := m.CreateSnapshot(srcDir, "testpkg", "1.0.0")
	if err != nil {
		t.Fatalf("CreateSnapshot failed: %v", err)
	}

	// Verify snapshot was created
	expectedPath := filepath.Join(destDir, "testpkg", "1.0.0")
	if snapshotPath != expectedPath {
		t.Errorf("expected snapshot path %s, got %s", expectedPath, snapshotPath)
	}

	// Verify file was copied
	copiedFile := filepath.Join(snapshotPath, "test.rb")
	if _, err := os.Stat(copiedFile); os.IsNotExist(err) {
		t.Error("expected test.rb to be copied to snapshot")
	}
}

func TestCleanup(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "snapshot-cleanup")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create package directory
	pkgDir := filepath.Join(tmpDir, "testpkg")
	if err := os.MkdirAll(pkgDir, 0755); err != nil {
		t.Fatalf("failed to create package dir: %v", err)
	}

	m := NewManager(tmpDir)
	if err := m.Cleanup("testpkg"); err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}

	// Verify directory was removed
	if _, err := os.Stat(pkgDir); !os.IsNotExist(err) {
		t.Error("expected package directory to be removed")
	}
}

func TestCheckDiskSpace(t *testing.T) {
	// Create temp directory with a small file
	tmpDir, err := os.MkdirTemp("", "diskspace-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("small file"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	m := NewManager(tmpDir)
	check, err := m.CheckDiskSpace(tmpDir)
	if err != nil {
		t.Fatalf("CheckDiskSpace failed: %v", err)
	}

	// Small file should always have enough space
	if !check.CanProceed {
		t.Error("expected CanProceed to be true for small file")
	}
}

func TestChangedFiles(t *testing.T) {
	tests := []struct {
		name     string
		diff     string
		newPath  string
		expected []string
	}{
		{
			name:     "empty diff returns empty slice",
			diff:     "",
			newPath:  "/opt/homebrew/Cellar/pkg/2.0.0",
			expected: []string{},
		},
		{
			name: "single modified file",
			diff: `--- /tmp/bsau-123/snapshots/pkg/1.0.0/lib/file.rb	2024-01-01 12:00:00.000000000 +0000
+++ /opt/homebrew/Cellar/pkg/2.0.0/lib/file.rb	2024-01-02 12:00:00.000000000 +0000
@@ -1,3 +1,4 @@
 line1
+new line
 line2`,
			newPath:  "/opt/homebrew/Cellar/pkg/2.0.0",
			expected: []string{"/opt/homebrew/Cellar/pkg/2.0.0/lib/file.rb"},
		},
		{
			name: "deleted file shows as /dev/null and is skipped",
			diff: `--- /tmp/bsau-123/snapshots/pkg/1.0.0/lib/deleted.rb	2024-01-01 12:00:00.000000000 +0000
+++ /dev/null	2024-01-02 12:00:00.000000000 +0000
@@ -1,3 +0,0 @@
-line1
-line2`,
			newPath:  "/opt/homebrew/Cellar/pkg/2.0.0",
			expected: []string{},
		},
		{
			name: "new file (added)",
			diff: `--- /dev/null	2024-01-01 12:00:00.000000000 +0000
+++ /opt/homebrew/Cellar/pkg/2.0.0/lib/new.rb	2024-01-02 12:00:00.000000000 +0000
@@ -0,0 +1,3 @@
+line1
+line2`,
			newPath:  "/opt/homebrew/Cellar/pkg/2.0.0",
			expected: []string{"/opt/homebrew/Cellar/pkg/2.0.0/lib/new.rb"},
		},
		{
			name: "multiple files with one deleted",
			diff: `--- /tmp/bsau-123/snapshots/pkg/1.0.0/lib/modified.rb	2024-01-01 12:00:00.000000000 +0000
+++ /opt/homebrew/Cellar/pkg/2.0.0/lib/modified.rb	2024-01-02 12:00:00.000000000 +0000
@@ -1,3 +1,4 @@
 line1
+new
--- /tmp/bsau-123/snapshots/pkg/1.0.0/lib/deleted.rb	2024-01-01 12:00:00.000000000 +0000
+++ /dev/null	2024-01-02 12:00:00.000000000 +0000
@@ -1,3 +0,0 @@
-gone
--- /dev/null	2024-01-01 12:00:00.000000000 +0000
+++ /opt/homebrew/Cellar/pkg/2.0.0/lib/added.rb	2024-01-02 12:00:00.000000000 +0000
@@ -0,0 +1,3 @@
+new file`,
			newPath: "/opt/homebrew/Cellar/pkg/2.0.0",
			expected: []string{
				"/opt/homebrew/Cellar/pkg/2.0.0/lib/modified.rb",
				"/opt/homebrew/Cellar/pkg/2.0.0/lib/added.rb",
			},
		},
		{
			name: "no duplicates",
			diff: `--- a	2024-01-01 12:00:00.000000000 +0000
+++ /opt/homebrew/Cellar/pkg/2.0.0/lib/file.rb	2024-01-02 12:00:00.000000000 +0000
@@ -1 +1 @@
-old
+new
--- b	2024-01-01 12:00:00.000000000 +0000
+++ /opt/homebrew/Cellar/pkg/2.0.0/lib/file.rb	2024-01-02 12:00:00.000000000 +0000
@@ -1 +1 @@
-old2
+new2`,
			newPath:  "/opt/homebrew/Cellar/pkg/2.0.0",
			expected: []string{"/opt/homebrew/Cellar/pkg/2.0.0/lib/file.rb"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ChangedFiles(tt.diff, tt.newPath)
			if len(result) != len(tt.expected) {
				t.Errorf("ChangedFiles() returned %d files, expected %d", len(result), len(tt.expected))
				t.Errorf("Got: %v", result)
				t.Errorf("Expected: %v", tt.expected)
				return
			}
			for i, path := range result {
				if path != tt.expected[i] {
					t.Errorf("ChangedFiles()[%d] = %s, expected %s", i, path, tt.expected[i])
				}
			}
		})
	}
}
