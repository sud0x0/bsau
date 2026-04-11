package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewRunManager(t *testing.T) {
	rm, err := NewRunManager()
	if err != nil {
		t.Fatalf("NewRunManager failed: %v", err)
	}
	defer func() { _ = rm.Cleanup() }()

	// Check that run directory was created
	if _, err := os.Stat(rm.runDir); os.IsNotExist(err) {
		t.Error("expected run directory to be created")
	}

	// Check that snapshots directory was created
	snapshotsDir := rm.SnapshotsDir()
	if _, err := os.Stat(snapshotsDir); os.IsNotExist(err) {
		t.Error("expected snapshots directory to be created")
	}
}

func TestRunManager_RunDir(t *testing.T) {
	rm, err := NewRunManager()
	if err != nil {
		t.Fatalf("NewRunManager failed: %v", err)
	}
	defer func() { _ = rm.Cleanup() }()

	runDir := rm.RunDir()
	if runDir == "" {
		t.Error("expected non-empty run directory")
	}
	if _, err := os.Stat(runDir); os.IsNotExist(err) {
		t.Error("expected run directory to exist")
	}
}

func TestRunManager_SaveAndLoadPreUpdateVulns(t *testing.T) {
	rm, err := NewRunManager()
	if err != nil {
		t.Fatalf("NewRunManager failed: %v", err)
	}
	defer func() { _ = rm.Cleanup() }()

	testData := map[string]interface{}{
		"package1": map[string]interface{}{
			"cve_count": 3,
			"severity":  "HIGH",
		},
	}

	if err := rm.SavePreUpdateVulns(testData); err != nil {
		t.Fatalf("SavePreUpdateVulns failed: %v", err)
	}

	// Verify file was created
	filePath := filepath.Join(rm.runDir, "pre-update-vuln.json")
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		t.Error("expected pre-update-vuln.json to be created")
	}
}

func TestRunManager_SaveScanResults(t *testing.T) {
	rm, err := NewRunManager()
	if err != nil {
		t.Fatalf("NewRunManager failed: %v", err)
	}
	defer func() { _ = rm.Cleanup() }()

	testData := map[string]interface{}{
		"package1": map[string]interface{}{
			"verdict": "SAFE",
		},
	}

	if err := rm.SaveScanResults(testData); err != nil {
		t.Fatalf("SaveScanResults failed: %v", err)
	}

	// Verify file was created
	filePath := filepath.Join(rm.runDir, "scan-results.json")
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		t.Error("expected scan-results.json to be created")
	}
}

func TestRunManager_Cleanup(t *testing.T) {
	rm, err := NewRunManager()
	if err != nil {
		t.Fatalf("NewRunManager failed: %v", err)
	}

	runDir := rm.RunDir()

	if err := rm.Cleanup(); err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}

	// Verify directory was removed
	if _, err := os.Stat(runDir); !os.IsNotExist(err) {
		t.Error("expected run directory to be removed")
	}
}

func TestRunManager_PackageSnapshotDir(t *testing.T) {
	rm, err := NewRunManager()
	if err != nil {
		t.Fatalf("NewRunManager failed: %v", err)
	}
	defer func() { _ = rm.Cleanup() }()

	expected := filepath.Join(rm.SnapshotsDir(), "testpkg", "1.0.0")
	got := rm.PackageSnapshotDir("testpkg", "1.0.0")

	if got != expected {
		t.Errorf("PackageSnapshotDir() = %v, expected %v", got, expected)
	}
}

func TestVTDailyManager_NewVTDailyManager(t *testing.T) {
	vt, err := NewVTDailyManager()
	if err != nil {
		t.Fatalf("NewVTDailyManager failed: %v", err)
	}

	if vt == nil {
		t.Error("expected non-nil VTDailyManager")
	}
}

func TestVTDailyManager_LoadAndIncrement(t *testing.T) {
	vt, err := NewVTDailyManager()
	if err != nil {
		t.Fatalf("NewVTDailyManager failed: %v", err)
	}

	// Load initial state
	state, err := vt.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	initialCount := state.Count

	// Increment
	if err := vt.Increment(); err != nil {
		t.Fatalf("Increment failed: %v", err)
	}

	// Load again and verify
	state, err = vt.Load()
	if err != nil {
		t.Fatalf("Load after increment failed: %v", err)
	}

	if state.Count != initialCount+1 {
		t.Errorf("expected count to increase by 1, got %d -> %d", initialCount, state.Count)
	}
}

func TestVTDailyManager_CanSubmit(t *testing.T) {
	vt, err := NewVTDailyManager()
	if err != nil {
		t.Fatalf("NewVTDailyManager failed: %v", err)
	}

	// Should be able to make requests with a high limit
	canSubmit, err := vt.CanSubmit(10000)
	if err != nil {
		t.Fatalf("CanSubmit failed: %v", err)
	}

	if !canSubmit {
		t.Error("expected CanSubmit to return true with high limit")
	}
}
