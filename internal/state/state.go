package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
)

// RunState holds temporary state for the current run only
// This is discarded after the run completes
type RunState struct {
	RunID          string                 `json:"run_id"`
	RunDir         string                 `json:"run_dir"`
	PreUpdateVulns map[string]interface{} `json:"pre_update_vulns"`
	ScanResults    map[string]interface{} `json:"scan_results"`
	YaraResults    map[string]interface{} `json:"yara_results"`
}

// VTDailyState tracks VirusTotal API usage across runs
// This is the ONLY persistent state - stored in ~/.bsau/vt-daily.json
type VTDailyState struct {
	Date  string `json:"date"`
	Count int    `json:"count"`
}

// RunManager handles run-scoped temporary state
type RunManager struct {
	runID  string
	runDir string
}

// NewRunManager creates a new run manager with a unique run ID
func NewRunManager() (*RunManager, error) {
	runID := uuid.New().String()[:8]
	runDir := filepath.Join(os.TempDir(), fmt.Sprintf("bsau-%s", runID))

	if err := os.MkdirAll(runDir, 0755); err != nil {
		return nil, fmt.Errorf("creating run directory: %w", err)
	}

	// Create snapshots subdirectory
	snapshotsDir := filepath.Join(runDir, "snapshots")
	if err := os.MkdirAll(snapshotsDir, 0755); err != nil {
		return nil, fmt.Errorf("creating snapshots directory: %w", err)
	}

	return &RunManager{
		runID:  runID,
		runDir: runDir,
	}, nil
}

// RunID returns the unique run identifier
func (m *RunManager) RunID() string {
	return m.runID
}

// RunDir returns the run's temporary directory path
func (m *RunManager) RunDir() string {
	return m.runDir
}

// SnapshotsDir returns the path to the snapshots subdirectory
func (m *RunManager) SnapshotsDir() string {
	return filepath.Join(m.runDir, "snapshots")
}

// PackageSnapshotDir returns the path where a package's pre-upgrade files are stored
func (m *RunManager) PackageSnapshotDir(pkg, version string) string {
	return filepath.Join(m.SnapshotsDir(), pkg, version)
}

// SavePreUpdateVulns saves vulnerability scan results before upgrade
func (m *RunManager) SavePreUpdateVulns(data map[string]interface{}) error {
	return m.saveJSON("pre-update-vuln.json", data)
}

// SaveScanResults saves per-package scan results
func (m *RunManager) SaveScanResults(data map[string]interface{}) error {
	return m.saveJSON("scan-results.json", data)
}

// SaveYaraResults saves YARA findings
func (m *RunManager) SaveYaraResults(data map[string]interface{}) error {
	return m.saveJSON("yara-results.json", data)
}

func (m *RunManager) saveJSON(filename string, data interface{}) error {
	path := filepath.Join(m.runDir, filename)
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating %s: %w", filename, err)
	}
	defer func() { _ = file.Close() }()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		return fmt.Errorf("encoding %s: %w", filename, err)
	}

	return nil
}

// Cleanup removes the entire run directory
func (m *RunManager) Cleanup() error {
	return os.RemoveAll(m.runDir)
}

// CleanupPackageSnapshot removes just one package's snapshot after Step 6a
func (m *RunManager) CleanupPackageSnapshot(pkg string) error {
	pkgDir := filepath.Join(m.SnapshotsDir(), pkg)
	return os.RemoveAll(pkgDir)
}

// VTDailyManager handles persistent VT daily tracking
type VTDailyManager struct {
	path string
}

// NewVTDailyManager creates a manager for VT daily state
func NewVTDailyManager() (*VTDailyManager, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("getting home directory: %w", err)
	}

	stateDir := filepath.Join(homeDir, ".bsau")
	if err := os.MkdirAll(stateDir, 0755); err != nil {
		return nil, fmt.Errorf("creating state directory: %w", err)
	}

	return &VTDailyManager{
		path: filepath.Join(stateDir, "vt-daily.json"),
	}, nil
}

// Load reads the VT daily state
func (m *VTDailyManager) Load() (*VTDailyState, error) {
	data, err := os.ReadFile(m.path)
	if err != nil {
		if os.IsNotExist(err) {
			return &VTDailyState{
				Date:  today(),
				Count: 0,
			}, nil
		}
		return nil, fmt.Errorf("reading VT daily state: %w", err)
	}

	var state VTDailyState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("parsing VT daily state: %w", err)
	}

	// Reset if it's a new day
	if state.Date != today() {
		state.Date = today()
		state.Count = 0
	}

	return &state, nil
}

// Save writes the VT daily state atomically
func (m *VTDailyManager) Save(state *VTDailyState) error {
	state.Date = today()

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling VT daily state: %w", err)
	}

	tempPath := m.path + ".tmp"
	if err := os.WriteFile(tempPath, data, 0644); err != nil {
		return fmt.Errorf("writing temp VT daily state: %w", err)
	}

	if err := os.Rename(tempPath, m.path); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("renaming VT daily state: %w", err)
	}

	return nil
}

// Increment increases the daily VT count
func (m *VTDailyManager) Increment() error {
	state, err := m.Load()
	if err != nil {
		return err
	}
	state.Count++
	return m.Save(state)
}

// CanSubmit checks if we're within the daily limit
func (m *VTDailyManager) CanSubmit(dailyLimit int) (bool, error) {
	state, err := m.Load()
	if err != nil {
		return false, err
	}
	return state.Count < dailyLimit, nil
}

// UsagePercent returns the percentage of daily limit used
func (m *VTDailyManager) UsagePercent(dailyLimit int) (float64, error) {
	state, err := m.Load()
	if err != nil {
		return 0, err
	}
	return float64(state.Count) / float64(dailyLimit) * 100, nil
}

// CurrentCount returns the current daily count
func (m *VTDailyManager) CurrentCount() (int, error) {
	state, err := m.Load()
	if err != nil {
		return 0, err
	}
	return state.Count, nil
}

func today() string {
	return time.Now().Format("2006-01-02")
}
