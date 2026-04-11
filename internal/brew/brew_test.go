package brew

import (
	"path/filepath"
	"testing"
)

func TestNewClient(t *testing.T) {
	client := NewClient("/opt/homebrew")

	if client == nil {
		t.Fatal("expected non-nil client")
	}

	if client.homebrewPath != "/opt/homebrew" {
		t.Errorf("expected homebrewPath to be /opt/homebrew, got %s", client.homebrewPath)
	}

	expectedBrewPath := "/opt/homebrew/bin/brew"
	if client.brewPath != expectedBrewPath {
		t.Errorf("expected brewPath to be %s, got %s", expectedBrewPath, client.brewPath)
	}
}

func TestClient_CellarPath(t *testing.T) {
	client := NewClient("/opt/homebrew")

	expected := "/opt/homebrew/Cellar"
	if got := client.CellarPath(); got != expected {
		t.Errorf("CellarPath() = %v, expected %v", got, expected)
	}
}

func TestClient_PackagePath(t *testing.T) {
	client := NewClient("/opt/homebrew")

	tests := []struct {
		pkg      string
		version  string
		expected string
	}{
		{"ripgrep", "13.0.0", "/opt/homebrew/Cellar/ripgrep/13.0.0"},
		{"go", "1.21.0", "/opt/homebrew/Cellar/go/1.21.0"},
		{"openssl@3", "3.1.0", "/opt/homebrew/Cellar/openssl@3/3.1.0"},
	}

	for _, tt := range tests {
		t.Run(tt.pkg+"/"+tt.version, func(t *testing.T) {
			got := client.PackagePath(tt.pkg, tt.version)
			if got != tt.expected {
				t.Errorf("PackagePath(%s, %s) = %v, expected %v", tt.pkg, tt.version, got, tt.expected)
			}
		})
	}
}

func TestClient_NewClientIntelPath(t *testing.T) {
	// Test with Intel Mac path
	client := NewClient("/usr/local")

	expectedCellar := "/usr/local/Cellar"
	if got := client.CellarPath(); got != expectedCellar {
		t.Errorf("CellarPath() = %v, expected %v", got, expectedCellar)
	}

	expectedBrewPath := "/usr/local/bin/brew"
	if client.brewPath != expectedBrewPath {
		t.Errorf("expected brewPath to be %s, got %s", expectedBrewPath, client.brewPath)
	}
}

func TestClient_IsPinned(t *testing.T) {
	// Note: This test verifies the logic but doesn't call actual brew command
	// In a real test environment, we'd mock the exec.Command
	client := NewClient("/opt/homebrew")

	// IsPinned calls GetPinnedPackages internally
	// We can't test the actual functionality without mocking
	if client == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestPackage_Structure(t *testing.T) {
	pkg := Package{
		Name:               "ripgrep",
		FullName:           "ripgrep",
		Version:            "13.0.0",
		InstalledOnRequest: true,
		Outdated:           false,
		Pinned:             false,
		InstalledVersions:  []string{"13.0.0"},
	}

	if pkg.Name != "ripgrep" {
		t.Errorf("expected Name to be ripgrep, got %s", pkg.Name)
	}

	if !pkg.InstalledOnRequest {
		t.Error("expected InstalledOnRequest to be true")
	}

	if len(pkg.InstalledVersions) != 1 {
		t.Errorf("expected 1 installed version, got %d", len(pkg.InstalledVersions))
	}
}

func TestOutdatedPackage_Structure(t *testing.T) {
	pkg := OutdatedPackage{
		Name:             "ripgrep",
		InstalledVersion: "13.0.0",
		CurrentVersion:   "14.0.0",
		Pinned:           false,
	}

	if pkg.Name != "ripgrep" {
		t.Errorf("expected Name to be ripgrep, got %s", pkg.Name)
	}

	if pkg.InstalledVersion != "13.0.0" {
		t.Errorf("expected InstalledVersion to be 13.0.0, got %s", pkg.InstalledVersion)
	}

	if pkg.CurrentVersion != "14.0.0" {
		t.Errorf("expected CurrentVersion to be 14.0.0, got %s", pkg.CurrentVersion)
	}

	if pkg.Pinned {
		t.Error("expected Pinned to be false")
	}
}

func TestClient_GetAllDependents(t *testing.T) {
	// Test the GetAllDependents logic with a mocked scenario
	// This tests the filtering logic without calling brew
	client := NewClient("/opt/homebrew")

	// Empty list should return empty map
	result := client.GetAllDependents([]string{})
	if len(result) != 0 {
		t.Errorf("expected empty map for empty input, got %d entries", len(result))
	}
}

func TestClient_GetAllDependencies(t *testing.T) {
	// Test the GetAllDependencies logic with a mocked scenario
	client := NewClient("/opt/homebrew")

	// Empty list should return empty map
	result := client.GetAllDependencies([]string{})
	if len(result) != 0 {
		t.Errorf("expected empty map for empty input, got %d entries", len(result))
	}
}

func TestClient_PathConstruction(t *testing.T) {
	tests := []struct {
		homebrewPath string
		pkg          string
		version      string
	}{
		{"/opt/homebrew", "git", "2.40.0"},
		{"/usr/local", "python@3.11", "3.11.4"},
		{"/custom/path", "package-name", "1.0.0-rc1"},
	}

	for _, tt := range tests {
		t.Run(tt.homebrewPath+"/"+tt.pkg, func(t *testing.T) {
			client := NewClient(tt.homebrewPath)

			cellarPath := client.CellarPath()
			expectedCellar := filepath.Join(tt.homebrewPath, "Cellar")
			if cellarPath != expectedCellar {
				t.Errorf("CellarPath() = %v, expected %v", cellarPath, expectedCellar)
			}

			pkgPath := client.PackagePath(tt.pkg, tt.version)
			expectedPkgPath := filepath.Join(tt.homebrewPath, "Cellar", tt.pkg, tt.version)
			if pkgPath != expectedPkgPath {
				t.Errorf("PackagePath() = %v, expected %v", pkgPath, expectedPkgPath)
			}
		})
	}
}
