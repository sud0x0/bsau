package brew

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/sud0x0/bsau/internal/ollama"
)

// Package represents a Homebrew package
type Package struct {
	Name               string   `json:"name"`
	FullName           string   `json:"full_name"`
	Version            string   `json:"version"`
	InstalledOnRequest bool     `json:"installed_on_request"`
	Outdated           bool     `json:"outdated"`
	Pinned             bool     `json:"pinned"`
	InstalledVersions  []string `json:"installed_versions"`
	SourceURL          string   `json:"source_url,omitempty"` // URL from urls.stable.url for ecosystem detection
}

// OutdatedPackage represents an outdated package with update info
type OutdatedPackage struct {
	Name             string `json:"name"`
	InstalledVersion string `json:"installed_version"`
	CurrentVersion   string `json:"current_version"`
	Pinned           bool   `json:"pinned"`
}

// Client provides Homebrew interaction methods
type Client struct {
	homebrewPath  string
	brewPath      string
	repoPath      string
	githubFetcher *GitHubFetcher
}

// NewClient creates a new Homebrew client
func NewClient(homebrewPath string) *Client {
	brewPath := filepath.Join(homebrewPath, "bin", "brew")
	return &Client{
		homebrewPath:  homebrewPath,
		brewPath:      brewPath,
		githubFetcher: NewGitHubFetcher(),
	}
}

// GetRepository returns the Homebrew repository path
func (c *Client) GetRepository() (string, error) {
	if c.repoPath != "" {
		return c.repoPath, nil
	}

	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd := exec.Command(c.brewPath, "--repository")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("getting brew repository: %w", err)
	}

	c.repoPath = strings.TrimSpace(string(output))
	return c.repoPath, nil
}

// GetFormulaPath returns the path to a formula file
func (c *Client) GetFormulaPath(pkg string) (string, error) {
	repo, err := c.GetRepository()
	if err != nil {
		return "", err
	}

	// Formula location: Library/Taps/homebrew/homebrew-core/Formula/<prefix>/<name>.rb
	// Prefix is usually first letter, but packages starting with "lib" use "lib" as prefix
	prefix := strings.ToLower(pkg[:1])
	if strings.HasPrefix(strings.ToLower(pkg), "lib") && len(pkg) > 3 {
		prefix = "lib"
	}

	formulaPath := filepath.Join(repo, "Library", "Taps", "homebrew", "homebrew-core",
		"Formula", prefix, pkg+".rb")

	if _, err := os.Stat(formulaPath); os.IsNotExist(err) {
		// Try alternate locations including first letter if lib prefix didn't work
		altPaths := []string{
			filepath.Join(repo, "Library", "Taps", "homebrew", "homebrew-core", "Formula", strings.ToLower(pkg[:1]), pkg+".rb"),
			filepath.Join(repo, "Library", "Taps", "homebrew", "homebrew-core", "Formula", pkg+".rb"),
			filepath.Join(repo, "Library", "Formula", pkg+".rb"),
		}
		for _, alt := range altPaths {
			if _, err := os.Stat(alt); err == nil {
				return alt, nil
			}
		}
		return "", fmt.Errorf("formula not found for %s", pkg)
	}

	return formulaPath, nil
}

// GetFormulaVersions retrieves the last 2 versions of a formula from git history (CURRENT and PREVIOUS)
// Falls back to GitHub API if local homebrew-core tap is not available
func (c *Client) GetFormulaVersions(pkg string) ([]ollama.FormulaVersion, error) {
	formulaPath, err := c.GetFormulaPath(pkg)
	if err != nil {
		// Local formula not found - try GitHub fallback
		if c.githubFetcher != nil {
			return c.githubFetcher.GetFormulaVersions(pkg)
		}
		return nil, err
	}

	repo, err := c.GetRepository()
	if err != nil {
		return nil, err
	}

	// Get the homebrew-core tap directory
	tapDir := filepath.Join(repo, "Library", "Taps", "homebrew", "homebrew-core")

	// Check if tap directory exists (API-only mode won't have it)
	if _, err := os.Stat(tapDir); os.IsNotExist(err) {
		// Tap not cloned - use GitHub fallback
		if c.githubFetcher != nil {
			return c.githubFetcher.GetFormulaVersions(pkg)
		}
		return nil, fmt.Errorf("homebrew-core tap not available and GitHub fallback disabled")
	}

	// Get relative path within the tap
	relPath, err := filepath.Rel(tapDir, formulaPath)
	if err != nil {
		return nil, fmt.Errorf("getting relative path: %w", err)
	}

	// Get last 2 commits that touched this formula (CURRENT and PREVIOUS)
	cmd := exec.Command("git", "-C", tapDir, "log", "--oneline", "-2", "--", relPath)
	output, err := cmd.Output()
	if err != nil {
		// If git history not available, just read current version
		content, err := os.ReadFile(formulaPath)
		if err != nil {
			return nil, fmt.Errorf("reading formula: %w", err)
		}
		return []ollama.FormulaVersion{{
			Label:   "CURRENT",
			Content: string(content),
		}}, nil
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) == 0 {
		content, err := os.ReadFile(formulaPath)
		if err != nil {
			return nil, fmt.Errorf("reading formula: %w", err)
		}
		return []ollama.FormulaVersion{{
			Label:   "CURRENT",
			Content: string(content),
		}}, nil
	}

	labels := []string{"CURRENT", "PREVIOUS"}
	versions := make([]ollama.FormulaVersion, 0, len(lines))

	for i, line := range lines {
		if i >= 2 {
			break
		}

		parts := strings.SplitN(line, " ", 2)
		sha := parts[0]

		// Get file content at this commit
		cmd := exec.Command("git", "-C", tapDir, "show", sha+":"+relPath)
		content, err := cmd.Output()
		if err != nil {
			continue
		}

		versions = append(versions, ollama.FormulaVersion{
			Label:   labels[i],
			SHA:     sha,
			Content: string(content),
		})
	}

	if len(versions) == 0 {
		// Fallback to current file
		content, err := os.ReadFile(formulaPath)
		if err != nil {
			return nil, fmt.Errorf("reading formula: %w", err)
		}
		return []ollama.FormulaVersion{{
			Label:   "CURRENT",
			Content: string(content),
		}}, nil
	}

	return versions, nil
}

// ListPackages returns all installed Homebrew packages
func (c *Client) ListPackages() ([]Package, error) {
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd := exec.Command(c.brewPath, "info", "--json", "--installed")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("running brew list: %w", err)
	}

	var formulae []struct {
		Name     string `json:"name"`
		FullName string `json:"full_name"`
		Versions struct {
			Stable string `json:"stable"`
		} `json:"versions"`
		URLs struct {
			Stable struct {
				URL string `json:"url"`
			} `json:"stable"`
		} `json:"urls"`
		Installed []struct {
			Version            string `json:"version"`
			InstalledOnRequest bool   `json:"installed_on_request"`
		} `json:"installed"`
	}

	if err := json.Unmarshal(output, &formulae); err != nil {
		return nil, fmt.Errorf("parsing brew info output: %w", err)
	}

	packages := make([]Package, 0, len(formulae))
	for _, f := range formulae {
		version := ""
		installedOnRequest := false
		installedVersions := make([]string, 0)
		for _, inst := range f.Installed {
			installedVersions = append(installedVersions, inst.Version)
			if version == "" {
				version = inst.Version
				installedOnRequest = inst.InstalledOnRequest
			}
		}

		packages = append(packages, Package{
			Name:               f.Name,
			FullName:           f.FullName,
			Version:            version,
			InstalledOnRequest: installedOnRequest,
			InstalledVersions:  installedVersions,
			SourceURL:          f.URLs.Stable.URL,
		})
	}

	return packages, nil
}

// GetOutdated returns all outdated packages
func (c *Client) GetOutdated() ([]OutdatedPackage, error) {
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd := exec.Command(c.brewPath, "outdated", "--json")
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && len(output) > 0 {
			_ = exitErr
		} else if len(output) == 0 {
			return []OutdatedPackage{}, nil
		} else {
			return nil, fmt.Errorf("running brew outdated: %w", err)
		}
	}

	var result struct {
		Formulae []struct {
			Name              string   `json:"name"`
			InstalledVersions []string `json:"installed_versions"`
			CurrentVersion    string   `json:"current_version"`
			Pinned            bool     `json:"pinned"`
		} `json:"formulae"`
	}

	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("parsing brew outdated output: %w", err)
	}

	packages := make([]OutdatedPackage, 0, len(result.Formulae))
	for _, f := range result.Formulae {
		installed := ""
		if len(f.InstalledVersions) > 0 {
			installed = f.InstalledVersions[0]
		}
		packages = append(packages, OutdatedPackage{
			Name:             f.Name,
			InstalledVersion: installed,
			CurrentVersion:   f.CurrentVersion,
			Pinned:           f.Pinned,
		})
	}

	return packages, nil
}

// GetPinnedPackages returns the list of pinned packages
func (c *Client) GetPinnedPackages() ([]string, error) {
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd := exec.Command(c.brewPath, "list", "--pinned")
	output, err := cmd.Output()
	if err != nil {
		return []string{}, nil
	}

	pinned := []string{}
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			pinned = append(pinned, line)
		}
	}

	return pinned, nil
}

// IsPinned checks if a specific package is pinned
func (c *Client) IsPinned(pkg string) (bool, error) {
	pinned, err := c.GetPinnedPackages()
	if err != nil {
		return false, err
	}

	for _, p := range pinned {
		if p == pkg {
			return true, nil
		}
	}
	return false, nil
}

// Upgrade upgrades a single package with stdio passthrough
func (c *Client) Upgrade(pkg string) error {
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd := exec.Command(c.brewPath, "upgrade", pkg)
	// Wire stdio directly to terminal for interactive prompts
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Prevent brew from upgrading dependents automatically
	// User should explicitly select each package they want to upgrade
	cmd.Env = append(os.Environ(),
		"HOMEBREW_NO_INSTALLED_DEPENDENTS_CHECK=1",
	)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("upgrading %s: %w", pkg, err)
	}

	return nil
}

// Info returns detailed information about a package
func (c *Client) Info(pkg string) (*Package, error) {
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd := exec.Command(c.brewPath, "info", "--json=v2", pkg)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("getting info for %s: %w", pkg, err)
	}

	var result struct {
		Formulae []struct {
			Name     string `json:"name"`
			FullName string `json:"full_name"`
			Versions struct {
				Stable string `json:"stable"`
			} `json:"versions"`
			URLs struct {
				Stable struct {
					URL string `json:"url"`
				} `json:"stable"`
			} `json:"urls"`
			Installed []struct {
				Version string `json:"version"`
			} `json:"installed"`
			Pinned bool `json:"pinned"`
		} `json:"formulae"`
	}

	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("parsing brew info output: %w", err)
	}

	if len(result.Formulae) == 0 {
		return nil, fmt.Errorf("package %s not found", pkg)
	}

	f := result.Formulae[0]
	version := ""
	installedVersions := make([]string, 0)
	for _, inst := range f.Installed {
		installedVersions = append(installedVersions, inst.Version)
		if version == "" {
			version = inst.Version
		}
	}

	return &Package{
		Name:              f.Name,
		FullName:          f.FullName,
		Version:           version,
		Pinned:            f.Pinned,
		InstalledVersions: installedVersions,
		SourceURL:         f.URLs.Stable.URL,
	}, nil
}

// CellarPath returns the path to the Homebrew Cellar
func (c *Client) CellarPath() string {
	return filepath.Join(c.homebrewPath, "Cellar")
}

// GetDependents returns packages that depend on the given package (reverse dependencies)
// These are packages that would need to be upgraded if the given package is upgraded
func (c *Client) GetDependents(pkg string) ([]string, error) {
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd := exec.Command(c.brewPath, "uses", "--installed", pkg)
	output, err := cmd.Output()
	if err != nil {
		// No dependents is not an error
		return []string{}, nil
	}

	dependents := []string{}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			dependents = append(dependents, line)
		}
	}
	return dependents, nil
}

// GetAllDependents returns a map of package -> list of packages that depend on it
// Only includes packages from the given list that are also outdated
func (c *Client) GetAllDependents(outdatedPkgs []string) map[string][]string {
	outdatedSet := make(map[string]bool)
	for _, pkg := range outdatedPkgs {
		outdatedSet[pkg] = true
	}

	result := make(map[string][]string)
	for _, pkg := range outdatedPkgs {
		dependents, err := c.GetDependents(pkg)
		if err != nil {
			continue
		}
		// Only include dependents that are also in the outdated list
		outdatedDependents := []string{}
		for _, dep := range dependents {
			if outdatedSet[dep] {
				outdatedDependents = append(outdatedDependents, dep)
			}
		}
		if len(outdatedDependents) > 0 {
			result[pkg] = outdatedDependents
		}
	}
	return result
}

// GetDependencies returns packages that the given package depends on (forward dependencies)
// These are packages that must be present for the given package to work
func (c *Client) GetDependencies(pkg string) ([]string, error) {
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd := exec.Command(c.brewPath, "deps", "--installed", pkg)
	output, err := cmd.Output()
	if err != nil {
		// No dependencies is not an error
		return []string{}, nil
	}

	dependencies := []string{}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			dependencies = append(dependencies, line)
		}
	}
	return dependencies, nil
}

// GetAllDependencies returns a map of package -> list of packages it depends on
// Only includes dependencies from the given list that are also outdated
func (c *Client) GetAllDependencies(outdatedPkgs []string) map[string][]string {
	outdatedSet := make(map[string]bool)
	for _, pkg := range outdatedPkgs {
		outdatedSet[pkg] = true
	}

	result := make(map[string][]string)
	for _, pkg := range outdatedPkgs {
		deps, err := c.GetDependencies(pkg)
		if err != nil {
			continue
		}
		// Only include dependencies that are also in the outdated list
		outdatedDeps := []string{}
		for _, dep := range deps {
			if outdatedSet[dep] {
				outdatedDeps = append(outdatedDeps, dep)
			}
		}
		if len(outdatedDeps) > 0 {
			result[pkg] = outdatedDeps
		}
	}
	return result
}

// PackagePath returns the full path to a package version in the Cellar
func (c *Client) PackagePath(pkg, version string) string {
	return filepath.Join(c.CellarPath(), pkg, version)
}

// Cleanup runs brew cleanup to remove old versions and free disk space
func (c *Client) Cleanup() error {
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd := exec.Command(c.brewPath, "cleanup")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("running brew cleanup: %w", err)
	}

	return nil
}
