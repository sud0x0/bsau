package brew

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/sud0x0/bsau/internal/llm"
)

const (
	// HomebrewAPIBaseURL is the base URL for Homebrew's formula API
	HomebrewAPIBaseURL = "https://formulae.brew.sh/api/formula"

	// GitHubAPIBaseURL is the base URL for GitHub API
	GitHubAPIBaseURL = "https://api.github.com/repos/Homebrew/homebrew-core"

	// GitHubRawBaseURL is the base URL for raw file content
	GitHubRawBaseURL = "https://raw.githubusercontent.com/Homebrew/homebrew-core"

	// GitHubRateLimit is the minimum interval between GitHub API calls (60/hour = 1/min, but we use 1.5s for safety)
	GitHubRateLimit = 1500 * time.Millisecond
)

// GitHubFetcher handles fetching formula content from GitHub when local files aren't available
type GitHubFetcher struct {
	httpClient  *http.Client
	lastAPICall time.Time
	rateLimitMu sync.Mutex
}

// NewGitHubFetcher creates a new GitHub fetcher
func NewGitHubFetcher() *GitHubFetcher {
	return &GitHubFetcher{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// HomebrewFormulaInfo represents the response from Homebrew's formula API
type HomebrewFormulaInfo struct {
	Name           string `json:"name"`
	RubySourcePath string `json:"ruby_source_path"`
}

// GitHubCommit represents a commit from GitHub API
type GitHubCommit struct {
	SHA string `json:"sha"`
}

// waitForRateLimit ensures we don't exceed GitHub's rate limit
func (g *GitHubFetcher) waitForRateLimit() {
	g.rateLimitMu.Lock()
	defer g.rateLimitMu.Unlock()

	elapsed := time.Since(g.lastAPICall)
	if elapsed < GitHubRateLimit {
		time.Sleep(GitHubRateLimit - elapsed)
	}
	g.lastAPICall = time.Now()
}

// GetFormulaPath fetches the ruby_source_path from Homebrew's API
func (g *GitHubFetcher) GetFormulaPath(pkg string) (string, error) {
	url := fmt.Sprintf("%s/%s.json", HomebrewAPIBaseURL, pkg)

	resp, err := g.httpClient.Get(url)
	if err != nil {
		return "", fmt.Errorf("fetching formula info: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("formula not found: %s", pkg)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var info HomebrewFormulaInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return "", fmt.Errorf("decoding formula info: %w", err)
	}

	if info.RubySourcePath == "" {
		return "", fmt.Errorf("ruby_source_path not found for %s", pkg)
	}

	return info.RubySourcePath, nil
}

// GetCommitHistory fetches the last N commits that touched a formula file
func (g *GitHubFetcher) GetCommitHistory(rubySourcePath string, count int) ([]string, error) {
	g.waitForRateLimit()

	url := fmt.Sprintf("%s/commits?path=%s&per_page=%d", GitHubAPIBaseURL, rubySourcePath, count)

	resp, err := g.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetching commit history: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API error (status %d): %s", resp.StatusCode, string(body))
	}

	var commits []GitHubCommit
	if err := json.NewDecoder(resp.Body).Decode(&commits); err != nil {
		return nil, fmt.Errorf("decoding commit history: %w", err)
	}

	shas := make([]string, 0, len(commits))
	for _, c := range commits {
		shas = append(shas, c.SHA)
	}

	return shas, nil
}

// GetFormulaContent fetches the formula content at a specific commit (or HEAD if sha is empty)
func (g *GitHubFetcher) GetFormulaContent(rubySourcePath, sha string) (string, error) {
	ref := "main"
	if sha != "" {
		ref = sha
	}

	url := fmt.Sprintf("%s/%s/%s", GitHubRawBaseURL, ref, rubySourcePath)

	resp, err := g.httpClient.Get(url)
	if err != nil {
		return "", fmt.Errorf("fetching formula content: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("formula not found at ref %s", ref)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading formula content: %w", err)
	}

	return string(content), nil
}

// GetFormulaVersions fetches the last 2 versions of a formula from GitHub (CURRENT and PREVIOUS)
func (g *GitHubFetcher) GetFormulaVersions(pkg string) ([]llm.FormulaVersion, error) {
	// Get the ruby_source_path from Homebrew API
	rubySourcePath, err := g.GetFormulaPath(pkg)
	if err != nil {
		return nil, err
	}

	// Get the last 2 commits that touched this formula
	shas, err := g.GetCommitHistory(rubySourcePath, 2)
	if err != nil {
		// If we can't get commit history, try to get current version
		content, contentErr := g.GetFormulaContent(rubySourcePath, "")
		if contentErr != nil {
			return nil, fmt.Errorf("getting formula versions: %w (commit history: %v)", contentErr, err)
		}
		return []llm.FormulaVersion{{
			Label:   "CURRENT",
			Content: content,
		}}, nil
	}

	if len(shas) == 0 {
		// No commits found, try current version
		content, err := g.GetFormulaContent(rubySourcePath, "")
		if err != nil {
			return nil, err
		}
		return []llm.FormulaVersion{{
			Label:   "CURRENT",
			Content: content,
		}}, nil
	}

	labels := []string{"CURRENT", "PREVIOUS"}
	versions := make([]llm.FormulaVersion, 0, len(shas))

	for i, sha := range shas {
		if i >= 2 {
			break
		}

		content, err := g.GetFormulaContent(rubySourcePath, sha)
		if err != nil {
			continue
		}

		versions = append(versions, llm.FormulaVersion{
			Label:   labels[i],
			SHA:     sha[:7], // Short SHA for display
			Content: content,
		})
	}

	if len(versions) == 0 {
		return nil, fmt.Errorf("no formula versions found for %s", pkg)
	}

	return versions, nil
}
