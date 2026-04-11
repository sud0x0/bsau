# bsau

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)](https://go.dev/)
[![macOS](https://img.shields.io/badge/macOS-compatible-000000?logo=apple)](https://www.apple.com/macos/)

> **Note:** This project is currently in active development and testing. If you encounter any issues or have suggestions, please [open an issue](https://github.com/sud0x0/bsau/issues)

bsau (Brew Scan and Update) is a security-focused Homebrew package manager wrapper written in Go.

It helps protect your macOS environment from **known security vulnerabilities** and **supply chain attacks** by:

- **Identifying vulnerable packages** - Scans for known CVEs before and after upgrades
- **Identifying malicious packages** - Detects malicious code patterns, suspicious binaries, and tampered files

bsau performs multiple layers of security analysis before and after every upgrade, ensuring you don't blindly trust package updates.

## Table of Contents

- [Summary](#summary)
  - [Key Features](#key-features)
  - [Workflow (7 Steps)](#workflow-7-steps)
  - [Limitations](#limitations)
- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Option 1: Download from Releases](#option-1-download-from-releases)
  - [Option 2: Build from Source](#option-2-build-from-source)
- [Usage](#usage)
  - [Quick Start](#quick-start)
  - [Commands](#commands)
  - [Configuration](#configuration)
  - [API Usage Management](#api-usage-management)
- [Detailed Information](#detailed-information)
- [Development Setup](#development-setup)
  - [Prerequisites](#prerequisites-1)
  - [Setup Steps](#setup-steps)
  - [Available Make Targets](#available-make-targets)
---

# Summary

## Key Features

1. Vulnerability Scanning - Uses embedded package mappings with dual-API approach:
   - **OSV.dev queries** for packages with known ecosystem mappings (PyPI, npm, Go, crates.io, etc.)
   - **NIST NVD queries** for packages with CPE identifiers (covers packages not in OSV ecosystems)
2. Hash Verification - Local bloom filter (~700MB) for fast lookups against NSRL and trusted sources
3. Static Analysis - Semgrep scans with supply-chain, secrets, and malicious-code rule sets
4. LLM Analysis - Claude API analyzes formula files and code diffs for suspicious patterns

## Workflow (7 Steps)

1. Audit - Identify outdated packages, check OSV for vulnerabilities
2. Select - Interactive package selector with dependency awareness
3. Pre-install scan - Claude analyzes formula history (current + 2 prior versions)
4. Approval gate - User approves/blocks packages based on scan results
5. Upgrade - Snapshot text files, run brew upgrade with stdio passthrough
6. Post-install verification - Bloom filter hash check, Semgrep + Claude on diffs
7. Cleanup - Remove temp files, run brew cleanup

## Limitations

1. **Binary-only casks**: Closed-source GUI applications have no formula source to analyze. Claude analysis is not meaningful for these - only CIRCL/VT hash checks provide signal.
2. **OSV coverage**: bsau uses embedded package mappings (~8,400 packages) to query OSV.dev and NIST NVD. `N/A` means no mapping exists for that package. Most common Homebrew packages are covered.
3. **Bloom filter coverage**: The bloom filter (~700MB, stored next to the bsau binary) contains ~298 million SHA-1 hashes from NSRL and trusted sources. A file marked "KNOWN" means it exists in these databases (likely safe). "UNKNOWN" means no record - not necessarily malicious, just not in the database. Use `--circl-full` for detailed API lookups on specific packages.
4. **Semgrep pattern matching**: Semgrep detects known malicious patterns (`p/supply-chain`, `p/secrets`, `p/malicious-code`). Novel or heavily obfuscated attacks may evade signature-based detection.
5. **Claude context window**: Large formula files are truncated at `claude_max_file_bytes` (default 12KB). Truncation is noted in findings but malicious code beyond the limit won't be analyzed.
6. **VirusTotal daily limit**: Free tier allows 500 lookups/day. VT is only called for CIRCL-flagged malicious hashes, so limits are rarely hit on clean machines.
7. **Snapshot disk usage**: Pre-upgrade snapshots of text files may consume significant `/tmp` space for large packages. bsau warns when space is low and skips snapshots if critically low.
8. **No transitive dependency scanning**: Only Homebrew-level packages are scanned, not runtime dependencies (e.g., Python packages inside a formula's venv).
9. **macOS only**: bsau is designed for Homebrew on macOS. It will not work on Linux Homebrew installations.
10. **LLM limitations**: Claude analysis may produce false positives or miss sophisticated attacks. It's a supplementary signal, not a guarantee.

# Installation

## Prerequisites

**Required:**
- macOS (Apple Silicon or Intel)
- [Homebrew](https://brew.sh/) installed

**Optional (for full functionality):**

- [Semgrep](https://semgrep.dev/docs/getting-started/quickstart) - for static analysis scans
- [Anthropic API Key](https://console.anthropic.com/) - for Claude formula/code analysis
- [VirusTotal API Key](https://www.virustotal.com/) - for hash verification fallback (free tier)

> **Note:** bsau works without optional dependencies. CIRCL hash lookup and OSV vulnerability scanning require no API keys and are always active.

## Option 1: Download from Releases

Download the latest pre-built binary from the [Releases](https://github.com/sud0x0/bsau/releases) page:

```bash
# Download the latest release (replace VERSION with actual version)
curl -LO https://github.com/sud0x0/bsau/releases/download/VERSION/bsau-darwin-arm64.tar.gz

# Extract
tar -xzf bsau-darwin-arm64.tar.gz

# Move to PATH
sudo mv bsau /usr/local/bin/

# Verify installation
bsau version
```

## Option 2: Build from Source

```bash
# Clone the repository
git clone https://github.com/sud0x0/bsau.git
cd bsau

# Build
make build

# Run from build directory
./_BUILD_/bsau version

# Or copy to PATH manually
sudo cp _BUILD_/bsau /usr/local/bin/
```

# Usage

## Quick Start

```bash
# Run the full scan and update workflow
bsau run

# Scan current installation without upgrading
bsau inspect

# Dry run - scan but don't upgrade
bsau run --dry-run
```

## Commands

| Command | Description |
|---------|-------------|
| `bsau run` | Full scan and update workflow |
| `bsau run --dry-run` | Run scans, show results, skip upgrades |
| `bsau run --no-circl` | Skip CIRCL bloom filter hash verification |
| `bsau run --no-claude` | Skip Claude analysis for this run |
| `bsau run --no-vt` | Skip VirusTotal fallback for this run |
| `bsau inspect` | Scan current installation (no upgrade) |
| `bsau inspect <package>` | Scan a specific package only |
| `bsau inspect --circl` | Fast bloom filter hash lookup (~700MB local) |
| `bsau inspect --circl-full <package>` | Full CIRCL API lookup for all files in package |
| `bsau inspect --circl-full <file>` | Full CIRCL API lookup for a single file |
| `bsau inspect --semgrep` | Semgrep scan only |
| `bsau inspect --claude` | Semgrep + Claude analysis |
| `bsau init` | Generate default config file in binary directory |
| `bsau update-bloom` | Download or update the CIRCL bloom filter |
| `bsau update-bloom --force` | Force re-download bloom filter |
| `bsau version` | Show version info |

> **Note**: The bloom filter is downloaded on first use (~700MB). It contains SHA-1 hashes from NSRL and trusted sources, updated monthly by CIRCL. bsau automatically checks for updates via ETag comparison and prompts when a newer version is available. Use `--circl-full` for detailed per-hash API lookups when investigating specific packages or individual files.

> **CTRL+C Handling**: During upgrades or scans, pressing CTRL+C will prompt you to confirm before exiting. This prevents accidental interruption that could leave temp files behind. If you confirm exit, bsau cleans up gracefully.

## Configuration

Generate a default config file in the same directory as the bsau binary:

```bash
bsau init
```

This creates `settings.yaml` next to the binary (e.g., `/usr/local/bin/settings.yaml`). Edit it to enable features:

```yaml
# Enable Claude formula analysis (requires ANTHROPIC_API_KEY)
features:
  claude_scan: true
  vt_fallback: false

# Claude model to use
claude_model: claude-sonnet-4-6
```

Set API keys via environment variables:

```bash
export ANTHROPIC_API_KEY="your-key"      # Required if claude_scan: true
export VIRUSTOTAL_API_KEY="your-key"     # Required if vt_fallback: true
```

**File Locations**: Both `settings.yaml` and the bloom filter (`hashlookup-full.bloom`) are stored in the same directory as the bsau binary. This makes the tool self-contained and easy to move.

## API Usage Management

bsau provides transparency and control over API usage before any tokens are consumed.

### Quota Display

Before scanning, bsau shows your current API quota for Claude (requests/tokens remaining) and VirusTotal (daily requests remaining). Color coding indicates quota health: green (>50%), yellow (20-50%), red (<20%).

### Token Estimation & Confirmation

Before each API step, bsau estimates tokens required and asks for confirmation. You can proceed or skip (marking packages as `REVIEW` for manual inspection).

### Interactive Scan Selection

When quota is limited, an interactive selector lets you choose which packages to scan. A progress bar shows token usage in real-time.

### Insufficient Quota

If quota is insufficient, you can:
1. **Partial scan** - scan what quota allows, mark rest as `REVIEW`
2. **Skip API scans** - mark all as `REVIEW`
3. **Cancel**

### Tips

- Use `--dry-run` to preview token usage without consuming any
- Large packages (ffmpeg, chromium) use more tokens - consider scanning separately
- VirusTotal is only called for CIRCL-flagged malicious hashes (typically 0 on clean systems)

# Detailed Information

## Step 1: Audit Current State

- Reads all installed packages via `brew list --json=v2`
- Identifies outdated packages via `brew outdated --json`
- Detects pinned packages via `brew list --pinned` (bsau never upgrades pinned packages)
- Scans for vulnerabilities using embedded package mappings (~8,400 packages):
  - **OSV.dev queries**: For packages with ecosystem mappings (PyPI, npm, Go, crates.io, RubyGems, Hackage, etc.)
  - **NIST NVD queries**: For packages with CPE identifiers (covers packages not in OSV ecosystems)
- Stores results in run-scoped temporary state (`/tmp/bsau-<run-id>/`)

## Step 2: Package Selection

- Displays a table showing: Package, Current Version, Available Version, Pinned Status, CVE Count, Severity
- Warns about pinned packages with known CVEs (but does not offer to update them)
- Interactive selector allows choosing which packages to update
- Dependency awareness: shows which packages depend on each other

## Step 3: Pre-install Security Scan

**Claude Formula Analysis** *(if enabled)*
- Retrieves the formula file from the local Homebrew tap
- Uses git history to get current + 2 previous versions of the formula
- Sends all versions to Claude API for analysis, focusing on what changed
- Looks for: suspicious URLs, shell hooks, obfuscated commands, credential harvesting, persistence mechanisms
- Returns verdict: `SAFE`, `REVIEW`, or `HOLD`

## Step 4: Per-Package Approval Gate

- Displays combined scan results in a table
- `HOLD` verdict → package blocked (requires manual override)
- `REVIEW` verdict → per-package confirmation prompt
- `SAFE` verdict → queued for upgrade
- User gives final approval before any `brew upgrade` runs

## Step 5: Upgrade

- Prints the run directory path for manual cleanup if needed
- Checks available `/tmp` disk space before snapshotting
- Snapshots all text-readable files from current Cellar version
- Runs `brew upgrade <package>` one at a time (never batched)
- Passes stdio directly to terminal for interactive prompts (sudo, Gatekeeper, etc.)
- On failure: deletes snapshot, stops processing

## Step 6: Post-install Verification

**6a. Hash Verification**
- Hashes all files in the newly installed package
- Checks each hash against CIRCL hashlookup (free, no API key)
- If CIRCL flags as malicious and VT is enabled, confirms with VirusTotal
- `VT_CONFIRMED` → warns user, suggests `brew uninstall`

**6b. Semgrep Scan**
- Updates Semgrep rules before scanning
- Runs with `p/supply-chain`, `p/secrets`, `p/malicious-code` rule sets
- Parses JSON output for flagged files and line numbers

**6c. Diff Generation**
- Generates unified diff between pre-upgrade snapshot and new install
- Only text-readable files are diffed; binaries noted as changed

**6d. Claude Code Analysis** *(if enabled)*
- Sends the diff + Semgrep findings to Claude API
- Analyzes for malicious patterns introduced in the new version
- Returns verdict: `SAFE`, `REVIEW`, or `HOLD`
- `HOLD` → warns user, suggests `brew uninstall`

**6e. Snapshot Cleanup**
- Deletes snapshot directory after analysis completes

## Step 7: Cleanup

- Re-runs vulnerability scan on updated packages
- Displays before/after CVE summary
- Shows post-update security summary table
- Removes temporary run directory (`/tmp/bsau-<run-id>/`)
- Runs `brew cleanup` to remove old versions

# Development Setup

## Prerequisites

- Go 1.21+
- Homebrew (macOS)
- [pre-commit](https://pre-commit.com/)
- [golangci-lint](https://golangci-lint.run/)
- [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck)
- [Semgrep](https://semgrep.dev/) (optional, for security scans)

## Setup Steps

1. **Clone the repository**
   ```bash
   git clone https://github.com/sud0x0/bsau.git
   cd bsau
   ```

2. **Install Go dependencies**
   ```bash
   go mod download
   ```

3. **Install development tools**
   ```bash
   # Install golangci-lint
   brew install golangci-lint

   # Install govulncheck
   go install golang.org/x/vuln/cmd/govulncheck@latest

   # Install pre-commit
   brew install pre-commit

   # Install semgrep (optional)
   brew install semgrep
   ```

4. **Install pre-commit hooks**
   ```bash
   pre-commit install
   ```

   This activates the following hooks that run automatically on every commit:
   - `trailing-whitespace`, `end-of-file-fixer`, `check-yaml` - Basic file hygiene
   - `gitleaks` - Secrets detection (prevents committing API keys)
   - `gofmt` - Go code formatting
   - `golangci-lint` - Go linting (same as `make lint`)
   - `govulncheck` - Go vulnerability scanning
   - `semgrep` - Security pattern scanning

5. **Build the binary**
   ```bash
   make build
   ```

6. **Verify the build**
   ```bash
   ./bsau version
   ```

## Available Make Targets

```bash
make help          # Show all available targets
make build         # Build the binary
make lint          # Run golangci-lint
make fmt           # Format all Go files
make vet           # Run go vet
make vulncheck     # Run govulncheck
make semgrep       # Run semgrep security scan
make pre-commit-run # Run all pre-commit hooks manually
```

## Configuration

Copy `settings.yaml` and configure as needed. API keys are set via environment variables:

```bash
export ANTHROPIC_API_KEY="your-key"      # Required if claude_scan: true
export VIRUSTOTAL_API_KEY="your-key"     # Required if vt_fallback: true
```

# TODO

- Use macOS Keychain for API key storage instead of environment variables
- Use a FOSS LLM instead of Claude API.
