# bsau

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)](https://go.dev/)
[![macOS](https://img.shields.io/badge/macOS-compatible-000000?logo=apple)](https://www.apple.com/macos/)

> **Note:** This project is currently in active development and testing. If you encounter any issues or have suggestions, please [open an issue](https://github.com/sud0x0/bsau/issues)

bsau (Brew Scan and Update) is a security-focused Homebrew package manager wrapper written in Go. It uses a local LLM (via [Ollama](https://ollama.ai/)) for code analysis.

It helps protect your macOS environment from **known security vulnerabilities** and **supply chain attacks** by:

- **Identifying vulnerable packages** - Scans for known CVEs before and after upgrades
- **Identifying malicious packages** - Detects malicious code patterns and suspicious changes

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
- [Detailed Information](#detailed-information)
- [Development Setup](#development-setup)
  - [Prerequisites](#prerequisites-1)
  - [Setup Steps](#setup-steps)
  - [Available Make Targets](#available-make-targets)
---

# Summary

## Key Features

1. **Vulnerability Scanning** - Uses OSV.dev and NIST NVD for comprehensive CVE detection
2. **Static Analysis** - Semgrep scans with supply-chain, secrets, and malicious-code rule sets
3. **Local LLM Analysis** - Analyzes formula files and code diffs for suspicious patterns

## Workflow (7 Steps)

1. **Audit** - Identify outdated packages, check OSV for vulnerabilities
2. **Select** - Interactive package selector with dependency awareness
3. **Pre-install scan** - Local LLM analyzes formula history (current + 2 prior versions)
4. **Approval gate** - User approves/blocks packages based on scan results
5. **Upgrade** - Snapshot text files, run brew upgrade with stdio passthrough
6. **Post-install verification** - Semgrep + local LLM on diffs
7. **Cleanup** - Remove temp files, run brew cleanup

## Limitations

1. **No static binary scanning**: bsau does not perform static analysis or hash verification on compiled binaries. Semgrep and local LLM analyse source/script files only. Compiled executables, libraries, and object files are not scanned for malware signatures or suspicious patterns.
2. **Binary-only casks**: Closed-source GUI applications have no formula source to analyze. Local LLM analysis is not meaningful for these.
3. **OSV coverage**: bsau uses embedded package mappings to query OSV.dev and NIST NVD. `N/A` means no mapping exists for that package.
4. **Semgrep pattern matching**: Semgrep detects known malicious patterns (`p/supply-chain`, `p/secrets`, `p/malicious-code`). Novel or heavily obfuscated attacks may evade signature-based detection.
5. **LLM context window**: Large formula files are truncated at `ollama_max_file_bytes` (default 12KB). Truncation is noted in findings but malicious code beyond the limit won't be analyzed.
6. **Snapshot disk usage**: Pre-upgrade snapshots of text files may consume significant `/tmp` space for large packages. bsau warns when space is low and skips snapshots if critically low.
7. **No transitive dependency scanning**: Only Homebrew-level packages are scanned, not runtime dependencies (e.g., Python packages inside a formula's venv).
8. **macOS only**: bsau is designed for Homebrew on macOS. It will not work on Linux Homebrew installations.
9. **LLM limitations**: Local LLM analysis may produce false positives or miss sophisticated attacks. It's a supplementary signal, not a guarantee.

# Installation

## Prerequisites

**Required:**
- macOS (Apple Silicon or Intel)
- [Homebrew](https://brew.sh/) installed

**Optional (for full functionality):**

- [Ollama](https://ollama.ai/) - for local LLM formula/code analysis (no API key needed)
- [Semgrep](https://semgrep.dev/docs/getting-started/quickstart) - for static analysis scans

> **Note:** bsau works without optional dependencies. OSV vulnerability scanning requires no API keys and is always active. Ollama runs locally so no API key is required - just install and run `ollama serve`.

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
| `bsau run --no-ollama` | Skip local LLM analysis for this run |
| `bsau inspect` | Show inspect help menu |
| `bsau inspect <package>` | Scan a specific package |
| `bsau inspect --all` | Scan all installed packages |
| `bsau inspect ... --no-vuln` | Skip vulnerability scan |
| `bsau inspect ... --no-semgrep` | Skip Semgrep scan |
| `bsau inspect ... --no-ollama` | Skip local LLM analysis |
| `bsau init` | Generate default config file in binary directory |
| `bsau version` | Show version info |

> **Note:** On first run, bsau automatically generates a default `settings.yaml` config file in the binary directory. By default, inspect runs all checks: vulnerability scan, Semgrep, and local LLM (if enabled in config).

> **CTRL+C Handling**: During upgrades or scans, pressing CTRL+C will prompt you to confirm before exiting. This prevents accidental interruption that could leave temp files behind. If you confirm exit, bsau cleans up gracefully.

## Configuration

Generate a default config file in the same directory as the bsau binary:

```bash
bsau init
```

This creates `settings.yaml` next to the binary (e.g., `/usr/local/bin/settings.yaml`). Edit it to enable features:

```yaml
# Enable local LLM formula analysis (requires Ollama running locally)
features:
  ollama_scan: true

# LLM model to use (Ollama model name)
ollama_model: gemma3
```

Make sure Ollama is running if `ollama_scan` is enabled:

```bash
ollama serve   # Start Ollama server
```

**File Locations**: `settings.yaml` is stored in the same directory as the bsau binary. This makes the tool self-contained and easy to move.

# Detailed Information

## Step 1: Audit Current State

- Reads all installed packages via `brew list --json=v2`
- Identifies outdated packages via `brew outdated --json`
- Detects pinned packages via `brew list --pinned` (bsau never upgrades pinned packages)
- Scans for vulnerabilities using OSV.dev and NIST NVD
- Stores results in run-scoped temporary state (`/tmp/bsau-<run-id>/`)

## Step 2: Package Selection

- Displays a table showing: Package, Current Version, Available Version, Pinned Status, CVE Count, Severity
- Warns about pinned packages with known CVEs (but does not offer to update them)
- Interactive selector allows choosing which packages to update
- Dependency awareness: shows which packages depend on each other

## Step 3: Pre-install Security Scan

**Local LLM Formula Analysis** *(if enabled)*
- Retrieves the formula file from the local Homebrew tap
- Uses git history to get current + 2 previous versions of the formula
- Sends all versions to local LLM for analysis, focusing on what changed
- Looks for: suspicious URLs, shell hooks, obfuscated commands, credential harvesting, persistence mechanisms
- Returns verdict: `SAFE`, `REVIEW`, or `HOLD`

## Step 4: Per-Package Approval Gate

- Displays combined scan results in a table
- `HOLD` verdict -> package blocked (requires manual override)
- `REVIEW` verdict -> per-package confirmation prompt
- `SAFE` verdict -> queued for upgrade
- User gives final approval before any `brew upgrade` runs

## Step 5: Upgrade

- Prints the run directory path for manual cleanup if needed
- Checks available `/tmp` disk space before snapshotting
- Snapshots all text-readable files from current Cellar version
- Runs `brew upgrade <package>` one at a time (never batched)
- Passes stdio directly to terminal for interactive prompts (sudo, Gatekeeper, etc.)
- On failure: deletes snapshot, stops processing

## Step 6: Post-install Verification

**6a. Semgrep Scan**
- Updates Semgrep rules before scanning
- Runs with `p/supply-chain`, `p/secrets`, `p/malicious-code` rule sets
- Parses JSON output for flagged files and line numbers

**6b. Diff Generation**
- Generates unified diff between pre-upgrade snapshot and new install
- Only text-readable files are diffed; binaries noted as changed

**6c. Local LLM Code Analysis** *(if enabled)*
- Sends the diff + Semgrep findings to local LLM
- Analyzes for malicious patterns introduced in the new version
- Returns verdict: `SAFE`, `REVIEW`, or `HOLD`
- `HOLD` -> warns user, suggests `brew uninstall`

**6d. Snapshot Cleanup**
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

For Ollama analysis, make sure Ollama is installed and running:

```bash
brew install ollama
ollama serve
```

# TODO

- Use macOS Keychain for API key storage instead of environment variables
