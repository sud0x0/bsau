# bsau

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)](https://go.dev/)
[![macOS](https://img.shields.io/badge/macOS-compatible-000000?logo=apple)](https://www.apple.com/macos/)

> **Note:** This project is currently in active development and testing. If you encounter any issues or have suggestions, please [open an issue](https://github.com/sud0x0/bsau/issues)

bsau (Brew Scan and Update) is a security-focused Homebrew package manager wrapper written in Go. It uses LLM analysis (via local [Ollama](https://ollama.ai/) or [Anthropic Claude API](https://www.anthropic.com/)) for intelligent code review.

It helps protect your macOS environment from **known security vulnerabilities** and **supply chain attacks** by:

- **Identifying vulnerable packages** - Scans for known CVEs before and after upgrades
- **Detecting malicious code patterns** - YARA rules catch reverse shells, credential theft, persistence mechanisms
- **Analyzing code changes** - LLM reviews formula changes and post-install diffs for suspicious patterns

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
2. **YARA Malware Detection** - Full YARA 4.x pattern matching via libyara detects:
   - Reverse shells and C2 patterns (ERROR severity - hard blocks)
   - Credential theft (AWS, SSH, keychain access)
   - Obfuscation patterns (base64 decode + exec)
   - Persistence mechanisms (LaunchAgent, crontab)
   - Security bypasses (Gatekeeper, SIP disable)
3. **LLM Code Analysis** - Supports both local Ollama and Anthropic Claude API:
   - Analyzes formula history (current + 2 prior versions)
   - Reviews post-install code diffs with YARA context
   - Smart chunking on file boundaries (never splits a file across chunks)
   - Automatic retry with rate limit handling
4. **Detailed Reports** - Generates timestamped report files with vulnerability details and per-package scan results

## Workflow (7 Steps)

1. **Audit** - Identify outdated packages, check OSV/NVD for vulnerabilities
2. **Select** - Interactive package selector with dependency awareness
3. **Pre-install scan** - LLM analyzes formula history (current + 2 prior versions)
4. **Approval gate** - User approves/blocks packages based on scan results
5. **Upgrade** - Snapshot text files, run brew upgrade with stdio passthrough
6. **Post-install verification** - YARA scan on changed files + LLM analysis of diffs
7. **Cleanup** - Remove temp files, run brew cleanup

## Limitations

1. **No static binary scanning**: bsau does not perform static analysis or hash verification on compiled binaries. The YARA scanner and LLM analyse source/script files only. Compiled executables, libraries, and object files are not scanned for malware signatures or suspicious patterns.
2. **Binary-only casks**: Closed-source GUI applications have no formula source to analyze. LLM analysis is not meaningful for these.
3. **Vulnerability database coverage**: bsau only queries OSV.dev and NIST NVD for vulnerabilities. Additional vulnerabilities may exist in other databases (e.g., GitHub Security Advisories, vendor-specific advisories, or security mailing lists) that are not checked. CVE counts shown may be incomplete or inaccurate. `N/A` means no mapping exists for that package.
4. **YARA pattern matching**: bsau uses libyara 4.x (installed via `brew install yara`) with custom `.yar` rules to detect malicious patterns. Novel or heavily obfuscated attacks may evade signature-based detection.
5. **LLM context window**: Large diffs are truncated at 20,000 lines. Diffs are chunked at 800 lines per chunk with smart file-boundary splitting.
6. **Snapshot disk usage**: Pre-upgrade snapshots of text files may consume significant `/tmp` space for large packages. bsau warns when space is low and skips snapshots if critically low.
7. **No transitive dependency scanning**: Only Homebrew-level packages are scanned, not runtime dependencies (e.g., Python packages inside a formula's venv).
8. **macOS only**: bsau is designed for Homebrew on macOS. It will not work on Linux Homebrew installations.
9. **LLM limitations**: LLM analysis may produce false positives or miss sophisticated attacks. It's a supplementary signal, not a guarantee.

# Installation

## Prerequisites

**Required:**
- [Homebrew](https://brew.sh/) installed
- [YARA](https://virustotal.github.io/yara/) — malware pattern matching engine

```bash
brew install yara
```

**Optional (for LLM analysis):**
- [Ollama](https://ollama.ai/) — for local LLM analysis (no API key needed), OR
- [Anthropic API key](https://www.anthropic.com/) — for Claude API analysis

> **Note:** OSV/NIST NVD vulnerability scanning requires no API keys and is always active. YARA malware scanning requires `brew install yara`. LLM analysis is optional and can use either local Ollama or Anthropic Claude API.

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

**Prerequisites:** Go 1.21+, and YARA (`brew install yara` — required for CGO build)

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
bsau inspect --all

# Dry run - scan but don't upgrade
bsau run --dry-run
```

## Commands

### Main Commands

| Command | Description |
|---------|-------------|
| `bsau run` | Full scan and update workflow |
| `bsau inspect <package>` | Scan a specific installed package |
| `bsau inspect --all` | Scan all installed packages |
| `bsau init` | Generate default config file |
| `bsau version` | Show version info |
| `bsau help` | Show help |

### Run Flags

| Flag | Description |
|------|-------------|
| `--dry-run` | Run all scans but skip the actual upgrade |
| `--no-llm` | Skip LLM analysis for this run |
| `--no-yara` | Skip YARA scan for this run |
| `-v, --verbose` | Enable verbose output (shows LLM requests/responses) |

### Inspect Flags

| Flag | Description |
|------|-------------|
| `--all` | Scan all installed packages (required if no package specified) |
| `--no-vuln` | Skip vulnerability scan (OSV/NVD) |
| `--no-yara` | Skip YARA malware scan |
| `--no-llm` | Skip LLM code analysis |
| `-v, --verbose` | Enable verbose output |

### Examples

```bash
# Full workflow with all scans
bsau run

# Dry run - see what would happen without upgrading
bsau run --dry-run

# Skip LLM (faster, still runs vuln + YARA)
bsau run --no-llm

# Verbose mode - see LLM requests/responses
bsau run -v

# Scan a specific package
bsau inspect wget

# Scan all packages with just YARA (fast)
bsau inspect --all --no-vuln --no-llm

# Full scan of all packages
bsau inspect --all
```

> **Note:** On first run, bsau automatically generates a default `settings.yaml` config file in the binary directory.

> **CTRL+C Handling**: During upgrades or scans, pressing CTRL+C will prompt you to confirm before exiting. This prevents accidental interruption that could leave temp files behind. If you confirm exit, bsau cleans up gracefully.

## Configuration

Generate a default config file in the same directory as the bsau binary:

```bash
bsau init
```

This creates `settings.yaml` next to the binary (e.g., `/usr/local/bin/settings.yaml`). Edit it to configure LLM providers:

### Option A: Local Ollama (no API key)

```yaml
features:
  llm_scan: true
  llm_provider: ollama

llm_url: http://localhost:11434
llm_model: gemma3  # or llama3, mistral, qwen2.5, etc.
```

Make sure Ollama is running:

```bash
ollama serve   # Start Ollama server
ollama pull gemma3  # Download a model
```

### Option B: Anthropic Claude API

```yaml
features:
  llm_scan: true
  llm_provider: anthropic

# llm_model is optional for Anthropic (defaults to claude-sonnet-4-6)
llm_model: claude-sonnet-4-6
```

Set your API key as an environment variable:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

### Configuration Options

| Setting | Description | Default |
|---------|-------------|---------|
| `features.llm_scan` | Enable LLM analysis | `false` |
| `features.llm_provider` | LLM provider: `ollama` or `anthropic` | `ollama` |
| `llm_url` | LLM server URL (Ollama only) | `http://localhost:11434` |
| `llm_model` | Model name (required for Ollama) | `""` |
| `llm_max_file_bytes` | Max file size for LLM | `12000` |
| `block_policy.llm_formula_hold` | Block on formula HOLD | `true` |
| `block_policy.llm_code_hold` | Block on code HOLD | `true` |

**File Locations**: `settings.yaml` and report files are stored in the same directory as the bsau binary. This makes the tool self-contained and easy to move.

# Detailed Information

## Step 1: Audit Current State

- Reads all installed packages via `brew list --json=v2`
- Identifies outdated packages via `brew outdated --json`
- Detects pinned packages via `brew list --pinned` (bsau never upgrades pinned packages)
- Scans for vulnerabilities using OSV.dev and NIST NVD
- Stores results in run-scoped temporary state (`/tmp/bsau-<run-id>/`)

## Step 2: Package Selection

- Creates a vulnerability report file in the binary directory: `bsau_report_YYYY-MM-DD_<unix_timestamp>.txt`
- Displays the report file location for reference
- Displays a table showing: Package, Current Version, Available Version, Pinned Status, CVE Count, Severity
- Warns about pinned packages with known CVEs (but does not offer to update them)
- Interactive selector allows choosing which packages to update
- Dependency awareness: shows which packages depend on each other

> **Limitation:** CVE data is sourced from OSV.dev and NIST NVD only. Additional vulnerabilities may exist in other databases that are not checked. CVE counts may be incomplete.

## Step 3: Pre-install Security Scan

**LLM Formula Analysis** *(if enabled)*
- Retrieves the formula file from the local Homebrew tap
- Uses git history to get current + 2 previous versions of the formula
- Sends all versions to LLM for analysis, focusing on what changed
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

**6a. YARA Scan**
- Scans only changed files (identified from diff) for efficiency
- Uses embedded `.yar` rules with severity levels:
  - **ERROR** (hard block): Reverse shells, curl/wget pipe to shell, keychain access
  - **WARNING** (review): Credential access, persistence mechanisms, security bypasses
- ERROR findings immediately block without waiting for LLM

**6b. Diff Generation**
- Generates unified diff between pre-upgrade snapshot and new install
- Only text-readable files are diffed; binaries noted as changed
- Large diffs (>20,000 lines) are truncated with a warning

**6c. LLM Code Analysis** *(if enabled)*
- Sends the diff + YARA findings to LLM
- Smart chunking on file boundaries (800 lines per chunk)
- Never splits a single file's diff across chunks
- Automatic retry (3 attempts, 60s wait) with rate limit detection
- Stops after 15 consecutive chunk failures (partial result with REVIEW verdict)
- Returns verdict: `SAFE`, `REVIEW`, or `HOLD`
- `HOLD` -> warns user, suggests `brew uninstall`

**6d. Snapshot Cleanup**
- Deletes snapshot directory after analysis completes

## Step 7: Cleanup

- Re-runs vulnerability scan on updated packages
- Displays before/after CVE summary
- Removes temporary run directory (`/tmp/bsau-<run-id>/`)
- Runs `brew cleanup` to remove old versions
- Writes final summary to report file and displays:
  - Packages updated vs not updated (with CVE counts)
  - Per-package scan results table showing status of:
    - YARA scan (clean/X findings/blocked)
    - LLM analysis (SAFE/REVIEW/HOLD/skipped/failed)
- Displays path to the full report file

# Development Setup

## Prerequisites

- Go 1.21+
- Homebrew (macOS)
- [YARA](https://virustotal.github.io/yara/) (`brew install yara`) — required for CGO build of the scanning engine
- [pre-commit](https://pre-commit.com/)
- [golangci-lint](https://golangci-lint.run/)
- [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck)

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

5. **Build the binary**
   ```bash
   make build
   ```

6. **Verify the build**
   ```bash
   ./_BUILD_/bsau version
   ```

## Available Make Targets

```bash
make help          # Show all available targets
make build         # Build the binary
make test          # Run tests
make lint          # Run golangci-lint
make fmt           # Format all Go files
make vet           # Run go vet
make vulncheck     # Run govulncheck
make pre-commit-run # Run all pre-commit hooks manually
make clean         # Remove build artifacts
```

## Architecture

```
bsau/
├── cmd/                    # CLI commands (root, run, inspect, init, version)
├── internal/
│   ├── brew/               # Homebrew interaction (list, outdated, upgrade)
│   ├── config/             # Configuration management
│   ├── llm/                # LLM provider abstraction (Ollama, Anthropic)
│   ├── logger/             # Centralized logging
│   ├── report/             # Report file generation
│   ├── snapshot/           # Pre-upgrade file snapshots
│   ├── state/              # Run-scoped temporary state
│   ├── ui/                 # Terminal UI (tables, progress, prompts)
│   ├── vuln/               # Vulnerability scanning (OSV, NVD)
│   └── yara/               # YARA malware scanning
│       └── rules/          # Embedded YARA rules (.yar files)
└── settings.yaml           # Configuration file
```

# TODO

- Terraform tap path bug — hashicorp/tap/terraform installs to /opt/homebrew/Cellar/terraform/ not /opt/homebrew/Cellar/hashicorp/tap/terraform/
- Better yara rules
- Premature packages scanning (N+2)
- Specific version installation support
- Tap verification
- Binary signing verification (where possible)
- Transitive dependency scanning
- Network monitoring during install

