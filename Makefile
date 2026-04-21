.PHONY: build clean test test-pretty lint fmt vet help pre-commit-run vulncheck semgrep socket check-yara

BINARY := bsau
BUILD_DIR := _BUILD_
VERSION := 0.1.0
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS := -ldflags "-X github.com/sud0x0/bsau/cmd.Version=$(VERSION) -X github.com/sud0x0/bsau/cmd.GitCommit=$(GIT_COMMIT) -X github.com/sud0x0/bsau/cmd.BuildDate=$(BUILD_DATE)"
YARA_PREFIX     ?= $(shell brew --prefix yara 2>/dev/null)
CGO_YARA_FLAGS  := CGO_CFLAGS="-I$(YARA_PREFIX)/include" CGO_LDFLAGS="-L$(YARA_PREFIX)/lib"

# Build the binary
build:
	@mkdir -p $(BUILD_DIR)
	@$(CGO_YARA_FLAGS) go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY) .

# Remove binary and clean build cache
clean:
	@rm -rf $(BUILD_DIR) _test_results_
	@go clean

# Verify libyara is installed (required for building)
check-yara:
	@brew list yara >/dev/null 2>&1 || { \
		echo "Error: yara not installed."; \
		echo "Run: brew install yara"; \
		exit 1; \
	}

# Run all tests
test:
	@go test ./...

# Run tests with formatted table output
test-pretty:
	@go run tests/test_runner.go

# Run golangci-lint
lint:
	@golangci-lint run

# Format all Go files
fmt:
	@gofmt -l -w .

# Run go vet
vet:
	@go vet ./...

# Run all pre-commit hooks manually against all files
pre-commit-run:
	@pre-commit run --all-files

# Run govulncheck against all packages
vulncheck:
	@govulncheck -show verbose ./...

# Run semgrep with auto config
semgrep:
	@semgrep --config=auto --error --skip-unknown-extensions .

# Run Socket.dev supply chain scan
# Requires: npm install -g socket && socket login
# Scans all dependencies for known malicious packages and supply chain risks.
socket:
	@socket scan create .

# Show this help
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Build targets:"
	@echo "  build          Build the binary (requires brew install yara)"
	@echo "  check-yara     Verify libyara is installed (brew install yara)"
	@echo "  clean          Remove binary and clean build cache"
	@echo ""
	@echo "Test targets:"
	@echo "  test           Run all tests"
	@echo "  test-pretty    Run tests with formatted table output"
	@echo ""
	@echo "Code quality targets:"
	@echo "  lint           Run golangci-lint"
	@echo "  fmt            Format all Go files"
	@echo "  vet            Run go vet"
	@echo ""
	@echo "Security targets:"
	@echo "  pre-commit-run Run all pre-commit hooks against all files"
	@echo "  vulncheck      Run govulncheck against all packages"
	@echo "  semgrep        Run semgrep with auto config"
	@echo "  socket         Run Socket.dev supply chain scan"
	@echo ""
	@echo "  help           Show this help"
