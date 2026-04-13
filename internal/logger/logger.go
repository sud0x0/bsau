package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const LogFileName = "bsau.log"

// Logger handles centralized logging for bsau
type Logger struct {
	file    *os.File
	verbose bool
	mu      sync.Mutex
}

var (
	instance *Logger
	once     sync.Once
)

// Init initializes the global logger
// Call this once at startup with the binary directory path
func Init(binaryDir string, verbose bool) error {
	var initErr error
	once.Do(func() {
		logPath := filepath.Join(binaryDir, LogFileName)

		// Truncate log file on each run
		f, err := os.OpenFile(logPath, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			initErr = fmt.Errorf("opening log file: %w", err)
			return
		}

		instance = &Logger{
			file:    f,
			verbose: verbose,
		}

		instance.writeHeader()
	})
	return initErr
}

// writeHeader writes initial log header
func (l *Logger) writeHeader() {
	l.write("=== bsau session started ===")
	l.write("Time: %s", time.Now().Format("2006-01-02 15:04:05"))
	l.write("Verbose: %v", l.verbose)
	l.write("Log file: %s", l.file.Name())
	l.write("")
}

// Close closes the log file
func Close() {
	if instance != nil && instance.file != nil {
		Info("=== Session ended ===")
		_ = instance.file.Close()
	}
}

// SetVerbose updates verbose mode (useful if set after init)
func SetVerbose(v bool) {
	if instance != nil {
		instance.mu.Lock()
		instance.verbose = v
		instance.mu.Unlock()
	}
}

// GetLogPath returns the path to the log file
func GetLogPath() string {
	if instance != nil && instance.file != nil {
		return instance.file.Name()
	}
	return ""
}

func (l *Logger) write(format string, args ...interface{}) {
	if l.file == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	timestamp := time.Now().Format("15:04:05")
	msg := fmt.Sprintf(format, args...)
	_, _ = fmt.Fprintf(l.file, "[%s] %s\n", timestamp, msg)
	_ = l.file.Sync()
}

// Info logs basic information (always logged)
func Info(format string, args ...interface{}) {
	if instance != nil {
		instance.write("[INFO] "+format, args...)
	}
}

// Step logs a workflow step (always logged)
func Step(step int, total int, description string) {
	if instance != nil {
		instance.write("[STEP %d/%d] %s", step, total, description)
	}
}

// Package logs package-specific info (always logged)
func Package(pkg, action string) {
	if instance != nil {
		instance.write("[PKG] %s: %s", pkg, action)
	}
}

// Result logs a scan result (always logged)
func Result(scanType, pkg, result string) {
	if instance != nil {
		instance.write("[RESULT] %s | %s: %s", scanType, pkg, result)
	}
}

// Warn logs a warning (always logged)
func Warn(format string, args ...interface{}) {
	if instance != nil {
		instance.write("[WARN] "+format, args...)
	}
}

// Error logs an error (always logged)
func Error(format string, args ...interface{}) {
	if instance != nil {
		instance.write("[ERROR] "+format, args...)
	}
}

// Debug logs detailed information (only when verbose)
func Debug(format string, args ...interface{}) {
	if instance != nil && instance.verbose {
		instance.write("[DEBUG] "+format, args...)
	}
}

// Section starts a new section in the log (always logged)
func Section(name string) {
	if instance != nil {
		instance.write("")
		instance.write("=== %s ===", name)
	}
}

// --- Ollama-specific logging ---

// OllamaRequest logs an Ollama API request
func OllamaRequest(model, systemPrompt, userPrompt string) {
	if instance == nil {
		return
	}
	instance.write("[OLLAMA] Request to model: %s", model)
	if instance.verbose {
		instance.write("[OLLAMA] System prompt (%d chars): %s", len(systemPrompt), truncate(systemPrompt, 300))
		instance.write("[OLLAMA] User prompt (%d chars): %s", len(userPrompt), truncate(userPrompt, 500))
	}
}

// OllamaResponse logs an Ollama API response
func OllamaResponse(elapsed time.Duration, content string) {
	if instance == nil {
		return
	}
	instance.write("[OLLAMA] Response in %v (%d chars)", elapsed, len(content))
	if instance.verbose {
		instance.write("[OLLAMA] Content: %s", truncate(content, 500))
	}
}

// OllamaError logs an Ollama error
func OllamaError(err error) {
	if instance != nil {
		instance.write("[OLLAMA] ERROR: %v", err)
	}
}

// OllamaChunk logs chunk processing
func OllamaChunk(file string, chunkNum, totalChunks int) {
	if instance != nil && instance.verbose {
		instance.write("[OLLAMA] Processing chunk %d/%d of %s", chunkNum, totalChunks, filepath.Base(file))
	}
}

// --- Semgrep-specific logging ---

// SemgrepScan logs a Semgrep scan
func SemgrepScan(pkg, path string) {
	if instance != nil {
		instance.write("[SEMGREP] Scanning %s: %s", pkg, path)
	}
}

// SemgrepResult logs Semgrep results
func SemgrepResult(pkg string, findingCount int) {
	if instance != nil {
		instance.write("[SEMGREP] %s: %d findings", pkg, findingCount)
	}
}

// SemgrepFinding logs individual findings (verbose only)
func SemgrepFinding(file string, line int, ruleID, severity string) {
	if instance != nil && instance.verbose {
		instance.write("[SEMGREP] Finding: %s:%d [%s] %s", filepath.Base(file), line, severity, ruleID)
	}
}

// --- Vulnerability-specific logging ---

// VulnScan logs a vulnerability scan
func VulnScan(packageCount int) {
	if instance != nil {
		instance.write("[VULN] Scanning %d packages for vulnerabilities", packageCount)
	}
}

// VulnResult logs vulnerability results
func VulnResult(pkg string, cveCount int, maxSeverity string) {
	if instance != nil {
		if cveCount > 0 {
			instance.write("[VULN] %s: %d CVEs (max severity: %s)", pkg, cveCount, maxSeverity)
		} else if instance.verbose {
			instance.write("[VULN] %s: no known vulnerabilities", pkg)
		}
	}
}

// truncate shortens a string for logging
func truncate(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\t", " ")
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
