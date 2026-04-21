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

		// Append to log file (preserves previous runs)
		f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
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
	l.writeRaw("")
	l.writeRaw("════════════════════════════════════════")
	l.writeRaw("SESSION START: %s", time.Now().Format("2006-01-02 15:04:05"))
	l.writeRaw("════════════════════════════════════════")
	l.writeRaw("")
}

// Close closes the log file
func Close() {
	if instance != nil && instance.file != nil {
		instance.writeRaw("")
		instance.writeRaw("════════════════════════════════════════")
		instance.writeRaw("SESSION END: %s", time.Now().Format("2006-01-02 15:04:05"))
		instance.writeRaw("════════════════════════════════════════")
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

// writeRaw writes to log file without timestamp prefix
func (l *Logger) writeRaw(format string, args ...interface{}) {
	if l.file == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	msg := fmt.Sprintf(format, args...)
	_, _ = fmt.Fprintln(l.file, msg)
	_ = l.file.Sync()
}

// write writes to log file with timestamp
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

// printVerbose prints to terminal only when verbose mode is active
// Does NOT write to log file
func (l *Logger) printVerbose(format string, args ...interface{}) {
	if !l.verbose {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Printf(format, args...)
}

// StepHeader writes a formatted step header to the log file
func StepHeader(step int, total int, title string) {
	if instance == nil {
		return
	}
	instance.writeRaw("")
	instance.writeRaw("════════════════════════════════════════")
	instance.writeRaw("STEP %d/%d: %s", step, total, title)
	instance.writeRaw("════════════════════════════════════════")
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

// Debug logs detailed information (only when verbose, to log file)
func Debug(format string, args ...interface{}) {
	if instance != nil && instance.verbose {
		instance.write("[DEBUG] "+format, args...)
	}
}

// Verbose prints to terminal only when -v is active
// Does NOT write to log file - use for terminal-only verbose output
func Verbose(format string, args ...interface{}) {
	if instance != nil {
		instance.printVerbose(format, args...)
	}
}

// Section starts a new section in the log (always logged)
func Section(name string) {
	if instance != nil {
		instance.writeRaw("")
		instance.write("── %s ──", name)
	}
}

// --- LLM-specific logging (provider-agnostic) ---

// LLMRequest logs an LLM API request (basic info to log file, full content to terminal in verbose)
func LLMRequest(provider, model, systemPrompt, userPrompt string) {
	if instance == nil {
		return
	}
	tag := strings.ToUpper(provider)
	// Basic info always goes to log file
	instance.write("[%s] Request to model: %s (%d chars)", tag, model, len(userPrompt))
}

// LLMResponse logs an LLM API response (basic info to log file, full content to terminal in verbose)
func LLMResponse(provider string, elapsed time.Duration, content string) {
	if instance == nil {
		return
	}
	tag := strings.ToUpper(provider)
	// Basic info always goes to log file
	instance.write("[%s] Response in %v (%d chars)", tag, elapsed, len(content))
}

// VerboseLLMRequest logs LLM request info and optionally prints to terminal in verbose mode
// Always writes compact summary to log file, full content to terminal only in verbose mode
func VerboseLLMRequest(pkg string, chunkNum, totalChunks int, systemPrompt, userPrompt string) {
	if instance == nil {
		return
	}
	// Always write compact summary to log file
	instance.write("[LLM] REQUEST pkg=%s chunk=%d/%d prompt_chars=%d", pkg, chunkNum, totalChunks, len(userPrompt))

	// Verbose terminal output only
	if instance.verbose {
		instance.printVerbose("\n── LLM REQUEST ─────────────────────────\n")
		instance.printVerbose("Package:  %s\n", pkg)
		if totalChunks > 1 {
			instance.printVerbose("Chunk:    %d of %d\n", chunkNum, totalChunks)
		}
		instance.printVerbose("System:   %s\n", truncateForDisplay(systemPrompt, 200))
		instance.printVerbose("User:     %s\n", truncateForDisplay(userPrompt, 500))
		instance.printVerbose("────────────────────────────────────────\n")
	}
}

// VerboseLLMResponse logs LLM response info and optionally prints to terminal in verbose mode
// Always writes compact summary to log file, full content to terminal only in verbose mode
func VerboseLLMResponse(pkg string, chunkNum, totalChunks int, elapsed time.Duration, verdict, content string) {
	if instance == nil {
		return
	}
	// Always write compact summary to log file
	instance.write("[LLM] RESPONSE pkg=%s chunk=%d/%d elapsed=%.1fs verdict=%s chars=%d",
		pkg, chunkNum, totalChunks, elapsed.Seconds(), verdict, len(content))

	// Verbose terminal output only
	if instance.verbose {
		instance.printVerbose("\n── LLM RESPONSE ────────────────────────\n")
		instance.printVerbose("%s\n", content)
		instance.printVerbose("────────────────────────────────────────\n")
	}
}

// LLMError logs an LLM error
func LLMError(provider string, err error) {
	if instance != nil {
		tag := strings.ToUpper(provider)
		instance.write("[%s] ERROR: %v", tag, err)
	}
}

// LLMChunk logs chunk processing
func LLMChunk(provider, file string, chunkNum, totalChunks int) {
	if instance != nil && instance.verbose {
		tag := strings.ToUpper(provider)
		instance.write("[%s] Processing chunk %d/%d of %s", tag, chunkNum, totalChunks, filepath.Base(file))
	}
}

// --- YARA-specific logging ---

// YaraScan logs a YARA scan
func YaraScan(pkg, path string) {
	if instance != nil {
		instance.write("[YARA] Scanning %s: %s", pkg, path)
	}
}

// YaraResult logs YARA results
func YaraResult(pkg string, findingCount int) {
	if instance != nil {
		instance.write("[YARA] %s: %d findings", pkg, findingCount)
	}
}

// YaraFinding logs individual findings (to log file)
func YaraFinding(file string, ruleID, severity string) {
	if instance != nil {
		instance.write("[YARA] Finding: %s [%s] %s", filepath.Base(file), severity, ruleID)
	}
}

// VerboseYaraFinding prints formatted YARA finding to terminal only (verbose mode)
func VerboseYaraFinding(ruleID, severity, filePath string, lineNum int, message string) {
	if instance == nil || !instance.verbose {
		return
	}
	instance.printVerbose("\n── YARA FINDING ────────────────────────\n")
	instance.printVerbose("Rule:     %s\n", ruleID)
	instance.printVerbose("Severity: %s\n", severity)
	instance.printVerbose("File:     %s\n", filePath)
	if lineNum > 0 {
		instance.printVerbose("Line:     %d\n", lineNum)
	}
	instance.printVerbose("Message:  %s\n", message)
	instance.printVerbose("────────────────────────────────────────\n")
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

// truncateForDisplay truncates a string for display, adding ellipsis if truncated
func truncateForDisplay(s string, maxLen int) string {
	// Replace newlines with spaces for single-line display
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	// Collapse multiple spaces
	for strings.Contains(s, "  ") {
		s = strings.ReplaceAll(s, "  ", " ")
	}
	s = strings.TrimSpace(s)

	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
