package llm

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// DiffChunkSize is the max lines per diff chunk
const DiffChunkSize = 800

// DiffChunkOverlap is the overlap between diff chunks to maintain context
const DiffChunkOverlap = 40

// MaxDiffLines is the maximum number of lines in a diff before truncation
const MaxDiffLines = 20000

// MaxConsecutiveChunkErrors is the threshold for stopping chunk processing
const MaxConsecutiveChunkErrors = 15

// MaxRetries is the number of retry attempts for LLM API calls
const MaxRetries = 3

// RetryWaitSeconds is the wait time between retries
const RetryWaitSeconds = 60

// generateFormulaDiff creates a unified diff between two formula contents
func generateFormulaDiff(oldContent, newContent, pkg string) (string, error) {
	// Create temp files for diff
	oldFile, err := os.CreateTemp("", "formula-old-*.rb")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.Remove(oldFile.Name()) }()

	newFile, err := os.CreateTemp("", "formula-new-*.rb")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.Remove(newFile.Name()) }()

	if _, err := oldFile.WriteString(oldContent); err != nil {
		return "", err
	}
	_ = oldFile.Close()

	if _, err := newFile.WriteString(newContent); err != nil {
		return "", err
	}
	_ = newFile.Close()

	// Run diff -u
	cmd := exec.Command("diff", "-u",
		"--label", fmt.Sprintf("%s (PREVIOUS)", pkg),
		"--label", fmt.Sprintf("%s (CURRENT)", pkg),
		oldFile.Name(), newFile.Name())
	output, err := cmd.Output()

	// diff returns exit code 1 when files differ - that's expected
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 1 {
				return string(output), nil
			}
		}
		return "", err
	}

	// Exit code 0 means no difference
	return "", nil
}

// chunkContent splits content into chunks of ChunkSize lines with ChunkOverlap overlap
func chunkContent(content string) []string {
	lines := strings.Split(content, "\n")
	totalLines := len(lines)

	if totalLines <= ChunkSize {
		return []string{content}
	}

	var chunks []string
	start := 0

	for start < totalLines {
		end := start + ChunkSize
		if end > totalLines {
			end = totalLines
		}

		chunk := strings.Join(lines[start:end], "\n")
		chunks = append(chunks, chunk)

		if end >= totalLines {
			break
		}

		start = end - ChunkOverlap
	}

	return chunks
}

// isFileBoundary checks if a line marks the start of a new file in a diff
func isFileBoundary(line string) bool {
	return strings.HasPrefix(line, "diff -ru ") ||
		strings.HasPrefix(line, "diff --git ") ||
		(strings.HasPrefix(line, "--- ") && !strings.HasPrefix(line, "--- a/dev/null"))
}

// chunkDiff splits diff content into chunks on file boundaries
// Takes the full diff string and returns chunks that never split a single file's diff
func chunkDiff(diff string) []string {
	lines := strings.Split(diff, "\n")
	totalLines := len(lines)

	if totalLines <= DiffChunkSize {
		return []string{diff}
	}

	// First pass: identify file boundaries and group lines by file
	type fileSection struct {
		startLine int
		lines     []string
	}
	var fileSections []fileSection
	currentSection := fileSection{startLine: 0}

	for i, line := range lines {
		if isFileBoundary(line) && len(currentSection.lines) > 0 {
			// Save previous section, start new one
			fileSections = append(fileSections, currentSection)
			currentSection = fileSection{startLine: i}
		}
		currentSection.lines = append(currentSection.lines, line)
	}
	// Don't forget the last section
	if len(currentSection.lines) > 0 {
		fileSections = append(fileSections, currentSection)
	}

	// If only one file section and it's large, fall back to line-based chunking
	if len(fileSections) == 1 && len(fileSections[0].lines) > DiffChunkSize {
		return chunkDiffByLines(fileSections[0].lines)
	}

	// Second pass: accumulate file sections into chunks
	var chunks []string
	var currentChunkLines []string

	for _, section := range fileSections {
		// If adding this section would exceed chunk size, close current chunk first
		// Exception: if current chunk is empty, we must include this section regardless of size
		if len(currentChunkLines) > 0 && len(currentChunkLines)+len(section.lines) > DiffChunkSize {
			chunks = append(chunks, strings.Join(currentChunkLines, "\n"))
			currentChunkLines = nil
		}

		// If this single section exceeds chunk size on its own, it becomes its own chunk
		if len(section.lines) > DiffChunkSize {
			// If we have accumulated lines, save them first
			if len(currentChunkLines) > 0 {
				chunks = append(chunks, strings.Join(currentChunkLines, "\n"))
				currentChunkLines = nil
			}
			// This large single-file section becomes its own chunk(s)
			sectionChunks := chunkDiffByLines(section.lines)
			chunks = append(chunks, sectionChunks...)
		} else {
			// Add section to current chunk
			currentChunkLines = append(currentChunkLines, section.lines...)
		}
	}

	// Don't forget remaining lines
	if len(currentChunkLines) > 0 {
		chunks = append(chunks, strings.Join(currentChunkLines, "\n"))
	}

	return chunks
}

// chunkDiffByLines splits lines into chunks by raw line count with overlap
// Used as fallback for single-file diffs that exceed chunk size
func chunkDiffByLines(lines []string) []string {
	totalLines := len(lines)

	if totalLines <= DiffChunkSize {
		return []string{strings.Join(lines, "\n")}
	}

	var chunks []string
	start := 0

	for start < totalLines {
		end := start + DiffChunkSize
		if end > totalLines {
			end = totalLines
		}

		chunk := strings.Join(lines[start:end], "\n")
		chunks = append(chunks, chunk)

		if end >= totalLines {
			break
		}

		start = end - DiffChunkOverlap
	}

	return chunks
}
