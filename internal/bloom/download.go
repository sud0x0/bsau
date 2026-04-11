package bloom

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	// BloomURL is the CIRCL hashlookup bloom filter download URL
	BloomURL = "https://cra.circl.lu/hashlookup/hashlookup-full.bloom"
	// ExpectedSize is the approximate expected size in bytes (~700MB)
	ExpectedSize = 700 * 1024 * 1024
)

// ProgressFunc is called during download to report progress
type ProgressFunc func(downloaded, total int64)

// Download downloads the bloom filter from CIRCL
func Download(progress ProgressFunc) error {
	destPath, err := GetBloomPath()
	if err != nil {
		return err
	}

	// Ensure directory exists
	dir := filepath.Dir(destPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating directory: %w", err)
	}

	// Create temporary file for download
	tmpPath := destPath + ".tmp"
	out, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	defer func() {
		_ = out.Close()
		// Clean up temp file on error
		if _, err := os.Stat(tmpPath); err == nil {
			_ = os.Remove(tmpPath)
		}
	}()

	// Start download
	resp, err := http.Get(BloomURL)
	if err != nil {
		return fmt.Errorf("downloading bloom filter: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}

	// Capture server's ETag for update checking
	etag := resp.Header.Get("ETag")

	total := resp.ContentLength
	if total <= 0 {
		total = ExpectedSize // Use expected size if Content-Length not provided
	}

	// Create progress reader
	var downloaded int64
	reader := &progressReader{
		reader: resp.Body,
		onRead: func(n int) {
			downloaded += int64(n)
			if progress != nil {
				progress(downloaded, total)
			}
		},
	}

	// Copy to file
	written, err := io.Copy(out, reader)
	if err != nil {
		return fmt.Errorf("writing bloom filter: %w", err)
	}

	// Close file before rename
	if err := out.Close(); err != nil {
		return fmt.Errorf("closing temp file: %w", err)
	}

	// Rename temp to final
	if err := os.Rename(tmpPath, destPath); err != nil {
		return fmt.Errorf("renaming temp file: %w", err)
	}

	// Save metadata
	meta := &Metadata{
		DownloadedAt: time.Now(),
		SizeBytes:    written,
		ETag:         etag,
	}
	if err := SaveMetadata(meta); err != nil {
		// Non-fatal, just warn
		fmt.Printf("Warning: failed to save bloom filter metadata: %v\n", err)
	}

	return nil
}

// progressReader wraps a reader to report progress
type progressReader struct {
	reader io.Reader
	onRead func(n int)
}

func (r *progressReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 && r.onRead != nil {
		r.onRead(n)
	}
	return n, err
}

// fetchAndSaveETag fetches the current server ETag and saves it to metadata.
// Used when bloom file exists but metadata doesn't (e.g., bloom downloaded before ETag tracking was added).
func fetchAndSaveETag() (*UpdateInfo, error) {
	resp, err := http.Head(BloomURL)
	if err != nil {
		return nil, fmt.Errorf("fetching ETag: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned HTTP %d", resp.StatusCode)
	}

	etag := resp.Header.Get("ETag")

	// Get file info for metadata
	bloomPath, _ := GetBloomPath()
	info, err := os.Stat(bloomPath)
	if err != nil {
		return nil, fmt.Errorf("stat bloom file: %w", err)
	}

	// Save metadata with current server ETag (assume local file is current)
	meta := &Metadata{
		DownloadedAt: info.ModTime(),
		SizeBytes:    info.Size(),
		ETag:         etag,
	}
	if err := SaveMetadata(meta); err != nil {
		return nil, fmt.Errorf("saving metadata: %w", err)
	}

	// Bloom exists, we just saved the ETag, so no update needed
	return &UpdateInfo{
		Available:  false,
		ServerETag: etag,
		LocalETag:  etag,
	}, nil
}

// FormatSize formats bytes as human-readable string
func FormatSize(bytes int64) string {
	const (
		MB = 1024 * 1024
		GB = 1024 * 1024 * 1024
	)
	if bytes >= GB {
		return fmt.Sprintf("%.1f GB", float64(bytes)/float64(GB))
	}
	return fmt.Sprintf("%.0f MB", float64(bytes)/float64(MB))
}

// UpdateInfo contains information about available updates
type UpdateInfo struct {
	Available  bool   // True if a newer version exists on server
	ServerETag string // Server's current ETag
	LocalETag  string // Our stored ETag from download
}

// CheckForUpdate checks if a newer bloom filter is available on the server
// by comparing the server's ETag header with our stored value
func CheckForUpdate() (*UpdateInfo, error) {
	// Load local metadata
	meta, err := loadMetadata()
	if err != nil {
		// No metadata file - if bloom exists, fetch ETag and save it
		if Exists() {
			return fetchAndSaveETag()
		}
		// No bloom file either, update is available
		return &UpdateInfo{Available: true}, nil
	}

	// Make HEAD request to check ETag
	resp, err := http.Head(BloomURL)
	if err != nil {
		return nil, fmt.Errorf("checking for updates: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned HTTP %d", resp.StatusCode)
	}

	serverETag := resp.Header.Get("ETag")
	if serverETag == "" {
		// No ETag header, can't determine if update available
		return &UpdateInfo{
			Available: false,
			LocalETag: meta.ETag,
		}, nil
	}

	// If we don't have a stored ETag, we can't compare (old metadata format)
	// Consider it up-to-date rather than forcing re-download
	if meta.ETag == "" {
		return &UpdateInfo{
			Available:  false,
			ServerETag: serverETag,
		}, nil
	}

	return &UpdateInfo{
		Available:  serverETag != meta.ETag,
		ServerETag: serverETag,
		LocalETag:  meta.ETag,
	}, nil
}
