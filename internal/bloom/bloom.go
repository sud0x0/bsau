package bloom

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/DCSO/bloom"
)

const (
	// BloomFileName is the bloom filter filename
	BloomFileName = "hashlookup-full.bloom"
	// MetadataFileName stores bloom filter metadata
	MetadataFileName = "bloom-meta.json"
)

// Metadata stores information about the downloaded bloom filter
type Metadata struct {
	DownloadedAt time.Time `json:"downloaded_at"`
	SizeBytes    int64     `json:"size_bytes"`
	ETag         string    `json:"etag,omitempty"` // ETag from server for update checking
}

// Filter wraps the DCSO bloom filter with metadata
type Filter struct {
	filter     *bloom.BloomFilter
	metadata   *Metadata
	filterPath string
}

// GetBinaryDir returns the directory where the bsau binary is located
func GetBinaryDir() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("getting executable path: %w", err)
	}
	// Resolve symlinks to get the real path
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return "", fmt.Errorf("resolving symlinks: %w", err)
	}
	return filepath.Dir(exe), nil
}

// GetBloomPath returns the full path to the bloom filter file
func GetBloomPath() (string, error) {
	dir, err := GetBinaryDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, BloomFileName), nil
}

// GetMetadataPath returns the full path to the metadata file
func GetMetadataPath() (string, error) {
	dir, err := GetBinaryDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, MetadataFileName), nil
}

// Exists checks if the bloom filter file exists
func Exists() bool {
	path, err := GetBloomPath()
	if err != nil {
		return false
	}
	_, err = os.Stat(path)
	return err == nil
}

// Load loads the bloom filter from disk
func Load() (*Filter, error) {
	path, err := GetBloomPath()
	if err != nil {
		return nil, err
	}

	// LoadFilter takes the path directly
	filter, err := bloom.LoadFilter(path, false)
	if err != nil {
		return nil, fmt.Errorf("loading bloom filter: %w", err)
	}

	// Load metadata
	meta, err := loadMetadata()
	if err != nil {
		// If metadata doesn't exist, create default based on file mod time
		info, statErr := os.Stat(path)
		if statErr == nil {
			meta = &Metadata{
				DownloadedAt: info.ModTime(),
				SizeBytes:    info.Size(),
			}
		} else {
			meta = &Metadata{
				DownloadedAt: time.Now(),
			}
		}
	}

	return &Filter{
		filter:     filter,
		metadata:   meta,
		filterPath: path,
	}, nil
}

// Contains checks if a SHA-1 hash exists in the bloom filter
// The hash should be uppercase hex (40 characters)
func (f *Filter) Contains(sha1Hash string) bool {
	return f.filter.Check([]byte(sha1Hash))
}

// Age returns how old the bloom filter is
func (f *Filter) Age() time.Duration {
	return time.Since(f.metadata.DownloadedAt)
}

// DownloadedAt returns when the bloom filter was downloaded
func (f *Filter) DownloadedAt() time.Time {
	return f.metadata.DownloadedAt
}

// SizeBytes returns the size of the bloom filter file
func (f *Filter) SizeBytes() int64 {
	return f.metadata.SizeBytes
}

func loadMetadata() (*Metadata, error) {
	path, err := GetMetadataPath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var meta Metadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, err
	}

	return &meta, nil
}

// SaveMetadata saves bloom filter metadata to disk
func SaveMetadata(meta *Metadata) error {
	path, err := GetMetadataPath()
	if err != nil {
		return err
	}

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating directory: %w", err)
	}

	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}
