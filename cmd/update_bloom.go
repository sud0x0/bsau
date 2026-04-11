package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/sud0x0/bsau/internal/bloom"
	"github.com/sud0x0/bsau/internal/ui"
)

var forceUpdate bool

var updateBloomCmd = &cobra.Command{
	Use:   "update-bloom",
	Short: "Download or update the CIRCL bloom filter",
	Long: `Download or update the CIRCL hashlookup bloom filter (~700MB).

The bloom filter contains ~298 million SHA-1 hashes from NSRL and other
trusted sources. It is used for fast local hash lookups during scans.

Use --force to re-download even if no update is available.`,
	RunE: runUpdateBloom,
}

func init() {
	updateBloomCmd.Flags().BoolVarP(&forceUpdate, "force", "f", false, "force re-download even if up to date")
	rootCmd.AddCommand(updateBloomCmd)
}

func runUpdateBloom(cmd *cobra.Command, args []string) error {
	bloomPath, err := bloom.GetBloomPath()
	if err != nil {
		return fmt.Errorf("getting bloom path: %w", err)
	}

	if !bloom.Exists() {
		// First download
		ui.PrintInfo("Bloom filter not found. Downloading...")
		fmt.Printf("URL: %s\n", bloom.BloomURL)
		fmt.Printf("Size: ~%s\n", bloom.FormatSize(bloom.ExpectedSize))
		fmt.Printf("Location: %s\n", bloomPath)
		fmt.Println()

		return downloadBloom()
	}

	// Check for updates
	ui.PrintInfo("Checking for updates...")
	updateInfo, err := bloom.CheckForUpdate()
	if err != nil {
		if forceUpdate {
			ui.PrintWarning(fmt.Sprintf("Could not check server: %v", err))
			ui.PrintInfo("Force downloading anyway...")
			return downloadBloom()
		}
		return fmt.Errorf("checking for updates: %w", err)
	}

	if !updateInfo.Available && !forceUpdate {
		ui.PrintSuccess("Bloom filter is up to date (ETag matches server)")
		return nil
	}

	if updateInfo.Available {
		ui.PrintInfo("Update available (server ETag changed)")
	} else {
		ui.PrintInfo("Force re-downloading...")
	}

	return downloadBloom()
}

func downloadBloom() error {
	fmt.Println()
	err := bloom.Download(func(downloaded, total int64) {
		pct := float64(downloaded) / float64(total) * 100
		fmt.Printf("\rDownloading: %s / %s (%.1f%%)",
			bloom.FormatSize(downloaded), bloom.FormatSize(total), pct)
	})
	fmt.Println()

	if err != nil {
		return fmt.Errorf("downloading bloom filter: %w", err)
	}

	bloomPath, _ := bloom.GetBloomPath()
	ui.PrintSuccess(fmt.Sprintf("Bloom filter saved to: %s", bloomPath))
	return nil
}
