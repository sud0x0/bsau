package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/sud0x0/bsau/internal/bloom"
	"github.com/sud0x0/bsau/internal/brew"
	"github.com/sud0x0/bsau/internal/claude"
	"github.com/sud0x0/bsau/internal/hashlookup"
	"github.com/sud0x0/bsau/internal/semgrep"
	"github.com/sud0x0/bsau/internal/ui"
)

var (
	inspectCIRCL     bool
	inspectCIRCLFull bool
	inspectVT        bool
	inspectSemgrep   bool
	inspectClaude    bool
	inspectAll       bool
)

var inspectCmd = &cobra.Command{
	Use:   "inspect [package|file]",
	Short: "Scan current installation without upgrading",
	Long: `Inspect runs security checks against the current installed state
of your Homebrew packages without any upgrade.

Use flags to select which checks to run:
  --circl       Fast local hash lookup using bloom filter (~700MB, SHA-1)
  --circl-full  Full CIRCL API lookup (slow, requires package or file argument)
  --vt          CIRCL API + VirusTotal confirmation for malicious hashes
  --semgrep     Semgrep malicious code scan
  --claude      Semgrep + Claude analysis of flagged files
  --all         All of the above (uses bloom filter for hash checks)

Without an argument, inspect runs against all installed packages.
With a package argument, it scopes to that package only.
With a file path, --circl-full checks that single file against CIRCL API.

Examples:
  bsau inspect                     # Scan all packages (bloom + semgrep)
  bsau inspect wget                # Scan specific package
  bsau inspect --circl-full wget   # Full API lookup for package
  bsau inspect --circl-full /path/to/file   # Check single file

Note: --circl uses a local bloom filter for fast lookups. The bloom filter
contains SHA-1 hashes of known files from NSRL and other trusted sources.`,
	RunE: runInspect,
}

func init() {
	inspectCmd.Flags().BoolVar(&inspectCIRCL, "circl", false, "fast local bloom filter hash lookup")
	inspectCmd.Flags().BoolVar(&inspectCIRCLFull, "circl-full", false, "full CIRCL API lookup (package or file)")
	inspectCmd.Flags().BoolVar(&inspectVT, "vt", false, "CIRCL API + VT confirmation")
	inspectCmd.Flags().BoolVar(&inspectSemgrep, "semgrep", false, "run Semgrep scan only")
	inspectCmd.Flags().BoolVar(&inspectClaude, "claude", false, "run Semgrep + Claude analysis")
	inspectCmd.Flags().BoolVar(&inspectAll, "all", false, "run all checks")
}

func runInspect(cmd *cobra.Command, args []string) error {
	prompter := ui.NewPrompter()

	// Initialize signal handler for graceful CTRL+C handling
	sigHandler := ui.NewSignalHandler()
	sigHandler.Start()
	defer sigHandler.Stop()

	// Validate --circl-full requires package or file argument
	if inspectCIRCLFull && len(args) == 0 {
		return fmt.Errorf("--circl-full requires a package or file argument")
	}

	// Check if argument is a file path (for --circl-full single file lookup)
	var singleFilePath string
	if inspectCIRCLFull && len(args) > 0 {
		if info, err := os.Stat(args[0]); err == nil && !info.IsDir() {
			singleFilePath = args[0]
		}
	}

	// Determine which checks to run
	runBloom := inspectCIRCL || inspectAll        // Fast bloom filter lookup
	runCIRCLFull := inspectCIRCLFull || inspectVT // Full API lookup
	runVT := inspectVT                            // VT requires full CIRCL lookup
	runSemgrepCheck := inspectSemgrep || inspectClaude || inspectAll
	runClaudeCheck := inspectClaude || inspectAll

	// If no flags specified, default to bloom + Semgrep
	if !inspectCIRCL && !inspectCIRCLFull && !inspectVT && !inspectSemgrep && !inspectClaude && !inspectAll {
		runBloom = true
		runSemgrepCheck = true
	}

	// Validate requirements
	if runVT && !cfg.IsVTEnabled() {
		ui.PrintWarning("VT inspection requires features.vt_fallback: true and VIRUSTOTAL_API_KEY")
		runVT = false
	}

	if runClaudeCheck && !cfg.IsClaudeEnabled() {
		ui.PrintWarning("Claude inspection requires features.claude_scan: true and ANTHROPIC_API_KEY")
		runClaudeCheck = false
	}

	// Initialize clients
	brewClient := brew.NewClient(cfg.HomebrewPath)

	// Determine packages to inspect (skip if single file mode)
	var packages []brew.Package
	if singleFilePath == "" {
		if len(args) > 0 {
			// Inspect specific package
			pkgName := args[0]
			info, err := brewClient.Info(pkgName)
			if err != nil {
				return fmt.Errorf("package %s not found: %w", pkgName, err)
			}
			packages = []brew.Package{*info}
		} else {
			// Inspect all installed packages
			var err error
			packages, err = brewClient.ListPackages()
			if err != nil {
				return fmt.Errorf("listing packages: %w", err)
			}
		}
	}

	if singleFilePath == "" {
		if len(packages) == 0 {
			ui.PrintInfo("No packages to inspect")
			return nil
		}
		ui.PrintInfo(fmt.Sprintf("Inspecting %d package(s)...", len(packages)))
	}

	// Mark as in-progress so CTRL+C prompts before exiting
	sigHandler.SetInProgress(true)
	defer sigHandler.SetInProgress(false)

	// Initialize bloom checker for fast lookups
	var bloomChecker *hashlookup.BloomChecker
	if runBloom {
		if !bloom.Exists() {
			// Prompt user to download
			bloomPath, _ := bloom.GetBloomPath()
			ui.PrintWarning("Bloom filter not found. Download required for fast hash lookups.")
			fmt.Printf("URL: %s\n", bloom.BloomURL)
			fmt.Printf("Size: ~%s | Location: %s\n", bloom.FormatSize(bloom.ExpectedSize), bloomPath)
			proceed, _ := prompter.Confirm("Download now?", false)
			if !proceed {
				ui.PrintInfo("Skipping bloom filter checks. Use --circl-full for API lookups.")
				runBloom = false
			} else {
				ui.PrintInfo("Downloading bloom filter (this may take a few minutes)...")
				err := bloom.Download(func(downloaded, total int64) {
					pct := float64(downloaded) / float64(total) * 100
					fmt.Printf("\rDownloading: %s / %s (%.1f%%)",
						bloom.FormatSize(downloaded), bloom.FormatSize(total), pct)
				})
				fmt.Println() // newline after progress
				if err != nil {
					ui.PrintError(fmt.Sprintf("Failed to download bloom filter: %v", err))
					runBloom = false
				} else {
					ui.PrintSuccess("Bloom filter downloaded successfully")
				}
			}
		}

		if runBloom {
			var err error
			bloomChecker, err = hashlookup.NewBloomChecker()
			if err != nil {
				ui.PrintWarning(fmt.Sprintf("Failed to load bloom filter: %v", err))
			} else {
				// Check if server has a newer version
				updateInfo, err := bloom.CheckForUpdate()
				if err != nil {
					ui.PrintWarning(fmt.Sprintf("Could not check for bloom filter updates: %v", err))
					ui.PrintInfo(fmt.Sprintf("Using bloom filter (%s)", bloomChecker.AgeInfo()))
				} else if updateInfo.Available {
					ui.PrintWarning("Bloom filter update available (server ETag changed)")
					proceed, _ := prompter.Confirm("Update now?", false)
					if proceed {
						ui.PrintInfo("Downloading updated bloom filter...")
						if err := bloom.Download(func(downloaded, total int64) {
							pct := float64(downloaded) / float64(total) * 100
							fmt.Printf("\rDownloading: %s / %s (%.1f%%)",
								bloom.FormatSize(downloaded), bloom.FormatSize(total), pct)
						}); err != nil {
							fmt.Println()
							ui.PrintError(fmt.Sprintf("Failed to update bloom filter: %v", err))
						} else {
							fmt.Println()
							ui.PrintSuccess("Bloom filter updated")
							// Reload the filter
							bloomChecker, _ = hashlookup.NewBloomChecker()
						}
					}
				} else {
					ui.PrintInfo(fmt.Sprintf("Using bloom filter (%s)", bloomChecker.AgeInfo()))
				}
			}
		}
	}

	// Initialize full hash checker for API lookups
	var hashChecker *hashlookup.HashChecker
	if runCIRCLFull {
		var err error
		hashChecker, err = hashlookup.NewHashChecker(
			cfg.HashCheck.CIRCLURL,
			runVT,
			cfg.VTDailyLimit,
			cfg.VTRateLimitPerMinute,
		)
		if err != nil {
			return fmt.Errorf("initializing hash checker: %w", err)
		}

		// Handle single file lookup
		if singleFilePath != "" {
			ui.PrintInfo(fmt.Sprintf("Checking file: %s", singleFilePath))
			result := hashChecker.CheckFile(singleFilePath)

			// Display result
			fmt.Println()
			if result.Error != nil {
				ui.PrintError(fmt.Sprintf("Error: %v", result.Error))
				return nil
			}

			fmt.Printf("File:   %s\n", result.FilePath)
			fmt.Printf("SHA256: %s\n", result.Hash)
			fmt.Printf("Result: %s\n", result.Result)

			if result.CIRCLResult != nil && result.CIRCLResult.Response != nil {
				resp := result.CIRCLResult.Response
				fmt.Printf("\nCIRCL Info:\n")
				if resp.FileName != "" {
					fmt.Printf("  Known as: %s\n", resp.FileName)
				}
				if resp.ProductCode != "" {
					fmt.Printf("  Product:  %s\n", resp.ProductCode)
				}
			}

			// Color-coded verdict
			switch result.Result {
			case hashlookup.HashNotInCIRCL:
				ui.PrintInfo("Hash not found in CIRCL database (unknown file)")
			case hashlookup.HashNotFlaggedByCIRCL:
				ui.PrintSuccess("Hash found in CIRCL - known clean file")
			case hashlookup.HashCIRCLMalicious:
				ui.PrintError("CIRCL flagged this hash as MALICIOUS!")
			case hashlookup.HashVTConfirmed:
				ui.PrintError("VirusTotal CONFIRMED this file as malicious!")
			case hashlookup.HashVTClean:
				ui.PrintWarning("CIRCL flagged malicious but VirusTotal says clean")
			case hashlookup.HashVTNotFound:
				ui.PrintWarning("CIRCL flagged malicious, VirusTotal has no record")
			}

			return nil
		}

		ui.PrintWarning("Full CIRCL API lookup is slow. Use --circl (bloom filter) for faster scans.")
	}

	var semgrepRunner *semgrep.Runner
	if runSemgrepCheck {
		var err error
		semgrepRunner, err = semgrep.NewRunner()
		if err != nil {
			ui.PrintWarning(fmt.Sprintf("Semgrep not available: %v", err))
		} else {
			ui.PrintInfo("Updating Semgrep rules...")
			if err := semgrepRunner.Update(); err != nil {
				ui.PrintWarning(fmt.Sprintf("Failed to update Semgrep rules: %v", err))
			}
		}
	}

	var claudeClient *claude.Client
	if runClaudeCheck {
		var err error
		claudeClient, err = claude.NewClient(cfg.ClaudeModel, cfg.ClaudeMaxFileBytes)
		if err != nil {
			ui.PrintWarning(fmt.Sprintf("Failed to initialize Claude: %v", err))
			runClaudeCheck = false
		}
	}

	// Run inspections
	results := make([]ui.PostInstallRow, 0, len(packages))

	for _, pkg := range packages {
		row := ui.PostInstallRow{
			Package: pkg.Name,
			Overall: "OK",
		}

		// Bloom filter check (fast, local)
		if bloomChecker != nil {
			bloomResult, err := bloomChecker.CheckPackage(
				brewClient.CellarPath(),
				pkg.Name,
				pkg.Version,
			)
			if err != nil {
				ui.PrintWarning(fmt.Sprintf("Bloom check failed for %s: %v", pkg.Name, err))
			} else {
				// Display bloom result summary
				ui.PrintInfo(fmt.Sprintf("%s: %s", pkg.Name, bloomResult.Summary()))
				// If many unknown files, suggest full lookup
				if bloomResult.UnknownCount > 0 && float64(bloomResult.UnknownCount)/float64(bloomResult.TotalFiles) > 0.5 {
					row.Overall = "REVIEW"
				}
			}
		}

		// Full CIRCL API hash check (slow, detailed)
		if hashChecker != nil {
			hashProgress := func(current, total int, filename string) {
				// Skip output if signal handler is prompting user
				if sigHandler.IsPrompting() {
					return
				}
				// \r moves to start of line, \033[K clears to end of line
				fmt.Printf("\r\033[K[%s] Checking hash [%d/%d] %s",
					pkg.Name, current, total, truncateFilename(filename, 40))
			}
			hashResult, err := hashChecker.CheckPackageWithProgress(
				brewClient.CellarPath(),
				pkg.Name,
				pkg.Version,
				hashProgress,
			)
			fmt.Println() // Clear the progress line
			if err != nil {
				ui.PrintWarning(fmt.Sprintf("Hash check failed for %s: %v", pkg.Name, err))
			} else {
				row.CIRCLResult = hashResult.OverallResult

				if hashlookup.IsBlockingResult(hashResult.OverallResult) {
					row.Overall = "MALICIOUS"
					ui.PrintError(fmt.Sprintf("Package %s has malicious binaries!", pkg.Name))
				} else if hashlookup.RequiresPrompt(hashResult.OverallResult) {
					row.Overall = "WARNING"
				}

				// Set VT result string
				if runVT && hashResult.OverallResult == hashlookup.HashVTConfirmed {
					row.VTResult = "CONFIRMED"
				} else if runVT && hashResult.OverallResult == hashlookup.HashVTClean {
					row.VTResult = "CLEAN"
				} else if runVT && hashResult.OverallResult == hashlookup.HashVTNotFound {
					row.VTResult = "NOT_FOUND"
				}
			}
		}

		// Semgrep scan
		if semgrepRunner != nil {
			semgrepResult, err := semgrepRunner.ScanPackage(
				brewClient.CellarPath(),
				pkg.Name,
				pkg.Version,
			)
			if err != nil {
				ui.PrintWarning(fmt.Sprintf("Semgrep failed for %s: %v", pkg.Name, err))
			} else {
				row.SemgrepCount = semgrepResult.FindingCount
				if semgrepResult.HasFindings && row.Overall == "OK" {
					row.Overall = "REVIEW"
				}

				// Claude analysis of Semgrep-flagged files
				if claudeClient != nil && semgrepResult.HasFindings {
					flaggedPaths := semgrep.GetFlaggedFilePaths(semgrepResult.Findings)
					files := make(map[string]string)
					for _, path := range flaggedPaths {
						content, err := os.ReadFile(path)
						if err == nil {
							files[path] = string(content)
						}
					}

					if len(files) > 0 {
						semgrepFindings := semgrep.FormatFindings(semgrepResult.Findings)
						codeResult, err := claudeClient.AnalyzeFiles(pkg.Name, files, semgrepFindings)
						if err != nil {
							ui.PrintWarning(fmt.Sprintf("Claude analysis failed for %s: %v", pkg.Name, err))
						} else {
							row.ClaudeVerdict = codeResult.Verdict
							if codeResult.Verdict == claude.VerdictHold {
								row.Overall = "HOLD"
							} else if codeResult.Verdict == claude.VerdictReview && row.Overall != "MALICIOUS" {
								row.Overall = "REVIEW"
							}
						}
					}
				}
			}
		}

		results = append(results, row)
	}

	// Display results
	fmt.Println()
	ui.RenderPostInstallTable(results, runVT, runClaudeCheck)

	// Summary
	malicious := 0
	warnings := 0
	for _, r := range results {
		switch r.Overall {
		case "MALICIOUS", "HOLD":
			malicious++
		case "WARNING", "REVIEW":
			warnings++
		}
	}

	fmt.Println()
	if malicious > 0 {
		ui.PrintError(fmt.Sprintf("%d package(s) flagged as malicious", malicious))
	}
	if warnings > 0 {
		ui.PrintWarning(fmt.Sprintf("%d package(s) require review", warnings))
	}
	if malicious == 0 && warnings == 0 {
		ui.PrintSuccess("All packages clean")
	}

	return nil
}
