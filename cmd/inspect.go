package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/sud0x0/bsau/internal/brew"
	"github.com/sud0x0/bsau/internal/logger"
	"github.com/sud0x0/bsau/internal/ollama"
	"github.com/sud0x0/bsau/internal/semgrep"
	"github.com/sud0x0/bsau/internal/snapshot"
	"github.com/sud0x0/bsau/internal/ui"
	"github.com/sud0x0/bsau/internal/vuln"
)

var (
	inspectNoVuln    bool
	inspectNoSemgrep bool
	inspectNoOllama  bool
	inspectAll       bool
)

var inspectCmd = &cobra.Command{
	Use:   "inspect [package]",
	Short: "Scan current installation without upgrading",
	Long: `Inspect runs security checks against the current installed state
of your Homebrew packages without any upgrade.

By default, runs all checks: Vulnerability scan + Semgrep + Ollama (if enabled).
Use --no-vuln, --no-semgrep, or --no-ollama to skip specific checks.

Examples:
  bsau inspect                       # Show this help menu
  bsau inspect <package>             # Scan specific package (all checks)
  bsau inspect --all                 # Scan all installed packages
  bsau inspect <package> --no-ollama # Skip Ollama analysis
  bsau inspect <package> --no-ollama --no-semgrep  # Vulnerability scan only`,
	RunE: runInspect,
}

func init() {
	inspectCmd.Flags().BoolVar(&inspectNoVuln, "no-vuln", false, "skip vulnerability scan")
	inspectCmd.Flags().BoolVar(&inspectNoSemgrep, "no-semgrep", false, "skip Semgrep scan")
	inspectCmd.Flags().BoolVar(&inspectNoOllama, "no-ollama", false, "skip Ollama analysis")
	inspectCmd.Flags().BoolVar(&inspectAll, "all", false, "scan all installed packages")
}

func runInspect(cmd *cobra.Command, args []string) error {
	// Close logger at the end
	defer logger.Close()

	// If no args and no --all flag, show help
	if len(args) == 0 && !inspectAll {
		return cmd.Help()
	}

	// Determine which checks to run based on config and flags
	// By default, run all checks (vuln, Semgrep, Ollama if enabled)
	runVulnCheck := !inspectNoVuln
	runSemgrepCheck := !inspectNoSemgrep
	runOllamaCheck := !inspectNoOllama && cfg.IsOllamaEnabled()

	// If all scans are disabled, show error
	if !runVulnCheck && !runSemgrepCheck && !runOllamaCheck {
		ui.PrintError("No scans enabled. At least one scan type must be enabled.")
		ui.PrintInfo("Remove one of: --no-vuln, --no-semgrep, --no-ollama")
		return nil
	}

	// Initialize signal handler for graceful CTRL+C handling
	sigHandler := ui.NewSignalHandler()
	sigHandler.Start()
	defer sigHandler.Stop()

	// Warn if Ollama is requested but not available
	if !inspectNoOllama && !cfg.IsOllamaEnabled() {
		ui.PrintWarning("Ollama is not enabled in config.")
		ui.PrintInfo("To enable Ollama, set features.ollama_scan: true in settings.yaml")
	}

	// Initialize clients
	brewClient := brew.NewClient(cfg.HomebrewPath)

	// Determine packages to inspect
	var packages []brew.Package
	if len(args) > 0 {
		// Inspect specific package
		pkgName := args[0]
		info, err := brewClient.Info(pkgName)
		if err != nil {
			return fmt.Errorf("package %s not found: %w", pkgName, err)
		}
		packages = []brew.Package{*info}
	} else if inspectAll {
		// --all flag: inspect all installed packages
		var err error
		packages, err = brewClient.ListPackages()
		if err != nil {
			return fmt.Errorf("listing packages: %w", err)
		}
	} else {
		// Should not reach here due to help check above, but just in case
		return cmd.Help()
	}

	if len(packages) == 0 {
		ui.PrintInfo("No packages to inspect")
		return nil
	}
	ui.PrintInfo(fmt.Sprintf("Inspecting %d package(s)...", len(packages)))

	// Run vulnerability scan if enabled
	var vulnResults map[string]*vuln.VulnResult
	if runVulnCheck {
		logger.Section("Vulnerability Scan")
		ui.PrintInfo("Scanning for known vulnerabilities...")
		logger.VulnScan(len(packages))
		vulnScanner := vuln.NewScanner()
		packageInfos := make([]vuln.PackageInfo, len(packages))
		for i, pkg := range packages {
			packageInfos[i] = vuln.PackageInfo{
				Name:    pkg.Name,
				Version: pkg.Version,
			}
		}
		var err error
		vulnResults, _, err = vulnScanner.QueryPackages(packageInfos)
		if err != nil {
			ui.PrintWarning(fmt.Sprintf("Vulnerability scan failed: %v", err))
			logger.Error("Vulnerability scan failed: %v", err)
		} else {
			// Log results
			for name, vr := range vulnResults {
				logger.VulnResult(name, vr.CVECount, string(vr.MaxSeverity))
			}
		}
	}

	// Mark as in-progress so CTRL+C prompts before exiting
	sigHandler.SetInProgress(true)
	defer sigHandler.SetInProgress(false)

	var semgrepRunner *semgrep.Runner
	if runSemgrepCheck {
		var err error
		semgrepRunner, err = semgrep.NewRunner()
		if err != nil {
			ui.PrintWarning(fmt.Sprintf("Semgrep not available: %v", err))
		}
	}

	var ollamaClient *ollama.Client
	if runOllamaCheck {
		ollamaClient = ollama.NewClient(cfg.OllamaURL, cfg.OllamaModel, cfg.OllamaMaxFileBytes)
		// Check if Ollama is actually running
		if err := ollamaClient.CheckAvailability(); err != nil {
			ui.PrintWarning(fmt.Sprintf("Ollama not available: %v", err))
			ui.PrintWarning("Make sure Ollama is running with: ollama serve")
			logger.Warn("Ollama not available: %v", err)
			runOllamaCheck = false
		}
	}

	// Run inspections
	results := make([]ui.PostInstallRow, 0, len(packages))

	for _, pkg := range packages {
		row := ui.PostInstallRow{
			Package: pkg.Name,
			Version: pkg.Version,
			Overall: "OK",
		}

		// Add vulnerability info if available
		if vulnResults != nil {
			if vr, ok := vulnResults[pkg.Name]; ok {
				row.CVECount = vr.CVECount
				row.Severity = vr.MaxSeverity
				if vr.CVECount > 0 {
					row.Overall = "REVIEW"
				}
			}
		}

		// Semgrep scan
		var semgrepFindings string
		if semgrepRunner != nil {
			logger.SemgrepScan(pkg.Name, brewClient.PackagePath(pkg.Name, pkg.Version))
			semgrepResult, err := semgrepRunner.ScanPackage(
				brewClient.CellarPath(),
				pkg.Name,
				pkg.Version,
			)
			if err != nil {
				ui.PrintWarning(fmt.Sprintf("Semgrep failed for %s: %v", pkg.Name, err))
				logger.Error("Semgrep failed for %s: %v", pkg.Name, err)
			} else {
				row.SemgrepCount = semgrepResult.FindingCount
				logger.SemgrepResult(pkg.Name, semgrepResult.FindingCount)
				if semgrepResult.HasFindings && row.Overall == "OK" {
					row.Overall = "REVIEW"
				}
				semgrepFindings = semgrep.FormatFindings(semgrepResult.Findings)
				// Log individual findings in verbose mode
				for _, f := range semgrepResult.Findings {
					logger.SemgrepFinding(f.Path, f.Start.Line, f.CheckID, f.Extra.Severity)
				}
			}
		}

		// Ollama analysis of ALL text files in the package
		if ollamaClient != nil {
			pkgPath := brewClient.PackagePath(pkg.Name, pkg.Version)
			files, err := snapshot.CollectTextFiles(pkgPath, cfg.OllamaMaxFileBytes)
			if err != nil {
				ui.PrintWarning(fmt.Sprintf("Failed to collect files for %s: %v", pkg.Name, err))
				logger.Error("Failed to collect files for %s: %v", pkg.Name, err)
			} else if len(files) > 0 {
				ui.PrintInfo(fmt.Sprintf("Analyzing %d text files for %s...", len(files), pkg.Name))
				logger.Info("Ollama analyzing %d files for %s", len(files), pkg.Name)
				codeResult, err := ollamaClient.AnalyzeFiles(pkg.Name, files, semgrepFindings)
				if err != nil {
					ui.PrintWarning(fmt.Sprintf("Ollama analysis failed for %s: %v", pkg.Name, err))
					logger.Error("Ollama analysis failed for %s: %v", pkg.Name, err)
				} else {
					row.OllamaVerdict = codeResult.Verdict
					logger.Result("Ollama", pkg.Name, string(codeResult.Verdict))
					if codeResult.Verdict == ollama.VerdictHold {
						row.Overall = "HOLD"
					} else if codeResult.Verdict == ollama.VerdictReview && row.Overall != "MALICIOUS" {
						row.Overall = "REVIEW"
					}
				}
			}
		}

		results = append(results, row)
	}

	// Display results
	fmt.Println()
	ui.RenderInspectTable(results, ui.InspectTableOptions{
		ShowVuln:    runVulnCheck,
		ShowSemgrep: runSemgrepCheck,
		ShowOllama:  runOllamaCheck,
	})

	// Display vulnerability details if any found
	if runVulnCheck && len(vulnResults) > 0 {
		hasVulns := false
		for _, vr := range vulnResults {
			if vr.CVECount > 0 {
				hasVulns = true
				break
			}
		}
		if hasVulns {
			fmt.Println()
			report := vuln.GenerateVulnReport(vulnResults)
			fmt.Print(report)
		}
	}

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
