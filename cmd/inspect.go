package cmd

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/sud0x0/bsau/internal/brew"
	"github.com/sud0x0/bsau/internal/config"
	"github.com/sud0x0/bsau/internal/llm"
	"github.com/sud0x0/bsau/internal/logger"
	"github.com/sud0x0/bsau/internal/snapshot"
	"github.com/sud0x0/bsau/internal/ui"
	"github.com/sud0x0/bsau/internal/vuln"
	"github.com/sud0x0/bsau/internal/yara"
)

var (
	inspectNoVuln bool
	inspectNoYara bool
	inspectNoLLM  bool
	inspectAll    bool
)

var inspectCmd = &cobra.Command{
	Use:   "inspect [package]",
	Short: "Scan current installation without upgrading",
	Long: `Inspect runs security checks against the current installed state
of your Homebrew packages without any upgrade.

By default, runs all checks: Vulnerability scan + YARA + LLM (if enabled).
Use --no-vuln, --no-yara, or --no-llm to skip specific checks.

Note: Both YARA and LLM can miss sophisticated attacks - using both provides defense in depth.

Examples:
  bsau inspect                       # Show this help menu
  bsau inspect <package>             # Scan specific package (all checks)
  bsau inspect --all                 # Scan all installed packages
  bsau inspect <package> --no-llm    # Skip LLM analysis
  bsau inspect <package> --no-llm --no-yara  # Vulnerability scan only`,
	RunE: runInspect,
}

func init() {
	inspectCmd.Flags().BoolVar(&inspectNoVuln, "no-vuln", false, "skip vulnerability scan")
	inspectCmd.Flags().BoolVar(&inspectNoYara, "no-yara", false, "skip YARA scan")
	inspectCmd.Flags().BoolVar(&inspectNoLLM, "no-llm", false, "skip LLM analysis")
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
	// By default, run all checks (vuln, YARA, LLM if enabled)
	runVulnCheck := !inspectNoVuln
	runYaraCheck := !inspectNoYara
	runLLMCheck := !inspectNoLLM && cfg.IsLLMEnabled()

	// If all scans are disabled, show error
	if !runVulnCheck && !runYaraCheck && !runLLMCheck {
		ui.PrintError("No scans enabled. At least one scan type must be enabled.")
		ui.PrintInfo("Remove one of: --no-vuln, --no-yara, --no-llm")
		return nil
	}

	// Initialize signal handler for graceful CTRL+C handling
	sigHandler := ui.NewSignalHandler()
	sigHandler.Start()
	defer sigHandler.Stop()

	// Warn if LLM is requested but not available
	if !inspectNoLLM && !cfg.IsLLMEnabled() {
		ui.PrintWarning("LLM is not enabled in config.")
		ui.PrintInfo("To enable LLM, set features.llm_scan: true in settings.yaml")
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
		var vulnStats *vuln.QueryStats
		vulnResults, vulnStats, err = vulnScanner.QueryPackages(packageInfos)
		if err != nil {
			ui.PrintWarning(fmt.Sprintf("Vulnerability scan failed: %v", err))
			logger.Error("Vulnerability scan failed: %v", err)
		} else {
			// Log results
			for name, vr := range vulnResults {
				logger.VulnResult(name, vr.CVECount, string(vr.MaxSeverity))
			}
		}

		// If NVD queries failed, ask user whether to proceed
		if vulnStats != nil && vulnStats.NVDFailures > 0 {
			fmt.Println()
			ui.PrintWarning(fmt.Sprintf("NVD queries failed for %d package(s): %v",
				vulnStats.NVDFailures, vulnStats.NVDFailedPkgs))
			ui.PrintWarning("CVE data from NVD may be incomplete for these packages.")
			prompter := ui.NewPrompter()
			proceed, promptErr := prompter.Confirm("Continue with potentially incomplete vulnerability data?", true)
			if promptErr != nil {
				return fmt.Errorf("reading user input: %w", promptErr)
			}
			if !proceed {
				ui.PrintInfo("Aborting. Try again later when NVD API is available.")
				return fmt.Errorf("user cancelled due to NVD query failures")
			}
		}
	}

	// Mark as in-progress so CTRL+C prompts before exiting
	sigHandler.SetInProgress(true)
	defer sigHandler.SetInProgress(false)

	var yaraEngine *yara.Engine
	if runYaraCheck {
		var err error
		yaraEngine, err = yara.New(cfg.YaraRulesDir, 30*time.Second)
		if err != nil {
			ui.PrintWarning(fmt.Sprintf("YARA not available: %v", err))
		} else {
			defer func() { _ = yaraEngine.Close() }()
		}
	}

	var llmProvider llm.Provider
	if runLLMCheck {
		var err error
		llmProvider, err = llm.New(cfg.Features.LLMProvider, cfg.LLMModel, cfg.LLMURL, cfg.LLMMaxFileBytes)
		if err != nil {
			ui.PrintWarning(fmt.Sprintf("LLM not available: %v", err))
			logger.Warn("LLM not available: %v", err)
			runLLMCheck = false
		} else {
			// Check if LLM is actually available
			if err := llmProvider.CheckAvailability(); err != nil {
				ui.PrintWarning(fmt.Sprintf("LLM not available: %v", err))
				if cfg.Features.LLMProvider == config.ProviderOllama {
					ui.PrintWarning("Make sure Ollama is running with: ollama serve")
				}
				logger.Warn("LLM not available: %v", err)
				runLLMCheck = false
			}
		}
	}

	// If LLM was requested but is not available, ask user whether to proceed
	if cfg.IsLLMEnabled() && !inspectNoLLM && !runLLMCheck {
		fmt.Println()
		prompter := ui.NewPrompter()
		proceed, err := prompter.Confirm("LLM analysis is unavailable. Continue without LLM code scan?", false)
		if err != nil {
			return fmt.Errorf("reading user input: %w", err)
		}
		if !proceed {
			ui.PrintInfo("Aborting. Please fix LLM configuration and try again.")
			return fmt.Errorf("user cancelled due to unavailable LLM")
		}
		ui.PrintInfo("Proceeding without LLM analysis...")
		fmt.Println()
	}

	// Run inspections
	results := make([]ui.PostInstallRow, 0, len(packages))
	type yaraFindingsWithPath struct {
		Findings []yara.Finding
		BasePath string
	}
	yaraFindingsForDisplay := make(map[string]yaraFindingsWithPath) // For displaying after table
	llmFindingsForDisplay := make(map[string][]llm.Finding)         // For displaying LLM findings after table

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

		// YARA scan
		var yaraFindings string
		if yaraEngine != nil {
			pkgPath := brewClient.PackagePath(pkg.Name, pkg.Version)
			logger.YaraScan(pkg.Name, pkgPath)
			yaraResult, err := yaraEngine.ScanDir(pkgPath)
			if err != nil {
				ui.PrintWarning(fmt.Sprintf("YARA scan failed for %s: %v", pkg.Name, err))
				logger.Error("YARA scan failed for %s: %v", pkg.Name, err)
			} else {
				row.YaraCount = yaraResult.FindingCount
				logger.YaraResult(pkg.Name, yaraResult.FindingCount)
				if yaraResult.HasFindings && row.Overall == "OK" {
					row.Overall = "REVIEW"
				}
				yaraFindings = yara.FormatFindings(yaraResult.Findings)
				// Store findings for display after table
				if yaraResult.HasFindings {
					yaraFindingsForDisplay[pkg.Name] = yaraFindingsWithPath{
						Findings: yaraResult.Findings,
						BasePath: pkgPath,
					}
				}
				// Log individual findings in verbose mode
				for _, f := range yaraResult.Findings {
					logger.YaraFinding(f.Path, f.RuleID, f.Severity)
				}
			}
		}

		// LLM analysis of ALL text files in the package
		if llmProvider != nil {
			pkgPath := brewClient.PackagePath(pkg.Name, pkg.Version)
			files, err := snapshot.CollectTextFiles(pkgPath, cfg.LLMMaxFileBytes)
			if err != nil {
				ui.PrintWarning(fmt.Sprintf("Failed to collect files for %s: %v", pkg.Name, err))
				logger.Error("Failed to collect files for %s: %v", pkg.Name, err)
			} else if len(files) > 0 {
				ui.PrintInfo(fmt.Sprintf("Analyzing %d text files for %s...", len(files), pkg.Name))
				logger.Info("LLM analyzing %d files for %s", len(files), pkg.Name)
				codeResult, err := llmProvider.AnalyzeFiles(pkg.Name, files, yaraFindings)
				if err != nil {
					ui.PrintWarning(fmt.Sprintf("LLM analysis failed for %s: %v", pkg.Name, err))
					logger.Error("LLM analysis failed for %s: %v", pkg.Name, err)
				} else {
					row.LLMVerdict = codeResult.Verdict
					logger.Result("LLM", pkg.Name, string(codeResult.Verdict))
					// Store findings for display after table
					if len(codeResult.Findings) > 0 {
						llmFindingsForDisplay[pkg.Name] = codeResult.Findings
					}
					if codeResult.Verdict == llm.VerdictHold {
						row.Overall = "HOLD"
					} else if codeResult.Verdict == llm.VerdictReview && row.Overall != "MALICIOUS" {
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
		ShowVuln: runVulnCheck,
		ShowYara: runYaraCheck,
		ShowLLM:  runLLMCheck,
	})

	// Display YARA findings details if any packages need review
	if len(yaraFindingsForDisplay) > 0 {
		fmt.Println()
		ui.PrintWarning("YARA findings requiring review:")
		for pkgName, data := range yaraFindingsForDisplay {
			fmt.Printf("\n  %s:\n", pkgName)
			fmt.Print(yara.FormatFindingsRelative(data.Findings, data.BasePath))
		}
		fmt.Println()
	}

	// Display LLM findings details if any packages need review
	if len(llmFindingsForDisplay) > 0 {
		fmt.Println()
		ui.PrintWarning("LLM code analysis findings requiring review:")
		for pkgName, findings := range llmFindingsForDisplay {
			fmt.Printf("\n  %s (%d findings):\n", pkgName, len(findings))
			for _, f := range findings {
				if f.LineNumber > 0 {
					fmt.Printf("    - %s:%d: %s\n", f.File, f.LineNumber, f.Description)
				} else if f.File != "" {
					fmt.Printf("    - %s: %s\n", f.File, f.Description)
				} else {
					fmt.Printf("    - %s\n", f.Description)
				}
			}
		}
		fmt.Println()
	}

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
