package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/sud0x0/bsau/internal/brew"
	"github.com/sud0x0/bsau/internal/logger"
	"github.com/sud0x0/bsau/internal/ollama"
	"github.com/sud0x0/bsau/internal/semgrep"
	"github.com/sud0x0/bsau/internal/snapshot"
	"github.com/sud0x0/bsau/internal/state"
	"github.com/sud0x0/bsau/internal/ui"
	"github.com/sud0x0/bsau/internal/vuln"
)

var (
	noOllama  bool
	noSemgrep bool
	dryRun    bool
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Scan and update Homebrew packages",
	Long: `Run executes the full bsau workflow:

1. Identify and audit current state (packages, CVEs)
2. Identify what needs to be updated
3. Pre-install security scan (local LLM formula analysis)
4. Per-package approval gate
5. Upgrade approved packages (with pre-upgrade snapshot)
6. Post-install verification (Semgrep, local LLM code analysis)
7. Cleanup`,
	RunE: runWorkflow,
}

func init() {
	runCmd.Flags().BoolVar(&noOllama, "no-ollama", false, "skip local LLM analysis for this run")
	runCmd.Flags().BoolVar(&noSemgrep, "no-semgrep", false, "skip Semgrep scan for this run")
	runCmd.Flags().BoolVar(&dryRun, "dry-run", false, "run scans but do not upgrade")
}

func runWorkflow(cmd *cobra.Command, args []string) error {
	// Apply CLI overrides
	cfg.NoOllama = noOllama
	cfg.NoSemgrep = noSemgrep
	cfg.DryRun = dryRun

	// Close logger at the end
	defer logger.Close()

	// Initialize run manager (creates /tmp/bsau-<run-id>/)
	runMgr, err := state.NewRunManager()
	if err != nil {
		return fmt.Errorf("initializing run manager: %w", err)
	}
	defer func() { _ = runMgr.Cleanup() }()
	logger.Info("Run directory: %s", runMgr.RunDir())

	// Initialize signal handler for graceful CTRL+C handling
	sigHandler := ui.NewSignalHandler()
	sigHandler.SetCleanup(func() {
		ui.PrintInfo("Cleaning up...")
		_ = runMgr.Cleanup()
	})
	sigHandler.Start()
	defer sigHandler.Stop()

	// Initialize clients
	brewClient := brew.NewClient(cfg.HomebrewPath)
	vulnScanner := vuln.NewScanner()
	prompter := ui.NewPrompter()

	// Track failures throughout the workflow
	var failures []ui.ScanFailure

	// === Step 1: Identify and audit current state ===
	ui.PrintStep(1, 7, "Identify and Audit Current State",
		"Scanning Homebrew packages, checking for outdated versions, and querying OSV/NIST NVD for vulnerabilities.")

	outdated, err := brewClient.GetOutdated()
	if err != nil {
		return fmt.Errorf("getting outdated packages: %w", err)
	}

	if len(outdated) == 0 {
		ui.PrintSuccess("All packages are up to date!")
		return nil
	}

	ui.PrintInfo(fmt.Sprintf("Found %d outdated package(s)", len(outdated)))

	// Get pinned packages
	pinnedPkgs, _ := brewClient.GetPinnedPackages()
	pinnedSet := make(map[string]bool)
	for _, p := range pinnedPkgs {
		pinnedSet[p] = true
	}

	// Query OSV and NIST NVD APIs for vulnerabilities
	ui.PrintInfo("Scanning for known vulnerabilities...")
	packageInfos := make([]vuln.PackageInfo, len(outdated))
	for i, pkg := range outdated {
		packageInfos[i] = vuln.PackageInfo{
			Name:      pkg.Name,
			Version:   pkg.InstalledVersion,
			SourceURL: pkg.SourceURL,
		}
	}

	vulnResults, vulnStats, err := vulnScanner.QueryPackages(packageInfos)
	if err != nil {
		ui.PrintWarning(fmt.Sprintf("OSV API query failed: %v", err))
		// Create placeholder results for all packages
		vulnResults = make(map[string]*vuln.VulnResult)
		for _, pkg := range outdated {
			vulnResults[pkg.Name] = &vuln.VulnResult{
				Package:     pkg.Name,
				Version:     pkg.InstalledVersion,
				MaxSeverity: ui.SeverityNA,
			}
		}
		failures = append(failures, ui.ScanFailure{
			Package: "all",
			Step:    "OSV API",
			Error:   err.Error(),
		})
	} else if vulnStats != nil && vulnStats.FetchErrors > 0 {
		ui.PrintWarning(fmt.Sprintf("Failed to fetch details for %d/%d vulnerabilities (severity may show as UNKNOWN)",
			vulnStats.FetchErrors, vulnStats.TotalVulns))
	}

	// Display query statistics
	if vulnStats != nil {
		ui.PrintInfo(fmt.Sprintf("Query methods: %d via OSV, %d via NIST NVD, %d skipped",
			vulnStats.OSVQueries, vulnStats.NVDQueries, vulnStats.PackagesSkipped))
	}

	// Save pre-update vulnerability results to run-scoped state
	preUpdateVulns := make(map[string]interface{})
	for name, result := range vulnResults {
		preUpdateVulns[name] = map[string]interface{}{
			"package":      result.Package,
			"version":      result.Version,
			"cve_count":    result.CVECount,
			"max_severity": string(result.MaxSeverity),
		}
	}
	if err := runMgr.SavePreUpdateVulns(preUpdateVulns); err != nil {
		ui.PrintWarning(fmt.Sprintf("Failed to save pre-update vuln state: %v", err))
	}

	// === Step 2: Identify what needs to be updated ===
	ui.PrintStep(2, 7, "Identify What Needs to Be Updated",
		"Displaying outdated packages with vulnerability info. Select which packages to update.")

	// Warn about skipped packages (no GitHub URL or unsupported registry)
	if vulnStats != nil && vulnStats.PackagesSkipped > 0 {
		ui.PrintWarning(fmt.Sprintf("%d package(s) could not be queried for vulnerabilities (no GitHub source URL or unsupported registry)",
			vulnStats.PackagesSkipped))
	}

	// Get package names for dependency check
	outdatedNames := make([]string, len(outdated))
	for i, pkg := range outdated {
		outdatedNames[i] = pkg.Name
	}

	// Get dependency maps
	ui.PrintInfo("Checking package dependencies...")
	dependentsMap := brewClient.GetAllDependents(outdatedNames)     // packages that depend ON each package
	dependenciesMap := brewClient.GetAllDependencies(outdatedNames) // packages that each package DEPENDS on

	// Build table rows and selector items
	rows := make([]ui.PackageRow, 0, len(outdated))
	selectorItems := make([]ui.PackageItem, 0, len(outdated))
	hasUpdatable := false

	for _, pkg := range outdated {
		vr := vulnResults[pkg.Name]
		isPinned := pkg.Pinned || pinnedSet[pkg.Name]

		if !isPinned {
			hasUpdatable = true
		}

		action := "Update"
		if isPinned {
			action = "Pinned"
		}

		rows = append(rows, ui.PackageRow{
			Package:   pkg.Name,
			Current:   pkg.InstalledVersion,
			Available: pkg.CurrentVersion,
			Pinned:    isPinned,
			CVECount:  vr.CVECount,
			Severity:  vr.MaxSeverity,
			Action:    action,
		})

		selectorItems = append(selectorItems, ui.PackageItem{
			Name:         pkg.Name,
			Current:      pkg.InstalledVersion,
			Latest:       pkg.CurrentVersion,
			CVECount:     vr.CVECount,
			Severity:     vr.MaxSeverity,
			Pinned:       isPinned,
			Selected:     !isPinned, // Pre-select non-pinned packages
			Dependents:   dependentsMap[pkg.Name],
			Dependencies: dependenciesMap[pkg.Name],
		})
	}

	// Display the summary table first
	fmt.Println()
	ui.RenderPackageTable(rows)

	// Warn about pinned packages with CVEs
	for _, pkg := range outdated {
		isPinned := pkg.Pinned || pinnedSet[pkg.Name]
		if isPinned && vulnResults[pkg.Name].CVECount > 0 {
			ui.PrintWarning(fmt.Sprintf("Pinned package %s has %d known CVE(s)", pkg.Name, vulnResults[pkg.Name].CVECount))
		}
	}

	if !hasUpdatable {
		ui.PrintInfo("No packages available for update (all pinned)")
		return nil
	}

	// Package selection
	fmt.Println()
	ui.PrintInfo("Press Enter to open package selector, or Esc to cancel...")
	if !prompter.WaitForEnterOrEsc() {
		ui.PrintInfo("Cancelled")
		return nil
	}

	selectedPkgs, err := prompter.SelectPackagesInteractive(selectorItems)
	if err != nil {
		return fmt.Errorf("selecting packages: %w", err)
	}

	if len(selectedPkgs) == 0 {
		ui.PrintInfo("No packages selected for update")
		return nil
	}

	// === Step 3: Pre-install security scan (Ollama formula analysis) ===
	ui.PrintStep(3, 7, "Pre-install Security Scan",
		"Analyzing formula files with Ollama to detect malicious patterns before upgrade.")

	var ollamaClient *ollama.Client
	formulaResults := make(map[string]*ollama.FormulaAnalysisResult)

	// Show scan status
	fmt.Println("Scan status:")
	if !cfg.IsOllamaEnabled() {
		ui.PrintSkipped("Ollama formula analysis: disabled (enable with 'ollama_scan: true' in settings.yaml)")
		fmt.Println()
	} else {
		ui.PrintInfo("Ollama formula analysis: enabled")
		fmt.Println()
		ollamaClient = ollama.NewClient(cfg.OllamaURL, cfg.OllamaModel, cfg.OllamaMaxFileBytes)
		// Check if Ollama is actually running
		if err := ollamaClient.CheckAvailability(); err != nil {
			ui.PrintWarning(fmt.Sprintf("Ollama not available: %v", err))
			ui.PrintWarning("Make sure Ollama is running with: ollama serve")
			ollamaClient = nil
		}

		if ollamaClient != nil {
			ollamaProgress := ui.NewProgress("Analyzing formulas", len(selectedPkgs))
			for _, pkgName := range selectedPkgs {
				ollamaProgress.Update(pkgName)
				versions, err := brewClient.GetFormulaVersions(pkgName)
				if err != nil {
					ollamaProgress.Clear()
					ui.PrintWarning(fmt.Sprintf("Failed to get formula for %s: %v", pkgName, err))
					continue
				}

				result, err := ollamaClient.AnalyzeFormula(pkgName, versions)
				if err != nil {
					ollamaProgress.Clear()
					ui.PrintWarning(fmt.Sprintf("Ollama analysis failed for %s: %v", pkgName, err))
					result = &ollama.FormulaAnalysisResult{
						Package: pkgName,
						Verdict: ollama.VerdictReview,
					}
				}
				formulaResults[pkgName] = result
			}
			ollamaProgress.Done()
		}

		// Save Ollama formula analysis results to run-scoped state
		scanResults := make(map[string]interface{})
		for name, result := range formulaResults {
			scanResults[name] = map[string]interface{}{
				"package":    result.Package,
				"verdict":    string(result.Verdict),
				"confidence": result.Confidence,
				"findings":   result.Findings,
			}
		}
		if err := runMgr.SaveScanResults(scanResults); err != nil {
			ui.PrintWarning(fmt.Sprintf("Failed to save scan results: %v", err))
		}
	}

	// === Step 4: Per-package approval gate ===
	ui.PrintStep(4, 7, "Per-Package Approval Gate",
		"Review scan results and approve packages for upgrade. Blocked packages require manual review.")

	preInstallRows := make([]ui.PreInstallRow, 0, len(selectedPkgs))
	approvedPkgs := make([]string, 0)

	for _, pkgName := range selectedPkgs {
		vr := vulnResults[pkgName]
		fr := formulaResults[pkgName]

		recommendation := "PROCEED"
		var verdict ollama.Verdict

		if fr != nil {
			verdict = fr.Verdict
			switch verdict {
			case ollama.VerdictHold:
				if cfg.BlockPolicy.OllamaFormulaHold {
					recommendation = "BLOCK"
				} else {
					recommendation = "REVIEW"
				}
			case ollama.VerdictReview:
				recommendation = "REVIEW"
			}
		}

		preInstallRows = append(preInstallRows, ui.PreInstallRow{
			Package:        pkgName,
			CVECount:       vr.CVECount,
			OllamaVerdict:  verdict,
			Recommendation: recommendation,
		})
	}

	fmt.Println()
	ui.RenderPreInstallTable(preInstallRows, cfg.IsOllamaEnabled())

	// Process approvals
	for _, row := range preInstallRows {
		if row.Recommendation == "BLOCK" {
			ui.PrintWarning(fmt.Sprintf("Package %s blocked: Ollama returned HOLD verdict", row.Package))
			continue
		}

		if row.Recommendation == "REVIEW" {
			approved, err := prompter.ConfirmPackageUpgrade(row.Package, row.OllamaVerdict, "Requires manual review")
			if err != nil {
				return fmt.Errorf("confirming upgrade: %w", err)
			}
			if !approved {
				continue
			}
		}

		approvedPkgs = append(approvedPkgs, row.Package)
	}

	if len(approvedPkgs) == 0 {
		ui.PrintInfo("No packages approved for upgrade")
		return nil
	}

	if dryRun {
		ui.PrintInfo("Dry run - skipping upgrades")
		fmt.Println("Would upgrade:", approvedPkgs)
		return nil
	}

	// === Step 5: Upgrade ===
	ui.PrintStep(5, 7, "Upgrade Packages",
		"Creating pre-upgrade snapshots and running brew upgrade for each approved package.")
	ui.PrintRunDir(runMgr.RunDir())
	ui.PrintInfo(fmt.Sprintf("Upgrading %d package(s)...", len(approvedPkgs)))

	// Mark as in-progress so CTRL+C prompts before exiting
	sigHandler.SetInProgress(true)

	snapshotMgr := snapshot.NewManager(runMgr.SnapshotsDir())
	upgraded := make([]struct {
		Name       string
		OldVersion string
		NewVersion string
	}, 0)
	failed := 0

	for _, pkgName := range approvedPkgs {
		// Get current version info
		var pkg brew.OutdatedPackage
		for _, p := range outdated {
			if p.Name == pkgName {
				pkg = p
				break
			}
		}

		// Check disk space for snapshot
		pkgPath := brewClient.PackagePath(pkgName, pkg.InstalledVersion)
		diskCheck, err := snapshotMgr.CheckDiskSpace(pkgPath)
		if err != nil {
			ui.PrintWarning(fmt.Sprintf("Failed to check disk space for %s: %v", pkgName, err))
		}

		snapshotPath := ""
		if diskCheck != nil {
			if diskCheck.SkipAutomatic {
				ui.PrintWarning(diskCheck.WarningMessage)
				ui.PrintWarning(fmt.Sprintf("Skipping snapshot for %s - post-install scan will be limited", pkgName))
			} else if diskCheck.NeedsPrompt {
				ui.PrintWarning(diskCheck.WarningMessage)
				proceed, _ := prompter.Confirm("Continue with snapshot?", false)
				if proceed {
					snapshotPath, _ = snapshotMgr.CreateSnapshot(pkgPath, pkgName, pkg.InstalledVersion)
				}
			} else if diskCheck.CanProceed {
				snapshotPath, err = snapshotMgr.CreateSnapshot(pkgPath, pkgName, pkg.InstalledVersion)
				if err != nil {
					ui.PrintWarning(fmt.Sprintf("Failed to create snapshot for %s: %v", pkgName, err))
				}
			}
		}

		// Run upgrade
		fmt.Printf("\n>>> Upgrading %s...\n", pkgName)
		if err := brewClient.Upgrade(pkgName); err != nil {
			ui.PrintError(fmt.Sprintf("Failed to upgrade %s: %v", pkgName, err))
			failed++
			// Clean up snapshot on failure
			if snapshotPath != "" {
				_ = snapshotMgr.Cleanup(pkgName)
			}
			break // Don't continue on failure per spec
		}

		// Get new version
		info, err := brewClient.Info(pkgName)
		if err != nil {
			ui.PrintWarning(fmt.Sprintf("Failed to get new version for %s: %v", pkgName, err))
			info = &brew.Package{Version: "unknown"}
		}

		upgraded = append(upgraded, struct {
			Name       string
			OldVersion string
			NewVersion string
		}{pkgName, pkg.InstalledVersion, info.Version})

		ui.PrintSuccess(fmt.Sprintf("Upgraded %s: %s -> %s", pkgName, pkg.InstalledVersion, info.Version))
	}

	// Upgrades complete, no longer in critical section
	sigHandler.SetInProgress(false)

	if len(upgraded) == 0 {
		ui.PrintError("No packages were upgraded")
		return nil
	}

	// === Step 6: Post-install verification ===
	ui.PrintStep(6, 7, "Post-Install Verification",
		"Verifying upgraded packages with Semgrep scan and local LLM code analysis.")

	// Track scan status for final report
	var semgrepStatus, ollamaStatus string

	// Show scan status
	fmt.Println("Scan status:")

	// Initialize Semgrep
	var semgrepRunner *semgrep.Runner
	if cfg.NoSemgrep {
		ui.PrintSkipped("Semgrep scan: skipped (--no-semgrep)")
		semgrepStatus = "skipped (--no-semgrep)"
	} else {
		semgrepRunner, err = semgrep.NewRunner()
		if err != nil {
			ui.PrintSkipped(fmt.Sprintf("Semgrep scan: not available (%v)", err))
			semgrepStatus = fmt.Sprintf("not run (not available: %v)", err)
		} else {
			ui.PrintInfo("Semgrep scan: enabled")
			semgrepStatus = "completed"
		}
	}

	// Ollama code analysis status
	if cfg.IsOllamaEnabled() && ollamaClient != nil {
		ui.PrintInfo("Local LLM code analysis: enabled")
		ollamaStatus = "completed"
	} else if cfg.NoOllama {
		ui.PrintSkipped("Local LLM code analysis: skipped (--no-ollama)")
		ollamaStatus = "skipped (--no-ollama)"
	} else if !cfg.Features.OllamaScan {
		ui.PrintSkipped("Local LLM code analysis: disabled in config")
		ollamaStatus = "disabled in config"
	} else {
		ui.PrintSkipped("Local LLM code analysis: not available (Ollama not running)")
		ollamaStatus = "not run (Ollama not running)"
	}
	fmt.Println()

	postInstallRows := make([]ui.PostInstallRow, 0, len(upgraded))
	semgrepResultsMap := make(map[string]interface{})

	verifyProgress := ui.NewProgress("Verifying packages", len(upgraded))
	for _, pkg := range upgraded {
		verifyProgress.Update(pkg.Name)
		row := ui.PostInstallRow{
			Package: pkg.Name,
			Overall: "OK",
		}

		// Semgrep scan
		verifyProgress.Update(fmt.Sprintf("%s (semgrep)", pkg.Name))
		if semgrepRunner != nil {
			semgrepResult, err := semgrepRunner.ScanPackage(
				brewClient.CellarPath(),
				pkg.Name,
				pkg.NewVersion,
			)
			if err != nil {
				verifyProgress.Clear()
				ui.PrintWarning(fmt.Sprintf("Semgrep scan failed for %s: %v", pkg.Name, err))
				failures = append(failures, ui.ScanFailure{
					Package: pkg.Name,
					Step:    "Semgrep",
					Error:   err.Error(),
				})
			} else {
				row.SemgrepCount = semgrepResult.FindingCount
				if semgrepResult.HasFindings && row.Overall == "OK" {
					row.Overall = "REVIEW"
				}
				// Store semgrep results for saving
				semgrepResultsMap[pkg.Name] = map[string]interface{}{
					"finding_count": semgrepResult.FindingCount,
					"has_findings":  semgrepResult.HasFindings,
					"findings":      semgrepResult.Findings,
				}
			}
		}

		// Diff and Ollama code analysis
		if cfg.IsOllamaEnabled() && ollamaClient != nil {
			// Generate diff if we have a snapshot
			snapshotPath := runMgr.PackageSnapshotDir(pkg.Name, pkg.OldVersion)
			newPath := brewClient.PackagePath(pkg.Name, pkg.NewVersion)

			diff, err := snapshotMgr.GenerateDiff(snapshotPath, newPath)
			if err == nil && diff != "" {
				semgrepFindings := ""
				if semgrepRunner != nil {
					semgrepResult, _ := semgrepRunner.ScanPackage(brewClient.CellarPath(), pkg.Name, pkg.NewVersion)
					if semgrepResult != nil {
						semgrepFindings = semgrep.FormatFindings(semgrepResult.Findings)
					}
				}

				codeResult, err := ollamaClient.AnalyzeCode(pkg.Name, pkg.OldVersion, pkg.NewVersion, diff, semgrepFindings)
				if err != nil {
					ui.PrintWarning(fmt.Sprintf("Ollama code analysis failed for %s: %v", pkg.Name, err))
					failures = append(failures, ui.ScanFailure{
						Package: pkg.Name,
						Step:    "Ollama Code",
						Error:   err.Error(),
					})
				} else {
					row.OllamaVerdict = codeResult.Verdict
					if codeResult.Verdict == ollama.VerdictHold {
						if cfg.BlockPolicy.OllamaCodeHold {
							row.Overall = "BLOCK"
							ui.PrintError(fmt.Sprintf("Package %s flagged by Ollama - consider `brew uninstall %s`", pkg.Name, pkg.Name))
						} else {
							row.Overall = "REVIEW"
						}
					}
				}
			}
		}

		// Cleanup snapshot after analysis
		_ = runMgr.CleanupPackageSnapshot(pkg.Name)

		postInstallRows = append(postInstallRows, row)
	}
	verifyProgress.Done()

	// Save semgrep results to run-scoped state
	if len(semgrepResultsMap) > 0 {
		if err := runMgr.SaveSemgrepResults(semgrepResultsMap); err != nil {
			ui.PrintWarning(fmt.Sprintf("Failed to save semgrep results: %v", err))
		}
	}

	// === Post-update summary ===
	ui.PrintInfo("Post-update summary:")
	fmt.Println()
	ui.RenderPostInstallTable(postInstallRows, cfg.IsOllamaEnabled())

	// Re-check vulnerabilities for summary using osv-scanner
	cvesResolved := 0
	cvesRemaining := 0

	// Build package info for post-upgrade OSV query
	postPackageInfos := make([]vuln.PackageInfo, len(upgraded))
	for i, pkg := range upgraded {
		// Find the source URL from the original outdated list
		sourceURL := ""
		for _, op := range outdated {
			if op.Name == pkg.Name {
				sourceURL = op.SourceURL
				break
			}
		}
		postPackageInfos[i] = vuln.PackageInfo{
			Name:      pkg.Name,
			Version:   pkg.NewVersion,
			SourceURL: sourceURL,
		}
	}

	ui.PrintInfo("Checking post-upgrade vulnerabilities...")
	postVulnResults, postVulnStats, err := vulnScanner.QueryPackages(postPackageInfos)
	if err != nil {
		ui.PrintWarning(fmt.Sprintf("Post-upgrade OSV query failed: %v", err))
		failures = append(failures, ui.ScanFailure{
			Package: "all",
			Step:    "Post-upgrade OSV",
			Error:   err.Error(),
		})
	} else if postVulnStats != nil && postVulnStats.FetchErrors > 0 {
		ui.PrintWarning(fmt.Sprintf("Failed to fetch details for %d/%d post-upgrade vulnerabilities (severity may show as UNKNOWN)",
			postVulnStats.FetchErrors, postVulnStats.TotalVulns))
	}

	for _, pkg := range upgraded {
		preCount := 0
		if preResult, ok := vulnResults[pkg.Name]; ok {
			preCount = preResult.CVECount
		}
		postCount := 0
		if postResult, ok := postVulnResults[pkg.Name]; ok {
			postCount = postResult.CVECount
		}
		if preCount > postCount {
			cvesResolved += preCount - postCount
		}
		cvesRemaining += postCount
	}

	ui.RenderSummary(len(upgraded), failed, cvesResolved, cvesRemaining)

	// Render failure summary if there were any failures
	if len(failures) > 0 {
		ui.RenderFailureSummary(failures, len(outdated))
	}

	// === Step 7: Cleanup ===
	ui.PrintStep(7, 7, "Cleanup",
		"Removing temporary files and running brew cleanup to free disk space.")

	// Clean up temporary run directory (snapshots, state files)
	ui.PrintInfo("Cleaning up temporary files...")
	if err := runMgr.Cleanup(); err != nil {
		ui.PrintWarning(fmt.Sprintf("Failed to cleanup run directory: %v", err))
	} else {
		ui.PrintSuccess("Temporary files removed")
	}

	// Run brew cleanup to remove old versions
	ui.PrintInfo("Running brew cleanup...")
	if err := brewClient.Cleanup(); err != nil {
		ui.PrintWarning(fmt.Sprintf("Brew cleanup failed: %v", err))
	} else {
		ui.PrintSuccess("Brew cleanup complete")
	}

	// Final scan status summary
	fmt.Println()
	fmt.Println("=== Scan Summary ===")
	fmt.Printf("Vulnerability scan: completed\n")
	fmt.Printf("Semgrep scan: %s\n", semgrepStatus)
	fmt.Printf("Local LLM analysis: %s\n", ollamaStatus)

	// Display vulnerability report
	hasVulns := false
	for _, vr := range vulnResults {
		if vr.CVECount > 0 {
			hasVulns = true
			break
		}
	}
	if hasVulns {
		fmt.Println()
		vulnReport := vuln.GenerateVulnReport(vulnResults)
		fmt.Print(vulnReport)
	}

	fmt.Println()
	ui.PrintSuccess("All done!")

	return nil
}
