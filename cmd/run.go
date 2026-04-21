package cmd

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/sud0x0/bsau/internal/brew"
	"github.com/sud0x0/bsau/internal/config"
	"github.com/sud0x0/bsau/internal/llm"
	"github.com/sud0x0/bsau/internal/logger"
	"github.com/sud0x0/bsau/internal/report"
	"github.com/sud0x0/bsau/internal/snapshot"
	"github.com/sud0x0/bsau/internal/state"
	"github.com/sud0x0/bsau/internal/ui"
	"github.com/sud0x0/bsau/internal/vuln"
	"github.com/sud0x0/bsau/internal/yara"
)

var (
	noLLM  bool
	noYara bool
	dryRun bool
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Scan and update Homebrew packages",
	Long: `Run executes the full bsau workflow:

1. Identify and audit current state (packages, CVEs)
2. Identify what needs to be updated
3. Pre-install security scan (LLM formula analysis)
4. Per-package approval gate
5. Upgrade approved packages (with pre-upgrade snapshot)
6. Post-install verification (YARA, LLM code analysis)
7. Cleanup`,
	RunE: runWorkflow,
}

func init() {
	runCmd.Flags().BoolVar(&noLLM, "no-llm", false, "skip LLM analysis for this run")
	runCmd.Flags().BoolVar(&noYara, "no-yara", false, "skip YARA scan for this run")
	runCmd.Flags().BoolVar(&dryRun, "dry-run", false, "run scans but do not upgrade")
}

// upgradedPkg represents a package that was successfully upgraded
type upgradedPkg struct {
	Name       string
	OldVersion string
	NewVersion string
}

// Workflow holds all shared state for the bsau workflow
type Workflow struct {
	cfg            *config.Config
	brewClient     *brew.Client
	vulnScanner    *vuln.Scanner
	prompter       *ui.Prompter
	runMgr         *state.RunManager
	snapshotMgr    *snapshot.Manager
	sigHandler     *ui.SignalHandler
	llmProvider    llm.Provider
	yaraEngine     *yara.Engine
	scanReport     *report.Report
	failures       []ui.ScanFailure
	outdated       []brew.OutdatedPackage
	vulnResults    map[string]*vuln.VulnResult
	formulaResults map[string]*llm.FormulaAnalysisResult
	yaraStatus     string
	llmStatus      string
	llmError       string // Stores LLM error message from Step 3 for display in Step 6
}

// stepAudit executes Step 1: get outdated packages, query OSV/NVD, save pre-update vulns
func (w *Workflow) stepAudit() error {
	ui.PrintStep(1, 7, "Identify and Audit Current State",
		"Scanning Homebrew packages, checking for outdated versions, and querying OSV/NIST NVD for vulnerabilities.")
	logger.StepHeader(1, 7, "Identify and Audit Current State")

	outdated, err := w.brewClient.GetOutdated()
	if err != nil {
		return fmt.Errorf("getting outdated packages: %w", err)
	}
	w.outdated = outdated

	if len(w.outdated) == 0 {
		ui.PrintSuccess("All packages are up to date!")
		return nil
	}

	ui.PrintInfo(fmt.Sprintf("Found %d outdated package(s)", len(w.outdated)))

	// Query OSV and NIST NVD APIs for vulnerabilities
	ui.PrintInfo("Scanning for known vulnerabilities...")
	packageInfos := make([]vuln.PackageInfo, len(w.outdated))
	for i, pkg := range w.outdated {
		packageInfos[i] = vuln.PackageInfo{
			Name:    pkg.Name,
			Version: pkg.InstalledVersion,
		}
	}

	vulnResults, vulnStats, err := w.vulnScanner.QueryPackages(packageInfos)
	if err != nil {
		ui.PrintWarning(fmt.Sprintf("OSV API query failed: %v", err))
		// Create placeholder results for all packages
		vulnResults = make(map[string]*vuln.VulnResult)
		for _, pkg := range w.outdated {
			vulnResults[pkg.Name] = &vuln.VulnResult{
				Package:     pkg.Name,
				Version:     pkg.InstalledVersion,
				MaxSeverity: ui.SeverityNA,
			}
		}
		w.failures = append(w.failures, ui.ScanFailure{
			Package: "all",
			Step:    "OSV API",
			Error:   err.Error(),
		})
	} else if vulnStats != nil && vulnStats.FetchErrors > 0 {
		ui.PrintWarning(fmt.Sprintf("Failed to fetch details for %d/%d vulnerabilities (severity may show as UNKNOWN)",
			vulnStats.FetchErrors, vulnStats.TotalVulns))
	}
	w.vulnResults = vulnResults

	// Display query statistics
	if vulnStats != nil {
		ui.PrintInfo(fmt.Sprintf("Query methods: %d via OSV, %d via NIST NVD, %d skipped",
			vulnStats.OSVQueries, vulnStats.NVDQueries, vulnStats.PackagesSkipped))
	}

	// If NVD queries failed, ask user whether to proceed
	if vulnStats != nil && vulnStats.NVDFailures > 0 {
		fmt.Println()
		ui.PrintWarning(fmt.Sprintf("NVD queries failed for %d package(s): %v",
			vulnStats.NVDFailures, vulnStats.NVDFailedPkgs))
		ui.PrintWarning("CVE data from NVD may be incomplete for these packages.")
		proceed, err := w.prompter.Confirm("Continue with potentially incomplete vulnerability data?", true)
		if err != nil {
			return fmt.Errorf("reading user input: %w", err)
		}
		if !proceed {
			ui.PrintInfo("Aborting. Try again later when NVD API is available.")
			return fmt.Errorf("user cancelled due to NVD query failures")
		}
	}

	// Save pre-update vulnerability results to run-scoped state
	preUpdateVulns := make(map[string]interface{})
	for name, result := range w.vulnResults {
		preUpdateVulns[name] = map[string]interface{}{
			"package":      result.Package,
			"version":      result.Version,
			"cve_count":    result.CVECount,
			"max_severity": string(result.MaxSeverity),
		}
	}
	if err := w.runMgr.SavePreUpdateVulns(preUpdateVulns); err != nil {
		ui.PrintWarning(fmt.Sprintf("Failed to save pre-update vuln state: %v", err))
	}

	return nil
}

// stepSelectPackages executes Step 2: create report, build table rows, render table, interactive selector
// Returns the list of selected package names
func (w *Workflow) stepSelectPackages(pinnedSet map[string]bool) ([]string, error) {
	ui.PrintStep(2, 7, "Identify What Needs to Be Updated",
		"Displaying outdated packages with vulnerability info. Select which packages to update.")
	logger.StepHeader(2, 7, "Identify What Needs to Be Updated")

	// Create report file in binary directory
	binDir, err := config.GetBinaryDir()
	if err != nil {
		ui.PrintWarning(fmt.Sprintf("Could not get binary directory for report: %v", err))
		binDir = "."
	}
	scanReport, err := report.New(binDir)
	if err != nil {
		ui.PrintWarning(fmt.Sprintf("Could not create report file: %v", err))
	} else {
		ui.PrintInfo(fmt.Sprintf("Vulnerability report: %s", scanReport.FilePath()))
	}
	w.scanReport = scanReport

	// Warn about OSV/NVD coverage limitations
	ui.PrintWarning("CVE data sourced from OSV.dev and NIST NVD only. Additional vulnerabilities may exist in other databases.")

	// Get package names for dependency check
	outdatedNames := make([]string, len(w.outdated))
	for i, pkg := range w.outdated {
		outdatedNames[i] = pkg.Name
	}

	// Get dependency maps
	ui.PrintInfo("Checking package dependencies...")
	dependentsMap := w.brewClient.GetAllDependents(outdatedNames)
	dependenciesMap := w.brewClient.GetAllDependencies(outdatedNames)

	// Build table rows and selector items
	rows := make([]ui.PackageRow, 0, len(w.outdated))
	selectorItems := make([]ui.PackageItem, 0, len(w.outdated))
	hasUpdatable := false

	for _, pkg := range w.outdated {
		vr := w.vulnResults[pkg.Name]
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
			Selected:     !isPinned,
			Dependents:   dependentsMap[pkg.Name],
			Dependencies: dependenciesMap[pkg.Name],
		})

		// Add to report
		if w.scanReport != nil {
			w.scanReport.AddPackage(pkg.Name, pkg.InstalledVersion, pkg.CurrentVersion, vr.CVECount, string(vr.MaxSeverity))
			if len(vr.Vulns) > 0 {
				details := make([]string, 0, len(vr.Vulns))
				for _, v := range vr.Vulns {
					details = append(details, fmt.Sprintf("%s (%s)", v.ID, v.Severity))
				}
				w.scanReport.AddVulnDetails(pkg.Name, details)
			}
		}
	}

	// Write vulnerability section to report
	if w.scanReport != nil {
		if err := w.scanReport.WriteVulnSection(); err != nil {
			ui.PrintWarning(fmt.Sprintf("Failed to write vulnerability section to report: %v", err))
		}
	}

	// Display the summary table first
	fmt.Println()
	ui.RenderPackageTable(rows)

	// Display CVE details if any packages have vulnerabilities
	hasVulns := false
	for _, vr := range w.vulnResults {
		if vr.CVECount > 0 {
			hasVulns = true
			break
		}
	}
	if hasVulns {
		fmt.Println()
		ui.PrintWarning("CVE details:")
		for name, vr := range w.vulnResults {
			if vr.CVECount > 0 {
				fmt.Printf("\n  %s (%d CVEs):\n", name, vr.CVECount)
				for _, v := range vr.Vulns {
					fmt.Printf("    - %s [%s]\n", v.ID, v.Severity)
				}
			}
		}
		fmt.Println()
	}

	// Warn about pinned packages with CVEs
	for _, pkg := range w.outdated {
		isPinned := pkg.Pinned || pinnedSet[pkg.Name]
		if isPinned && w.vulnResults[pkg.Name].CVECount > 0 {
			ui.PrintWarning(fmt.Sprintf("Pinned package %s has %d known CVE(s)", pkg.Name, w.vulnResults[pkg.Name].CVECount))
		}
	}

	if !hasUpdatable {
		ui.PrintInfo("No packages available for update (all pinned)")
		return nil, nil
	}

	// Package selection
	fmt.Println()
	ui.PrintInfo("Press Enter to open package selector, or Esc to cancel...")
	if !w.prompter.WaitForEnterOrEsc() {
		ui.PrintInfo("Cancelled")
		return nil, nil
	}

	selectedPkgs, err := w.prompter.SelectPackagesInteractive(selectorItems)
	if err != nil {
		return nil, fmt.Errorf("selecting packages: %w", err)
	}

	return selectedPkgs, nil
}

// stepPreInstallScan executes Step 3: LLM formula analysis
func (w *Workflow) stepPreInstallScan(selectedPkgs []string) error {
	ui.PrintStep(3, 7, "Pre-install Security Scan",
		"Analyzing formula files with LLM to detect malicious patterns before upgrade.")
	logger.StepHeader(3, 7, "Pre-install Security Scan")

	w.formulaResults = make(map[string]*llm.FormulaAnalysisResult)

	// Show scan status
	fmt.Println("Scan status:")
	if !w.cfg.IsLLMEnabled() {
		ui.PrintSkipped("LLM formula analysis: disabled (enable with 'llm_scan: true' in settings.yaml)")
		// Mark all selected packages as skipped for formula analysis
		for _, pkgName := range selectedPkgs {
			if w.scanReport != nil {
				w.scanReport.SetFormulaAnalysis(pkgName, "disabled")
			}
		}
		fmt.Println()
		return nil
	}

	ui.PrintInfo("LLM formula analysis: enabled")
	fmt.Println()

	// Create LLM provider based on config
	var err error
	w.llmProvider, err = llm.New(w.cfg.Features.LLMProvider, w.cfg.LLMModel, w.cfg.LLMURL, w.cfg.LLMMaxFileBytes)
	if err != nil {
		w.llmError = err.Error()
		ui.PrintWarning(fmt.Sprintf("LLM not available: %v", err))
		w.llmProvider = nil
	}

	// Check if LLM is actually available
	if w.llmProvider != nil {
		if err := w.llmProvider.CheckAvailability(); err != nil {
			w.llmError = err.Error()
			ui.PrintWarning(fmt.Sprintf("LLM not available: %v", err))
			if w.cfg.Features.LLMProvider == config.ProviderOllama {
				ui.PrintWarning("Make sure Ollama is running with: ollama serve")
			}
			w.llmProvider = nil
		}
	}

	// If LLM is not available, ask user whether to proceed
	if w.llmProvider == nil {
		fmt.Println()
		proceed, err := w.prompter.Confirm("LLM analysis is unavailable. Continue without formula security scan?", false)
		if err != nil {
			return fmt.Errorf("reading user input: %w", err)
		}
		if !proceed {
			ui.PrintInfo("Aborting. Please fix LLM configuration and try again.")
			return fmt.Errorf("user cancelled due to unavailable LLM")
		}
		ui.PrintInfo("Proceeding without LLM formula analysis...")
		fmt.Println()
		// Mark all selected packages as skipped for formula analysis
		for _, pkgName := range selectedPkgs {
			if w.scanReport != nil {
				w.scanReport.SetFormulaAnalysis(pkgName, "skipped")
			}
		}
		return nil
	}

	if w.llmProvider != nil {
		llmProgress := ui.NewProgress("Analyzing formulas", len(selectedPkgs))
		for _, pkgName := range selectedPkgs {
			llmProgress.Update(pkgName)
			versions, err := w.brewClient.GetFormulaVersions(pkgName)
			if err != nil {
				llmProgress.Clear()
				ui.PrintWarning(fmt.Sprintf("Failed to get formula for %s: %v", pkgName, err))
				llmProgress.Skip()
				if w.scanReport != nil {
					w.scanReport.SetFormulaAnalysis(pkgName, "failed")
				}
				continue
			}

			result, err := w.llmProvider.AnalyzeFormula(pkgName, versions)
			if err != nil {
				llmProgress.Clear()
				ui.PrintWarning(fmt.Sprintf("LLM analysis failed for %s: %v", pkgName, err))
				result = &llm.FormulaAnalysisResult{
					Package: pkgName,
					Verdict: llm.VerdictReview,
				}
				if w.scanReport != nil {
					w.scanReport.SetFormulaAnalysis(pkgName, "failed")
				}
			} else if w.scanReport != nil {
				w.scanReport.SetFormulaAnalysis(pkgName, string(result.Verdict))
				// Add detailed findings to report
				if len(result.Findings) > 0 {
					reportFindings := make([]report.LLMFinding, len(result.Findings))
					for i, f := range result.Findings {
						reportFindings[i] = report.LLMFinding{
							File:        f.File,
							LineNumber:  f.LineNumber,
							Description: f.Description,
						}
					}
					w.scanReport.AddFormulaFindings(pkgName, reportFindings)
				}
			}
			w.formulaResults[pkgName] = result
		}
		llmProgress.Done()
	} else {
		// LLM not available, mark all as skipped
		for _, pkgName := range selectedPkgs {
			if w.scanReport != nil {
				w.scanReport.SetFormulaAnalysis(pkgName, "skipped")
			}
		}
	}

	// Save LLM formula analysis results to run-scoped state
	scanResults := make(map[string]interface{})
	for name, result := range w.formulaResults {
		scanResults[name] = map[string]interface{}{
			"package":    result.Package,
			"verdict":    string(result.Verdict),
			"confidence": result.Confidence,
			"findings":   result.Findings,
		}
	}
	if err := w.runMgr.SaveScanResults(scanResults); err != nil {
		ui.PrintWarning(fmt.Sprintf("Failed to save scan results: %v", err))
	}

	return nil
}

// stepApproval executes Step 4: approval gate; returns approved package names
func (w *Workflow) stepApproval(selectedPkgs []string) ([]string, error) {
	ui.PrintStep(4, 7, "Per-Package Approval Gate",
		"Review scan results and approve packages for upgrade. Blocked packages require manual review.")
	logger.StepHeader(4, 7, "Per-Package Approval Gate")

	preInstallRows := make([]ui.PreInstallRow, 0, len(selectedPkgs))
	approvedPkgs := make([]string, 0)

	for _, pkgName := range selectedPkgs {
		vr := w.vulnResults[pkgName]
		fr := w.formulaResults[pkgName]

		recommendation := "PROCEED"
		var verdict llm.Verdict

		if fr != nil {
			verdict = fr.Verdict
			switch verdict {
			case llm.VerdictHold:
				if w.cfg.BlockPolicy.LLMFormulaHold {
					recommendation = "BLOCK"
				} else {
					recommendation = "REVIEW"
				}
			case llm.VerdictReview:
				recommendation = "REVIEW"
			}
		}

		preInstallRows = append(preInstallRows, ui.PreInstallRow{
			Package:        pkgName,
			CVECount:       vr.CVECount,
			LLMVerdict:     verdict,
			Recommendation: recommendation,
		})
	}

	fmt.Println()
	ui.RenderPreInstallTable(preInstallRows, w.cfg.IsLLMEnabled())

	// Process approvals
	for _, row := range preInstallRows {
		if row.Recommendation == "BLOCK" {
			ui.PrintWarning(fmt.Sprintf("Package %s blocked: LLM returned HOLD verdict", row.Package))
			// Show findings if available
			if fr := w.formulaResults[row.Package]; fr != nil && len(fr.Findings) > 0 {
				for _, f := range fr.Findings {
					ui.PrintWarning(fmt.Sprintf("  - %s", f.Description))
				}
			}
			continue
		}

		if row.Recommendation == "REVIEW" {
			// Build reason from findings if available
			reason := "Requires manual review"
			if fr := w.formulaResults[row.Package]; fr != nil && len(fr.Findings) > 0 {
				reason = ""
				for _, f := range fr.Findings {
					if reason != "" {
						reason += "; "
					}
					reason += f.Description
				}
			}
			approved, err := w.prompter.ConfirmPackageUpgrade(row.Package, row.LLMVerdict, reason)
			if err != nil {
				return nil, fmt.Errorf("confirming upgrade: %w", err)
			}
			if !approved {
				continue
			}
		}

		approvedPkgs = append(approvedPkgs, row.Package)
	}

	return approvedPkgs, nil
}

// stepUpgrade executes Step 5: snapshot + brew upgrade; returns upgraded slice, failed count, and error
func (w *Workflow) stepUpgrade(approvedPkgs []string) ([]upgradedPkg, int, error) {
	ui.PrintStep(5, 7, "Upgrade Packages",
		"Creating pre-upgrade snapshots and running brew upgrade for each approved package.")
	logger.StepHeader(5, 7, "Upgrade Packages")
	ui.PrintRunDir(w.runMgr.RunDir())
	ui.PrintInfo(fmt.Sprintf("Upgrading %d package(s)...", len(approvedPkgs)))

	// Mark as in-progress so CTRL+C prompts before exiting
	w.sigHandler.SetInProgress(true)
	defer w.sigHandler.SetInProgress(false)

	w.snapshotMgr = snapshot.NewManager(w.runMgr.SnapshotsDir())
	upgraded := make([]upgradedPkg, 0)
	failed := 0

	for _, pkgName := range approvedPkgs {
		// Get current version info
		var pkg brew.OutdatedPackage
		for _, p := range w.outdated {
			if p.Name == pkgName {
				pkg = p
				break
			}
		}

		// Check disk space for snapshot
		pkgPath := w.brewClient.PackagePath(pkgName, pkg.InstalledVersion)
		diskCheck, err := w.snapshotMgr.CheckDiskSpace(pkgPath)
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
				proceed, _ := w.prompter.Confirm("Continue with snapshot?", false)
				if proceed {
					snapshotPath, _ = w.snapshotMgr.CreateSnapshot(pkgPath, pkgName, pkg.InstalledVersion)
				}
			} else if diskCheck.CanProceed {
				snapshotPath, err = w.snapshotMgr.CreateSnapshot(pkgPath, pkgName, pkg.InstalledVersion)
				if err != nil {
					ui.PrintWarning(fmt.Sprintf("Failed to create snapshot for %s: %v", pkgName, err))
				}
			}
		}

		// Run upgrade
		fmt.Printf("\n>>> Upgrading %s...\n", pkgName)
		if err := w.brewClient.Upgrade(pkgName); err != nil {
			ui.PrintError(fmt.Sprintf("Failed to upgrade %s: %v", pkgName, err))
			failed++
			if w.scanReport != nil {
				w.scanReport.SetUpdated(pkgName, false, err.Error())
			}
			// Clean up snapshot on failure
			if snapshotPath != "" {
				_ = w.snapshotMgr.Cleanup(pkgName)
			}
			break // Don't continue on failure per spec
		}

		// Get new version
		info, err := w.brewClient.Info(pkgName)
		if err != nil {
			ui.PrintWarning(fmt.Sprintf("Failed to get new version for %s: %v", pkgName, err))
			info = &brew.Package{Version: "unknown"}
		}

		upgraded = append(upgraded, upgradedPkg{
			Name:       pkgName,
			OldVersion: pkg.InstalledVersion,
			NewVersion: info.Version,
		})

		if w.scanReport != nil {
			w.scanReport.SetUpdated(pkgName, true, "")
		}

		ui.PrintSuccess(fmt.Sprintf("Upgraded %s: %s -> %s", pkgName, pkg.InstalledVersion, info.Version))
	}

	return upgraded, failed, nil
}

// stepVerify executes Step 6: yara + llm post-install verification
func (w *Workflow) stepVerify(upgraded []upgradedPkg) ([]ui.PostInstallRow, error) {
	ui.PrintStep(6, 7, "Post-Install Verification",
		"Verifying upgraded packages with YARA and LLM code analysis.\n  Note: Both tools can miss sophisticated attacks - using both provides defense in depth.")
	logger.StepHeader(6, 7, "Post-Install Verification")

	// Show scan status
	fmt.Println("Scan status:")

	// Initialize YARA
	if w.cfg.NoYara {
		ui.PrintSkipped("YARA scan: skipped (--no-yara)")
		w.yaraStatus = "skipped (--no-yara)"
	} else {
		var err error
		w.yaraEngine, err = yara.New(w.cfg.YaraRulesDir, 30*time.Second)
		if err != nil {
			ui.PrintSkipped(fmt.Sprintf("YARA scan: not available (%v)", err))
			w.yaraStatus = fmt.Sprintf("not run (not available: %v)", err)
		} else {
			defer func() { _ = w.yaraEngine.Close() }()
			ui.PrintInfo("YARA scan: enabled")
			w.yaraStatus = "completed"
		}
	}

	// LLM code analysis status
	if w.cfg.IsLLMEnabled() && w.llmProvider != nil {
		ui.PrintInfo("LLM code analysis: enabled")
		w.llmStatus = "completed"
	} else if w.cfg.NoLLM {
		ui.PrintSkipped("LLM code analysis: skipped (--no-llm)")
		w.llmStatus = "skipped (--no-llm)"
	} else if !w.cfg.Features.LLMScan {
		ui.PrintSkipped("LLM code analysis: disabled in config")
		w.llmStatus = "disabled in config"
	} else if w.llmError != "" {
		ui.PrintWarning(fmt.Sprintf("LLM not available: %s", w.llmError))
		w.llmStatus = fmt.Sprintf("not run (%s)", w.llmError)
	} else {
		ui.PrintSkipped("LLM code analysis: not available (LLM provider not running)")
		w.llmStatus = "not run (LLM provider not running)"
	}
	fmt.Println()

	postInstallRows := make([]ui.PostInstallRow, 0, len(upgraded))
	yaraResultsMap := make(map[string]interface{})
	type yaraFindingsWithPath struct {
		Findings []yara.Finding
		BasePath string
	}
	yaraFindingsForDisplay := make(map[string]yaraFindingsWithPath) // For displaying after table
	llmFindingsForDisplay := make(map[string][]llm.Finding)         // For displaying LLM findings after table

	verifyProgress := ui.NewProgress("Verifying packages", len(upgraded))
	for _, pkg := range upgraded {
		verifyProgress.Update(pkg.Name)
		row := ui.PostInstallRow{
			Package: pkg.Name,
			Overall: "OK",
		}

		// Track YARA result for reuse in LLM analysis
		var lastYaraResult *yara.DirScanResult

		// Get paths for this package
		snapshotPath := w.runMgr.PackageSnapshotDir(pkg.Name, pkg.OldVersion)
		newPath := w.brewClient.PackagePath(pkg.Name, pkg.NewVersion)

		// Generate diff FIRST (before YARA) so we can scope YARA to changed files
		var diff string
		if w.snapshotMgr != nil {
			var err error
			diff, err = w.snapshotMgr.GenerateDiff(snapshotPath, newPath)
			if err != nil {
				// Diff generation failed - will fall back to full scan
				diff = ""
			}
		}

		// YARA scan - scoped to changed files when diff is available
		verifyProgress.SetStatus(fmt.Sprintf("%s (yara)", pkg.Name))
		if w.yaraEngine != nil {
			var yaraResult *yara.DirScanResult
			var err error

			// If we have a diff, scan only the changed files
			if diff != "" {
				changedFiles := snapshot.ChangedFiles(diff, newPath)
				if len(changedFiles) > 0 {
					yaraResult, err = w.yaraEngine.ScanFiles(changedFiles)
				} else {
					// Empty diff means no text files changed - no YARA findings
					yaraResult = &yara.DirScanResult{}
				}
			} else {
				// No snapshot/diff available - fall back to full directory scan
				// This happens during `bsau inspect` or if snapshot was skipped
				yaraResult, err = w.yaraEngine.ScanDir(newPath)
			}

			if err != nil {
				verifyProgress.Clear()
				ui.PrintWarning(fmt.Sprintf("YARA scan failed for %s: %v", pkg.Name, err))
				w.failures = append(w.failures, ui.ScanFailure{
					Package: pkg.Name,
					Step:    "YARA",
					Error:   err.Error(),
				})
				if w.scanReport != nil {
					w.scanReport.SetYaraScan(pkg.Name, "failed")
				}
			} else {
				lastYaraResult = yaraResult
				row.YaraCount = yaraResult.FindingCount

				// Check for ERROR severity findings - these hard-block without LLM
				hasErrorFinding := false
				for _, f := range yaraResult.Findings {
					// Log all findings to log file
					logger.YaraFinding(f.Path, f.RuleID, f.Severity)

					// Verbose terminal output for each finding
					lineNum := 0
					if len(f.LineNumbers) > 0 {
						lineNum = f.LineNumbers[0]
					}
					logger.VerboseYaraFinding(f.RuleID, f.Severity, f.Path, lineNum, f.Message)

					if f.Severity == "ERROR" {
						hasErrorFinding = true
						verifyProgress.Clear()
						lineInfo := ""
						if lineNum > 0 {
							lineInfo = fmt.Sprintf(":%d", lineNum)
						}
						ui.PrintError(fmt.Sprintf("YARA ERROR: %s in %s%s - %s", f.RuleID, f.Path, lineInfo, f.Message))
					}
				}

				if hasErrorFinding {
					row.Overall = "BLOCK"
				} else if yaraResult.HasFindings && row.Overall == "OK" {
					row.Overall = "REVIEW"
				}

				// Store YARA results for saving
				yaraResultsMap[pkg.Name] = map[string]interface{}{
					"finding_count": yaraResult.FindingCount,
					"has_findings":  yaraResult.HasFindings,
					"findings":      yaraResult.Findings,
				}
				// Store findings for display after table
				if yaraResult.HasFindings {
					yaraFindingsForDisplay[pkg.Name] = yaraFindingsWithPath{
						Findings: yaraResult.Findings,
						BasePath: newPath,
					}
				}
				if w.scanReport != nil {
					if yaraResult.FindingCount > 0 {
						w.scanReport.SetYaraScan(pkg.Name, fmt.Sprintf("%d findings", yaraResult.FindingCount))
						// Add detailed findings to report
						reportFindings := make([]report.YaraFinding, len(yaraResult.Findings))
						for i, f := range yaraResult.Findings {
							reportFindings[i] = report.YaraFinding{
								RuleID:      f.RuleID,
								Path:        f.Path,
								Severity:    f.Severity,
								Message:     f.Message,
								LineNumbers: f.LineNumbers,
							}
						}
						w.scanReport.AddYaraFindings(pkg.Name, reportFindings)
					} else {
						w.scanReport.SetYaraScan(pkg.Name, "clean")
					}
				}
			}
		} else if w.scanReport != nil {
			w.scanReport.SetYaraScan(pkg.Name, "skipped")
		}

		// Check if we should skip LLM due to YARA ERROR findings
		skipLLMDueToYaraError := row.Overall == "BLOCK"

		// LLM code analysis - reuse the diff generated above
		// Skip LLM if YARA found ERROR-severity findings (already hard-blocked)
		verifyProgress.SetStatus(fmt.Sprintf("%s (llm)", pkg.Name))
		if w.cfg.IsLLMEnabled() && w.llmProvider != nil && !skipLLMDueToYaraError {
			if diff != "" {
				yaraFindings := ""
				if lastYaraResult != nil {
					yaraFindings = yara.FormatFindings(lastYaraResult.Findings)
				}

				codeResult, err := w.llmProvider.AnalyzeCode(pkg.Name, pkg.OldVersion, pkg.NewVersion, diff, yaraFindings)
				if err != nil {
					ui.PrintWarning(fmt.Sprintf("LLM code analysis failed for %s: %v", pkg.Name, err))
					w.failures = append(w.failures, ui.ScanFailure{
						Package: pkg.Name,
						Step:    "LLM Code",
						Error:   err.Error(),
					})
					if w.scanReport != nil {
						w.scanReport.SetLLMMalwareScan(pkg.Name, "failed")
					}
				} else {
					row.LLMVerdict = codeResult.Verdict
					if codeResult.Verdict == llm.VerdictHold {
						if w.cfg.BlockPolicy.LLMCodeHold {
							row.Overall = "BLOCK"
							ui.PrintError(fmt.Sprintf("Package %s flagged by LLM - consider `brew uninstall %s`", pkg.Name, pkg.Name))
						} else {
							row.Overall = "REVIEW"
						}
					} else if codeResult.Verdict == llm.VerdictReview && row.Overall == "OK" {
						row.Overall = "REVIEW"
					}
					// Store findings for display after table
					if len(codeResult.Findings) > 0 {
						llmFindingsForDisplay[pkg.Name] = codeResult.Findings
					}
					if w.scanReport != nil {
						w.scanReport.SetLLMMalwareScan(pkg.Name, string(codeResult.Verdict))
						// Add detailed findings to report
						if len(codeResult.Findings) > 0 {
							reportFindings := make([]report.LLMFinding, len(codeResult.Findings))
							for i, f := range codeResult.Findings {
								reportFindings[i] = report.LLMFinding{
									File:        f.File,
									LineNumber:  f.LineNumber,
									Description: f.Description,
								}
							}
							w.scanReport.AddLLMFindings(pkg.Name, reportFindings)
						}
					}
				}
			} else if w.scanReport != nil {
				w.scanReport.SetLLMMalwareScan(pkg.Name, "no diff")
			}
		} else if skipLLMDueToYaraError {
			// LLM skipped because YARA found ERROR-severity findings
			if w.scanReport != nil {
				w.scanReport.SetLLMMalwareScan(pkg.Name, "skipped (YARA ERROR)")
			}
		} else if w.scanReport != nil {
			w.scanReport.SetLLMMalwareScan(pkg.Name, "skipped")
		}

		// Cleanup snapshot after analysis
		_ = w.runMgr.CleanupPackageSnapshot(pkg.Name)

		postInstallRows = append(postInstallRows, row)
	}
	verifyProgress.Done()
	fmt.Println() // Blank line after progress

	// Save YARA results to run-scoped state
	if len(yaraResultsMap) > 0 {
		if err := w.runMgr.SaveYaraResults(yaraResultsMap); err != nil {
			ui.PrintWarning(fmt.Sprintf("Failed to save YARA results: %v", err))
		}
	}

	// === Post-update summary ===
	ui.PrintInfo("Post-update summary:")
	fmt.Println()
	ui.RenderPostInstallTable(postInstallRows, w.cfg.IsLLMEnabled())

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

	// Re-check vulnerabilities for summary using osv-scanner
	cvesResolved := 0
	cvesRemaining := 0

	// Build package info for post-upgrade OSV query
	postPackageInfos := make([]vuln.PackageInfo, len(upgraded))
	for i, pkg := range upgraded {
		postPackageInfos[i] = vuln.PackageInfo{
			Name:    pkg.Name,
			Version: pkg.NewVersion,
		}
	}

	ui.PrintInfo("Checking post-upgrade vulnerabilities...")
	postVulnResults, postVulnStats, err := w.vulnScanner.QueryPackages(postPackageInfos)
	if err != nil {
		ui.PrintWarning(fmt.Sprintf("Post-upgrade OSV query failed: %v", err))
		w.failures = append(w.failures, ui.ScanFailure{
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
		if preResult, ok := w.vulnResults[pkg.Name]; ok {
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

	ui.RenderSummary(len(upgraded), 0, cvesResolved, cvesRemaining)

	// Render failure summary if there were any failures
	if len(w.failures) > 0 {
		ui.RenderFailureSummary(w.failures, len(w.outdated))
	}

	return postInstallRows, nil
}

// stepCleanup executes Step 7: runMgr cleanup + brew cleanup + final report
func (w *Workflow) stepCleanup() error {
	ui.PrintStep(7, 7, "Cleanup",
		"Removing temporary files and running brew cleanup to free disk space.")
	logger.StepHeader(7, 7, "Cleanup")

	// Clean up temporary run directory (snapshots, state files)
	ui.PrintInfo("Cleaning up temporary files...")
	if err := w.runMgr.Cleanup(); err != nil {
		ui.PrintWarning(fmt.Sprintf("Failed to cleanup run directory: %v", err))
	} else {
		ui.PrintSuccess("Temporary files removed")
	}

	// Run brew cleanup to remove old versions
	ui.PrintInfo("Running brew cleanup...")
	if err := w.brewClient.Cleanup(); err != nil {
		ui.PrintWarning(fmt.Sprintf("Brew cleanup failed: %v", err))
	} else {
		ui.PrintSuccess("Brew cleanup complete")
	}

	// Final scan status summary
	fmt.Println()
	fmt.Println("=== Scan Summary ===")

	// Write final summary to report and display
	if w.scanReport != nil {
		if err := w.scanReport.WriteFinalSummary(); err != nil {
			ui.PrintWarning(fmt.Sprintf("Failed to write final summary to report: %v", err))
		}
		fmt.Println()
		fmt.Print(w.scanReport.GetSummary())
		fmt.Println()
		ui.PrintInfo(fmt.Sprintf("Full report saved to: %s", w.scanReport.FilePath()))
	} else {
		// Fallback if report not available
		fmt.Printf("Vulnerability scan: completed\n")
		fmt.Printf("YARA scan: %s\n", w.yaraStatus)
		fmt.Printf("LLM analysis: %s\n", w.llmStatus)
	}

	fmt.Println()
	ui.PrintSuccess("All done!")

	return nil
}

func runWorkflow(cmd *cobra.Command, args []string) error {
	// Apply CLI overrides
	cfg.NoLLM = noLLM
	cfg.NoYara = noYara
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

	// Initialize workflow
	w := &Workflow{
		cfg:         cfg,
		brewClient:  brew.NewClient(cfg.HomebrewPath),
		vulnScanner: vuln.NewScanner(),
		prompter:    ui.NewPrompter(),
		runMgr:      runMgr,
		sigHandler:  sigHandler,
		failures:    []ui.ScanFailure{},
	}

	// === Step 1: Identify and audit current state ===
	if err := w.stepAudit(); err != nil {
		return err
	}

	// Exit if no outdated packages
	if len(w.outdated) == 0 {
		return nil
	}

	// Get pinned packages
	pinnedPkgs, _ := w.brewClient.GetPinnedPackages()
	pinnedSet := make(map[string]bool)
	for _, p := range pinnedPkgs {
		pinnedSet[p] = true
	}

	// === Step 2: Identify what needs to be updated ===
	selectedPkgs, err := w.stepSelectPackages(pinnedSet)
	if err != nil {
		return err
	}

	// Exit if no packages selected
	if len(selectedPkgs) == 0 {
		return nil
	}

	// === Step 3: Pre-install security scan ===
	if err := w.stepPreInstallScan(selectedPkgs); err != nil {
		return err
	}

	// === Step 4: Per-package approval gate ===
	approvedPkgs, err := w.stepApproval(selectedPkgs)
	if err != nil {
		return err
	}

	// Exit if no packages approved
	if len(approvedPkgs) == 0 {
		ui.PrintInfo("No packages approved for upgrade")
		return nil
	}

	// Exit if dry run
	if dryRun {
		ui.PrintInfo("Dry run - skipping upgrades")
		fmt.Println("Would upgrade:", approvedPkgs)
		return nil
	}

	// === Step 5: Upgrade ===
	upgraded, _, err := w.stepUpgrade(approvedPkgs)
	if err != nil {
		return err
	}

	// Exit if no packages were upgraded
	if len(upgraded) == 0 {
		ui.PrintError("No packages were upgraded")
		return nil
	}

	// === Step 6: Post-install verification ===
	_, err = w.stepVerify(upgraded)
	if err != nil {
		return err
	}

	// === Step 7: Cleanup ===
	return w.stepCleanup()
}
