package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/sud0x0/bsau/internal/brew"
	"github.com/sud0x0/bsau/internal/config"
	"github.com/sud0x0/bsau/internal/logger"
	"github.com/sud0x0/bsau/internal/ollama"
	"github.com/sud0x0/bsau/internal/report"
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
	ollamaClient   *ollama.Client
	semgrepRunner  *semgrep.Runner
	scanReport     *report.Report
	failures       []ui.ScanFailure
	outdated       []brew.OutdatedPackage
	vulnResults    map[string]*vuln.VulnResult
	formulaResults map[string]*ollama.FormulaAnalysisResult
	semgrepStatus  string
	ollamaStatus   string
}

// stepAudit executes Step 1: get outdated packages, query OSV/NVD, save pre-update vulns
func (w *Workflow) stepAudit() error {
	ui.PrintStep(1, 7, "Identify and Audit Current State",
		"Scanning Homebrew packages, checking for outdated versions, and querying OSV/NIST NVD for vulnerabilities.")

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

// stepPreInstallScan executes Step 3: Ollama formula analysis
func (w *Workflow) stepPreInstallScan(selectedPkgs []string) error {
	ui.PrintStep(3, 7, "Pre-install Security Scan",
		"Analyzing formula files with OLLAMA LLM to detect malicious patterns before upgrade.")

	w.formulaResults = make(map[string]*ollama.FormulaAnalysisResult)

	// Show scan status
	fmt.Println("Scan status:")
	if !w.cfg.IsOllamaEnabled() {
		ui.PrintSkipped("OLLAMA LLM formula analysis: disabled (enable with 'ollama_scan: true' in settings.yaml)")
		// Mark all selected packages as skipped for formula analysis
		for _, pkgName := range selectedPkgs {
			if w.scanReport != nil {
				w.scanReport.SetFormulaAnalysis(pkgName, "disabled")
			}
		}
		fmt.Println()
		return nil
	}

	ui.PrintInfo("OLLAMA LLM formula analysis: enabled")
	fmt.Println()
	w.ollamaClient = ollama.NewClient(w.cfg.OllamaURL, w.cfg.OllamaModel, w.cfg.OllamaMaxFileBytes)
	// Check if Ollama is actually running
	if err := w.ollamaClient.CheckAvailability(); err != nil {
		ui.PrintWarning(fmt.Sprintf("OLLAMA LLM not available: %v", err))
		ui.PrintWarning("Make sure OLLAMA is running with: ollama serve")
		w.ollamaClient = nil
	}

	if w.ollamaClient != nil {
		ollamaProgress := ui.NewProgress("Analyzing formulas", len(selectedPkgs))
		for _, pkgName := range selectedPkgs {
			ollamaProgress.Update(pkgName)
			versions, err := w.brewClient.GetFormulaVersions(pkgName)
			if err != nil {
				ollamaProgress.Clear()
				ui.PrintWarning(fmt.Sprintf("Failed to get formula for %s: %v", pkgName, err))
				ollamaProgress.Skip()
				if w.scanReport != nil {
					w.scanReport.SetFormulaAnalysis(pkgName, "failed")
				}
				continue
			}

			result, err := w.ollamaClient.AnalyzeFormula(pkgName, versions)
			if err != nil {
				ollamaProgress.Clear()
				ui.PrintWarning(fmt.Sprintf("OLLAMA LLM analysis failed for %s: %v", pkgName, err))
				result = &ollama.FormulaAnalysisResult{
					Package: pkgName,
					Verdict: ollama.VerdictReview,
				}
				if w.scanReport != nil {
					w.scanReport.SetFormulaAnalysis(pkgName, "failed")
				}
			} else if w.scanReport != nil {
				w.scanReport.SetFormulaAnalysis(pkgName, string(result.Verdict))
			}
			w.formulaResults[pkgName] = result
		}
		ollamaProgress.Done()
	} else {
		// Ollama not available, mark all as skipped
		for _, pkgName := range selectedPkgs {
			if w.scanReport != nil {
				w.scanReport.SetFormulaAnalysis(pkgName, "skipped")
			}
		}
	}

	// Save Ollama formula analysis results to run-scoped state
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

	preInstallRows := make([]ui.PreInstallRow, 0, len(selectedPkgs))
	approvedPkgs := make([]string, 0)

	for _, pkgName := range selectedPkgs {
		vr := w.vulnResults[pkgName]
		fr := w.formulaResults[pkgName]

		recommendation := "PROCEED"
		var verdict ollama.Verdict

		if fr != nil {
			verdict = fr.Verdict
			switch verdict {
			case ollama.VerdictHold:
				if w.cfg.BlockPolicy.OllamaFormulaHold {
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
	ui.RenderPreInstallTable(preInstallRows, w.cfg.IsOllamaEnabled())

	// Process approvals
	for _, row := range preInstallRows {
		if row.Recommendation == "BLOCK" {
			ui.PrintWarning(fmt.Sprintf("Package %s blocked: OLLAMA LLM returned HOLD verdict", row.Package))
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
			approved, err := w.prompter.ConfirmPackageUpgrade(row.Package, row.OllamaVerdict, reason)
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

// stepVerify executes Step 6: semgrep + ollama post-install verification
func (w *Workflow) stepVerify(upgraded []upgradedPkg) ([]ui.PostInstallRow, error) {
	ui.PrintStep(6, 7, "Post-Install Verification",
		"Verifying upgraded packages with Semgrep and OLLAMA LLM code analysis.\n  Note: Both tools can miss sophisticated attacks - using both provides defense in depth.")

	// Show scan status
	fmt.Println("Scan status:")

	// Initialize Semgrep
	if w.cfg.NoSemgrep {
		ui.PrintSkipped("Semgrep scan: skipped (--no-semgrep)")
		w.semgrepStatus = "skipped (--no-semgrep)"
	} else {
		var err error
		w.semgrepRunner, err = semgrep.NewRunner()
		if err != nil {
			ui.PrintSkipped(fmt.Sprintf("Semgrep scan: not available (%v)", err))
			w.semgrepStatus = fmt.Sprintf("not run (not available: %v)", err)
		} else {
			ui.PrintInfo("Semgrep scan: enabled")
			w.semgrepStatus = "completed"
		}
	}

	// OLLAMA LLM code analysis status
	if w.cfg.IsOllamaEnabled() && w.ollamaClient != nil {
		ui.PrintInfo("OLLAMA LLM code analysis: enabled")
		w.ollamaStatus = "completed"
	} else if w.cfg.NoOllama {
		ui.PrintSkipped("OLLAMA LLM code analysis: skipped (--no-ollama)")
		w.ollamaStatus = "skipped (--no-ollama)"
	} else if !w.cfg.Features.OllamaScan {
		ui.PrintSkipped("OLLAMA LLM code analysis: disabled in config")
		w.ollamaStatus = "disabled in config"
	} else {
		ui.PrintSkipped("OLLAMA LLM code analysis: not available (OLLAMA not running)")
		w.ollamaStatus = "not run (OLLAMA not running)"
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

		// Track semgrep result for reuse in Ollama analysis
		var lastSemgrepResult *semgrep.PackageScanResult

		// Semgrep scan
		verifyProgress.Update(fmt.Sprintf("%s (semgrep)", pkg.Name))
		if w.semgrepRunner != nil {
			semgrepResult, err := w.semgrepRunner.ScanPackage(
				w.brewClient.CellarPath(),
				pkg.Name,
				pkg.NewVersion,
			)
			if err != nil {
				verifyProgress.Clear()
				ui.PrintWarning(fmt.Sprintf("Semgrep scan failed for %s: %v", pkg.Name, err))
				w.failures = append(w.failures, ui.ScanFailure{
					Package: pkg.Name,
					Step:    "Semgrep",
					Error:   err.Error(),
				})
				if w.scanReport != nil {
					w.scanReport.SetSemgrepScan(pkg.Name, "failed")
				}
			} else {
				lastSemgrepResult = semgrepResult
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
				if w.scanReport != nil {
					if semgrepResult.FindingCount > 0 {
						w.scanReport.SetSemgrepScan(pkg.Name, fmt.Sprintf("%d findings", semgrepResult.FindingCount))
					} else {
						w.scanReport.SetSemgrepScan(pkg.Name, "clean")
					}
				}
			}
		} else if w.scanReport != nil {
			w.scanReport.SetSemgrepScan(pkg.Name, "skipped")
		}

		// Diff and Ollama code analysis
		if w.cfg.IsOllamaEnabled() && w.ollamaClient != nil {
			// Generate diff if we have a snapshot
			snapshotPath := w.runMgr.PackageSnapshotDir(pkg.Name, pkg.OldVersion)
			newPath := w.brewClient.PackagePath(pkg.Name, pkg.NewVersion)

			diff, err := w.snapshotMgr.GenerateDiff(snapshotPath, newPath)
			if err == nil && diff != "" {
				semgrepFindings := ""
				if lastSemgrepResult != nil {
					semgrepFindings = semgrep.FormatFindings(lastSemgrepResult.Findings)
				}

				codeResult, err := w.ollamaClient.AnalyzeCode(pkg.Name, pkg.OldVersion, pkg.NewVersion, diff, semgrepFindings)
				if err != nil {
					ui.PrintWarning(fmt.Sprintf("OLLAMA LLM code analysis failed for %s: %v", pkg.Name, err))
					w.failures = append(w.failures, ui.ScanFailure{
						Package: pkg.Name,
						Step:    "OLLAMA LLM Code",
						Error:   err.Error(),
					})
					if w.scanReport != nil {
						w.scanReport.SetOllamaMalwareScan(pkg.Name, "failed")
					}
				} else {
					row.OllamaVerdict = codeResult.Verdict
					if codeResult.Verdict == ollama.VerdictHold {
						if w.cfg.BlockPolicy.OllamaCodeHold {
							row.Overall = "BLOCK"
							ui.PrintError(fmt.Sprintf("Package %s flagged by OLLAMA LLM - consider `brew uninstall %s`", pkg.Name, pkg.Name))
						} else {
							row.Overall = "REVIEW"
						}
					} else if codeResult.Verdict == ollama.VerdictReview && row.Overall == "OK" {
						row.Overall = "REVIEW"
					}
					if w.scanReport != nil {
						w.scanReport.SetOllamaMalwareScan(pkg.Name, string(codeResult.Verdict))
					}
				}
			} else if w.scanReport != nil {
				w.scanReport.SetOllamaMalwareScan(pkg.Name, "no diff")
			}
		} else if w.scanReport != nil {
			w.scanReport.SetOllamaMalwareScan(pkg.Name, "skipped")
		}

		// Cleanup snapshot after analysis
		_ = w.runMgr.CleanupPackageSnapshot(pkg.Name)

		postInstallRows = append(postInstallRows, row)
	}
	verifyProgress.Done()

	// Save semgrep results to run-scoped state
	if len(semgrepResultsMap) > 0 {
		if err := w.runMgr.SaveSemgrepResults(semgrepResultsMap); err != nil {
			ui.PrintWarning(fmt.Sprintf("Failed to save semgrep results: %v", err))
		}
	}

	// === Post-update summary ===
	ui.PrintInfo("Post-update summary:")
	fmt.Println()
	ui.RenderPostInstallTable(postInstallRows, w.cfg.IsOllamaEnabled())

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
		fmt.Printf("Semgrep scan: %s\n", w.semgrepStatus)
		fmt.Printf("Local LLM analysis: %s\n", w.ollamaStatus)
	}

	fmt.Println()
	ui.PrintSuccess("All done!")

	return nil
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
