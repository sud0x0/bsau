package llm

import (
	"regexp"
	"strings"
)

// parseFormulaResponse parses an LLM response into FormulaAnalysisResult
func parseFormulaResponse(response string, result *FormulaAnalysisResult) {
	// Parse VERDICT
	verdictRegex := regexp.MustCompile(`VERDICT:\s*(SAFE|REVIEW|HOLD)`)
	if match := verdictRegex.FindStringSubmatch(response); len(match) > 1 {
		result.Verdict = Verdict(match[1])
	} else {
		result.Verdict = VerdictReview
	}

	// Parse CONFIDENCE
	confRegex := regexp.MustCompile(`CONFIDENCE:\s*(HIGH|MEDIUM|LOW)`)
	if match := confRegex.FindStringSubmatch(response); len(match) > 1 {
		result.Confidence = Confidence(match[1])
	} else {
		result.Confidence = ConfidenceMedium
	}

	// Parse FINDINGS
	findingsRegex := regexp.MustCompile(`(?m)^-\s*\[([^\]]+)\]`)
	matches := findingsRegex.FindAllStringSubmatch(response, -1)
	for _, match := range matches {
		if len(match) > 1 {
			result.Findings = append(result.Findings, Finding{
				Description: match[1],
			})
		}
	}
}

// parseCodeResponse parses an LLM response into CodeAnalysisResult
func parseCodeResponse(response string, result *CodeAnalysisResult) {
	// Parse VERDICT
	verdictRegex := regexp.MustCompile(`VERDICT:\s*(SAFE|REVIEW|HOLD)`)
	if match := verdictRegex.FindStringSubmatch(response); len(match) > 1 {
		result.Verdict = Verdict(match[1])
	} else {
		// Fallback: infer verdict from response content if format wasn't followed
		result.Verdict = inferVerdictFromContent(response)
	}

	// Parse CONFIDENCE
	confRegex := regexp.MustCompile(`CONFIDENCE:\s*(HIGH|MEDIUM|LOW)`)
	if match := confRegex.FindStringSubmatch(response); len(match) > 1 {
		result.Confidence = Confidence(match[1])
	} else {
		result.Confidence = ConfidenceMedium
	}

	// Parse FINDINGS
	findingsRegex := regexp.MustCompile(`(?m)^-\s*\[([^\]]+)\]`)
	matches := findingsRegex.FindAllStringSubmatch(response, -1)
	for _, match := range matches {
		if len(match) > 1 {
			result.Findings = append(result.Findings, Finding{
				Description: match[1],
			})
		}
	}
}

// inferVerdictFromContent attempts to determine verdict when LLM doesn't follow expected format
func inferVerdictFromContent(response string) Verdict {
	lower := strings.ToLower(response)

	// Check for clear indicators of malicious content
	holdIndicators := []string{
		"malicious", "malware", "backdoor", "reverse shell",
		"credential harvesting", "data exfiltration", "c2 server",
	}
	for _, indicator := range holdIndicators {
		if strings.Contains(lower, indicator) && !strings.Contains(lower, "no "+indicator) {
			return VerdictHold
		}
	}

	// Check for clear indicators of safe content
	safeIndicators := []string{
		"no malicious", "no security", "no suspicious",
		"no vulnerabilities", "no actionable security",
		"safe change", "normal update", "standard upgrade",
		"metadata update", "version bump",
	}
	for _, indicator := range safeIndicators {
		if strings.Contains(lower, indicator) {
			return VerdictSafe
		}
	}

	// Default to REVIEW if unclear
	return VerdictReview
}
