package llm

// SystemPrompt is the generic system prompt for code analysis
const SystemPrompt = `OUTPUT FORMAT (mandatory - no other text allowed):

VERDICT: SAFE
CONFIDENCE: HIGH
FINDINGS:
- None

Or:

VERDICT: HOLD
CONFIDENCE: HIGH
FINDINGS:
- [file:line] malicious pattern detected

Rules:
1. First line MUST be "VERDICT: SAFE" or "VERDICT: HOLD" or "VERDICT: REVIEW"
2. No text before VERDICT
3. No explanations
4. If safe, FINDINGS must be exactly "- None"`

// FormulaSystemPrompt is the system prompt specifically for formula version comparison
const FormulaSystemPrompt = `OUTPUT FORMAT (mandatory - no other text allowed):

VERDICT: SAFE
CONFIDENCE: HIGH
FINDINGS:
- None

Or:

VERDICT: HOLD
CONFIDENCE: HIGH
FINDINGS:
- [line] suspicious change detected

Rules:
1. First line MUST be "VERDICT: SAFE" or "VERDICT: HOLD" or "VERDICT: REVIEW"
2. No text before VERDICT
3. No explanations
4. If safe, FINDINGS must be exactly "- None"

Suspicious patterns: URL domain changes, new postinstall scripts, base64/obfuscated code, hardcoded IPs.
Safe patterns: version bumps, SHA256 updates, dependency updates.`

// UserPromptFileAnalysis is the base prompt for analyzing files
const UserPromptFileAnalysis = `Scan for malware. Output ONLY the format. No explanations.`

// UserPromptFormulaAnalysis is the prompt for analyzing Homebrew formula files
const UserPromptFormulaAnalysis = `Scan for malware. Output ONLY the format. No explanations.`

// DiffSystemPrompt is the system prompt for analyzing code diffs (Step 6 post-upgrade)
const DiffSystemPrompt = `OUTPUT FORMAT (mandatory - no other text allowed):

VERDICT: SAFE
CONFIDENCE: HIGH
FINDINGS:
- None

Or:

VERDICT: HOLD
CONFIDENCE: HIGH
FINDINGS:
- [file:line] malicious pattern detected

Rules:
1. First line MUST be "VERDICT: SAFE" or "VERDICT: HOLD" or "VERDICT: REVIEW"
2. No text before VERDICT
3. No explanations
4. If safe, FINDINGS must be exactly "- None"

Malicious patterns to detect in added lines (+):
- Hardcoded IPs, curl|sh, base64 decode, credential access, LaunchAgent, reverse shells`

// UserPromptDiffAnalysis is the prompt for analyzing code diffs (post-upgrade)
const UserPromptDiffAnalysis = `Scan for malware. Output ONLY the format. No explanations.`

// Chunking configuration
const (
	ChunkSize    = 50 // Lines per chunk
	ChunkOverlap = 5  // Overlap between chunks
)
