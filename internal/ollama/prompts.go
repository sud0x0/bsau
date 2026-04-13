package ollama

// System prompt for malware analysis - used for all analysis types
const SystemPrompt = `You are a malware analyst. Analyse source code chunks for malicious patterns. Always respond with EXACTLY this format and no other text:
VERDICT: SAFE | REVIEW | HOLD
CONFIDENCE: HIGH | MEDIUM | LOW
FINDINGS:
- [file path, line number, what is suspicious, why]`

// UserPromptFileAnalysis is the base prompt for analyzing files
const UserPromptFileAnalysis = `Analyze these files for malicious patterns:
- Exfiltration of credentials or files to remote endpoints
- Encoded or obfuscated payloads
- Unexpected network calls
- Persistence mechanisms
- Privilege escalation
- Reverse shell patterns

Respond with EXACTLY this format:
VERDICT: SAFE | REVIEW | HOLD
CONFIDENCE: HIGH | MEDIUM | LOW
FINDINGS:
- [file path, line number, what is suspicious, why]`

// UserPromptFormulaAnalysis is the prompt for analyzing Homebrew formula files
const UserPromptFormulaAnalysis = `Analyze this Homebrew formula for malicious patterns.
Focus on what changed between versions - patterns in CURRENT but not in prior versions are higher suspicion.

Look for:
- New or changed download URLs pointing to unexpected or non-canonical domains
- Newly added or modified shell hooks (postinstall, preinstall, caveats)
- Obfuscated shell commands or base64+eval patterns
- curl | bash or wget | sh without checksum verification
- Credential harvesting from environment variables
- Persistence mechanisms (LaunchAgent/LaunchDaemon writes)
- Exfiltration endpoints (hardcoded IPs, unusual domains)

Respond with EXACTLY this format:
VERDICT: SAFE | REVIEW | HOLD
CONFIDENCE: HIGH | MEDIUM | LOW
FINDINGS:
- [version label, line number, what changed, why suspicious]`

// UserPromptDiffAnalysis is the prompt for analyzing code diffs (post-upgrade)
const UserPromptDiffAnalysis = `Analyze this diff for malicious patterns introduced in the new version.
Focus on what is NEW or CHANGED - patterns in the old version that remain unchanged are lower priority.

Look for:
- Exfiltration of credentials, environment variables, or files to remote endpoints
- Encoded or obfuscated payloads being decoded and executed
- Unexpected network calls (curl, wget, requests, http) in non-networking code
- Persistence mechanisms (LaunchAgent/LaunchDaemon, cron, startup items)
- Privilege escalation or unexpected sudo usage
- Reverse shell or command-and-control patterns

Respond with EXACTLY this format:
VERDICT: SAFE | REVIEW | HOLD
CONFIDENCE: HIGH | MEDIUM | LOW
FINDINGS:
- [file path, line number, what changed, why suspicious]`

// Chunking configuration
const (
	ChunkSize   = 50 // Lines per chunk
	ChunkOverlap = 5  // Overlap between chunks
)
