rule base64_decode_execute {
    meta:
        id = "base64-decode-execute"
        severity = "WARNING"
        message = "Base64 decode piped to shell execution - obfuscated payload"
    strings:
        $cmd = /base64\s+(-d|--decode|-D)\s*\|/
    condition:
        $cmd
}

rule base64_decode_eval {
    meta:
        id = "base64-decode-eval"
        severity = "WARNING"
        message = "Base64 decoded content passed to eval - obfuscated code execution"
    strings:
        $cmd = /eval\s*\(\s*(Base64\.decode64|base64\.b64decode|atob|Buffer\.from)/
    condition:
        $cmd
}
