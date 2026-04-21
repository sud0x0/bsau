rule curl_wget_pipe_shell {
    meta:
        id = "curl-wget-pipe-shell"
        severity = "ERROR"
        message = "curl/wget output piped to shell - potential remote code execution"
    strings:
        $cmd = /(curl|wget)\s+[^|]*\|\s*(ba)?sh/
    condition:
        $cmd
}

rule curl_wget_pipe_shell_variants {
    meta:
        id = "curl-wget-pipe-shell-variants"
        severity = "ERROR"
        message = "curl/wget with shell execution flags - potential remote code execution"
    strings:
        $cmd = /(curl|wget)\s+(-[sqOfL]+\s+)*(-O-|-o\s*-|--output\s*-)\s+[^|]*\|\s*(ba)?sh/
    condition:
        $cmd
}
