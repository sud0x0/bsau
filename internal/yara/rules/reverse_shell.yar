rule reverse_shell_bash_tcp {
    meta:
        id = "reverse-shell-bash-tcp"
        severity = "ERROR"
        message = "Bash reverse shell via /dev/tcp - backdoor detected"
    strings:
        $cmd = /\/dev\/tcp\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d+/
    condition:
        $cmd
}

rule reverse_shell_nc {
    meta:
        id = "reverse-shell-nc"
        severity = "ERROR"
        message = "Netcat reverse shell - backdoor detected"
    strings:
        $cmd = /nc\s+(-[elp]+\s+)*(\/bin\/(ba)?sh|\/bin\/zsh)/
    condition:
        $cmd
}

rule reverse_shell_python {
    meta:
        id = "reverse-shell-python"
        severity = "ERROR"
        message = "Python reverse shell pattern detected"
    strings:
        $cmd = /socket\.(socket|create_connection).*(subprocess|os\.dup2|pty\.spawn)/
    condition:
        $cmd
}

rule reverse_shell_ruby {
    meta:
        id = "reverse-shell-ruby"
        severity = "ERROR"
        message = "Ruby reverse shell pattern detected"
    strings:
        $cmd = /TCPSocket\.(new|open).*exec\s*\(/
    condition:
        $cmd
}
