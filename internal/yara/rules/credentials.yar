rule aws_credentials_access {
    meta:
        id = "aws-credentials-access"
        severity = "WARNING"
        message = "Accessing AWS credentials file - potential credential theft"
    strings:
        $path = /~?\/?\.aws\/credentials/
    condition:
        $path
}

rule ssh_key_access {
    meta:
        id = "ssh-key-access"
        severity = "WARNING"
        message = "Accessing SSH keys - potential credential theft"
    strings:
        $path = /~?\/?\.ssh\/(id_rsa|id_ed25519|id_dsa|id_ecdsa|authorized_keys)/
    condition:
        $path
}

rule ssh_directory_glob {
    meta:
        id = "ssh-directory-glob"
        severity = "WARNING"
        message = "Globbing SSH directory - potential mass credential theft"
    strings:
        $path = /\.ssh\/\*/
    condition:
        $path
}

rule env_secret_network_exfil {
    meta:
        id = "env-secret-network-exfil"
        severity = "WARNING"
        message = "Harvesting secrets from environment variables with network activity - potential exfiltration"
    strings:
        $ruby_secret = /ENV\s*\[.*(SECRET|TOKEN|PASSWORD|API_KEY|CREDENTIAL)/
        $python_secret = /os\.environ.*(SECRET|TOKEN|PASSWORD|API_KEY|CREDENTIAL)/
        $node_secret = /process\.env\.(SECRET|TOKEN|PASSWORD|API_KEY|CREDENTIAL|AUTH)[^_]/
        $net1 = /https?:\/\//
        $net2 = "fetch("
        $net3 = "XMLHttpRequest"
        $net4 = "axios"
        $net5 = /curl\s/
        $net6 = /wget\s/
    condition:
        any of ($ruby_secret, $python_secret, $node_secret) and any of ($net1, $net2, $net3, $net4, $net5, $net6)
}

rule env_secret_file_write {
    meta:
        id = "env-secret-file-write"
        severity = "WARNING"
        message = "Harvesting secrets from environment variables with file write - potential credential theft"
    strings:
        $ruby_secret = /ENV\s*\[.*(SECRET|TOKEN|PASSWORD|API_KEY|CREDENTIAL)/
        $python_secret = /os\.environ.*(SECRET|TOKEN|PASSWORD|API_KEY|CREDENTIAL)/
        $node_secret = /process\.env\.(SECRET|TOKEN|PASSWORD|API_KEY|CREDENTIAL|AUTH)[^_]/
        $write1 = /fs\.(write|append)/
        $write2 = /open\(.*[\"']w[\"']/
        $write3 = /File\.write/
        $write4 = />>/
    condition:
        any of ($ruby_secret, $python_secret, $node_secret) and any of ($write1, $write2, $write3, $write4)
}

rule keychain_access {
    meta:
        id = "keychain-access"
        severity = "ERROR"
        message = "Accessing macOS Keychain - potential credential theft"
    strings:
        $cmd = /security\s+(find-generic-password|find-internet-password|dump-keychain)/
    condition:
        $cmd
}
