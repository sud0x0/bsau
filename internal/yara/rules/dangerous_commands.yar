rule sudo_nopasswd {
    meta:
        id = "sudo-nopasswd"
        severity = "WARNING"
        message = "Configuring passwordless sudo - privilege escalation"
    strings:
        $nopass = "NOPASSWD"
        $sudoers = "sudoers"
    condition:
        any of them
}

rule chmod_dangerous {
    meta:
        id = "chmod-dangerous"
        severity = "WARNING"
        message = "Setting dangerous permissions (777 or setuid)"
    strings:
        $perm = /chmod\s+(777|\+s|4755|u\+s)/
    condition:
        $perm
}

rule gatekeeper_disable {
    meta:
        id = "gatekeeper-disable"
        severity = "WARNING"
        message = "Disabling macOS Gatekeeper - security bypass"
    strings:
        $disable = /spctl.*--master-disable/
        $add = /spctl.*--disable/
        $add2 = /spctl.*--add/
    condition:
        any of them
}

rule sip_disable {
    meta:
        id = "sip-disable"
        severity = "WARNING"
        message = "Attempting to disable System Integrity Protection"
    strings:
        $cmd = /csrutil\s+disable/
    condition:
        $cmd
}

rule xattr_quarantine_remove {
    meta:
        id = "xattr-quarantine-remove"
        severity = "WARNING"
        message = "Removing quarantine attribute - bypassing Gatekeeper"
    strings:
        $cmd = /xattr\s+-[dr]\s+com\.apple\.quarantine/
    condition:
        $cmd
}
