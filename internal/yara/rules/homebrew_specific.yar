rule formula_write_to_ssh {
    meta:
        id = "formula-write-to-ssh"
        severity = "WARNING"
        message = "Formula install block writing to ~/.ssh - credential theft risk"
    strings:
        $path = /~\/\.ssh\//
    condition:
        $path
}

rule formula_write_to_aws {
    meta:
        id = "formula-write-to-aws"
        severity = "WARNING"
        message = "Formula install block writing to ~/.aws - credential theft risk"
    strings:
        $path = /~\/\.aws\//
    condition:
        $path
}

rule formula_write_to_launchagent {
    meta:
        id = "formula-write-launchagent"
        severity = "WARNING"
        message = "Formula install block writing to LaunchAgents - persistence risk"
    strings:
        $path = /Library\/LaunchAgents/
    condition:
        $path
}
