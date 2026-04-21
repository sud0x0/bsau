rule crontab_persistence {
    meta:
        id = "crontab-persistence"
        severity = "WARNING"
        message = "Adding crontab entry - persistence mechanism"
    strings:
        $cmd = "crontab"
    condition:
        $cmd
}

rule launchagent_persistence {
    meta:
        id = "launchagent-persistence"
        severity = "WARNING"
        message = "Creating LaunchAgent or LaunchDaemon - macOS persistence mechanism"
    strings:
        $user = "~/Library/LaunchAgents"
        $sys1 = "/Library/LaunchAgents"
        $sys2 = "/Library/LaunchDaemons"
    condition:
        any of them
}

rule shell_rc_persistence {
    meta:
        id = "bashrc-persistence"
        severity = "WARNING"
        message = "Modifying shell config - persistence mechanism"
    strings:
        $rc = />>?\s*~?\/?\.(bashrc|zshrc|profile|bash_profile)/
    condition:
        $rc
}
