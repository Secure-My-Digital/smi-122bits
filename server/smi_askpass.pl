#!/usr/bin/env perl
use strict;
use warnings;
use JSON::XS;
use SMI::Derive;

# The rule is simple: If a secret must be sanitized from memory,
# the process that obtains it must be the same process that sanitizes it.
# Python cannot sanitize what it cannot control. Let Perl ask, let Perl derive, let Perl burn.

# Read request from Python (only index, never the password)
my $input = <STDIN>;
chomp $input;
my $req = eval { decode_json($input) } or die "Invalid JSON\n";
my $index = $req->{index} // 0;

# Obtain master password via askpass utility
my $askpass = $ENV{SMI_ASKPASS} // "systemd-askpassword";
my $prompt  = $req->{prompt} // "Enter SMI Master Password";

# Execute askpass; read password directly
my $master = do {
    open my $fh, "-|", $askpass, $prompt
        or die "Failed to execute askpass: $!\n";
    local $/;
    my $pw = <$fh>;
    close $fh;
    chomp $pw if defined $pw;
    $pw;
};

die "No password provided\n" unless defined $master && length($master);

# Load seed from .env (or receive from Python if you prefer)
my $seed_hex = read_env_seed(); # your existing logic
my $seed = pack("H*", $seed_hex);

# Derive in XS; C buffers are zeroized internally
my $password = SMI::Derive::derive_password($master, $seed, $index);

# Best-effort wipe of Perl scalar (overwrites buffer, may not catch all copies)
$master = "\0" x length($master);
$seed   = "\0" x length($seed);

print "$password\n";
exit 0;
