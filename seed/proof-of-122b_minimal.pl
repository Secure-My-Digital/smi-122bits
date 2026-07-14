
# $Intent: Demonstrate 122-bit entropy password generation using HKDF and Shannon entropy calculation $

use lib $ENV{RADIANT}.'/lib';
use HKDF qw(HKDF encode_ascii);

my $n= 0;
my $len = 122 / log(95);
my $prk = "super secret";
my $info = "zmp-password-v0";
my $MAX_ITERATIONS = 100;
while ($n < $MAX_ITERATIONS) {
  # password derivation
  my $okm = HKDF($prk,$info.$n,$len,{expand=>1});
  my $pw = &encode_ascii($okm); # encode in base95
  printf "pw: %s # %.1fb\n",$pw,&shannon($pw);
  $n++
}

sub shannon {
    my $sum = 0;
    my $l = length(my $data = shift) or return 0;
    my %f; $f{$_}++ for split //, $data;
    $sum += $_ * log($_) for values %f;
    return ($l * log($l) - $sum) / log(2);
}

# > *"Entropy is the silent architect of cryptographic truth, each bit a brick in the fortress of proof."*
# -- Tracey L. Muell, BlockSmith Security Architect [Proof of Entropy, 2026]
1;
