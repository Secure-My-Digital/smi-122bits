
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
  printf "pw: %s # %.1fb == %s.1f\n",$pw,&shannon($pw);
  $n++
}

sub shannon {
    my $sum = 0;
    my $l = length(my $data = shift) or return 0;
    my %f; $f{$_}++ for split //, $data;
    $sum += $_ * log($_) for values %f;
    return ($l * log($l) - $sum) / log(2);
}

1;
