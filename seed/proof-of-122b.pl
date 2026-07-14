#!/usr/bin/perl

use YAML::XS qw(Dump);
use lib $ENV{RADIANT}.'/lib';
use misc::env;
use HKDF qw(HKDF);
use encode qw(encode_base95);
# ----------------------------------
$_ = '$Intent: proof all the password we deterministically generate in our password manager has at least 122-bits of Shannon Entropy $';
my $ALPHABET = [' '..'~'];
my $MAX_ITERATIONS = 1<<15 // ~0;
# ----------------------------------

my $ikm = pack'H32', &ENV('AXIOME_IKM') // '4c6fd3a8-379e-467b-9574-25e620eba357' =~ y/-//dr; # /!\ secret key obtained from Key Broker Server (unwrapped)
my $salt = pack'H32', 'd9266e3c-ce25-46b6-a11f-7e7d1fe6ae23' =~ y/-//dr;
my $len = int( (117 + log(94))/log(95) ); # ~145bits keysize


my $prk = HKDF($ikm,'prk:v1:'.$salt, {extract => 1});
die if $ikm;


printf ".env: %s\n",encode_base95(substr($prk,-31,30));
printf "prk: %s\n",unpack('H64',$prk),
# --------------------------------------------------
my $info =  "okm:v1:$len:proof of entropy";
printf "info: %s\n",$info;
# Welford's algorithm for mean and variance memory in O(1)
my $n = 0;
my $mean = 0;
my $M2 = 0;  # Sum of squared differences from mean
my $min_entropy = "Inf";
my $max_entropy = "-Inf";
my $interrupted = 0;

# Catch Ctrl+C to exit gracefully
$SIG{INT} = sub { $interrupted = 1; warn "\n^ C caught, finishing current iteration...\n" };

$|++;
while ($n < $MAX_ITERATIONS && !$interrupted) {
  # password derivation
  my $okm = HKDF($prk,$info.$n,$len,{expand=>1});
  #printf "okm: %s\n",unpack'H64',$okm;
  my $pw = &encode_base95($okm); # encode on ASCII charset
  my $entropy = &shannon($pw);
  
  # Welford's algorithm
  $n++;
  my $delta = $entropy - $mean;
  $mean += $delta / $n;
  my $delta2 = $entropy - $mean;
  $M2 += $delta * $delta2;
  # Update min/max
  $min_entropy = $entropy if $entropy < $min_entropy;
  $max_entropy = $entropy if $entropy > $max_entropy;
  
  if ($entropy < 122) {
    printf "\rpw%d: %s # %.2fbits -> avg:%.4f stdev:%.4f",$n,$pw,$entropy,$mean,sqrt($M2/$n);
    die
  }
}
print ".\n";

# Compute variance and stddev from M2
my $variance = ($n > 0) ? $M2 / $n : 0;  # Population variance
my $stddev = sqrt($variance);

printf "\nStatistics for %d iterations:\n", $n;
printf "  Average entropy: %.3f bits\n", $mean;
printf "  Variance: %.6f bits^2\n", $variance;
printf "  Std deviation: %.6f bits\n", $stddev;
printf "  Min: %.3f bits\n", $min_entropy;
printf "  Max: %.3f bits\n", $max_entropy;
printf "  Length: %s %.3f bits\n",$len, 122 + 6 * $stddev;

printf "rate: %sh/s\n",$n/(time - $^T);
# --------------------------------------------------
exit $?;

sub shannon { # Shannon entropy
  my ($data) = @_;
  my %freq;
  
  # Count frequency of each byte value
  #$freq{$_}++ for unpack('C*', $data);
  $freq{$_}++ for split//,$data;
  
  my $len = length($data);
  my $entropy = 0;
  
  # Calculate Shannon entropy: -Σ p(x) * log2(p(x))
  for my $chr (keys %freq) {
    my $p = $freq{$chr} / $len;
    $entropy -= $p * log($p) / log(2);
  }
  return $entropy * $len;
}
1;

