#!/usr/bin/env perl

use strict;
use warnings;

my ($out, $fdout) = ("nist_aes_xts.json");
my ($state, $i, $first) = (0, 0, 1);
my ($bufpre, $buf, $bufpost) = ("", "", "");
my ($in, $fdin, $line);

my ($keylen) = (undef);
my ($count, $countre) = ("", '^COUNT = (\d+)');
my ($bits, $bitsre) = ("", '^DataUnitLen = (\d+)');
my ($key, $keyre) = ("", '^Key = ([0-9a-f]*)');
my ($iv, $ivre) = ("", '^i = ([0-9a-f]*)');
my ($pt, $ptre) = ("", '^PT = ([0-9a-f]*)');
my ($ct, $ctre) = ("", '^CT = ([0-9a-f]*)');

sub print_begin_tests {
    $buf .= ",\n" if ($first != 1);
    $buf .= <<__;
    {
      "keySize" : $keylen,
      "tests" : [
__
    $keylen = undef;
    $first = 0;
}

sub print_test {
    return if ($bits % 8 != 0);
    $buf .= ",\n" if ($state == 2);
    $buf .= <<__;
        {
          "tcId" : $i,
          "comment" : "$count",
          "key" : "$key",
          "iv" : "$iv",
          "msg" : "$pt",
          "ct" : "$ct"
__
    $buf .= "        }";

    $i = $i + 1;
    $bits = "",
    $key = "";
    $iv="";
    $ct = "";
    $pt = "";
}

sub print_end_tests {
    $buf .= "\n      ]\n";
    $buf .= "    }";
}

printf("Parsing NIST AES-XTS test vectors ...\n");

for (@ARGV) {
    $in=$_;
    open($fdin, '<', $in) || die("ERROR: couldn't open $in ($!).");
 
    $keylen = 128 if ($in =~ /128/);
    $keylen = 256 if ($in =~ /256/);

    print_begin_tests();

    $state = 0;

    while ($line = <$fdin>) {
        chomp($line);

        $bits = $1 if ($line =~ /$bitsre/);
        $key = $1 if ($line =~ /$keyre/);
        $iv = $1 if ($line =~ /$ivre/);
        $ct = $1 if ($line =~ /$ctre/);
        $pt = $1 if ($line =~ /$ptre/);

        if ($state == 0 && $line =~ /$countre/) {
            $state = 1;
            next;
        }
        if ($state == 1 && $line =~ /$countre/) {
            print_test();
            $state = 2;
            next;
        }
        if ($state == 2 && $line =~ /$countre/) {
            print_test();
            next;
        }
    }

    print_test();
    print_end_tests();

    close($fdin);
}

$bufpre = <<__;
{
  "algorithm" : "AES-XTS",
  "numberOfTests" : $i,
  "testGroups" : [
__
$bufpost = "\n  ]\n}";

$buf = $bufpre . $buf . $bufpost;

# Expect 60
printf("$i test vectors found.\n");

open($fdout, '>', $out) || die("ERROR: couldn't open $out ($!).");
print({$fdout}$buf);
close($fdout);
