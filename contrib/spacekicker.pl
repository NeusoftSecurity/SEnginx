#!/usr/bin/perl

use strict;

open(IN, "$ARGV[0]") or die "Can't read file $ARGV[0]\n";

my @result;
my $i = 1;
my $red_bg = "\033[41m";
my $non = "\033[0m";

foreach (<IN>) {
    if (s/^(.*\S)*( +)\n/$1\n/) {
        print "line $i: stripped out spaces: ".$1.$red_bg.$2.$non."\n";
    }

    push @result, $_;

    $i++;
}

close(IN);

open(OUT, ">$ARGV[0]") or die "Can't write file $ARGV[0]\n";
print OUT @result;
close(OUT);
