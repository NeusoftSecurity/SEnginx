#!/usr/bin/perl

use strict;
use warnings;

use File::Basename;

my $error_log = $ARGV[1];
my $wl_file = $ARGV[2];
my @wl;
my @output;

die "Usage: gen-wl.pl /path/to/error.log /path/to/wl.conf\n" if @ARGV == 0;
die "invalid number of args\n" if @ARGV != 2;

$error_log = $ARGV[0];
$wl_file = $ARGV[1];

!system("python ./nx_intercept.py -c ./naxsi-ui.conf -l $error_log -n")
    or die 'first step failed';

die 'second step failed' unless (@output = `python nx_extract.py -c ./naxsi-ui.conf -o`);

foreach (@output) {
    if (/(^BasicRule)/) {
        push @wl, $_;
    }
}

open WL_FILE, "> $wl_file" or die "can't open whitelist file: $wl_file";

print WL_FILE @wl;

system 'rm naxsi_sig';

