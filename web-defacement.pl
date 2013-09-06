#!/usr/bin/perl

use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use File::Find;
use Getopt::Std;
use vars qw($opt_d $opt_o $opt_v $opt_h);
use Cwd qw(abs_path);

no warnings 'File::Find';

getopts('d:o:vh');

my $usage = "Usage: $0 -d \"directories\" -o output_file [-v]";

if (defined $opt_h) {
    print "$usage\n";
    exit 0;
}

defined $opt_d or die "parameter error.\n$usage\n";
defined $opt_o or die "parameter error.\n$usage\n";

my @input_dir = split / /, $opt_d;
my @abs_input_dir = map {abs_path($_)} @input_dir;
my $output_file = abs_path($opt_o);
my $verbose = $opt_v;
my %result;
my $count = 0;
my @keys;

open OUTPUT, ">$output_file" or die "Can't open $output_file for write\n"; 

find(\&calc, @abs_input_dir);

@keys = keys %result;
foreach (@keys) {
    print OUTPUT $_, "\x01", $result{$_}, "\n";
}

close OUTPUT;

print "Done: $count records have been written into $output_file.\n";

0;

sub calc {
    my $file;
    my $hash_value;

    if (-d $_) {
        return;
    }

    $file = $File::Find::name;

    !defined $verbose or print "Processing: $file ... ";

    # calc the md5sum of this file
    if (!open READ, "<$file") {
        !defined $verbose or print "Can't open this file, skip\n";
        return;
    }

    $hash_value = md5_hex(<READ>);
    if (defined($hash_value)) {
        !defined $verbose or print "MD5: $hash_value\n";
    } else {
        !defined $verbose or print "Can't read this file, skip\n";
        close READ;
        return;
    }

    close READ;

    $result{$file} = $hash_value;
    $count++;
}
