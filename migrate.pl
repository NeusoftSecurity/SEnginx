#!/usr/bin/perl

use strict;
use Getopt::Std;
use vars qw($opt_p $opt_h);

getopts('p:h');

sub usage {
    print ("usage: $0 -p [path of nginx binary file]\n");
}

if ($opt_h) {
    &usage;
    exit 0;
}

if (!$opt_p) {
    &usage;
    exit 1;
}

# we have a path of original nginx binary file

my $nginx = "$opt_p";
my @rslt = split("\n", `$nginx -V 2>&1`);
my ($version, $config);

if (!@rslt) {
    print "Invalid nginx binary file\n";
    exit 1;
}

foreach (@rslt) {
    m/nginx version: nginx\/(.*)/;
    $version = $1;

    m/configure arguments: (.*)/;
    $config = $1;
}

print "\n";
print "nginx found at $nginx, version: $version\n";
print "\n";
print "use configuration: $config\n";
print "\n";

print "Are you sure to continue?[y/n] ";
chomp(my $flag = <STDIN>);

if ($flag eq "y") {
    print "Configuring SEnginx...";
    `./se-configure.sh $config`;
    print "Done.\n";
    print "Building SEnginx...";
    `make`;
    print "Done.\n";
    print "Installing SEnginx...";
    `make install`;
    print "Done.\n";
} else {
    exit 0;
}

exit 0;
