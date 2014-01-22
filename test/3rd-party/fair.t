#!/usr/bin/perl

# (C) Jason Liu

# Tests for nginx fair module.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib '../lib';
use Test::Nginx;
use Net::DNS::Nameserver;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

plan(skip_all => 'win32') if $^O eq 'MSWin32';

my @domain_name = (
    "test1.senginx-test.com",
    "test2.senginx-test.com",
    "test3.senginx-test.com");

my $resolve_count = 0;

my @addrs = ("3.0.0.1", "3.0.0.2", "3.0.0.3");
for (my $i = 0; $i < @addrs; $i++) {
    my $ret = system("ifconfig lo:$i $addrs[$i]/8");
    if ($ret) {
        die("Config $addrs[$i] to lo:$i failed!\n");
    }
}


my $port = 8081;
my $port2 = 8082;

my $t = Test::Nginx->new()->has(qw/upstream_fair/)->plan(4);

$t->write_file_expand('nginx.conf', <<"EOF");

%%TEST_GLOBALS%%

daemon         off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    upstream pool {
        fair;
        server $domain_name[0]:$port;
        server $domain_name[1]:$port;
        server $domain_name[2]:$port;
    }

    upstream pool2 {
        fair;
        server can-not-resolve.com:$port;
        server 127.0.0.1:$port2;
    }

    resolver 127.0.0.1:53530 valid=1;
    resolver_timeout 1s;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /dyn_resolve {
            proxy_pass http://pool dynamic_resolve;
        }

        location /dyn_resolve_error {
            proxy_pass http://pool2 dynamic_resolve;
        }
    }
}

EOF

foreach my $addr (@addrs) {
    $t->run_daemon(\&http_daemon, $addr, $port);
}
$t->run_daemon(\&http_daemon, "127.0.0.1", $port);
$t->run_daemon(\&http_daemon, "127.0.0.1", $port2);
$t->run_daemon(\&dns_server_daemon);
$t->run();

##########################################################################################################
sleep 1;
like(http_get('/dyn_resolve '), qr/TEST-DR-OK-IF-YOU-SEE-THIS-FROM-127/m, "request after reslove");
sleep 2;
like(http_get('/dyn_resolve '), qr/TEST-DR-OK-IF-YOU-SEE-THIS-FROM-3/m, "request after reslove");
sleep 2;
like(http_get('/dyn_resolve '), qr/TEST-DR-OK-IF-YOU-SEE-THIS-FROM-127/m, "request after reslove");
like(http_get('/dyn_resolve_error '), qr/TEST-DR-OK-IF-YOU-SEE-THIS-FROM-127.0.0.1-$port2/m, "get next when reslove failed");

for (my $i = 0; $i < @addrs; $i++) {
    system("ifconfig lo:$i 0.0.0.0 2>/dev/null");
}
##########################################################################################################

sub http_daemon {
    my ($addr, $port) = @_;
	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalHost => "$addr:$port",
		Listen => 5,
		Reuse => 1
	)
		or die "Can't create listening socket: $!\n";

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		my $headers = '';
		my $uri = '';

		while (<$client>) {
			$headers .= $_;
			last if (/^\x0d?\x0a?$/);
		}

		$uri = $1 if $headers =~ /^\S+\s+([^ ]+)\s+HTTP/i;

		if ($uri eq '/') {

			print $client <<"EOF";
HTTP/1.1 200 OK
Connection: close

TEST-OK-IF-YOU-SEE-THIS-FROM-$addr

EOF
	} elsif ($uri =~ /dyn_resolve/) {

			print $client <<"EOF";
HTTP/1.1 200 OK
Connection: close

TEST-DR-OK-IF-YOU-SEE-THIS-FROM-$addr-$port

EOF
	
	} else {

			print $client <<"EOF";
HTTP/1.1 404 Not Found
Connection: close

Oops, '$uri' not found
EOF
		}

		close $client;
	}
}

sub reply_handler {
    my ($qname, $qclass, $qtype, $peerhost,$query,$conn) = @_;
    my ($rcode, $rr, $ttl, $rdata, @ans, @auth, @add,);

    #print "Received query from $peerhost to ". $conn->{sockhost}. "\n";
    $query->print;

    if ($qtype ne "A") {
        $rcode = "NXDOMAIN";
        return ($rcode, \@ans, \@auth, \@add, { aa => 1 });
    }

    $rcode = "NXDOMAIN";
    for (my $i = 0; $i < @domain_name; $i++) {
        my $domain = $domain_name[$i];
        if ($qname eq $domain) {
            if ($resolve_count == 0) {
                $resolve_count = 1;
                ($ttl, $rdata) = (3600, "127.0.0.1");
            } else {
                $resolve_count = 0;
                ($ttl, $rdata) = (3600, $addrs[$i]);
            }

            $rr = new Net::DNS::RR("$qname $ttl $qclass $qtype $rdata");
            push @ans, $rr;
            $rcode = "NOERROR";
            return ($rcode, \@ans, \@auth, \@add, { aa => 1 });
        }
    }

# mark the answer as authoritive (by setting the 'aa' flag
    return ($rcode, \@ans, \@auth, \@add, { aa => 1 });
}

sub dns_server_daemon {
    my $ns = new Net::DNS::Nameserver(
        LocalPort    => 53530,
        ReplyHandler => \&reply_handler,
        Verbose      => 0
    ) || die "couldn't create nameserver object\n";

    $ns->main_loop;
}

###############################################################################
