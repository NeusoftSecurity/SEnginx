#!/usr/bin/perl

# (C) Jason Liu

# Tests for nginx fastest module.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Net::DNS::Nameserver;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

plan(skip_all => 'win32') if $^O eq 'MSWin32';

my @domain_name = (
    "www.senginx.org",
    "bbs.senginx.org",
    "mail.senginx.org");

my %resolve_count;

foreach my $domain (@domain_name) {
    $resolve_count{$domain} = 0;
}

my @addrs = ("3.0.0.1", "3.0.0.2", "3.0.0.3");
for (my $i = 0; $i < @addrs; $i++) {
    my $ret = system("ifconfig lo:$i $addrs[$i]/8");
    if ($ret) {
        die("Config $addrs[$i] to lo:$i failed!\n");
    }
}


my @port_array = (8081, 8082, 8083);

my $unsleep_port = 8084;

my $t = Test::Nginx->new()->has(qw/upstream_least_conn/)->plan(5);

$t->write_file_expand('nginx.conf', <<"EOF");

%%TEST_GLOBALS%%

daemon         off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    upstream pool {
        least_conn;
        server 127.0.0.1:$port_array[0];
        server 127.0.0.1:$port_array[1];
        server 127.0.0.1:$port_array[2];
    }

    upstream pool2 {
        least_conn;
        server $domain_name[0]:$port_array[0];
        server $domain_name[1]:$port_array[1]; 
        server $domain_name[2]:$port_array[2]; 
    }

    upstream pool3 {
        least_conn;
        server www.baidu.com:$port_array[0];
        server 127.0.0.1:$unsleep_port;
    }

    resolver 127.0.0.1:53530 valid=1 ipv6=off;
    resolver_timeout 1s;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;
        location / {
            proxy_pass http://pool;
        }

        location /dyn_resolve {
            proxy_pass http://pool2 dynamic_resolve;
        }

        location /dyn_resolve_error {
            proxy_pass http://pool3 dynamic_resolve;
        }
    }
}

EOF

my $fastest = int(rand(@port_array));

my $def_sleep_time = 6;

for(my $index = 0; $index < @port_array; $index++) {
    my $sleep_time;

    if ($index == $fastest) {
        $sleep_time = 0;
    } else {
        $sleep_time = $def_sleep_time;
    }

    $t->run_daemon(\&http_daemon, "127.0.0.1", $port_array[$index], $sleep_time);
    $t->run_daemon(\&http_daemon, $addrs[$index], $port_array[$index], $sleep_time);
}
$t->run_daemon(\&http_daemon, "127.0.0.1", $unsleep_port, 0);
$t->run_daemon(\&dns_server_daemon);
$t->run();

##########################################################################################################
for(my $index = 0; $index < @port_array; $index++) {
    $t->run_daemon(\&get_resp, "/test.html");
    $t->run_daemon(\&get_resp, "/dyn_resolve");
}

sleep 1;
like(http_get('/test.html'), qr/TEST-OK-IF-YOU-SEE-THIS-FROM-$port_array[$fastest]/m, "request fastest");
like(http_get('/test.html'), qr/TEST-OK-IF-YOU-SEE-THIS-FROM-$port_array[$fastest]/m, "request fastest");
sleep 2;
like(http_get('/dyn_resolve '), qr/TEST-DR-OK-IF-YOU-SEE-THIS-FROM-$port_array[$fastest]-127/m, "request fastest after reslove");
sleep 2;
like(http_get('/dyn_resolve '), qr/TEST-DR-OK-IF-YOU-SEE-THIS-FROM-$port_array[$fastest]-$addrs[$fastest]/m, "request fastest after reslove");
like(http_get('/dyn_resolve_error '), qr/TEST-DR-OK-IF-YOU-SEE-THIS-FROM-$unsleep_port-127/m, "get next when reslove failed");

for (my $i = 0; $i < @addrs; $i++) {
    system("ifconfig lo:$i 0.0.0.0 2>/dev/null");
}
##########################################################################################################

sub http_daemon {
    my ($addr, $port, $sleep_time) = @_;
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

        sleep $sleep_time;

		$uri = $1 if $headers =~ /^\S+\s+([^ ]+)\s+HTTP/i;

		if ($uri eq '/test.html') {

			print $client <<"EOF";
HTTP/1.1 200 OK
Connection: close

TEST-OK-IF-YOU-SEE-THIS-FROM-$port

EOF
        } elsif ($uri =~ /dyn_resolve/) {

			print $client <<"EOF";
HTTP/1.1 200 OK
Connection: close

TEST-DR-OK-IF-YOU-SEE-THIS-FROM-$port-$addr

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

sub get_resp {
    my ($url) = @_;
    http_get($url);
    while (1) {
        sleep 100;
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
            if ($resolve_count{$domain} == 0) {
                ($ttl, $rdata) = (3600, $addrs[$i]);
                $resolve_count{$domain} = 1;
            } else {
                $resolve_count{$domain} = 0;
                ($ttl, $rdata) = (3600, "127.0.0.1");
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
