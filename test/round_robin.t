#!/usr/bin/perl

# (C) Jason Liu

# Tests for nginx round_robin module.

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

my @port_array = (8081, 8082, 8083);

my $test_num = @port_array;
my $resolve_count1 = 0;
my $resolve_count2 = 0;
my $domain_name1 = "www.senginx.org";
my $domain_name2 = "bbs.senginx.org";

my @addrs = ("3.0.0.1", "3.0.0.2", "3.0.0.3");
for (my $i = 0; $i < @addrs; $i++) {
    my $ret = system("ifconfig lo:$i $addrs[$i]/8");
    if ($ret) {
        die("Config $addrs[$i] to lo:$i failed!\n");
    }
}

$test_num = 2*$test_num + 6;
my $t = Test::Nginx->new()->has(qw/upstream_round_robin/)->plan($test_num);

$t->write_file_expand('nginx.conf', <<"EOF");

%%TEST_GLOBALS%%

daemon         off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    upstream pool {
        server 127.0.0.1:$port_array[0];
        server 127.0.0.1:$port_array[1];
        server 127.0.0.1:$port_array[2];
    }

    upstream pool2 {
        server $domain_name1:$port_array[0];
        server 127.0.0.1:$port_array[1];
        server $domain_name2:$port_array[2]; 
    }

    upstream pool3 {
        server $domain_name1:$port_array[0];
        server $domain_name2:$port_array[2] backup; 
    }

    upstream pool4 {
        server $domain_name1:$port_array[0];
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

        location /dyn_resolve_error2 {
            proxy_pass http://pool4 dynamic_resolve;
        }
    }
}

EOF

my $each_port;
foreach $each_port (@port_array) {
    $t->run_daemon(\&http_daemon, "127.0.0.1", $each_port);
}
$t->run_daemon(\&http_daemon, $addrs[0], $port_array[0]);
foreach my $ip (@addrs) {
    $t->run_daemon(\&http_daemon, $ip, $port_array[2]);
}
$t->run_daemon(\&dns_server_daemon);
$t->run();

##########################################################################################################
foreach $each_port (@port_array) {
    like(http_get('/test.html'), qr/TEST-OK-IF-YOU-SEE-THIS-FROM-$each_port/m, "request $each_port");
}

foreach $each_port (@port_array) {
    like(http_get('/dyn_resolve'), qr/TEST-DR-OK-IF-YOU-SEE-THIS-FROM-$each_port-127/m, "get response from 127 port:$each_port");
}
sleep(2);
like(http_get('/dyn_resolve'), qr/TEST-DR-OK-IF-YOU-SEE-THIS-FROM-$port_array[0]-$addrs[0]/m, "get response after server ip changed");
like(http_get('/dyn_resolve'), qr/TEST-DR-OK-IF-YOU-SEE-THIS-FROM-$port_array[1]-127/m, "get response after server ip changed");
like(http_get('/dyn_resolve'), qr/TEST-DR-OK-IF-YOU-SEE-THIS-FROM-$port_array[2]-3/m, "get response after server ip changed");
sleep(2);
like(http_get('/dyn_resolve'), qr/TEST-DR-OK-IF-YOU-SEE-THIS-FROM-$port_array[1]-127/m, "get response when DNS failed");
sleep(2);
like(http_get('/dyn_resolve_error'), qr/TEST-DR-OK-IF-YOU-SEE-THIS-FROM-$port_array[2]-127/m, "get response from backup server");
like(http_get('/dyn_resolve_error2'), qr/502 Bad Gateway/m, "get 502 when resolve failed");

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


sub reply_handler {
    my ($qname, $qclass, $qtype, $peerhost,$query,$conn) = @_;
    my ($rcode, $rr, $ttl, $rdata, @ans, @auth, @add,);
    my $addr;

    #print "Received query from $peerhost to ". $conn->{sockhost}. "\n";
    $query->print;

    if ($qtype ne "A") {
        $rcode = "NXDOMAIN";
        return ($rcode, \@ans, \@auth, \@add, { aa => 1 });
    }

    if ($qname eq $domain_name1) {
        if ($resolve_count1 == 0) {
            $resolve_count1 = 1; 
            ($ttl, $rdata) = (3600, "127.0.0.1");
        } elsif ($resolve_count1 == 1) {
            $resolve_count1 = 2; 
            ($ttl, $rdata) = (3600, $addrs[0]);
        } else {
            $rcode = "NXDOMAIN";
            return ($rcode, \@ans, \@auth, \@add, { aa => 1 });
        }

        $rr = new Net::DNS::RR("$qname $ttl $qclass $qtype $rdata");
        push @ans, $rr;
        $rcode = "NOERROR";
    } elsif ($qname eq $domain_name2) {
        if ($resolve_count2 == 0) {
            $resolve_count2 = 1; 
            ($ttl, $rdata) = (3600, "127.0.0.1");
            $rr = new Net::DNS::RR("$qname $ttl $qclass $qtype $rdata");
            push @ans, $rr;
        } else {
            $resolve_count2 = 0; 
            foreach my $ip (@addrs) {
                ($ttl, $rdata) = (3600, $ip);
                $rr = new Net::DNS::RR("$qname $ttl $qclass $qtype $rdata");
            }
            push @ans, $rr;
        }
        $rcode = "NOERROR";
    } else {
        $rcode = "NXDOMAIN";
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
