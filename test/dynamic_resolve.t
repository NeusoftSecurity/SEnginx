#!/usr/bin/perl

# (C) Jason Liu

# Tests for dynamic resolve in proxy module.

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

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(6);
my $resolve_count = 0;
my @addrs = ("3.0.0.1", "3.0.0.2", "3.0.0.3");
for (my $i = 0; $i < @addrs; $i++) {
    my $ret = system("ifconfig lo:$i $addrs[$i]/8");
    if ($ret) {
        die("Config $addrs[$i] to lo:$i failed!\n");
    }
}

my $domain_name1 = "www.senginx-test.com";
my $domain_name2 = "test.senginx-test.com";
my $domain_name3 = "can-not-resolve.com";
$t->write_file_expand('nginx.conf', <<"EOF");

%%TEST_GLOBALS%%

daemon         off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    resolver 127.0.0.1:53530 valid=1;
    resolver_timeout 1s;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            proxy_pass http://$domain_name1:8081 dynamic_resolve;
        }

        location /dns_loadblance {
            proxy_pass http://$domain_name2:8081 dynamic_resolve;
        }

        location /dns_error {
            proxy_pass http://$domain_name3:8081 dynamic_resolve;
        }
    }
}

EOF

$t->run_daemon(\&http_daemon, "127.0.0.1");
foreach my $ip (@addrs) {
    $t->run_daemon(\&http_daemon, $ip);
}
$t->run_daemon(\&dns_server_daemon);
$t->run();

###############################################################################

like(http_get('/'), qr/TEST-1-OK-IF-YOU-SEE-THIS-127/, 'expect http server is 127');
sleep(2);
like(http_get('/'), qr/TEST-1-OK-IF-YOU-SEE-THIS-$addrs[0]/, 'expect http server is the first member in @addrs');
sleep(2);
like(http_get('/'), qr/TEST-1-OK-IF-YOU-SEE-THIS-127/, 'expect http server is 127');
sleep(2);
like(http_get('/dns_loadblance'), qr/TEST-2-OK-IF-YOU-SEE-THIS-3/, 'expect http server is one of @addrs');
sleep(2);
like(http_get('/dns_loadblance'), qr/TEST-2-OK-IF-YOU-SEE-THIS-127/, 'expect http server is 127');
like(http_get('/dns_error'), qr/502 Bad Gateway/, 'get 502 when resolve failed');

for (my $i = 0; $i < @addrs; $i++) {
    system("ifconfig lo:$i 0.0.0.0 2>/dev/null");
}
###############################################################################

sub http_daemon {
    my ($addr) = @_;
    my $server = IO::Socket::INET->new(
        Proto => 'tcp',
        LocalHost => "$addr:8081",
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
            print $client <<'EOF';
HTTP/1.1 200 OK
Connection: close

EOF
            print $client "TEST-1-OK-IF-YOU-SEE-THIS-$addr"
            unless $headers =~ /^HEAD/i;

        } elsif ($uri eq '/dns_loadblance') {
            print $client <<'EOF';
HTTP/1.1 200 OK
Connection: close

EOF
            print $client "TEST-2-OK-IF-YOU-SEE-THIS-$addr"
            unless $headers =~ /^HEAD/i;

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

    if ($resolve_count == 0) {
        $resolve_count = 1; 
    } else {
        $resolve_count = 0; 
    }

    if ($resolve_count == 1) {
        ($ttl, $rdata) = (3600, "127.0.0.1");
        $rr = new Net::DNS::RR("$qname $ttl $qclass $qtype $rdata");
        push @ans, $rr;
        $rcode = "NOERROR";
    } elsif ($qname eq $domain_name1) {
        ($ttl, $rdata) = (3600, $addrs[0]);
        $rr = new Net::DNS::RR("$qname $ttl $qclass $qtype $rdata");
        push @ans, $rr;
        $rcode = "NOERROR";
    } elsif ($qname eq $domain_name2) {
        foreach my $ip (@addrs) {
            ($ttl, $rdata) = (3600, $ip);
            $rr = new Net::DNS::RR("$qname $ttl $qclass $qtype $rdata");
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
