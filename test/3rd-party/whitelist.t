#!/usr/bin/perl

# (C) Paul Yang

# Tests for whitelist module.

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

my $t = Test::Nginx->new()->has(qw/http proxy whitelist/)->plan(5);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon         off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    resolver 127.0.0.1:53530;
    resolver_timeout 1s;

    whitelist_ua $lista {
        "ua1" ".*\.ua1\.com";
    }

    whitelist_ua $listb {
        caseless;
        "ua2";
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            if ($lista) {
                return 403;
            }

            if ($listb) {
                return 404;
            }

            proxy_pass http://127.0.0.1:8081;
        }
    }
}

EOF

$t->run_daemon(\&http_daemon);
$t->run_daemon(\&dns_server_daemon);
$t->run();

###############################################################################

like(http_get('/'), qr/TEST-OK-IF-YOU-SEE-THIS/,
    'http get with no UA header');

like(http_get_with_header('/', 'User-Agent: autotest'),
    qr/TEST-OK-IF-YOU-SEE-THIS/, 'http get with normal UA');

like(http_get_with_header('/', 'User-Agent: ua1'),
    qr/403/, 'http get with whitelist matched, sould return 403');

like(http_get_with_header('/', 'User-Agent: ua2'),
    qr/404/, 'http get with whitelist matched, sould return 404');

like(http_get_with_header('/', 'User-Agent: Ua2'),
    qr/404/, 'http get with caseless whitelist matched, sould return 404');
###############################################################################

sub http_daemon {
    my $server = IO::Socket::INET->new(
        Proto => 'tcp',
        LocalHost => '127.0.0.1:8081',
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
            print $client "TEST-OK-IF-YOU-SEE-THIS"
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

    print "Received query from $peerhost to ". $conn->{sockhost}. "\n";
    $query->print;

    if ($qtype eq "PTR" && $qname eq "1.0.0.127.in-addr.arpa") {
        ($ttl, $rdata) = (3600, "senginx.ua1.com");
        $rr = new Net::DNS::RR("$qname $ttl $qclass $qtype $rdata");
        push @ans, $rr;
        $rcode = "NOERROR";
    }else{
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
