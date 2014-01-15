#!/usr/bin/perl

# (C) Paul Yang

# Tests for active challenge (aka. L7 DDoS Mitigation/Active Challenge) module.

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

my $t = Test::Nginx->new()->has(qw/http proxy robot_mitigation/)->plan(4);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon         off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    robot_mitigation_resolver 127.0.0.1:53530;
    robot_mitigation_resolver_timeout 1s;
            
    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /ip_whitelist1 {
            robot_mitigation on;
            robot_mitigation_cookie_name rm-autotest;
            robot_mitigation_mode js;
            robot_mitigation_timeout 600;

            robot_mitigation_ip_whitelist {
                "3.0.0.1" "3.2.1.254";
                "127.0.0.1";
                "6.0.0.1" "7.2.1.254";
            }

            robot_mitigation_whitelist {
                "autotest" ".*.test.com";
            }
            
            proxy_pass http://127.0.0.1:8081;
            proxy_read_timeout 1s;
        }

        location /ip_whitelist2 {
            robot_mitigation on;
            robot_mitigation_cookie_name rm-autotest;
            robot_mitigation_mode js;
            robot_mitigation_timeout 600;

            robot_mitigation_whitelist {
                "autotest" ".*.test.com";
            }
            
            robot_mitigation_ip_whitelist {
                "3.0.0.1" "3.2.1.254";
                "12.0.0.1";
                "8.0.0.1" "9.2.1.254";
            }

            proxy_pass http://127.0.0.1:8081;
            proxy_read_timeout 1s;
        }
    }
}

EOF

$t->run_daemon(\&http_daemon);
$t->run_daemon(\&dns_server_daemon);
$t->run();

###############################################################################

like(http_get_with_header('/ip_whitelist1', 'User-Agent: autotest'), qr/TEST-OK-IF-YOU-SEE-THIS/, 'http get request with special user-agent and location to bypass anti-robot, ac method js');
like(http_get('/ip_whitelist1'), qr/TEST-OK-IF-YOU-SEE-THIS/, 'http get request, ac method js');
#Send http request with both of header whitelist and ip whitelist matched, but domain not match, expect get js
like(http_get_with_header('/ip_whitelist2', 'User-Agent: autotest'), qr/rm-autotest/, 'http get request with special user-agent and location to bypass anti-robot, but should failed, ac method js');
#Send http request with ip whitelist matched but header whitelist not matched, expect get js
like(http_get('/ip_whitelist2'), qr/rm-autotest/, 'http get request, ac method js');

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
        } elsif ($uri eq '/whitelist_caseless'){
            print $client <<'EOF';
HTTP/1.1 200 OK
Connection: close

EOF
            print $client "TEST-OK-IF-YOU-SEE-THIS"
            unless $headers =~ /^HEAD/i;
        } elsif ($uri eq '/ip_whitelist1') {
            print $client <<'EOF';
HTTP/1.1 200 OK
Connection: close

EOF
            print $client "TEST-OK-IF-YOU-SEE-THIS"
            unless $headers =~ /^HEAD/i;

        } elsif ($uri eq '/ip_whitelist2') {
            print $client <<'EOF';
HTTP/1.1 200 OK
Connection: close

EOF
            print $client "TEST-OK-IF-YOU-SEE-THIS"
            unless $headers =~ /^HEAD/i;

        } elsif ($uri eq '/post') {

            print $client <<"EOF";
HTTP/1.1 200 OK
Connection: close

TEST-OK-IF-YOU-SEE-THIS

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

    $query->print;

    $rcode = "NXDOMAIN";

# Only return "Not found"
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
