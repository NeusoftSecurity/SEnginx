#!/usr/bin/perl

# (C) Paul Yang

# Tests for active challenge (aka. L7 DDoS Mitigation/Active Challenge) module.

###############################################################################

use warnings;
use strict;

use Test::More;
use Net::DNS::Nameserver;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib '../lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http proxy robot_mitigation/)->plan(18);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon         off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    robot_mitigation_resolver 127.0.0.1;
    robot_mitigation_resolver_timeout 1s;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            robot_mitigation on;
            robot_mitigation_cookie_name rm-autotest;
            robot_mitigation_mode js;
            robot_mitigation_timeout 600;

            robot_mitigation_whitelist {
                "autotest" ".*.test.com";
            }

            proxy_pass http://127.0.0.1:8081;
            proxy_read_timeout 1s;
        }

        location /whitelist_caseless {
            robot_mitigation on;
            robot_mitigation_cookie_name rm-autotest;
            robot_mitigation_mode js;
            robot_mitigation_timeout 600;

            robot_mitigation_whitelist_caseless on;
            robot_mitigation_whitelist {
                "autotest" ".*.test.com";
            }

            proxy_pass http://127.0.0.1:8081;
            proxy_read_timeout 1s;
        }

        location /ip_whitelist1 {
            robot_mitigation on;
            robot_mitigation_cookie_name rm-autotest;
            robot_mitigation_mode js;
            robot_mitigation_timeout 600;

            robot_mitigation_ip_whitelist {
                "127.0.0.1";
                "3.0.0.1" "3.2.1.254";
            }

            robot_mitigation_whitelist {
                "autotest";
            }
            
            proxy_pass http://127.0.0.1:8081;
            proxy_read_timeout 1s;
        }

        location /ip_whitelist2 {
            robot_mitigation on;
            robot_mitigation_cookie_name rm-autotest;
            robot_mitigation_mode js;
            robot_mitigation_timeout 600;

            robot_mitigation_ip_whitelist {
                "1.0.0.1" "2.2.1.254";
                "127.0.0.1";
            }

            proxy_pass http://127.0.0.1:8081;
            proxy_read_timeout 1s;
        }

        location /ip_whitelist3 {
            robot_mitigation on;
            robot_mitigation_cookie_name rm-autotest;
            robot_mitigation_mode js;
            robot_mitigation_timeout 600;

            robot_mitigation_whitelist {
                "autotest";
            }
            
            robot_mitigation_ip_whitelist {
                "1.0.0.1" "3.2.1.254";
                "127.0.0.1";
                "3.0.0.1" "5.2.1.254";
            }

            proxy_pass http://127.0.0.1:8081;
            proxy_read_timeout 1s;
        }

        location /ip_whitelist4 {
            robot_mitigation on;
            robot_mitigation_cookie_name rm-autotest;
            robot_mitigation_mode js;
            robot_mitigation_timeout 600;

            robot_mitigation_whitelist {
                "autotest";
            }
            
            robot_mitigation_ip_whitelist {
                "1.0.0.1" "3.2.1.254";
                "12.0.0.1";
                "3.0.0.1" "7.2.1.254";
            }

            proxy_pass http://127.0.0.1:8081;
            proxy_read_timeout 1s;
        }

        location /ip_whitelist5 {
            robot_mitigation on;
            robot_mitigation_cookie_name rm-autotest;
            robot_mitigation_mode js;
            robot_mitigation_timeout 600;

            robot_mitigation_whitelist {
                "autotest" "senginx.test.com";
            }
            
            proxy_pass http://127.0.0.1:8081;
            proxy_read_timeout 1s;
        }

        location /ip_whitelist6 {
            robot_mitigation on;
            robot_mitigation_cookie_name rm-autotest;
            robot_mitigation_mode js;
            robot_mitigation_timeout 600;

            robot_mitigation_whitelist {
                "autotest" "www.test.com";
            }
            
            proxy_pass http://127.0.0.1:8081;
            proxy_read_timeout 1s;
        }

        location /ip_whitelist7 {
            robot_mitigation on;
            robot_mitigation_cookie_name rm-autotest;
            robot_mitigation_mode js;
            robot_mitigation_timeout 600;

            robot_mitigation_whitelist {
                "autotest" ".*.test.com";
            }
            
            proxy_pass http://127.0.0.1:8081;
            proxy_read_timeout 1s;
        }

        location /ip_whitelist8 {
            robot_mitigation on;
            robot_mitigation_cookie_name rm-autotest;
            robot_mitigation_mode js;
            robot_mitigation_timeout 600;

            robot_mitigation_whitelist {
                "autotest" ".*.test.com";
            }
            
            robot_mitigation_ip_whitelist {
                "127.0.0.1" "127.0.0.189";
            }

            
            proxy_pass http://127.0.0.1:8081;
            proxy_read_timeout 1s;
        }

        location /ip_whitelist9 {
            robot_mitigation on;
            robot_mitigation_cookie_name rm-autotest;
            robot_mitigation_mode js;
            robot_mitigation_timeout 600;

            robot_mitigation_whitelist {
                "autotest" ".*.test.com";
            }
            
            robot_mitigation_ip_whitelist {
                "12.0.0.1";
            }

            
            proxy_pass http://127.0.0.1:8081;
            proxy_read_timeout 1s;
        }

        location /ip_whitelist10 {
            robot_mitigation on;
            robot_mitigation_cookie_name rm-autotest;
            robot_mitigation_mode js;
            robot_mitigation_timeout 600;

            robot_mitigation_whitelist {
                "autotest" "www.test.com";
            }
            
            robot_mitigation_ip_whitelist {
                "1.0.1.1" "127.0.0.12";
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

like(http_get('/'), qr/rm-autotest/, 'http get request, ac method js');

like(http_get_with_header('/', 'User-Agent: autotest'), qr/TEST-OK-IF-YOU-SEE-THIS/, 'http get request with special user-agent to bypass anti-robot, ac method js');
like(http_get_with_header('/whitelist_caseless', 'User-Agent: AUTOTEST'), qr/TEST-OK-IF-YOU-SEE-THIS/, 'http get request with special user-agent to bypass anti-robot, ac method js');
like(http_get_with_header('/ip_whitelist1', 'User-Agent: autotest'), qr/TEST-OK-IF-YOU-SEE-THIS/, 'http get request with special user-agent and location to bypass anti-robot, ac method js');

like(http_get('/ip_whitelist1'), qr/TEST-OK-IF-YOU-SEE-THIS/, 'http get request, ac method js');
like(http_get('/ip_whitelist2'), qr/TEST-OK-IF-YOU-SEE-THIS/, 'http get request with special location to bypass anti-robot, ac method js');
#Send http request with both of header whitelist and ip whitelist matched, expect get response from server
like(http_get_with_header('/ip_whitelist3', 'User-Agent: autotest'), qr/TEST-OK-IF-YOU-SEE-THIS/, 'http get request with special user-agent and location to bypass anti-robot, ac method js');
#Send http request with ip whitelist matched but header whitelist not matched, expect get response from server
like(http_get('/ip_whitelist3'), qr/TEST-OK-IF-YOU-SEE-THIS/, 'http get request, ac method js');
#Send http request with header whitelist matched but ip whitelist not matched, expect get response from server
like(http_get_with_header('/ip_whitelist4', 'User-Agent: autotest'), qr/TEST-OK-IF-YOU-SEE-THIS/, 'http get request with special user-agent and location to bypass anti-robot, but shuold be failed, ac method js');
#Send http request with both of header whitelist and ip whitelist matched, expect get response from server
like(http_get_with_header('/ip_whitelist5', 'User-Agent: autotest'), qr/TEST-OK-IF-YOU-SEE-THIS/, 'http get request with special user-agent and location to bypass anti-robot, ac method js');
#Send http request with domain whitelist matched but header whitelist not matched, expect get js
like(http_get('/ip_whitelist5'), qr/rm-autotest/, 'http get request with special user-agent and location to bypass anti-robot, ac method js');
#Send http request with header whitelist matched but ip whitelist not matched, expect get js
like(http_get_with_header('/ip_whitelist6', 'User-Agent: autotest'), qr/rm-autotest/, 'http get request with special user-agent and location to bypass anti-robot, ac method js');
#Send http request with both of ip whitelist and header whitelist not matched, expect get js
like(http_get('/ip_whitelist6'), qr/rm-autotest/, 'http get request, ac method js');
#Send http request with both of header and domain name matched by regular expression, expect get response from server
like(http_get_with_header('/ip_whitelist7', 'User-Agent: autotest'), qr/TEST-OK-IF-YOU-SEE-THIS/, 'http get request with special user-agent and location to bypass anti-robot, ac method js');
#Send http request with all of header, domain name and ip whitelist matched, expect get response from server
like(http_get_with_header('/ip_whitelist8', 'User-Agent: autotest'), qr/TEST-OK-IF-YOU-SEE-THIS/, 'http get request with special user-agent and location to bypass anti-robot, ac method js');
#Send http request with header and domain matched but ip whitelist not matched, expect get response from server
like(http_get_with_header('/ip_whitelist9', 'User-Agent: autotest'), qr/TEST-OK-IF-YOU-SEE-THIS/, 'http get request with special user-agent and location to bypass anti-robot, ac method js');
#Send http request with both of ip whitelist and header whitelist not matched, expect get js
like(http_get('/ip_whitelist9'), qr/rm-autotest/, 'http get request, ac method js');
#Send http request with header and ip whitelist matched but domain not matched, expect get response from server
like(http_get('/ip_whitelist10'), qr/TEST-OK-IF-YOU-SEE-THIS/, 'http get request with special user-agent and location to bypass anti-robot, ac method js');
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

        } elsif ($uri eq '/ip_whitelist3') {
            print $client <<'EOF';
HTTP/1.1 200 OK
Connection: close

EOF
            print $client "TEST-OK-IF-YOU-SEE-THIS"
            unless $headers =~ /^HEAD/i;

        } elsif ($uri eq '/ip_whitelist4') {
            print $client <<'EOF';
HTTP/1.1 200 OK
Connection: close

EOF
            print $client "TEST-OK-IF-YOU-SEE-THIS"
            unless $headers =~ /^HEAD/i;

        } elsif ($uri eq '/ip_whitelist5') {
            print $client <<'EOF';
HTTP/1.1 200 OK
Connection: close

EOF
            print $client "TEST-OK-IF-YOU-SEE-THIS"
            unless $headers =~ /^HEAD/i;

        } elsif ($uri eq '/ip_whitelist6') {
            print $client <<'EOF';
HTTP/1.1 200 OK
Connection: close

EOF
            print $client "TEST-OK-IF-YOU-SEE-THIS"
            unless $headers =~ /^HEAD/i;

        } elsif ($uri eq '/ip_whitelist7') {
            print $client <<'EOF';
HTTP/1.1 200 OK
Connection: close

EOF
            print $client "TEST-OK-IF-YOU-SEE-THIS"
            unless $headers =~ /^HEAD/i;

        } elsif ($uri eq '/ip_whitelist8') {
            print $client <<'EOF';
HTTP/1.1 200 OK
Connection: close

EOF
            print $client "TEST-OK-IF-YOU-SEE-THIS"
            unless $headers =~ /^HEAD/i;

        } elsif ($uri eq '/ip_whitelist9') {
            print $client <<'EOF';
HTTP/1.1 200 OK
Connection: close

EOF
            print $client "TEST-OK-IF-YOU-SEE-THIS"
            unless $headers =~ /^HEAD/i;

        } elsif ($uri eq '/ip_whitelist10') {
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

    print "Received query from $peerhost to ". $conn->{sockhost}. "\n";
    $query->print;

    if ($qtype eq "PTR" && $qname eq "1.0.0.127.in-addr.arpa") {
        ($ttl, $rdata) = (3600, "senginx.test.com");
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
        LocalPort    => 53,
        ReplyHandler => \&reply_handler,
    Verbose      => 1
    ) || die "couldn't create nameserver object\n";

    $ns->main_loop;
}

###############################################################################
