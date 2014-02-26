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

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http proxy robot_mitigation/)->plan(21);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon         off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    whitelist_ua $u_a {
        "autotest";
    }

    whitelist_ua $u_b {
        caseless;
        "autotest";
    }

    geo $i_a {
        ranges;
        default 0;
        1.0.0.1-3.2.1.254 1;
        127.0.0.1-127.0.0.1 1;
    }

    geo $i_b {
        ranges;
        default 0;
        10.0.0.1-30.2.1.254 1;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            robot_mitigation on;
            robot_mitigation_cookie_name rm-autotest;
            robot_mitigation_mode js;
            robot_mitigation_timeout 600;

            robot_mitigation_global_whitelist ua_var_name=u_a;

            proxy_pass http://127.0.0.1:8081;
            proxy_read_timeout 1s;
        }

        location /whitelist_caseless {
            robot_mitigation on;
            robot_mitigation_cookie_name rm-autotest;
            robot_mitigation_mode js;
            robot_mitigation_timeout 600;

            robot_mitigation_global_whitelist ua_var_name=u_b;

            proxy_pass http://127.0.0.1:8081;
            proxy_read_timeout 1s;
        }

        location /ip_whitelist1 {
            robot_mitigation on;
            robot_mitigation_cookie_name rm-autotest;
            robot_mitigation_mode js;
            robot_mitigation_timeout 600;

            robot_mitigation_global_whitelist ua_var_name=u_a ip_var_name=i_a ip_var_value=1;

            proxy_pass http://127.0.0.1:8081;
            proxy_read_timeout 1s;
        }

        location /ip_whitelist2 {
            robot_mitigation on;
            robot_mitigation_cookie_name rm-autotest;
            robot_mitigation_mode js;
            robot_mitigation_timeout 600;

            robot_mitigation_global_whitelist ip_var_name=i_a ip_var_value=1;

            proxy_pass http://127.0.0.1:8081;
            proxy_read_timeout 1s;
        }

        location /ip_whitelist3 {
            robot_mitigation on;
            robot_mitigation_cookie_name rm-autotest;
            robot_mitigation_mode js;
            robot_mitigation_timeout 600;

            robot_mitigation_global_whitelist ua_var_name=u_a ip_var_name=i_a ip_var_value=1;

            proxy_pass http://127.0.0.1:8081;
            proxy_read_timeout 1s;
        }

        location /ip_whitelist4 {
            robot_mitigation on;
            robot_mitigation_cookie_name rm-autotest;
            robot_mitigation_mode js;
            robot_mitigation_timeout 600;

            robot_mitigation_global_whitelist ua_var_name=u_a ip_var_name=i_b ip_var_value=1;

            proxy_pass http://127.0.0.1:8081;
            proxy_read_timeout 1s;
        }

        location /ip_whitelist5 {
            robot_mitigation on;
            robot_mitigation_cookie_name rm-autotest;
            robot_mitigation_mode js;
            robot_mitigation_timeout 600;

            robot_mitigation_global_whitelist ua_var_name=u_a ip_var_name=i_a ip_var_value=1;

            proxy_pass http://127.0.0.1:8081;
            proxy_read_timeout 1s;
        }
    }
}

EOF

$t->run_daemon(\&http_daemon);
$t->run();

###############################################################################

my $r = http_get('/');
like($r, qr/rm-autotest/, 'http get request, ac method js');
like($r, qr/Cache-Control: no-cache, no-store/, 'http get request, ac method js');

like(http_get_with_header('/', 'User-Agent: autotest'), qr/TEST-OK-IF-YOU-SEE-THIS/, 'http get request with special user-agent to bypass anti-robot, ac method js');
like(http_get_with_header('/whitelist_caseless', 'User-Agent: AUTOTEST'), qr/TEST-OK-IF-YOU-SEE-THIS/, 'http get request with special user-agent to bypass anti-robot, ac method js');
like(http_get_with_header('/ip_whitelist1', 'User-Agent: autotest'), qr/TEST-OK-IF-YOU-SEE-THIS/, 'http get request with special user-agent and location to bypass anti-robot, ac method js');

like(http_get('/ip_whitelist1'), qr/TEST-OK-IF-YOU-SEE-THIS/, 'http get request with special location to bypass anti-robot, ac method js');
like(http_get('/ip_whitelist2'), qr/TEST-OK-IF-YOU-SEE-THIS/, 'http get request with special location to bypass anti-robot, ac method js');
#Send http request with both of header whitelist and ip whitelist matched, expect get response from server
like(http_get_with_header('/ip_whitelist3', 'User-Agent: autotest'), qr/TEST-OK-IF-YOU-SEE-THIS/, 'http get request with special user-agent and location to bypass anti-robot, ac method js');
#Send http request with header whitelist not matched but ip whitelist matched, expect get response from server
like(http_get('/ip_whitelist3'), qr/TEST-OK-IF-YOU-SEE-THIS/, 'http get request bypass anti-robot, ac method js');
#Send http request with header whitelist matched but ip whitelist not matched, expect get response from server
like(http_get_with_header('/ip_whitelist4', 'User-Agent: autotest'), qr/TEST-OK-IF-YOU-SEE-THIS/, 'http get request with special user-agent and location to bypass anti-robot');
#Send http request with both header whitelist and ip whitelist not matched, expect get js
like(http_get('/ip_whitelist4'), qr/rm-autotest/, 'http get request, ac method js');
#Send http request with both of header whitelist and ip whitelist matched, expect get response from server
like(http_get_with_header('/ip_whitelist5', 'User-Agent: autotest'), qr/TEST-OK-IF-YOU-SEE-THIS/, 'http get request with special user-agent and location to bypass anti-robot, ac method js');
#Send http request with ip whitelist matched but header whitelist not matched, expect get response from server
like(http_get('/ip_whitelist5'), qr/TEST-OK-IF-YOU-SEE-THIS/, 'http get request with special user-agent and location to bypass anti-robot, ac method js');
like(http_post('/post', 'a=1&b=2'), qr/<form name=\"response\" method=\"post\"><input type=\"hidden\" name=\"a\" value=\"1\">\n<input type=\"hidden\" name=\"b\" value=\"2\">\n<\/form>/, 'http post request, ac method js');

like(http_post('/post', '&b=2'), qr/<form name=\"response\" method=\"post\"><input type=\"hidden\" name=\"b\" value=\"2\">\n<\/form>/, 'http post request, ac method js');

like(http_post('/post', 'b=2'), qr/<form name=\"response\" method=\"post\"><input type=\"hidden\" name=\"b\" value=\"2\">\n<\/form>/, 'http post request, ac method js');

like(http_post('/post', 'b=2&'), qr/<form name=\"response\" method=\"post\"><input type=\"hidden\" name=\"b\" value=\"2\">\n<\/form>/, 'http post request, ac method js');

like(http_post('/post', 'b=2&&'), qr/<form name=\"response\" method=\"post\"><input type=\"hidden\" name=\"b\" value=\"2\">\n<\/form>/, 'http post request, ac method js');

like(http_post('/post', '&&b=2'), qr/<form name=\"response\" method=\"post\"><input type=\"hidden\" name=\"b\" value=\"2\">\n<\/form>/, 'http post request, ac method js');

like(http_post_multipart('/post', 'some dummy things'), qr/TEST-OK-IF-YOU-SEE-THIS/, 'http multipart post request, ac method js');

unlike(http_head('/'), qr/SEE-THIS/, 'http head request, ac method js');

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

###############################################################################
