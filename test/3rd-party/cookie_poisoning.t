#!/usr/bin/perl

# (C) Paul Yang
# (C) Neusoft Corporation

# Tests for cookie poisoning module.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib '../lib';
use Test::Nginx;

###############################################################################

#select STDERR; $| = 1;
#select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http proxy session cookie_poisoning/)->plan(14);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon         off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    whitelist_ua $u_a {
        "something";
    }

    session_max_size 1000;
    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        session on;

        location / {
            proxy_pass http://127.0.0.1:8081;
        }

        location /cp-block {
            cookie_poisoning on;
            cookie_poisoning_action block;
            cookie_poisoning_log on;
 
            proxy_pass http://127.0.0.1:8081;
        }

        location /cp-whitelist {
            cookie_poisoning on;
            cookie_poisoning_action block;
            cookie_poisoning_log on;
            cookie_poisoning_whitelist ua_var_name=u_a;
 
            proxy_pass http://127.0.0.1:8081;
        }

        location /cp-pass {
            cookie_poisoning on;
            cookie_poisoning_action pass;
 
            proxy_pass http://127.0.0.1:8081;
        }

        location /cp-remove {
            cookie_poisoning on;
            cookie_poisoning_action remove;
 
            proxy_pass http://127.0.0.1:8081;
        }

        location /cp-log {
            cookie_poisoning on;
            cookie_poisoning_action block;
            cookie_poisoning_log on;
            
            proxy_pass http://127.0.0.1:8081;
        }

        location /cp-disable {
            cookie_poisoning off;
            
            proxy_pass http://127.0.0.1:8081;
        }

        location /cp-local.html {
            cookie_poisoning on;
            cookie_poisoning_action block;
            cookie_poisoning_log on;
            add_header Set-Cookie "cp-local-test-cookie=7654321";
        }
    }
}

EOF

my $errlog_dir = $t->{_testdir};
my $errlog = $errlog_dir.'/'.'error.log';
$t->write_file('cp-local.html', 'This-is-local-file');

$t->run_daemon(\&http_daemon);
$t->run();

###############################################################################

my $r = http_get('/');
my $cookie;

my $cookie_session = &cp_get_cookie($r);

$r = http_get_with_header('/cp-block', $cookie_session);
like($r, qr/cp-test-cookie/, 'http cp-block 1st get');

$cookie = &cp_get_cookie($r);
$cookie =~ s/abcdefg/1234567/;
$cookie = $cookie_session."\r\n".$cookie;

unlike(http_get_with_header('/cp-block', $cookie), qr/TEST-OK-IF-YOU-SEE-THIS/, 'http cp-block 2nd get with poisoned cookie');

$r = http_get_with_header('/cp-whitelist', $cookie_session);
like($r, qr/cp-test-cookie/, 'http cp-whitelist 1st get');

$cookie = &cp_get_cookie($r);
$cookie =~ s/abcdefg/1234567/;
$cookie = $cookie_session."\r\n".$cookie;
$cookie = $cookie."\r\nUser-Agent: something";

like(http_get_with_header('/cp-whitelist', $cookie), qr/TEST-OK-IF-YOU-SEE-THIS/, 'http cp-whitelist 2nd get with poisoned cookie');

$r = http_get_with_header('/cp-pass', $cookie_session);
like($r, qr/cp-test-cookie/, 'http cp-pass 1st get');

$cookie = &cp_get_cookie($r);
$cookie =~ s/1234567/abcdefg/;
$cookie = $cookie_session."\r\n".$cookie;

like(http_get_with_header('/cp-pass', $cookie), qr/TEST-OK-IF-YOU-SEE-THIS/, 'http cp-pass 2nd get with poisoned cookie');

$r = http_get_with_header('/cp-remove', $cookie_session);
like($r, qr/cp-test-cookie/, 'http cp-remove 1st get');

$cookie = &cp_get_cookie($r);
$cookie =~ s/1234567/abcdefg/;
$cookie = $cookie_session."\r\n".$cookie;

like(http_get_with_header('/cp-remove', $cookie), qr/TEST-OK-IF-YOU-SEE-THIS/, 'http cp-remove 2nd get with poisoned cookie');

$r = http_get_with_header('/cp-log', $cookie_session);
like($r, qr/cp-test-cookie/, 'http cp-log 1st get');

$cookie = &cp_get_cookie($r);
$cookie =~ s/abcdefg/1234567/;
$cookie = $cookie_session."\r\n".$cookie;
http_get_with_header('/cp-log', $cookie);
like(&cp_check_log(), qr/good/, 'http cp-log 2nd get with poisoned cookie');

$r = http_get_with_header('/cp-disable', $cookie_session);
like($r, qr/cp-test-cookie/, 'http cp-disable 1st get');

$cookie = &cp_get_cookie($r);
$cookie =~ s/abcdefg/1234567/;
$cookie = $cookie_session."\r\n".$cookie;

like(http_get_with_header('/cp-disable', $cookie), qr/TEST-OK-IF-YOU-SEE-THIS/, 'http cp-disable 2nd get with poisoned cookie');

$r = http_get_with_header('/cp-local.html', $cookie_session);
like($r, qr/cp-local-test-cookie/, 'http cp-local.html 1st get');

$cookie = &cp_get_cookie($r);
$cookie =~ s/7654321/1234567/;
$cookie = $cookie_session."\r\n".$cookie;

unlike(http_get_with_header('/cp-local.html', $cookie), qr/This-is-local-file/, 'http cp-local.html 2nd get with poisoned cookie');


###############################################################################

sub cp_get_cookie {
    my $r = shift @_;
    my $cookie;
    my @content = split /\r\n/, $r;
    foreach (@content) {
        if (/^Set-Cookie:/) {
            $cookie = (split /;/)[0];
            $cookie =~ s/Set-Cookie/Cookie/;

            return $cookie;
        }
    }
}

sub cp_check_log {
    open ERRLOG, '<', $errlog
        or return "bad"; 

    while (<ERRLOG>) {
        chomp;
        if (/error.*cookie poisoning: /) {
            return "good";
            close ERRLOG;
        }
    }
    
    close ERRLOG;
    return "bad";
}

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
                my $cookie = '';

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
		} elsif ($uri eq '/cp-block') {
			print $client <<'EOF';
HTTP/1.1 200 OK
Connection: close
Set-Cookie: cp-test-cookie=abcdefg; PATH=/; HttpOnly

EOF
			print $client "TEST-OK-IF-YOU-SEE-THIS";

                } elsif ($uri eq '/cp-whitelist') {
			print $client <<'EOF';
HTTP/1.1 200 OK
Connection: close
Set-Cookie: cp-test-cookie=abcdefg; PATH=/; HttpOnly

EOF
			print $client "TEST-OK-IF-YOU-SEE-THIS";

		} elsif ($uri eq '/cp-pass') {
                    print $client <<'EOF';
HTTP/1.1 200 OK
Connection: close
Set-Cookie: cp-test-cookie=1234567; PATH=/; HttpOnly

EOF
                    print $client "TEST-OK-IF-YOU-SEE-THIS";
		} elsif ($uri eq '/cp-remove') {
                    if (!($headers =~ /^Cookie: cp-test-cookie=(.*)/)) {
                        #first get
                        print $client <<'EOF';
HTTP/1.1 200 OK
Connection: close
Set-Cookie: cp-test-cookie=1234567; PATH=/; HttpOnly

EOF
                        print $client "TEST-OK-IF-YOU-SEE-THIS";
                    } else {
                        $cookie = $1 if $headers =~ /^Cookie: cp-test-cookie=(.*);/;
                        if ($cookie =~ /\s*/) {
                            print $client <<'EOF';
HTTP/1.1 200 OK
Connection: close

EOF
                            print $client "TEST-OK-IF-YOU-SEE-THIS";
                        } else {
                            print $client <<'EOF';
HTTP/1.1 200 OK
Connection: close

EOF
                            print $client "TEST-FAILED-IF-YOU-SEE-THIS";
                        }
                    } 
                } elsif ($uri eq '/cp-log') {
                        print $client <<'EOF';
HTTP/1.1 200 OK
Connection: close
Set-Cookie: cp-test-cookie=abcdefg; PATH=/; HttpOnly

EOF
                        print $client "TEST-OK-IF-YOU-SEE-THIS";
                } elsif ($uri eq '/cp-disable') {
                        print $client <<'EOF';
HTTP/1.1 200 OK
Connection: close
Set-Cookie: cp-test-cookie=abcdefg; PATH=/; HttpOnly

EOF
                        print $client "TEST-OK-IF-YOU-SEE-THIS";

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
