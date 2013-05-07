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

my $t = Test::Nginx->new()->has(qw/http proxy ngx_http_if_extend/)->plan(3);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon         off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            ifall ($http_user_agent = a) ($server_port > 80) {
                proxy_pass http://127.0.0.1:8082;
            }
            
            ifany ($http_user_agent = b) ($server_port < 80) {
                proxy_pass http://127.0.0.1:8083;
            }
           
            proxy_pass http://127.0.0.1:8081;
            proxy_read_timeout 1s;
        }
    }
}

EOF

$t->run_daemon(\&http_daemon);
$t->run_daemon(\&http_daemon_2);
$t->run_daemon(\&http_daemon_3);
$t->run();

###############################################################################

like(http_get('/'), qr/TEST-OK-IF-YOU-SEE-THIS/, 'http get request, no user-agent');

like(http_get_with_header('/', 'User-Agent: a'), qr/ifall-works/, 'ifall test');

like(http_get_with_header('/', 'User-Agent: b'), qr/ifany-works/, 'ifany test');
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

sub http_daemon_2 {
	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalHost => '127.0.0.1:8082',
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
			print $client "ifall-works"
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

sub http_daemon_3 {
	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalHost => '127.0.0.1:8083',
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
			print $client "ifany-works"
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

###############################################################################
