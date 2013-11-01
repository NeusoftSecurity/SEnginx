#!/usr/bin/perl

# (C) Jason Liu

# Tests for nginx round_robin module.

###############################################################################

use warnings;
use strict;

use Test::More;
use Time::ParseDate;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib '../lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

plan(skip_all => 'win32') if $^O eq 'MSWin32';

my @port_array = (8081, 8082);

my $t = Test::Nginx->new()->has(qw/upstream_persistence/)->plan(10);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon         off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    session_max_size 1000;
    upstream pool1 {
        persistence http_cookie cookie_name=senginxforward;
        server 127.0.0.1:8081;
        server 127.0.0.1:8082;
    }

    upstream pool2 {
        persistence http_cookie cookie_name=senginxforward timeout=2;
        server 127.0.0.1:8081;
        server 127.0.0.1:8082;
    }

   upstream pool3 {
        persistence session_cookie cookie_name=JSESSIONID;
        server 127.0.0.1:8081;
        server 127.0.0.1:8082;
    }

   upstream pool4 {
        persistence session_based;
        server 127.0.0.1:8081;
        server 127.0.0.1:8082;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;
        location /1 {
            proxy_pass http://pool1;
        }

        location /2 {
            proxy_pass http://pool2;
        }

        location /3 {
            session on;
            proxy_pass http://pool3;
        }

        location /4 {
            session on;
            proxy_pass http://pool4;
        }
    }
}

EOF

my $each_port;
foreach $each_port (@port_array) {
    $t->run_daemon(\&http_daemon, $each_port);
}
$t->run();

##########################################################################################################
sub get_cookie {
    my @content = split /\r\n/, $_[0];
    my @cookies;
    my $cookie;
    my $x;
    foreach $x (@content) {
        if ($x =~ /^Set-Cookie:/) {
            @cookies = split /;/, $x;
            $_ = $cookies[0];
            s/Set-Cookie/Cookie/;
            if ($cookie) {
                $cookie = $cookie . "\r\n";
                $cookie = $cookie . $_;
            } else {
                $cookie = $_;
            }
        }
    }
    $cookie;
}

sub check_cookie_exp {
    my @content = split /\r\n/, $_[0];
    my $cookie_name = $_[1];
    my $time_len = $_[2];
    my $x;
    my $c;
    my @cookies;
    my @expires;
    my $expire;
    my $time;
    my $ret = 0;
    foreach $x (@content) {
        if ($x =~ /^Set-Cookie:/) {
            @cookies = split /;/, $x;
            $_ = $cookies[0];
            s/Set-Cookie://;
            $cookies[0] = $_;
            if ($cookies[0] =~ /$cookie_name/) {
                foreach $c (@cookies) {
                    if ($c =~ /expires=/) {
                        @expires = split /=/, $c;
                        $time = time();
                        $time = $time + $time_len;
                        $expire = parsedate($expires[1]);
                        if ($time == $expire) {
                            $ret = 1;
                        }
                    }
                }
            }
        }
    }
    $ret;
}


#sub check_cookie {
#    my @content = split /\r\n/, $_[0];
#    my @paths;
#    my $path;
#    my $x;
#    my $ret = 1;
#    foreach $x (@content) {
#        if ($x =~ /^Set-Cookie:/) {
#            @paths = split /path=/ $x;
#            if ($path) {
#                if ($path eq $paths[1]) {
#                    $ret = 0;
#                }
#            } else ｛
#                $path = $paths[1];
#            }
#        }
#    }
#    $ret;
#}

# Insert cookie persistence
my $r = http_get('/1');
my $my_cookie = get_cookie($r);
like($r, qr/TEST-OK-IF-YOU-SEE-THIS-FROM-$port_array[0]/, "request $port_array[0]");
like($r, qr/senginxforward=/, "request $port_array[0]");
$r = http_get('/1');
like($r, qr/TEST-OK-IF-YOU-SEE-THIS-FROM-$port_array[1]/, "request $port_array[1]");
my $def_timeout = 7*24*60*60;
ok(&check_cookie_exp($r, 'senginxforward', $def_timeout), "check Set-Cookie expires time");
$r = http_get_with_header('/1', $my_cookie);
like($r, qr/TEST-OK-IF-YOU-SEE-THIS-FROM-$port_array[0]/, "request $port_array[0]");
unlike($r, qr/senginxforward=/, "request $port_array[0]");
$r = http_get('/2');
like($r, qr/TEST-OK-IF-YOU-SEE-THIS-FROM-$port_array[0]/, "request $port_array[0]");
ok(&check_cookie_exp($r, 'senginxforward', 120), "check Set-Cookie expires time");

# Listen cookie persistence
#$r = http_get('/2');
#ok(&check_cookie($r), "check Set-Cookie path");
#$my_cookie = get_cookie($r);
#like($r, qr/TEST-OK-IF-YOU-SEE-THIS-FROM-$port_array[0]/, "request $port_array[0]");
#like($r, qr/SENGINX-PERSISTENCE_ID=/, "request $port_array[0]");
#$r = http_get_with_header('/2', $my_cookie);
#like($r, qr/TEST-OK-IF-YOU-SEE-THIS-FROM-$port_array[0]/, "request $port_array[0]");
#unlike($r, qr/SENGINX-PERSISTENCE_ID=/, "request $port_array[0]");

# Session based persistence
$r = http_get('/4');
$my_cookie = get_cookie($r);
like($r, qr/TEST-OK-IF-YOU-SEE-THIS-FROM-$port_array[0]/, "request $port_array[0]");
like(http_get_with_header('/4', $my_cookie), qr/TEST-OK-IF-YOU-SEE-THIS-FROM-$port_array[0]/, "request $port_array[0]");

##########################################################################################################


sub http_daemon {
    my ($port) = @_;
	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalHost => "127.0.0.1:$port",
		Listen => 5,
		Reuse => 1
	)
		or die "Can't create listening socket: $!\n";

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		my $headers = '';
		my $uri = '';
        my $accessed;

		while (<$client>) {
			$headers .= $_;
			last if (/^\x0d?\x0a?$/);
		}

		$uri = $1 if $headers =~ /^\S+\s+([^ ]+)\s+HTTP/i;

		if ($uri eq '/1' || $uri eq '/2') {

			print $client <<"EOF";
HTTP/1.1 200 OK
Connection: close
Set-Cookie: JSESSIONID=000222333; expires=Wed, 30-Oct-2014 06:41:05 GMT; path=/1
Set-Cookie: JSESSIONID=000222333; expires=Wed, 30-Oct-2014 06:41:05 GMT; path=/2
Set-Cookie: JSESSIONID=000222333; expires=Wed, 30-Oct-2014 06:41:05 GMT; path=/3
Set-Cookie: JSESSIONID1=000222; expires=Wed, 30-Oct-2014 06:41:05 GMT; path=/
Set-Cookie: JSESSIONID2=000223; expires=Wed, 30-Oct-2014 06:41:05 GMT; path=/

TEST-OK-IF-YOU-SEE-THIS-FROM-$port

EOF
        } elsif ($uri eq '/3') {
        } elsif ($uri eq '/4') {
			print $client <<"EOF";
HTTP/1.1 200 OK
Connection: close

TEST-OK-IF-YOU-SEE-THIS-FROM-$port

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
