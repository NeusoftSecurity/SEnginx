#!/usr/bin/perl

# (C) Jason Liu

# Tests for nginx round_robin module.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib '../lib';
use Test::Nginx;
use Time::ParseDate;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

plan(skip_all => 'win32') if $^O eq 'MSWin32';

my @port_array = (8081, 8082);

my $t = Test::Nginx->new()->has(qw/upstream_persistence/)->plan(27);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon         off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    session_max_size 1000;
    upstream pool1 {
        persistence insert_cookie cookie_name=senginxforward;
        least_conn;
        server 127.0.0.1:8081;
        server 127.0.0.1:8082;
    }

    upstream pool2 {
        persistence insert_cookie cookie_name=senginxforward timeout=2;
        least_conn;
        server 127.0.0.1:8081;
        server 127.0.0.1:8082;
    }

    upstream pool3 {
        persistence insert_cookie cookie_name=senginxforward timeout=session;
        least_conn;
        server 127.0.0.1:8081;
        server 127.0.0.1:8082;
    }

   upstream pool4 {
        persistence insert_cookie cookie_name=senginxforward monitor_cookie=JSESSIONID;
        least_conn;
        server 127.0.0.1:8081;
        server 127.0.0.1:8082;
    }

    upstream pool5 {
        persistence insert_cookie cookie_name=senginxforward monitor_cookie=JSESSIONID timeout=2;
        least_conn;
        server 127.0.0.1:8081;
        server 127.0.0.1:8082;
    }

    upstream pool6 {
        persistence insert_cookie cookie_name=senginxforward monitor_cookie=JSESSIONID timeout=session;
        least_conn;
        server 127.0.0.1:8081;
        server 127.0.0.1:8082;
    }

    upstream pool7 {
        persistence insert_cookie cookie_name=senginxforward monitor_cookie=JSESSIONID timeout=auto;
        least_conn;
        server 127.0.0.1:8081;
        server 127.0.0.1:8082;
    }


   upstream pool8 {
        persistence session_based;
        least_conn;
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
            proxy_pass http://pool3;
        }

        location /4 {
            proxy_pass http://pool4;
        }

        location /5 {
            proxy_pass http://pool5;
        }

        location /6 {
            proxy_pass http://pool6;
        }

        location /7 {
            proxy_pass http://pool7;
        }

        location /8 {
            session on;
            proxy_pass http://pool8;
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
    my $name = $_[1];
    my $path = $_[2];
    my @cookies;
    my $cookie;
    my $x;
    foreach $x (@content) {
        if ($x =~ /^Set-Cookie:/) {
            @cookies = split /;/, $x;
            $_ = $cookies[0];
            if ((!$name || $name eq 'all' || $cookies[0] =~ /$name/) && 
                (!$path || $x =~ /path=$path/)) {
                s/Set-Cookie/Cookie/;
                if ($cookie) {
                    $cookie = $cookie . "\r\n";
                    $cookie = $cookie . $_;
                } else {
                    $cookie = $_;
                }
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
    my $ck;
    my $ret = 0;
    foreach $x (@content) {
        if ($x =~ /^Set-Cookie:/) {
            @cookies = split /;/, $x;
            $_ = $cookies[0];
            s/Set-Cookie://;
            $cookies[0] = $_;
            if ($cookies[0] =~ /$cookie_name/) {
                $ck = 1;
                foreach $c (@cookies) {
                    if ($c =~ /expires=/) {
                        @expires = split /=/, $c;
                        $time = time();
                        $time = $time + $time_len;
                        $expire = parsedate($expires[1]);
                        if ($time == $expire) {
                            $ret = 1;
                        } else {
                            $ret = 3;
                            last;
                        }
                    }
                }
            }
        }
    }
    if ($ck && $ret == 0) {
        $ret = 2;
    }
    $ret;
}

sub get_opt_value {
    my $str = $_[0];
    my $key = $_[1];
    my @cookies = split /;/, $str;
    my @values;
    my $value = "no-$key";
    my $c;
    my $i = 0;
    foreach $c (@cookies) {
        if ($i == 0) {
            $i = 1;
            next;
        }

        if ($c =~ /$key=/) {
            @values = split /=/, $c;
            $value = $values[1];
            last;
        }
    }

    $value;
}

sub check_cookie_opt {
    my @content = split /\r\n/, $_[0];
    my $monitor = $_[1];
    my $insert = $_[2];
    my $opt = $_[3];
    my @opts;
    my @cookies;
    my $wopt;
    my $iopt;
    my $found;
    my $x;
    my $t;
    my $c;
    my $ret = 1;

    foreach $x (@content) {
        if ($x =~ /^Set-Cookie:/ && $x =~ /$monitor=/) {
            $wopt = get_opt_value($x, $opt);
            $found = 0;
            foreach $t (@content) {
                if ($t =~ /^Set-Cookie:/ && $t =~ /$insert=/) {
                    $iopt = get_opt_value($t, $opt);
                    if ($iopt eq $wopt) {
                        $found = 1;
                        last;
                    }
                }
            }
            if ($found == 0) {
                $ret = 0;
                last;
            }
        }
    }
    $ret;
}

#print STDERR "start!\n";
# Insert cookie persistence
my $r = http_get('/1');
my $my_cookie = get_cookie($r);
like($r, qr/TEST-OK-IF-YOU-SEE-THIS-FROM-$port_array[0]/, "request $port_array[0]");
ok(&check_cookie_exp($r, 'senginxforward', 120) == 2, "check Set-Cookie expires time");
like($r, qr/senginxforward=/, "request $port_array[0]");
$r = http_get_with_header('/1', $my_cookie);
like($r, qr/TEST-OK-IF-YOU-SEE-THIS-FROM-$port_array[0]/, "request $port_array[0]");
unlike($r, qr/senginxforward=/, "request $port_array[0]");
$r = http_get('/1');
like($r, qr/TEST-OK-IF-YOU-SEE-THIS-FROM-$port_array[1]/, "request $port_array[1]");
ok(&check_cookie_exp($r, 'senginxforward', 120) == 2, "check Set-Cookie expires time");

$r = http_get('/2');
ok(&check_cookie_exp($r, 'senginxforward', 120) == 1, "check Set-Cookie expires time");
$r = http_get('/3');
ok(&check_cookie_exp($r, 'senginxforward', 120) == 2, "check Set-Cookie expires time");

# Monitor cookie persistence
$r = http_get('/4');
$my_cookie = get_cookie($r, 'all', '/4');
like($r, qr/TEST-OK-IF-YOU-SEE-THIS-FROM-$port_array[0]/, "request $port_array[0]");
ok(&check_cookie_exp($r, 'senginxforward', 120) == 2, "check Set-Cookie expires time");
ok(&check_cookie_opt($r, 'JSESSIONID', 'senginxforward', 'path') == 1, 'check path');
ok(&check_cookie_opt($r, 'JSESSIONID1', 'senginxforward', 'path') == 0, 'check path');
ok(&check_cookie_opt($r, 'JSESSIONID2', 'senginxforward', 'path') == 0, 'check path');
$r = http_get_with_header('/4', $my_cookie);
like($r, qr/TEST-OK-IF-YOU-SEE-THIS-FROM-$port_array[0]/, "request $port_array[0]");
$r = http_get('/4');
like($r, qr/TEST-OK-IF-YOU-SEE-THIS-FROM-$port_array[1]/, "request $port_array[1]");
$r = http_get('/5');
ok(&check_cookie_exp($r, 'senginxforward', 120) == 1, "check Set-Cookie expires time");
$my_cookie = get_cookie($r, 'senginxforward', '/5');
$r = http_get_with_header('/5', $my_cookie);
like($r, qr/TEST-OK-IF-YOU-SEE-THIS-FROM-$port_array[1]/, "request $port_array[1]");
$r = http_get('/6');
ok(&check_cookie_exp($r, 'senginxforward', 120) == 2, "check Set-Cookie expires time");
$my_cookie = get_cookie($r, 'JSESSIONID', '/6');
$r = http_get_with_header('/6', $my_cookie);
like($r, qr/TEST-OK-IF-YOU-SEE-THIS-FROM-$port_array[1]/, "request $port_array[1]");

$r = http_get('/7');
$my_cookie = get_cookie($r, 'all', '/7');
like($r, qr/TEST-OK-IF-YOU-SEE-THIS-FROM-$port_array[0]/, "request $port_array[0]");
ok(&check_cookie_opt($r, 'JSESSIONID', 'senginxforward', 'path') == 1, 'check path');
ok(&check_cookie_opt($r, 'JSESSIONID', 'senginxforward', 'expires') == 1, 'check path');
ok(&check_cookie_opt($r, 'JSESSIONID1', 'senginxforward', 'path') == 0, 'check path');
ok(&check_cookie_opt($r, 'JSESSIONID2', 'senginxforward', 'path') == 0, 'check path');

# Session based persistence
$r = http_get('/8');
$my_cookie = get_cookie($r);
like($r, qr/TEST-OK-IF-YOU-SEE-THIS-FROM-$port_array[0]/, "request $port_array[0]");
like(http_get_with_header('/8', $my_cookie), qr/TEST-OK-IF-YOU-SEE-THIS-FROM-$port_array[0]/, "request $port_array[0]");

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

		if ($uri eq '/1' || $uri eq '/2' || $uri eq '/3') {

			print $client <<"EOF";
HTTP/1.1 200 OK
Connection: close
Set-Cookie: JSESSIONID=000222333; expires=Wed, 30-Oct-2014 06:41:05 GMT; path=/1
Set-Cookie: JSESSIONID=000222333; expires=Wed, 30-Oct-2014 06:41:05 GMT; path=/2
Set-Cookie: JSESSIONID=000222333; expires=Wed, 30-Oct-2014 06:41:05 GMT; path=/3
Set-Cookie: JSESSIONID1=000222; expires=Wed, 30-Oct-2014 06:41:05 GMT; path=/x1
Set-Cookie: JSESSIONID2=000223; expires=Wed, 30-Oct-2014 06:41:05 GMT; path=/x2

TEST-OK-IF-YOU-SEE-THIS-FROM-$port

EOF
        } elsif ($uri eq '/4' || $uri eq '/5' || $uri eq '/6') {

			print $client <<"EOF";
HTTP/1.1 200 OK
Connection: close
Set-Cookie: JSESSIONID=000222333; expires=Wed, 30-Oct-2014 06:41:05 GMT; path=/4
Set-Cookie:      JSESSIONID =000222333; expires=Wed, 30-Oct-2014 06:41:05 GMT; path=/5
Set-Cookie: JSESSIONID   =000222333; expires=Wed, 30-Oct-2014 06:41:05 GMT; path=/6
Set-Cookie:          JSESSIONID=000222333; expires=Wed, 30-Oct-2014 06:41:05 GMT; path=/7
Set-Cookie: JSESSIONID1=000222; expires=Wed, 30-Oct-2014 06:41:05 GMT; path=/x1
Set-Cookie: JSESSIONID2=000223; expires=Wed, 30-Oct-2014 06:41:05 GMT; path=/x2

TEST-OK-IF-YOU-SEE-THIS-FROM-$port

EOF
        } elsif ($uri eq '/7') {

			print $client <<"EOF";
HTTP/1.1 200 OK
Connection: close
Set-Cookie: JSESSIONID=000222333; path=/4
Set-Cookie:    JSESSIONID  =000222333; expires=Wed, 30-Oct-2015 06:41:05 GMT; path=/5
Set-Cookie:   expires=Wed, 30-Oct-2016 06:41:05 GMT; path=/6;JSESSIONID=00path=ssss 
Set-Cookie:   path   =/7; JSESSIONID    =00ssss; expires  =Wed, 30-Oct-2017 06:41:05 GMT
Set-Cookie:    JSESSIONID=00path=xxx
Set-Cookie: JSESSIONID1=000222; expires=Wed, 30-Oct-2014 06:41:05 GMT; path=/
Set-Cookie: JSESSIONID2=000223; expires=Wed, 30-Oct-2014 06:41:05 GMT; path=/

TEST-OK-IF-YOU-SEE-THIS-FROM-$port

EOF
        } elsif ($uri eq '/8') {
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
