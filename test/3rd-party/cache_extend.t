#!/usr/bin/perl

# (C) Maxim Dounin

# Tests for http proxy cache.

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

plan(skip_all => 'win32') if $^O eq 'MSWin32';

my $t = Test::Nginx->new()->has(qw/http proxy cache cache_extend/)->plan(8)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon         off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    proxy_cache_path   %%TESTDIR%%/cache  levels=1:2
                       keys_zone=NAME:10m;

    proxy_cache_path   %%TESTDIR%%/cach2  levels=1:2
                       keys_zone=NAME2:10m;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            proxy_pass    http://127.0.0.1:8081;

            proxy_cache   NAME;

            proxy_cache_valid   200 302  1m;
            proxy_cache_valid   any      1m;

            proxy_cache_min_uses  1;

            proxy_cache_types text/css;

            proxy_cache_use_stale  error timeout invalid_header http_500
                                   http_404;
        }

        location /always {
            proxy_pass    http://127.0.0.1:8081;

            proxy_cache   NAME2;

            proxy_cache_valid   200 302  1m;
            proxy_cache_valid   any      1m;

            proxy_cache_min_uses  1;

            proxy_cache_use_stale  error timeout invalid_header http_500
                                   http_404;
        }
    }

    server {
        listen       127.0.0.1:8081;
        server_name  localhost;

        rewrite ^/always/(.*) /$1;

        location / {
        }
    }
}

EOF

$t->write_file('t.html', 'SEE-THIS');
$t->write_file('t2.js', 'SEE-THIS');
$t->write_file('t3.html', 'SEE-THIS');
$t->write_file('t4.js', 'SEE-THIS');
$t->run();

###############################################################################

like(http_get('/t.html'), qr/SEE-THIS/, 'proxy request');
$t->write_file('t.html', 'NOOP');
like(http_get('/t.html'), qr/SEE-THIS/, 'proxy request cached');

like(http_get('/t2.js'), qr/SEE-THIS/, 'proxy request');
$t->write_file('t2.js', 'NOOP');
like(http_get('/t2.js'), qr/NOOP/, 'proxy request not cached');

like(http_get('/always/t3.html'), qr/SEE-THIS/, 'proxy request');
$t->write_file('t3.html', 'NOOP');
like(http_get('/always/t3.html'), qr/SEE-THIS/, 'proxy request cached');

like(http_get('/always/t4.js'), qr/SEE-THIS/, 'proxy request');
$t->write_file('t4.js', 'NOOP');
like(http_get('/always/t4.js'), qr/SEE-THIS/, 'proxy request cached');
###############################################################################
