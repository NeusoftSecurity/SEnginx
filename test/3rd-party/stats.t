#!/usr/bin/perl

# (C) Paul Yang

# Tests for statistics

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

my $t = Test::Nginx->new()->has(qw/http statistics/)->plan(3)
	->write_file_expand('nginx.conf', <<"EOF");

%%TEST_GLOBALS%%

daemon         off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    statistics_zone 10m;

    server {
        listen       127.0.0.1:8080;
        server_name  traffic_server;

        virtual_server_name traffic_server;

        location / {
        }
    }

    server {
        listen       127.0.0.1:8080;
        server_name  stats_server;

        location /stats {
            statistics;
        }
    }
}

EOF

$t->write_file('a.html', ' ');
$t->run();

###############################################################################

http_get_with_host('/a.html', 'traffic_server');
like(http_get_with_host('/stats', 'stats_server'),
    qr/{.*"name":"traffic_server".*"req":1.*"res_2xx":1.*}/,
    'check 200 stats');

http_get_with_host('/b.html', 'traffic_server');
like(http_get_with_host('/stats', 'stats_server'),
    qr/{"name":"traffic_server".*"req":2.*"res_4xx":1.*}/, 'check 404 stats');

http_get_with_host('/a.html', ' ');
like(http_get_with_host('/stats', 'stats_server'),
    qr/{"name":"traffic_server".*"cur_req":0.*"req":2.*
        "res_2xx":1.*"res_4xx":1.*}/x,
    'check bad request stats');
###############################################################################
