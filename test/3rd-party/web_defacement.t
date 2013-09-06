#!/usr/bin/perl

# (C) Paul Yang

# Tests for web defacement protection module.

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

my $t = Test::Nginx->new()->has(qw/http proxy ngx_http_web_defacement/)->plan(7);
my $test_dir = $t->testdir();

$t->write_file_expand('nginx.conf', <<"EOF");

%%TEST_GLOBALS%%

daemon         off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        web_defacement on;
        web_defacement_original $test_dir/;
        web_defacement_hash_data $test_dir/hash_data;

        location /recover/ {
            web_defacement off;
            index index.html;
        }

        location /original/ {
            web_defacement_index index.html;
            web_defacement_log off;

            if (\$web_defacement) {
                rewrite ^/original/(.*)\$ /recover/\$1 last;
            }

            index index.html;
        }

        location /original/notify {
            web_defacement off;
        }

        location /original/a {
            web_defacement_log off;
            
            if (\$web_defacement) {
                rewrite ^/original/(.*)\$ /recover/\$1 last;
            }
        }

        location /original/b {
            if (\$web_defacement) {
                rewrite ^.*\$ /original/notify\$1 last;
            }
        }

        location /original/e {
            web_defacement_log on;

            if (\$web_defacement) {
                return 403;
            }
        }
    }
}

EOF

mkdir("$test_dir/original");
mkdir("$test_dir/recover");
$t->write_file('original/index.html', 'This-is-test-index');
$t->write_file('original/a', 'This-is-test-a');
$t->write_file('original/b', 'This-is-test-b');
$t->write_file('original/e', 'This-is-test-e');
$t->write_file('original/notify', 'This-is-block-notify-page');
$t->write_file('recover/index.html', 'This-is-test-index');
$t->write_file('recover/a', 'This-is-test-a');
$t->write_file('recover/b', 'This-is-test-b');
$t->write_file('recover/e', 'This-is-test-e');
$t->write_file('recover/notify', 'This-is-block-notify-page');
system("../../web-defacement.pl -d $test_dir/original -o $test_dir/hash_data");

$t->run();

###############################################################################
like(http_get('/original/a'), qr/This-is-test-a/, 'a, no defacement');
$t->write_file('original/a', 'Test-a-is-hacked');
like(http_get('/original/a'), qr/This-is-test-a/, 'a, defacement but recovered');

like(http_get('/original/b'), qr/This-is-test-b/, 'b, no defacement');
$t->write_file('original/b', 'Test-b-is-hacked');
like(http_get('/original/b'), qr/This-is-block-notify-page/,
    'b, defacement but blocked with page');

like(http_get('/original/'), qr/This-is-test-index/, 'index, no defacement');
$t->write_file('original/index.html', 'Test-index-is-hacked');
like(http_get('/original/'), qr/This-is-test-index/,
    'index, no defacement but recovered');

http_get('/original/e');
$t->write_file('original/e', 'Test-e-is-hacked');
http_get_with_header('/original/e', 'User-Agent: abcdefg');

my $log_line;
open LOG, "<", "$test_dir/error.log" or die "Can't open error log file";
foreach (<LOG>) {
    chomp;
    if (/web_defacement/) {
        $log_line = $_;
        last;
    }
}

like($log_line, qr/abcdefg/, 'check log output');

################################################################################
