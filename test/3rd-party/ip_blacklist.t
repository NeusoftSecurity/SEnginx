#!/usr/bin/perl

# (C) Paul Yang

# Tests for ip blacklist module.

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

my $t = Test::Nginx->new()->has(qw/http ip_blacklist robot_mitigation/)->plan(1);
my $test_dir = $t->testdir();

$t->write_file_expand('nginx.conf', <<"EOF");

%%TEST_GLOBALS%%

daemon         off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    ip_blacklist on;
    ip_blacklist_size 1000;
    ip_blacklist_timeout 60;
    ip_blacklist_log on;
    ip_blacklist_mode sys;
    ip_blacklist_syscmd "/bin/touch $test_dir/%V";

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            robot_mitigation on;
            robot_mitigation_blacklist 3;
        }
    }
}

EOF

$t->run();

###############################################################################
my $i = 10;

while ($i > 0) {
    http_get('/');
} continue {
    $i--;
}

ok(-e "$test_dir/127.0.0.1", 'test file created');
###############################################################################
