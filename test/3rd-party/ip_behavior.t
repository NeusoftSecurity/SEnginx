#!/usr/bin/perl

# (C) Paul Yang

# Tests for ip behavior module.

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

my $t = Test::Nginx->new()->has(qw/http ip_behavior/)->plan(2);
my $test_dir = $t->testdir();

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon         off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    ip_behavior_zone zone=abc:10m sample_base=10 sample_cycle=1s;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        ip_behavior zone=abc type=sensitive_url;

        location /sensitive {
            ip_behavior_sensitive;
        
            ifall ($insensitive_percent >= 0) ($insensitive_percent < 5) {
                return 403;
            }
        }

        location /insensitive {
        }

    }
}

EOF

$t->write_file('sensitive.html', 'sensitive');
$t->write_file('insensitive.html', 'insensitive');
$t->run();

###############################################################################
my $i = 10;

while ($i > 0) {
    http_get('/sensitive.html');
    http_get('/insensitive.html');
} continue {
    $i--;
}

# insensitive_percent > 50%
like(http_get('/sensitive.html'), qr/sensitive/, 'should not blocked');

sleep(1);

$i = 15;

while ($i > 0) {
    http_get('/sensitive.html');
} continue {
    $i--;
}

# insensitive_percent < 5%
unlike(http_get('/sensitive.html'), qr/sensitive/, 'should return 403');
###############################################################################
