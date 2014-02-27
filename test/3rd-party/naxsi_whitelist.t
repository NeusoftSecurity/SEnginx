#!/usr/bin/perl

# (C) Paul Yang

# Tests for naxsi whitelist.

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

my $naxsi_rule;
if ($ENV{TEST_NAXSI_RULE}) {
    $naxsi_rule = $ENV{TEST_NAXSI_RULE};
} else {
    Test::More::plan(skip_all => "naxsi core rule is not specified");
}


plan(skip_all => 'win32') if $^O eq 'MSWin32';


my $t = Test::Nginx->new()->has(qw/http naxsi /)->plan(2)
	->write_file_expand('nginx.conf', <<"EOF");

%%TEST_GLOBALS%%

daemon         off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    include  $naxsi_rule;

    whitelist_ua \$u_a {
        'something';
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /a.html {
             #LearningMode;
             SecRulesEnabled;
             #SecRulesDisabled;


             DeniedUrl '/rd';
             ## check rules
             CheckRule '\$XSS >= 4' BLOCK;
             CheckRule '\$TRAVERSAL >= 4' BLOCK;
             CheckRule '\$EVADE >= 8' BLOCK;
             CheckRule '\$UPLOAD >= 8' BLOCK;
             CheckRule '\$RFI >= 8' BLOCK;
             CheckRule '\$SQL >= 8' BLOCK;
        }

        location /b.html {
             #LearningMode;
             SecRulesEnabled;
             #SecRulesDisabled;


             DeniedUrl '/rd';
             ## check rules
             CheckRule '\$XSS >= 4' BLOCK;
             CheckRule '\$TRAVERSAL >= 4' BLOCK;
             CheckRule '\$EVADE >= 8' BLOCK;
             CheckRule '\$UPLOAD >= 8' BLOCK;
             CheckRule '\$RFI >= 8' BLOCK;
             CheckRule '\$SQL >= 8' BLOCK;

             naxsi_whitelist ua_var_name=u_a;
        }

        location /rd {
             return 403;
        }
    }
}

EOF

$t->write_file('b.html', 'SEE-THIS');
$t->run();

###############################################################################

like(http_get('/a.html?v=<<<<<<>>>>>>'), qr/403/, 'xss attack');
like(http_get_with_header('/b.html?v=<<<<<<>>>>>>', 'User-Agent: something'),
    qr/SEE-THIS/, 'xss attack but whitelisted');
###############################################################################
