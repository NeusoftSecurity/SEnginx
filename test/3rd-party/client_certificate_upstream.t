#!/usr/bin/perl

# (C) Paul Yang

# Tests for client/server certificate in upstream.

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

use Cwd 'abs_path';
my $dir = abs_path();

my $t = Test::Nginx->new()->has(qw/http proxy upstream ssl/)->plan(7)
	->write_file_expand('nginx.conf', <<"EOF");

%%TEST_GLOBALS%%

daemon         off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:44443;
        ssl on;
        server_name  localhost;

        ssl_certificate $dir/certs/server.crt;
        ssl_certificate_key $dir/certs/server.key;

        ssl_verify_client on;
        ssl_client_certificate $dir/certs/ca.crt;

        rewrite .* /a.html;

        location / {
        }
    }

    server {
        listen       127.0.0.1:44444;
        ssl on;
        server_name  localhost;

        ssl_certificate $dir/certs/server.crt;
        ssl_certificate_key $dir/certs/server.key;

        rewrite .* /a.html;

        location / {
        }
    }

    server {
        listen      127.0.0.1:8080;
        server_name  localhost;

        proxy_ssl_session_reuse off;

        location /real_crt {
            proxy_ssl_certificate $dir/certs/client.crt;
            proxy_ssl_certificate_key $dir/certs/client.key;

            proxy_pass https://127.0.0.1:44443; 
        }

        location /fake_crt {
            proxy_ssl_certificate $dir/certs/client_fake.crt;
            proxy_ssl_certificate_key $dir/certs/client.key;

            proxy_pass https://127.0.0.1:44443; 
        }

        location /dual_auth {
            proxy_ssl_certificate $dir/certs/client.crt;
            proxy_ssl_certificate_key $dir/certs/client.key;

            proxy_ssl_verify_server on;
            proxy_ssl_server_certificate $dir/certs/ca.crt;

            proxy_pass https://127.0.0.1:44443; 
        }

        location /dual_auth_fake_ca {
            proxy_ssl_certificate $dir/certs/client.crt;
            proxy_ssl_certificate_key $dir/certs/client.key;

            proxy_ssl_verify_server on;
            proxy_ssl_server_certificate $dir/certs/ca_fake.crt;

            proxy_pass https://127.0.0.1:44443; 
        }

        location /server_auth {
            proxy_ssl_verify_server on;
            proxy_ssl_server_certificate $dir/certs/ca.crt;

            proxy_pass https://127.0.0.1:44444; 
        }

        location /server_auth_fake_ca {
            proxy_ssl_verify_server on;
            proxy_ssl_server_certificate $dir/certs/ca_fake.crt;

            proxy_pass https://127.0.0.1:44444; 
        }

        location /still_with_client_certificate {
            proxy_ssl_certificate $dir/certs/client.crt;
            proxy_ssl_certificate_key $dir/certs/client.key;

            proxy_pass https://127.0.0.1:44444; 
        }

        location / {
            return 404;
        }
    }
}

EOF

$t->write_file('a.html', 'SEE-THIS');
$t->run();

###############################################################################

like(http_get('/real_crt/a.html'), qr/SEE-THIS/, 'client auth with real crt');
like(http_get('/fake_crt/a.html'), qr/400/, 'client auth with fake crt');
like(http_get('/dual_auth/a.html'), qr/SEE-THIS/,
    'dual auth with real server ca');
like(http_get('/dual_auth_fake_ca/a.html'), qr/400/,
    'dual auth with fake server ca');
like(http_get('/server_auth/a.html'), qr/SEE-THIS/,
    'server auth with real server ca');
like(http_get('/server_auth_fake_ca/a.html'), qr/400/,
    'server auth with fake server ca');
like(http_get('/still_with_client_certificate/a.html'), qr/SEE-THIS/,
    'still using client cert even server does not require');
###############################################################################
