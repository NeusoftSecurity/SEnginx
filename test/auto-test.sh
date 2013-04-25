#!/bin/bash

usage()
{
    echo "usage: bash $0 -s [test_case_dir] -n [nginx_bin_path]"
}

unset TEST_SRC
unset NGINX_DIR
while getopts ":s:n:" Option
do
    case $Option in
        s)
        TEST_SRC=$OPTARG
        ;;
        n)
        NGINX_DIR=$OPTARG
        ;;
    esac
done

if [ x = x$TEST_SRC ]; then
    echo "please input test case dir with -s"
    usage
    exit 1
fi

if [ x = x$NGINX_DIR ]; then
    echo "please input nginx binary file path with -n"
    usage
    exit 1
fi

cd $TEST_SRC

#
# original nginx features
#

echo ""
echo ""
echo "#####################################"
echo "#     Original NGINX features       #"
echo "#####################################"
echo ""

# gzip
echo "############  gzip start  ###########"
TEST_NGINX_BINARY=$NGINX_DIR prove ./gzip.t
echo "############  gzip end  #############"
echo ""

# cache
echo "############  cache start  ###########"
TEST_NGINX_BINARY=$NGINX_DIR prove ./proxy_cache.t
echo "############  cache end  #############"
echo ""

# proxy
echo "############  proxy start  ###########"
TEST_NGINX_BINARY=$NGINX_DIR prove ./proxy.t
TEST_NGINX_BINARY=$NGINX_DIR prove ./proxy_noclose.t
TEST_NGINX_BINARY=$NGINX_DIR prove ./proxy_merge_headers.t
TEST_NGINX_BINARY=$NGINX_DIR prove ./proxy_chunked.t
TEST_NGINX_BINARY=$NGINX_DIR prove ./proxy_cookie.t
TEST_NGINX_BINARY=$NGINX_DIR prove ./proxy_redirect.t
TEST_NGINX_BINARY=$NGINX_DIR prove ./proxy_store.t
TEST_NGINX_BINARY=$NGINX_DIR prove ./proxy_xar.t
echo "############  proxy end  #############"
echo ""

# rewrite
echo "############  rewrite start  ###########"
TEST_NGINX_BINARY=$NGINX_DIR prove ./rewrite.t
TEST_NGINX_BINARY=$NGINX_DIR prove ./rewrite_unescape.t
echo "############  rewrite end  #############"
echo ""

# realip
echo "############  realip start  ###########"
TEST_NGINX_BINARY=$NGINX_DIR prove ./realip.t
echo "############  realip end  #############"
echo ""

# limit req
echo "############  limit req start  ###########"
TEST_NGINX_BINARY=$NGINX_DIR prove ./limit_req.t
echo "############  limit req end  #############"
echo ""

# gunzip 
echo "############  gunzip start  ###########"
TEST_NGINX_BINARY=$NGINX_DIR prove ./gunzip.t
echo "############  limit req end  #############"
echo ""

# http core
echo "############  http core start  ###########"
TEST_NGINX_BINARY=$NGINX_DIR prove ./http_error_page.t
TEST_NGINX_BINARY=$NGINX_DIR prove ./http_expect_100_continue.t
TEST_NGINX_BINARY=$NGINX_DIR prove ./http_host.t
TEST_NGINX_BINARY=$NGINX_DIR prove ./http_location.t
TEST_NGINX_BINARY=$NGINX_DIR prove ./http_server_name.t
TEST_NGINX_BINARY=$NGINX_DIR prove ./http_try_files.t
TEST_NGINX_BINARY=$NGINX_DIR prove ./http_variables.t
echo "############  http core end  #############"
echo ""

# round robin
echo "############  round robin start  ###########"
TEST_NGINX_BINARY=$NGINX_DIR prove ./round_robin.t
echo "############  round robin end  #############"
echo ""

echo "############  least connection start  ###########"
TEST_NGINX_BINARY=$NGINX_DIR prove ./least_conn.t
echo "############  least connection end  #############"
echo ""

# neteye customized features
echo "#####################################"
echo "#     Neteye customized features    #"
echo "#####################################"

cd 3rd-party

# anti-robot
echo "############  anti-robot start  ###########"
TEST_NGINX_BINARY=$NGINX_DIR prove ./robot_mitigation.t
echo "############  anti-robot end  #############"
echo ""

# fastest
echo "############  fastest start  ###########"
TEST_NGINX_BINARY=$NGINX_DIR prove ./fastest.t
echo "############  fastest end  #############"
echo ""

# least connection
cd -
