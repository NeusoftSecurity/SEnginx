#!/bin/bash

set -e

TRD_DIR=$PWD/3rd-party
MOD_SECURITY_DIR=${TRD_DIR}/ModSecurity
NO_MOD_SECURITY_CONFIG='--nomodsecurity'
unset HAVE_MOD_SECURITY
for arg in $*
do
    if [ $arg = $NO_MOD_SECURITY_CONFIG ]; then
        HAVE_MOD_SECURITY='y'
        break;
    fi
done

NGX_ARGS=`echo $* | sed "s/$NO_MOD_SECURITY_CONFIG//"`
if [ -z $HAVE_MOD_SECURITY ]; then
    echo "compile with modsecurity, use \"$NO_MOD_SECURITY_CONFIG\" to cancel"
    cd $MOD_SECURITY_DIR
    ./configure --enable-standalone-module $NGX_ARGS
    make
    cd -
    NGX_ARGS="$NGX_ARGS --add-module=${MOD_SECURITY_DIR}/nginx/modsecurity"
fi

./configure $NGX_ARGS \
    --with-http_ssl_module \
    --add-module=${TRD_DIR}/ngx_http_neteye_security \
    --add-module=${TRD_DIR}/ngx_http_naxsi_neteye_helper \
    --add-module=${TRD_DIR}/naxsi/naxsi_src \
    --add-module=${TRD_DIR}/nginx-upstream-fair \
    --add-module=${TRD_DIR}/headers-more-nginx-module \
    --add-module=${TRD_DIR}/ngx_http_substitutions_filter_module \
    --add-module=${TRD_DIR}/nginx_tcp_proxy_module \
    --add-module=${TRD_DIR}/ngx_http_upstream_fastest \
    --add-module=${TRD_DIR}/ngx_http_upstream_persistence \
    --add-module=${TRD_DIR}/ngx_http_session \
    --add-module=${TRD_DIR}/ngx_http_robot_mitigation \
    --add-module=${TRD_DIR}/ngx_http_status_page \
    --add-module=${TRD_DIR}/ngx_http_if_extend \
    --add-module=${TRD_DIR}/ngx_http_cache_extend

get_line_num()
{
    LINE_NUM=`grep -n ^$1$ Makefile | cut -d ':' -f 1`
    while :
    do
        LINE_NUM=$((LINE_NUM + 1))
        if [ `head -n $LINE_NUM Makefile | tail -n 1 | grep -c ^$` -eq 1 ]; then
            break;
        fi
    done
}

if [ -z $HAVE_MOD_SECURITY ]; then
    get_line_num clean:
    sed -i "$LINE_NUM i \\\tcd $MOD_SECURITY_DIR;make clean" Makefile
    get_line_num build:
    sed -i "$LINE_NUM i \\\tcd $MOD_SECURITY_DIR;\$(MAKE) -f Makefile" Makefile
    PREFIX=`grep ^#define objs/ngx_auto_config.h | grep NGX_PREFIX | awk '{print $3}' | sed 's/"//' | sed 's/"//'`
    get_line_num install:
    sed -i "$LINE_NUM i \\\tcd $MOD_SECURITY_DIR;\$(MAKE) -f Makefile" Makefile
    sed -i "$LINE_NUM i \\\tcp -f ${MOD_SECURITY_DIR}/modsecurity.conf-recommended \$(DESTDIR)${PREFIX}conf" Makefile
fi
