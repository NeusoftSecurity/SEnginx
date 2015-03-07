#!/bin/bash

set -e

TRD_DIR=$PWD/3rd-party
NEU_DIR=$PWD/neusoft
MOD_SECURITY_DIR=${TRD_DIR}/ModSecurity
MOD_SECURITY_CONFIG='--with-modsecurity'
NGX_LUA_CONFIG='--with-lua'
unset HAVE_MOD_SECURITY
unset HAVE_NGX_LUA
for arg in $*
do
    if [ $arg = $MOD_SECURITY_CONFIG ]; then
        HAVE_MOD_SECURITY='y'
    fi

    if [ $arg = $NGX_LUA_CONFIG ]; then
        HAVE_NGX_LUA='y'
    fi
done

if [ $# -ne 0 ]; then
    NGX_ARGS=`echo $* | sed "s/$MOD_SECURITY_CONFIG//"`
    NGX_ARGS=`echo $NGX_ARGS | sed "s/$NGX_LUA_CONFIG//"`
else
    unset NGX_ARGS
fi

if [ ! -z $HAVE_MOD_SECURITY ]; then
    cd $MOD_SECURITY_DIR
    ./autogen.sh
    ./configure --enable-standalone-module
    make
    cd -
    NGX_ARGS="$NGX_ARGS --add-module=${MOD_SECURITY_DIR}/nginx/modsecurity"
fi

if [ ! -z $HAVE_NGX_LUA ]; then
    NGX_ARGS="$NGX_ARGS --add-module=${TRD_DIR}/ngx_devel_kit --add-module=${TRD_DIR}/lua-nginx-module"
fi

./configure $NGX_ARGS \
    --add-module=${NEU_DIR}/ngx_http_neteye_security \
    --add-module=${TRD_DIR}/naxsi/naxsi_src \
    --add-module=${TRD_DIR}/nginx-upstream-fair \
    --add-module=${TRD_DIR}/headers-more-nginx-module \
    --add-module=${TRD_DIR}/ngx_http_substitutions_filter_module \
    --add-module=${TRD_DIR}/nginx_tcp_proxy_module \
    --add-module=${NEU_DIR}/ngx_http_upstream_fastest \
    --add-module=${NEU_DIR}/ngx_http_upstream_persistence \
    --add-module=${NEU_DIR}/ngx_http_session \
    --add-module=${NEU_DIR}/ngx_http_robot_mitigation \
    --add-module=${NEU_DIR}/ngx_http_status_page \
    --add-module=${NEU_DIR}/ngx_http_if_extend \
    --add-module=${NEU_DIR}/ngx_http_cache_extend \
    --add-module=${NEU_DIR}/ngx_http_cookie_poisoning \
    --add-module=${NEU_DIR}/ngx_http_web_defacement \
    --add-module=${NEU_DIR}/ngx_http_ip_blacklist \
    --add-module=${NEU_DIR}/ngx_http_ip_behavior \
    --add-module=${NEU_DIR}/ngx_http_whitelist \
    --add-module=${NEU_DIR}/ngx_http_statistics \
    --add-module=${TRD_DIR}/ngx_cache_purge-1.3 \
    --add-module=${TRD_DIR}/srcache-nginx-module \
    --add-module=${TRD_DIR}/memc-nginx-module

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

if [ ! -z $HAVE_MOD_SECURITY ]; then
    sed -i "/clean:/ a \\\tcd $MOD_SECURITY_DIR;make clean" Makefile
    sed -i "/build:/ a \\\tcd $MOD_SECURITY_DIR;\$(MAKE) -f Makefile" Makefile
    PREFIX=`grep -A 1 ^upgrade:$ Makefile | tail -n 1 | awk '{print $1}' | sed "s/sbin\/nginx//"`
    sed -i "/install:/ a \\\tcd $MOD_SECURITY_DIR;\$(MAKE) -f Makefile" Makefile
    get_line_num install:
    sed -i "$LINE_NUM i \\\tcp -f ${MOD_SECURITY_DIR}/modsecurity.conf-recommended \$(DESTDIR)${PREFIX}conf" Makefile
fi
