#ifndef _NGX_HTTP_WEB_DEFACEMENT_H_INCLUDED_
#define _NGX_HTTP_WEB_DEFACEMENT_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_hash.h>


/* TODO: use neteye security in the future */
#undef NGX_HTTP_NETEYE_SECURITY

#if (NGX_HTTP_NETEYE_SECURITY)
#include <ngx_http_neteye_security.h>
#endif

#include <ngx_http_whitelist.h>

#define NGX_HTTP_WD_MD5_LEN 32

typedef struct {
    ngx_int_t                 enabled;
    ngx_int_t                 log_enabled;
    ngx_str_t                 orig_path;
    ngx_str_t                 index_file;
    ngx_hash_t                file_name_hash;

    /* whitelist */
    ngx_http_wl_variables_t   whitelist;
} ngx_http_wd_loc_conf_t;

#if (NGX_HTTP_NETEYE_SECURITY)
#define NGX_HTTP_WD_ACTION_PASS NGX_HTTP_NS_ACTION_PASS
#define NGX_HTTP_WD_ACTION_BLOCK NGX_HTTP_NS_ACTION_BLOCK
#else
enum {
    NGX_HTTP_WD_ACTION_PASS = 0,
    NGX_HTTP_WD_ACTION_BLOCK,
};
#endif

typedef struct {
    u_char             defaced;
    ngx_str_t          file;
} ngx_http_wd_ctx_t;

#endif
