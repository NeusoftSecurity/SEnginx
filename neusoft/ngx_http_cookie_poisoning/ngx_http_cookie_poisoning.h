#ifndef _NGX_HTTP_COOKIE_POISONING_H_INCLUDED_
#define _NGX_HTTP_COOKIE_POISONING_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_hash.h>

#include <ngx_http_status_page.h>
#include <ngx_http_whitelist.h>

#define NGX_HTTP_CP_MD5_LEN 32
#define NGX_HTTP_CP_DEFAULT_BUCKETS_NUM 8

typedef struct {
    ngx_int_t                 enabled;
    ngx_int_t                 log_enabled;
    ngx_int_t                 action;
    ngx_str_t                 error_page;
    ngx_int_t                 bl_times;

    /* whitelist */
    ngx_http_wl_variables_t   whitelist;
} ngx_http_cp_loc_conf_t;

struct ngx_http_cp_monitored_cookie_s {
    ngx_str_t     cookie_name;
    u_char        cookie_magic[NGX_HTTP_CP_MD5_LEN];
    ngx_uint_t    magic;

    struct ngx_http_cp_monitored_cookie_s *next;
};

typedef struct ngx_http_cp_monitored_cookie_s ngx_http_cp_monitored_cookie_t;

typedef struct {
    ngx_http_cp_monitored_cookie_t    **buckets;
    ngx_uint_t        nr_buckets;
} ngx_http_cp_hash_t;

typedef struct {
    ngx_int_t bl_times;
    ngx_http_cp_hash_t monitored_cookies;
} ngx_http_cp_session_ctx_t;

#endif
