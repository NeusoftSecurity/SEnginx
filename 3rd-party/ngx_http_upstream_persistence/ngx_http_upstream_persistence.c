/*
 * Copyright (c) 2013 Neusoft Corperation., Ltd.
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event_connect.h>
#include <ngx_http.h>
#include <ngx_http_upstream.h>
#include <ngx_http_upstream_persistence.h>
#if (NGX_HTTP_SESSION)
#include <ngx_http_session.h>
#endif

#define NGX_HTTP_SESSION_PS_COOKIE_KEY        "cookie_name="
#define NGX_HTTP_SESSION_PS_ID_COOKIE          "ADSG-PSENCE_ID"
#define NGX_HTTP_SESSION_DEFAULT_TIMEOUT            (7*24*60*60)   //7 days

#define NGX_HTTP_FASTEST_VALID_TIME_LENGTH          (60*1000)      //ms

#if (NGX_HTTP_SESSION)
static u_char *ngx_http_upstream_ps_session_name = (u_char *)"persistence";
#endif

static char *ngx_http_upstream_ps(ngx_conf_t *cf, ngx_command_t *cmd,
                                    void *conf);
static ngx_int_t ngx_http_upstream_ps_init(ngx_conf_t *cf);

static ngx_command_t  ngx_http_upstream_ps_commands[] = {

    {
        ngx_string("persistence"),
        NGX_HTTP_UPS_CONF | NGX_CONF_TAKE1234,
        ngx_http_upstream_ps,
        0,
        0,
        NULL
    },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_upstream_ps_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_upstream_ps_init,             /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_upstream_persistence_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_ps_module_ctx, /* module context */
    ngx_http_upstream_ps_commands,    /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


ngx_int_t ngx_http_upstream_ps_get(ngx_http_request_t *r, 
        ngx_uint_t peer_number,
        ngx_http_upstream_ps_group_t *group)
{
    ngx_http_upstream_ps_group_t   *p_group = group;
    ngx_int_t                               current;

    if (r == NULL || p_group == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                "r or group is NULL\n");
        return -1;
    }

    if (p_group->sess_persistence_get == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                "persistence get not set\n");
        return -1;
    }
 
    current = p_group->sess_persistence_get(r, group); 
    if (current >= (ngx_int_t)peer_number) {
        return -1;
    }

    return current;
}

void ngx_http_upstream_ps_set(ngx_http_request_t *r, 
        ngx_uint_t current, void *group)
{
    ngx_http_upstream_ps_group_t *p_group = group;

    if (r == NULL || p_group == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                "r or group is NULL\n");
        return;
    }

    if (p_group->sess_persistence_set == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                "persistence set not set\n");
        return;
    }
    
    p_group->sess_persistence_set(r, current, group); 
}

static ngx_int_t
ngx_http_upstream_ps_cookie_get_peer(ngx_http_request_t *r, 
                ngx_str_t *data)
{
    ngx_str_t       index_string;
    ngx_int_t       n;

    n = ngx_http_parse_multi_header_lines(&r->headers_in.cookies,
            data, &index_string);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
            "cookie_get_peer\n");

    if (n == NGX_DECLINED ) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                "get peer failed\n");
        return -1;
    }

    if (index_string.len == 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                "get peer failed, index string len is 0\n");
        return -1;
    }

    return ngx_atoi(index_string.data, index_string.len);
}

static void
ngx_http_upstream_ps_set_cookie(ngx_http_request_t *r, 
        ngx_uint_t current, ngx_str_t *opt, ngx_uint_t timeout,
        ngx_str_t *value)
{
    ngx_table_elt_t                 *set_cookie;
    u_char                          *cookie;
    u_char                          *tmp;
    u_char                          *cookie_opt = NULL;
    size_t                          len;
    
    
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
            "http_cookie_refresh_peer\n");
    len = value->len + strlen("=655350") + strlen("; ") + opt->len; 
    if (timeout) {
        len += 38;
    }//38 is + strlen("; expires=Thu, 31-Dec-37 23:55:55 GMT") + 1;
    cookie = ngx_pcalloc(r->pool, len * sizeof (u_char));
    if (cookie == NULL) {
        return;
    }

    if (opt->len) {
        cookie_opt = ngx_pcalloc(r->pool, opt->len + 1);
        if (cookie_opt == NULL) {
            return;
        }
        memcpy(cookie_opt, opt->data, opt->len);
    }

    tmp = ngx_sprintf(cookie, "%s=%d", value->data, current);

    if (timeout) {
        tmp = ngx_cpymem(tmp, "; expires=", strlen("; expires="));
        tmp = ngx_http_cookie_time(tmp, ngx_time() + timeout);
    }

    if (cookie_opt) {
        tmp = ngx_sprintf(tmp, "%s", cookie_opt);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
        "http_cookie_refresh_peer: set cookie %s", cookie);

    set_cookie = ngx_list_push(&r->headers_out.headers);
    if (set_cookie == NULL) {
        return;
    }

    set_cookie->hash = 1;
    set_cookie->key.len = sizeof("Set-Cookie") - 1;
    set_cookie->key.data = (u_char *)"Set-Cookie";
    set_cookie->value.len = ngx_strlen(cookie);
    set_cookie->value.data = cookie;
}

static ngx_int_t ngx_http_upstream_ps_cookie_get(ngx_http_request_t *r, 
        ngx_http_upstream_ps_group_t *group)
{
    return ngx_http_upstream_ps_cookie_get_peer(r, group->data);
}

static void ngx_http_upstream_ps_cookie_set(ngx_http_request_t *r, 
        ngx_uint_t current,
        ngx_http_upstream_ps_group_t *group)
{
    ngx_str_t     opt_path = ngx_string("; Path=/; HttpOnly");

    if (ngx_http_upstream_ps_cookie_get_peer(r, group->data) >= 0) {
        return;
    }

    ngx_http_upstream_ps_set_cookie(r, current, &opt_path, 
            group->timeout, group->data);
}

static ngx_int_t ngx_http_upstream_ps_session_cookie_get(ngx_http_request_t *r, 
        ngx_http_upstream_ps_group_t *group)
{
    ngx_str_t     session_string;
    ngx_str_t     session_key = ngx_string(NGX_HTTP_SESSION_PS_ID_COOKIE);
    ngx_int_t     n;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
            "http_session_cookie_get_peer\n");

    n = ngx_http_parse_multi_header_lines (&r->headers_in.cookies,
            (ngx_str_t *)group->data, &session_string);

    if (n == NGX_DECLINED || session_string.len == 0) {
        return -1;
    }

    return ngx_http_upstream_ps_cookie_get_peer(r, &session_key);
}

static void ngx_http_upstream_ps_session_cookie_set(ngx_http_request_t *r,
        ngx_uint_t current,
        ngx_http_upstream_ps_group_t *group)
{
    ngx_str_t     opt_path = ngx_string("; Path=/; HttpOnly");
    ngx_str_t     session_key = ngx_string(NGX_HTTP_SESSION_PS_ID_COOKIE);
    ngx_str_t     session_string;
    ngx_int_t     n;

    n = ngx_http_parse_multi_header_lines(&r->headers_in.cookies,
            (ngx_str_t *)group->data, &session_string);

    if (n != NGX_DECLINED && session_string.len != 0) {
        if (ngx_http_upstream_ps_cookie_get_peer(r, &session_key) >= 0) {
            return;
        }
    }

    ngx_http_upstream_ps_set_cookie(r, current, &opt_path, 
            group->timeout, &session_key);
}

#if (NGX_HTTP_SESSION)
static ngx_int_t ngx_http_upstream_ps_proc_session_ctx(ngx_http_request_t *r,
        void (*proc)(ngx_http_upstream_ps_session_ctx_t *ps_ctx, void *data),
        void *arg)
{
    ngx_http_session_t                              *session;
    ngx_http_session_ctx_t                          *session_ctx;
    ngx_http_upstream_ps_session_ctx_t     *ps_ctx;

    if (!ngx_http_session_is_enabled(r)) {
        return -1;
    }

    session = ngx_http_session_get(r);
    if (!session) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                "get session failed, treat this session as new\n");
        return -1;
    }

    ngx_shmtx_lock(&session->mutex);
    session_ctx = ngx_http_session_find_ctx(session, 
            ngx_http_upstream_ps_session_name);

    if (!session_ctx) {
        ngx_shmtx_unlock(&session->mutex);
        return -1;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "found session ctx\n");
    ps_ctx = session_ctx->data;
    proc(ps_ctx, arg);
    ngx_shmtx_unlock(&session->mutex);

    return 0;
}

static void 
ngx_http_upstream_ps_get_current(ngx_http_upstream_ps_session_ctx_t *ps_ctx,
        void *data)
{
    ngx_int_t                               *ret;

    ret = data;
    *ret = ps_ctx->server_index;
}

static ngx_int_t ngx_http_upstream_ps_session_get(ngx_http_request_t *r, 
        ngx_http_upstream_ps_group_t *group)
{
    ngx_int_t                               ret;

    if (ngx_http_upstream_ps_proc_session_ctx(r, 
                ngx_http_upstream_ps_get_current, &ret) == -1) {
        return -1;
    }

    return ret;
}

static void 
ngx_http_upstream_ps_set_current(ngx_http_upstream_ps_session_ctx_t *ps_ctx,
        void *data)
{
    ngx_int_t       *ret;

    if (ps_ctx->server_index < 0) {
        ret = data;
        ps_ctx->server_index = *ret;
    }
}


static void ngx_http_upstream_ps_session_set(ngx_http_request_t *r,
        ngx_uint_t current,
        ngx_http_upstream_ps_group_t *group)
{
    ngx_http_upstream_ps_proc_session_ctx(r, 
                ngx_http_upstream_ps_set_current, &current);
}
#endif

static char *
ngx_http_upstream_ps_config(ngx_http_upstream_ps_group_t 
        *group, ngx_conf_t *cf)
{
    ngx_str_t                        *value, *str;
    ngx_uint_t                        i;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_strcasecmp((u_char *)"http_cookie", (u_char *)value[i].data) == 0) {
            if (group->sess_persistence_get != NULL) {
                return "duplicate session persister";
            }

            if (cf->module_type != NGX_HTTP_MODULE) {
                return NGX_CONF_ERROR;
            }

            group->sess_persistence_get = ngx_http_upstream_ps_cookie_get;
            group->sess_persistence_set = ngx_http_upstream_ps_cookie_set;
            continue;
        }

        if (ngx_strcasecmp((u_char *)"session_cookie", (u_char *)value[i].data) == 0) {

            if (group->sess_persistence_get != NULL) {
                return "duplicate session persister";
            }

            if (cf->module_type != NGX_HTTP_MODULE) {
                return NGX_CONF_ERROR;
            }

            group->sess_persistence_get = &ngx_http_upstream_ps_session_cookie_get;
            group->sess_persistence_set = &ngx_http_upstream_ps_session_cookie_set;
            continue;
        }

#if (NGX_HTTP_SESSION)
        if (ngx_strcasecmp((u_char *)"session_based", (u_char *)value[i].data) == 0) {

            if (group->sess_persistence_get != NULL) {
                return "duplicate session persister";
            }

            if (cf->module_type != NGX_HTTP_MODULE) {
                return NGX_CONF_ERROR;
            }

            group->sess_persistence_get = &ngx_http_upstream_ps_session_get;
            group->sess_persistence_set = &ngx_http_upstream_ps_session_set;
            return NGX_CONF_OK;
        }
#endif

        if (ngx_strncmp(value[i].data, NGX_HTTP_SESSION_PS_COOKIE_KEY, 
                    ngx_strlen(NGX_HTTP_SESSION_PS_COOKIE_KEY)) == 0) {
            if (group->data != NULL) {
                return "duplicate cookie_name";
            }

            str = ngx_pcalloc(cf->pool, sizeof (ngx_str_t) );

            if (str == NULL) {
                return NGX_CONF_ERROR;
            }

            str->data = value[i].data + 
                ngx_strlen(NGX_HTTP_SESSION_PS_COOKIE_KEY);
            str->len = value[i].len -
                ngx_strlen(NGX_HTTP_SESSION_PS_COOKIE_KEY);

            if (str->len == 0) {
                return NGX_CONF_ERROR;
            }

            group->data = str;
            continue;
        }

        if (ngx_strncasecmp((u_char *) "timeout=", (u_char *) value[i].data, 8) == 0) {
            group->timeout = ngx_atoi(value[i].data + 8, value[i].len - 8);
            group->timeout *= 60;
            continue;
        }

        return NGX_CONF_ERROR;
    }

    if (group->data == NULL) {
        return "cookie_name is NULL";
    }

    if (group->timeout == 0) {
        group->timeout = NGX_HTTP_SESSION_DEFAULT_TIMEOUT;
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_upstream_ps(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upstream_srv_conf_t  *uscf;

    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
    if (ngx_http_upstream_ps_config(&uscf->group, cf) != NGX_CONF_OK) {
        return "config error";
    }

    return NGX_CONF_OK;
}

#if (NGX_HTTP_SESSION)
static ngx_int_t 
ngx_http_upstream_ps_init_ctx_handler(void *ctx)
{
    ngx_http_session_ctx_t                  *session_ctx;
    ngx_http_upstream_ps_session_ctx_t      *ps_ctx;

    session_ctx = (ngx_http_session_ctx_t *)ctx;

    /* initial session ctx */
    session_ctx->data = 
        ngx_http_session_shm_alloc_nolock(sizeof(*ps_ctx));
    if (!session_ctx->data) {
        fprintf(stderr, "create ac ctx error\n");
        return NGX_ERROR;
    }
    ps_ctx = session_ctx->data;
    ps_ctx->server_index = -1;

    return NGX_OK;
}

static void 
ngx_http_upstream_ps_destroy_ctx_handler(void *ctx)
{
    ngx_http_session_ctx_t *session_ctx;

    session_ctx = (ngx_http_session_ctx_t *)ctx;

    return ngx_http_session_shm_free_nolock(session_ctx->data);
}

static void
ngx_http_upstream_ps_create_session_ctx(ngx_http_session_t *session)
{
    ngx_http_session_ctx_t           *session_ctx;

    session_ctx = ngx_http_session_create_ctx(session,
            ngx_http_upstream_ps_session_name,
            ngx_http_upstream_ps_init_ctx_handler,
            ngx_http_upstream_ps_destroy_ctx_handler);

    if (!session_ctx) {
        return;
    }

    /* TODO: maybe do some intialization here? */
}
#endif

static ngx_int_t ngx_http_upstream_ps_init(ngx_conf_t *cf)
{
#if (NGX_HTTP_SESSION)
    ngx_http_session_register_create_ctx_handler(
            ngx_http_upstream_ps_create_session_ctx);
#endif
    return NGX_OK;
}

