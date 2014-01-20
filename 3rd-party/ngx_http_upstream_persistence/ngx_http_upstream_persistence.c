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

#define NGX_HTTP_PS_INSERT_COOKIE        "cookie_name="
#define NGX_HTTP_PS_MONITOR_COOKIE       "monitor_cookie="
#define NGX_HTTP_PS_TIMEOUT              "timeout="

/* Our session_ctx conflict with the sesion_ctx define in 
 * openssl/ssl.h, we need to undefine it 
 */
#undef session_ctx

#if (NGX_HTTP_SESSION)
static u_char *ngx_http_upstream_ps_session_name = (u_char *)"persistence";
#endif
static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
 
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

    if (p_group->ps_get == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                "persistence get not set\n");
        return -1;
    }
 
    current = p_group->ps_get(r, group); 
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

    if (p_group->ps_set == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                "persistence set not set\n");
        return;
    }
    
    p_group->ps_set(r, current, group); 
}

static ngx_int_t
ngx_http_upstream_ps_cookie_get_peer(ngx_http_request_t *r, ngx_str_t *data)
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
        ngx_uint_t current, ngx_str_t *opt, ngx_int_t timeout,
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

    if (timeout > 0) {
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
    ngx_int_t       n;
    ngx_str_t       value;

    if (group->monitor_cookie.len) {
        n = ngx_http_parse_multi_header_lines(&r->headers_in.cookies,
                &group->monitor_cookie, &value);
        if (n == NGX_DECLINED || value.len == 0) {
            return -1;
        }
    }

    return ngx_http_upstream_ps_cookie_get_peer(r, &group->insert_cookie);
}

static void ngx_http_upstream_ps_cookie_set(ngx_http_request_t *r, 
        ngx_uint_t current,
        ngx_http_upstream_ps_group_t *group)
{
    ngx_str_t     opt_path = ngx_string("; Path=/; HttpOnly");

    if (group->monitor_cookie.len) {
        r->group = group;
        r->current = current;
        return;
    }

    if (ngx_http_upstream_ps_cookie_get_peer(r, &group->insert_cookie) >= 0) {
        return;
    }

    ngx_http_upstream_ps_set_cookie(r, current, &opt_path, 
            group->timeout, &group->insert_cookie);
}

static void
ngx_http_upstream_ps_get_cookie_opt(ngx_str_t *str, 
        char *name, ngx_str_t *result)
{
    char                                    *sp; //';' postion in str
    char                                    *start;
    size_t                                  offset = 0;
    size_t                                  soffset = 0;

    if (str->len <= 0) {
        goto no_result;
    }

    start = (char *)str->data;
    while (offset < str->len) {
        if (*start == ' ') {
            start++;
            offset++;
            continue;
        }

        if (str->len - offset < strlen(name) + 1) {
            break;
        }

        if (ngx_strncmp(start, name, strlen(name)) == 0) {
            soffset = strlen(name);
            if (start[soffset] != '=') {
                while (start[soffset] == ' ') {
                    if (str->len <= soffset + offset) {
                        break;
                    }
                    soffset++;
                }
            }
            if (start[soffset] != '=') {
                goto next;
            }

            result->data = (u_char *)start;
            sp = ngx_strstr(start, ";");
            if (sp) {
                result->len = (sp - start);
            } else {
                result->len = str->len - offset;
            }
            return;
        }

next:
        sp = ngx_strstr(start, ";");
        if (sp == NULL) {
            goto no_result;
        }
        start = sp + 1;
        offset = (size_t)(start - (char *)str->data);
        continue;
    }

no_result:
    result->data = NULL;
    result->len = 0;
}

static ngx_int_t
ngx_http_upstream_ps_header_filter(ngx_http_request_t *r)
{
    ngx_str_t                           opt_value = ngx_string("; HttpOnly");
    ngx_str_t                           opt;
    ngx_str_t                           monitor_cookie;
    ngx_str_t                           opt_path;
    ngx_str_t                           opt_expires;
    ngx_http_upstream_ps_group_t        *group;
    ngx_list_part_t                     *part;
    ngx_uint_t                          i;
    ngx_table_elt_t                     *header;
    ngx_str_t                           *cookie_name;
    u_char                              *tmp;

    group = r->group;
    if (group == NULL) {
        goto next;
    }

    cookie_name = &group->monitor_cookie;
    part = &r->headers_out.headers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }
        if (i < part->nelts && 
                ngx_strncmp(header->key.data, "Set-Cookie", 
                    header->key.len) == 0) {
            ngx_http_upstream_ps_get_cookie_opt(&header->value, 
                    (char *)cookie_name->data, &monitor_cookie);
            if (monitor_cookie.len == 0) {
                /* Not monitored cookie */
                continue;
            }

            if (group->timeout < 0) {
                ngx_http_upstream_ps_get_cookie_opt(&header->value, 
                        "expires", &opt_expires);
            } else {
                memset(&opt_expires, 0, sizeof(opt_expires));
            }

            ngx_http_upstream_ps_get_cookie_opt(&header->value, 
                    "path", &opt_path);
            opt.len = opt_value.len + opt_expires.len + 2 + opt_path.len + 2;
            opt.data = ngx_pcalloc(r->pool, opt.len);
            if (opt.data == NULL) {
                goto next;
            }
            tmp = opt.data;
            if (opt_expires.len) {
                *tmp++ = ';';
                *tmp++ = ' ';
                tmp = ngx_cpymem(tmp, opt_expires.data, opt_expires.len);
            }

            if (opt_path.len) {
                *tmp++ = ';';
                *tmp++ = ' ';
                tmp = ngx_cpymem(tmp, opt_path.data, opt_path.len);
            }

            memcpy(tmp, opt_value.data, opt_value.len);

            ngx_http_upstream_ps_set_cookie(r, r->current, &opt, 
                    group->timeout, &group->insert_cookie);
        }
        header = (ngx_table_elt_t *)((char *)header + 
                r->headers_out.headers.size);
    }

next:
    return ngx_http_next_header_filter(r);
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
    ngx_str_t                        *value;
    ngx_uint_t                        i;
    size_t                           slen;
    u_char                           *timeout;

    value = cf->args->elts;

    group->timeout = 0;

    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_strcmp("http_cookie", value[i].data) == 0) {
            if (group->ps_get != NULL) {
                return "duplicate session persister";
            }

            if (cf->module_type != NGX_HTTP_MODULE) {
                return NGX_CONF_ERROR;
            }

            group->ps_get = ngx_http_upstream_ps_cookie_get;
            group->ps_set = ngx_http_upstream_ps_cookie_set;
            continue;
        }

#if (NGX_HTTP_SESSION)
        if (ngx_strcmp("session_based", value[i].data) == 0) {

            if (group->ps_get != NULL) {
                return "duplicate session persister";
            }

            if (cf->module_type != NGX_HTTP_MODULE) {
                return NGX_CONF_ERROR;
            }

            group->ps_get = ngx_http_upstream_ps_session_get;
            group->ps_set = ngx_http_upstream_ps_session_set;
            return NGX_CONF_OK;
        }
#endif

        slen = ngx_strlen(NGX_HTTP_PS_INSERT_COOKIE);
        if (ngx_strncmp(value[i].data, NGX_HTTP_PS_INSERT_COOKIE, slen) == 0) {
            group->insert_cookie.data = value[i].data + slen;
            group->insert_cookie.len = value[i].len - slen;
            continue;
        }

        slen = ngx_strlen(NGX_HTTP_PS_MONITOR_COOKIE);
        if (ngx_strncmp(value[i].data, NGX_HTTP_PS_MONITOR_COOKIE, slen) == 0) {
            group->monitor_cookie.data = value[i].data + slen;
            group->monitor_cookie.len = value[i].len - slen;
            continue;
        }

        if (ngx_strncmp(value[i].data, NGX_HTTP_PS_TIMEOUT,
                    ngx_strlen(NGX_HTTP_PS_TIMEOUT)) == 0) {
            timeout = value[i].data + ngx_strlen(NGX_HTTP_PS_TIMEOUT);
            if (ngx_strcmp(timeout, "session") == 0) {
                continue;
            }

            if (ngx_strcmp(timeout, "auto") == 0) {
                group->timeout = -1;
                continue;
            }
            group->timeout = ngx_atoi(timeout, 
                    value[i].len - ngx_strlen(NGX_HTTP_PS_TIMEOUT));
            if (group->timeout <= 0) {
                return "timeout must bigger then 0";
            }
            group->timeout *= 60;
            continue;
        }

        fprintf(stderr, "Can't parse %s\n", value[i].data);
        return NGX_CONF_ERROR;
    }

    if (group->monitor_cookie.len == 0) {
        if (group->timeout < 0) {
            return "timeout error";
        }
    } else if (group->ps_get != ngx_http_upstream_ps_cookie_get) {
        return "config monitor_cookie not in http_cookie";
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
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_upstream_ps_header_filter;
#if (NGX_HTTP_SESSION)
    ngx_http_session_register_create_ctx_handler(
            ngx_http_upstream_ps_create_session_ctx);
#endif
    return NGX_OK;
}

