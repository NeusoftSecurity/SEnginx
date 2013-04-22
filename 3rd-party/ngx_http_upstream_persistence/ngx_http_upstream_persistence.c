/*
 * Copyright (c) 2013 Neusoft Corperation., Ltd.
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event_connect.h>
#include <ngx_http.h>
#include <ngx_http_upstream.h>
#include <ngx_http_upstream_persistence.h>


#define NGX_HTTP_SESSION_PERSIST_COOKIE_KEY        "cookie_name="
#define NGX_HTTP_SESSION_PERSIST_ID_COOKIE          "ADSG-PERSISTENCE_ID"
#define NGX_HTTP_SESSION_DEFAULT_TIMEOUT            (30*60)

#define NGX_HTTP_FASTEST_VALID_TIME_LENGTH          (60*1000)      //ms


static char *ngx_http_upstream_persistence(ngx_conf_t *cf, ngx_command_t *cmd,
                                    void *conf);

static ngx_command_t  ngx_http_upstream_persistence_commands[] = {

    {
        ngx_string("persistence"),
        NGX_HTTP_UPS_CONF | NGX_CONF_TAKE1234,
        ngx_http_upstream_persistence,
        0,
        0,
        NULL
    },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_upstream_persistence_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_upstream_persistence_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_persistence_module_ctx, /* module context */
    ngx_http_upstream_persistence_commands,    /* module directives */
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


ngx_int_t ngx_http_upstream_persistence_get(ngx_http_request_t *r, 
        ngx_uint_t peer_number,
        ngx_http_upstream_persistence_group_t *group)
{
    ngx_http_upstream_persistence_group_t   *p_group = group;
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

void ngx_http_upstream_persistence_set(ngx_http_request_t *r, 
        ngx_uint_t current, void *group)
{
    ngx_http_upstream_persistence_group_t *p_group = group;

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
ngx_http_upstream_persistence_cookie_get_peer(ngx_http_request_t *r, 
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
ngx_http_upstream_persistence_set_cookie(ngx_http_request_t *r, 
        ngx_uint_t current,
        ngx_http_upstream_persistence_group_t *group, 
        ngx_str_t *value)
{
    ngx_table_elt_t                 *set_cookie;
    u_char                          *cookie;
    u_char                          *key_value;
    u_char                          *tmp;
    size_t                          len = value->len + 50; 
    //50 is strlen("=655350") + strlen("; expires=Thu, 31-Dec-37 23:55:55 GMT") + 1;
    
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
            "http_cookie_refresh_peer\n");

    cookie = ngx_pcalloc(r->pool, len * sizeof (u_char));
    if (cookie == NULL) {
        return;
    }

    key_value = ngx_pcalloc(r->pool, value->len + 1);
    if (key_value == NULL) {
        return;
    }

    ngx_memcpy(key_value, value->data, value->len);

    tmp = ngx_sprintf(cookie, "%s=%d", key_value, current);
    tmp = ngx_cpymem(tmp, "; expires=", sizeof("; expires=") - 1);
    ngx_http_cookie_time(tmp, ngx_time() + group->timeout);

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

static ngx_int_t ngx_upstream_persistence_http_cookie_get(ngx_http_request_t *r, 
        ngx_http_upstream_persistence_group_t *group)
{
    return ngx_http_upstream_persistence_cookie_get_peer(r, group->data);
}

static void ngx_upstream_persistence_http_cookie_set(ngx_http_request_t *r, 
        ngx_uint_t current,
        ngx_http_upstream_persistence_group_t *group)
{
    ngx_http_upstream_persistence_set_cookie(r, current, group, group->data);
}

static ngx_int_t ngx_upstream_persistence_session_cookie_get(ngx_http_request_t *r, 
        ngx_http_upstream_persistence_group_t *group)
{
    ngx_str_t     session_string;
    ngx_str_t     session_key = ngx_string(NGX_HTTP_SESSION_PERSIST_ID_COOKIE);
    ngx_int_t     n;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
            "http_session_cookie_get_peer\n");

    n = ngx_http_parse_multi_header_lines (&r->headers_in.cookies,
            (ngx_str_t *)group->data, &session_string);

    if (n == NGX_DECLINED ) {
        return -1;
    }

    if (session_string.len == 0) {
        return -1;
    }

    return ngx_http_upstream_persistence_cookie_get_peer(r, &session_key);
}

static void ngx_upstream_persistence_session_cookie_set(ngx_http_request_t *r,
        ngx_uint_t current,
        ngx_http_upstream_persistence_group_t *group)
{
    ngx_str_t session_key = ngx_string(NGX_HTTP_SESSION_PERSIST_ID_COOKIE);

    ngx_http_upstream_persistence_set_cookie(r, current, group, &session_key);
}

static char *
ngx_http_upstream_persistence_config(ngx_http_upstream_persistence_group_t 
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

            group->sess_persistence_get = ngx_upstream_persistence_http_cookie_get;
            group->sess_persistence_set = ngx_upstream_persistence_http_cookie_set;
            continue;
        }

        if (ngx_strcasecmp((u_char *)"session_cookie", (u_char *)value[i].data) == 0) {

            if (group->sess_persistence_get != NULL) {
                return "duplicate session persister";
            }

            if (cf->module_type != NGX_HTTP_MODULE) {
                return NGX_CONF_ERROR;
            }

            group->sess_persistence_get = &ngx_upstream_persistence_session_cookie_get;
            group->sess_persistence_set = &ngx_upstream_persistence_session_cookie_set;
            continue;
        }

        if (ngx_strncmp(value[i].data, NGX_HTTP_SESSION_PERSIST_COOKIE_KEY, 
                    ngx_strlen(NGX_HTTP_SESSION_PERSIST_COOKIE_KEY)) == 0) {
            if (group->data != NULL) {
                return "duplicate cookie_name";
            }

            str = ngx_pcalloc(cf->pool, sizeof (ngx_str_t) );

            if (str == NULL) {
                return NGX_CONF_ERROR;
            }

            str->data = value[i].data + 
                ngx_strlen(NGX_HTTP_SESSION_PERSIST_COOKIE_KEY);
            str->len = value[i].len -
                ngx_strlen(NGX_HTTP_SESSION_PERSIST_COOKIE_KEY);

            if (str->len == 0) {
                return NGX_CONF_ERROR;
            }

            group->data = str;
            continue;
        }

        if (ngx_strncasecmp((u_char *) "timeout=", (u_char *) value[i].data, 8) == 0) {
            group->timeout = ngx_atoi(value[i].data + 8, value[i].len - 8);
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
ngx_http_upstream_persistence(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upstream_srv_conf_t  *uscf;

    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
    if (ngx_http_upstream_persistence_config(&uscf->group, cf) != NGX_CONF_OK) {
        return "config error";
    }

    return NGX_CONF_OK;
}

