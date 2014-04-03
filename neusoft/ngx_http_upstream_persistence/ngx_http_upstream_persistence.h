/*
 * Copyright (c) 2013 Neusoft Corperation., Ltd.
 */


#ifndef _NGX_HTTP_UPSTREAM_PERSISTENCE_H_INCLUDE_
#define _NGX_HTTP_UPSTREAM_PERSISTENCE_H_INCLUDE_

#include <ngx_event_connect.h>
#include <ngx_http.h>

typedef struct ngx_http_upstream_ps_group_s {
    ngx_int_t                               (*ps_get)(ngx_http_request_t *r, 
                                                    struct ngx_http_upstream_ps_group_s *group);
    void                                    (*ps_set)(ngx_http_request_t *r, 
                                                    ngx_uint_t current,
                                                    struct ngx_http_upstream_ps_group_s *group);
    ngx_str_t                               insert_cookie;
    ngx_str_t                               monitor_cookie;
    ngx_int_t                               timeout;
}ngx_http_upstream_ps_group_t;

typedef struct {
    ngx_int_t                               server_index;
} ngx_http_upstream_ps_session_ctx_t;

extern ngx_int_t ngx_http_upstream_ps_get(ngx_http_request_t *r,
        ngx_uint_t peer_number,
        ngx_http_upstream_ps_group_t *group);
extern void ngx_http_upstream_ps_set(ngx_http_request_t *r, 
        ngx_uint_t current, void *group);

#endif
