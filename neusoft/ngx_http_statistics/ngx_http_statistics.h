/*
 * Copyright (c) 2014 Neusoft Corperation., Ltd.
 */

#ifndef _NGX_HTTP_STATISTICS_H_INCLUDED_
#define _NGX_HTTP_STATISTICS_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_STATS_TYPE_SERVER      1
#define NGX_HTTP_STATS_TYPE_UPSTREAM    2

#define NGX_HTTP_STATS_TYPE_ATTACK      0
#define NGX_HTTP_STATS_TYPE_CUR_REQ     1
#define NGX_HTTP_STATS_TYPE_REQ         2
#define NGX_HTTP_STATS_TYPE_RES_2xx     3
#define NGX_HTTP_STATS_TYPE_RES_3xx     4
#define NGX_HTTP_STATS_TYPE_RES_4xx     5
#define NGX_HTTP_STATS_TYPE_RES_5xx     6
#define NGX_HTTP_STATS_TYPE_SENT        7
#define NGX_HTTP_STATS_TYPE_RECVD       8


enum ngx_http_statistics_attack_types {

    NGX_HTTP_STATS_ATTACK_SQL_INJECTION,
    NGX_HTTP_STATS_ATTACK_XSS,
    NGX_HTTP_STATS_ATTACK_RFI,
    NGX_HTTP_STATS_ATTACK_DIR_TRAVERSAL,
    NGX_HTTP_STATS_ATTACK_EVADING,
    NGX_HTTP_STATS_ATTACK_FILE_UPLOAD,
    NGX_HTTP_STATS_ATTACK_OTHER,

    NGX_HTTP_STATS_ATTACK_MAX
};


typedef struct {
    ngx_rbtree_node_t                node;

    /* name must be the second element next to rbtree node */
    ngx_str_t                        name;

    ngx_queue_t                      queue;

    ngx_uint_t                       attacks[NGX_HTTP_STATS_ATTACK_MAX];

    /* request & response */
    ngx_uint_t                       current_requests;
    ngx_uint_t                       requests;

    ngx_uint_t                       response_2xx;
    ngx_uint_t                       response_3xx;
    ngx_uint_t                       response_4xx;
    ngx_uint_t                       response_5xx;

    /* traffic */
    ngx_uint_t                       sent;
    ngx_uint_t                       recvd;

    ngx_int_t                        ref;
} ngx_http_statistics_server_t;


typedef struct {
    ngx_rbtree_node_t                node;

    /* name must be the second element next to rbtree node */
    ngx_str_t                        name;

    ngx_queue_t                      queue;

    /* request & response */
    ngx_uint_t                       current_requests;
    ngx_uint_t                       requests;

    ngx_uint_t                       response_2xx;
    ngx_uint_t                       response_3xx;
    ngx_uint_t                       response_4xx;
    ngx_uint_t                       response_5xx;

    /* traffic */
    ngx_uint_t                       sent;
    ngx_uint_t                       recvd;

    ngx_int_t                        ref;
} ngx_http_statistics_upstream_server_t;


typedef struct {
    ngx_rbtree_t                  server_tree;
    ngx_rbtree_t                  upstream_tree;
    ngx_rbtree_node_t             sentinel;
    ngx_queue_t                   server_queue;
    ngx_queue_t                   upstream_queue;
} ngx_http_statistics_shctx_t;


typedef struct {
    ngx_http_statistics_shctx_t   *sh;
    ngx_slab_pool_t               *shpool;
} ngx_http_statistics_ctx_t;


typedef struct {
    ngx_int_t                      enabled;
} ngx_http_statistics_conf_t;


extern ngx_http_statistics_server_t *
ngx_http_statistics_server_add(ngx_cycle_t *cycle, ngx_str_t *name);
extern void 
ngx_http_statistics_server_del(ngx_cycle_t *cycle, ngx_str_t *name);
#endif
