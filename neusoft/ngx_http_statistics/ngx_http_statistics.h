/*
 * Copyright (c) 2014 Neusoft Corperation., Ltd.
 */

#ifndef _NGX_HTTP_STATISTICS_H_INCLUDED_
#define _NGX_HTTP_STATISTICS_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_STATS_TYPE_ATTACK      0
#define NGX_HTTP_STATS_TYPE_TRAFFIC     1


enum ngx_http_statistics_attack_types {

    NGX_HTTP_STATS_ATTACK_SQL_INJECTION,
    NGX_HTTP_STATS_ATTACK_XSS,
    NGX_HTTP_STATS_ATTACK_RFI,
    NGX_HTTP_STATS_ATTACK_DIR_TRAVERSAL,
    NGX_HTTP_STATS_ATTACK_EVADING,
    NGX_HTTP_STATS_ATTACK_FILE_UPLOAD,
    NGX_HTTP_STATS_ATTACK_CP,
    NGX_HTTP_STATS_ATTACK_WD,
    NGX_HTTP_STATS_ATTACK_RM,
    NGX_HTTP_STATS_ATTACK_OTHER,

    NGX_HTTP_STATS_ATTACK_MAX
};


enum ngx_http_statistics_traffic_types {

    NGX_HTTP_STATS_TRAFFIC_CUR_REQ,
    NGX_HTTP_STATS_TRAFFIC_REQ,
    NGX_HTTP_STATS_TRAFFIC_RES_2xx,
    NGX_HTTP_STATS_TRAFFIC_RES_3xx,
    NGX_HTTP_STATS_TRAFFIC_RES_4xx,
    NGX_HTTP_STATS_TRAFFIC_RES_5xx,
    NGX_HTTP_STATS_TRAFFIC_SENT,
    NGX_HTTP_STATS_TRAFFIC_RECVD,

    NGX_HTTP_STATS_TRAFFIC_MAX
};


typedef struct {
    ngx_rbtree_node_t                node;

    /* name must be the second element next to rbtree node */
    ngx_str_t                        name;

    ngx_queue_t                      queue;

    /* request & response */
    ngx_uint_t                       traffic[NGX_HTTP_STATS_TRAFFIC_MAX];

    /* attacks detected by naxsi, modsecurity ... */
    ngx_uint_t                       attacks[NGX_HTTP_STATS_ATTACK_MAX];

    ngx_int_t                        ref;
} ngx_http_statistics_server_t;


typedef struct {
    ngx_rbtree_node_t                node;

    /* name must be the second element next to rbtree node */
    ngx_str_t                        name;

    ngx_queue_t                      queue;

    /* request & response */
    ngx_uint_t                       traffic[NGX_HTTP_STATS_TRAFFIC_MAX];

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
extern void
ngx_http_stats_server_inc(ngx_http_statistics_server_t *server,
        ngx_uint_t type, ngx_uint_t slot);
extern void
ngx_http_stats_server_add(ngx_http_statistics_server_t *server,
        ngx_uint_t type, ngx_uint_t slot, ngx_int_t add);
extern void
ngx_http_stats_server_dec(ngx_http_statistics_server_t *server,
        ngx_uint_t type, ngx_uint_t slot);
extern ngx_int_t
ngx_http_stats_enabled(ngx_cycle_t *cycle);
#endif
