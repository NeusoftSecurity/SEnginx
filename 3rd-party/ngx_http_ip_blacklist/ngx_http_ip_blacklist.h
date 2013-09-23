/*
 * Copyright (c) 2013 Neusoft Corperation., Ltd.
 */
#ifndef _NGX_HTTP_IP_BLACKLIST_H_INCLUDED_
#define _NGX_HTTP_IP_BLACKLIST_H_INCLUDED_

#include <ngx_rbtree.h>

#define NGX_HTTP_IP_BLACKLIST_MOD_NUM 8
#define NGX_HTTP_IP_BLACKLIST_ADDR_LEN 64

typedef struct {
    ngx_int_t                 enabled;
    ngx_int_t                 timeout;
    ngx_int_t                 size;
} ngx_http_ip_blacklist_main_conf_t;

typedef struct {
    ngx_int_t                 log_enabled;
} ngx_http_ip_blacklist_loc_conf_t;

typedef struct {
    ngx_module_t          *module;
    ngx_int_t             count;
} ngx_http_ip_blacklist_module_t;

/* The IP blacklist "node" in rbtree */
typedef struct {
    ngx_rbtree_node_t               node;
    ngx_queue_t                     queue;

    u_char                          addr[NGX_HTTP_IP_BLACKLIST_ADDR_LEN];
    u_short                         len;

    u_char                          ref:1;
    u_char                          blacklist:1;
    u_char                          timed:1;
 
    ngx_int_t                       timeout;

    ngx_http_ip_blacklist_module_t  counts[NGX_HTTP_IP_BLACKLIST_MOD_NUM];
} ngx_http_ip_blacklist_t;

typedef struct {
    ngx_slab_pool_t                *shpool;

    ngx_rbtree_t                    blacklist;
    ngx_queue_t                     garbage;
} ngx_http_ip_blacklist_tree_t;

typedef struct {
    ngx_http_ip_blacklist_t        *node;
} ngx_http_ip_blacklist_ctx_t;

ngx_int_t
ngx_http_ip_blacklist_update(ngx_http_request_t *r,
        ngx_str_t *addr,
        ngx_int_t max,
        ngx_module_t *module);
ngx_int_t
ngx_http_ip_blacklist_register_mod(ngx_module_t *mod);

#endif
