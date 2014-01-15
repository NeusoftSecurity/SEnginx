
/*
 * Copyright (c) 2014 Neusoft Corperation., Ltd.
 */


#ifndef _NGX_HTTP_IP_BEHAVIOR_H_INCLUDED_
#define _NGX_HTTP_IP_BEHAVIOR_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define TYPE_SENSITIVE_URL_STR "sensitive_url"
#define TYPE_BAD_RESPONSE_STR "bad_response"
#define TYPE_SENSITIVE_URL 0x1
#define TYPE_BAD_RESPONSE 0x2


typedef struct {
    u_char                       color;
    u_char                       dummy;
    u_short                      len;
    ngx_queue_t                  queue;
    ngx_msec_t                   last;
    /* statistics of requests */
    ngx_uint_t                   total;
    ngx_uint_t                   insensitive;
    ngx_uint_t                   bad_response;

    u_char                       addr[1];
} ngx_http_ip_behavior_node_t;


typedef struct {
    ngx_rbtree_t                  rbtree;
    ngx_rbtree_node_t             sentinel;
    ngx_queue_t                   queue;
} ngx_http_ip_behavior_shctx_t;


typedef struct {
    ngx_http_ip_behavior_shctx_t  *sh;
    ngx_slab_pool_t               *shpool;

    ngx_int_t                     sample_base;
    ngx_int_t                     sample_cycle;
} ngx_http_ip_behavior_ctx_t;


typedef struct {
    ngx_shm_zone_t              *shm_zone;

    ngx_int_t                    enabled;
    ngx_int_t                    x_forwarded_for;
    ngx_int_t                    sensitive;
    ngx_int_t                    type;
} ngx_http_ip_behavior_conf_t;


#endif
