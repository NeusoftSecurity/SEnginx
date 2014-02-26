#ifndef _NGX_HTTP_WHITELIST_H_INCLUDED_
#define _NGX_HTTP_WHITELIST_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_hash.h>


#define NGX_HTTP_WL_ADDR_TIMEOUT (5*1000)  //5s
#define NGX_HTTP_WL_ADDR_LEN 64

typedef struct {
    ngx_rbtree_node_t               node;
    u_char                          addr[NGX_HTTP_WL_ADDR_LEN];
    size_t                          len;
    ngx_str_t                       name;
    ngx_event_t                     timeout_ev;
} ngx_http_wl_dns_t;

typedef struct {
    ngx_http_regex_t  *regex;
    ngx_http_regex_t  *domain_name;

    ngx_uint_t         domain_enable:1;
} ngx_http_wl_item_t;

typedef struct {
    ngx_array_t       *items;
    ngx_str_t          name;
    ngx_int_t          var_index;

    /* flags */
    ngx_uint_t         caseless:1;
} ngx_http_wl_list_t;

typedef struct {
    ngx_array_t       *whitelists;
} ngx_http_wl_main_conf_t;

#endif
