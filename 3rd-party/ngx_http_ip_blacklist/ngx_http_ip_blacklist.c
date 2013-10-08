/*
 * Copyright (c) 2013 Neusoft Corperation., Ltd.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_core_module.h>
#include <ngx_times.h>
#include <ngx_md5.h>

#include <ngx_http_ip_blacklist.h>

static ngx_int_t
ngx_http_ip_blacklist_manager(void);
static ngx_int_t
ngx_http_ip_blacklist_init(ngx_conf_t *cf);
static ngx_int_t
ngx_http_ip_blacklist_handler(ngx_http_request_t *r);
static void *
ngx_http_ip_blacklist_create_main_conf(ngx_conf_t *cf);
static char *
ngx_http_ip_blacklist_init_main_conf(ngx_conf_t *cf, void *conf);
static char *
ngx_http_ip_blacklist_timeout(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *
ngx_http_ip_blacklist(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *
ngx_http_ip_blacklist_timeout(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *
ngx_http_ip_blacklist_size(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_http_ip_blacklist_t *
ngx_http_ip_blacklist_lookup(ngx_rbtree_t *tree, ngx_str_t *addr, uint32_t hash);
static ngx_int_t
ngx_http_ip_blacklist_request_cleanup_init(ngx_http_request_t *r);
static void
ngx_http_ip_blacklist_cleanup(void *data);
static ngx_int_t
ngx_http_ip_blacklist_pre_init(ngx_conf_t *cf);
static ngx_int_t
ngx_http_ip_blacklist_init_shm_zone(ngx_shm_zone_t *shm_zone, void *data);
static char *
ngx_http_ip_blacklist_show(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *
ngx_http_ip_blacklist_create_loc_conf(ngx_conf_t *cf);
static char *
ngx_http_ip_blacklist_merge_loc_conf(ngx_conf_t *cf,
        void *parent, void *child);
static char *
ngx_http_ip_blacklist_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *
ngx_http_ip_blacklist_flush(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_shm_zone_t *ngx_http_ip_blacklist_shm_zone;
static ngx_module_t *
ngx_http_ip_blacklist_modules[NGX_HTTP_IP_BLACKLIST_MOD_NUM];

static ngx_command_t ngx_http_ip_blacklist_commands[] = {

    { ngx_string("ip_blacklist"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_http_ip_blacklist,
        NGX_HTTP_MAIN_CONF_OFFSET,
        0,
        NULL },

    { ngx_string("ip_blacklist_size"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_http_ip_blacklist_size,
        NGX_HTTP_MAIN_CONF_OFFSET,
        0,
        NULL },

    { ngx_string("ip_blacklist_timeout"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_http_ip_blacklist_timeout,
        NGX_HTTP_MAIN_CONF_OFFSET,
        0,
        NULL },

    { ngx_string("ip_blacklist_show"),
        NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
        ngx_http_ip_blacklist_show,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },

    { ngx_string("ip_blacklist_log"),
        NGX_HTTP_LOC_CONF|NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
        ngx_http_ip_blacklist_log,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },

    { ngx_string("ip_blacklist_flush"),
        NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
        ngx_http_ip_blacklist_flush,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },

    ngx_null_command,
};

static ngx_http_module_t ngx_http_ip_blacklist_module_ctx = {
    ngx_http_ip_blacklist_pre_init,          /* preconfiguration */
    ngx_http_ip_blacklist_init,              /* postconfiguration */

    ngx_http_ip_blacklist_create_main_conf,  /* create main configuration */
    ngx_http_ip_blacklist_init_main_conf,    /* merge main configuration */

    NULL,                                 /* create server configuration */
    NULL,                                 /* merge server configuration */

    ngx_http_ip_blacklist_create_loc_conf,   /* create location configuration */
    ngx_http_ip_blacklist_merge_loc_conf     /* merge location configuration */
};


ngx_module_t ngx_http_ip_blacklist_module = {
    NGX_MODULE_V1,
    &ngx_http_ip_blacklist_module_ctx,     /* module context */
    ngx_http_ip_blacklist_commands,        /* module directives */
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

static ngx_int_t
ngx_http_ip_blacklist_pre_init(ngx_conf_t *cf)
{
    memset(ngx_http_ip_blacklist_modules, 0,
            sizeof(ngx_module_t *) * NGX_HTTP_IP_BLACKLIST_MOD_NUM);
    
    return NGX_OK;
}

static ngx_int_t
ngx_http_ip_blacklist_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt         *h;
    ngx_http_core_main_conf_t   *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
    if (h == NULL)
        return NGX_ERROR;

    *h = ngx_http_ip_blacklist_handler;

    return NGX_OK;
}

static ngx_int_t
ngx_http_ip_blacklist_handler(ngx_http_request_t *r)
{
    ngx_http_ip_blacklist_main_conf_t         *imcf;
    ngx_http_ip_blacklist_t                   *node;
    ngx_http_ip_blacklist_tree_t              *blacklist;
    ngx_http_ip_blacklist_ctx_t               *ctx;
    uint32_t                                   hash;
    ngx_array_t                               *xfwd;
    ngx_table_elt_t                          **h;
    ngx_str_t                                  src_addr_text;
    ngx_int_t                                  i;
    
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
            "ip blacklist handler begin");
    
    imcf = ngx_http_get_module_main_conf(r, ngx_http_ip_blacklist_module);
    
    if (!imcf->enabled) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_ip_blacklist_module);
    if (!ctx) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_ip_blacklist_ctx_t));
        if (!ctx) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_http_set_ctx(r, ctx, ngx_http_ip_blacklist_module);
    }

#if (NGX_HTTP_X_FORWARDED_FOR)
    if (r->headers_in.x_forwarded_for.nelts > 0) {
        xfwd = &r->headers_in.x_forwarded_for;
        h = xfwd->elts;
        src_addr_text = h[0]->value;
    } else
#endif
    {
        src_addr_text = r->connection->addr_text;
    }

    hash = ngx_crc32_short(src_addr_text.data,
            src_addr_text.len);

    blacklist = ngx_http_ip_blacklist_shm_zone->data;
    ngx_shmtx_lock(&blacklist->shpool->mutex);

    node = ngx_http_ip_blacklist_lookup(&blacklist->blacklist,
            &src_addr_text,
            hash);
    if (node == NULL) {
        ngx_shmtx_unlock(&blacklist->shpool->mutex);
        return NGX_DECLINED;
    }

    if (!node->blacklist) {
        if (node->timed) {
            /* node is timed out, reuse this node, reset the count */
            node->timed = 0;

            for (i = 0; i < NGX_HTTP_IP_BLACKLIST_MOD_NUM; i++) {
                node->counts[i].count = 0;
            }
        }

        /* avoid being destroyed by manager */
        ctx->node = node;
        node->ref++;

        ngx_http_ip_blacklist_request_cleanup_init(r);

        ngx_shmtx_unlock(&blacklist->shpool->mutex);
        return NGX_DECLINED;
    }

    /* deny this request */

    ngx_shmtx_unlock(&blacklist->shpool->mutex);

    return NGX_ERROR;
}

static void *
ngx_http_ip_blacklist_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_ip_blacklist_main_conf_t  *imcf;

    imcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ip_blacklist_main_conf_t));
    if (imcf == NULL) {
        return NULL;
    }

    imcf->timeout = 60;
    imcf->size = 1024;

    return imcf;
}

static char *
ngx_http_ip_blacklist_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_ip_blacklist_main_conf_t     *imcf = conf;
    ngx_str_t                             *shm_name;
    ngx_int_t                              shm_size;

    if (imcf->enabled == 0) {
        cf->cycle->ip_blacklist_callback = ngx_http_ip_blacklist_manager;
        cf->cycle->ip_blacklist_enabled = 0;

        return NGX_CONF_OK;
    }

    /* set up shared memory for ip blacklist */
    shm_name = ngx_palloc(cf->pool, sizeof(*shm_name));
    ngx_str_set(shm_name, "ip_blacklist");

    shm_size = (sizeof(ngx_http_ip_blacklist_t)
            + NGX_HTTP_IP_BLACKLIST_ADDR_LEN)
        * imcf->size
        + sizeof(ngx_http_ip_blacklist_tree_t);

    ngx_http_ip_blacklist_shm_zone = ngx_shared_memory_add(
            cf, shm_name, shm_size,
            &ngx_http_ip_blacklist_module);

    if (ngx_http_ip_blacklist_shm_zone == NULL) {
        return "init shared memory failed";
    }

    ngx_http_ip_blacklist_shm_zone->init = ngx_http_ip_blacklist_init_shm_zone;

    /* set and enable ip blacklist manager */
    cf->cycle->ip_blacklist_callback = ngx_http_ip_blacklist_manager;
    cf->cycle->ip_blacklist_enabled = 1;

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_ip_blacklist_manager(void)
{
    ngx_queue_t                               *node;
    ngx_queue_t                               *tmp;
    ngx_http_ip_blacklist_tree_t              *blacklist;
    ngx_http_ip_blacklist_t                   *bn;

    blacklist = ngx_http_ip_blacklist_shm_zone->data;

    ngx_shmtx_lock(&blacklist->shpool->mutex);

    if (ngx_queue_empty(&blacklist->garbage)) {
        goto out;
    }

    for (node = ngx_queue_head(&blacklist->garbage);
            node != ngx_queue_sentinel(&blacklist->garbage);
            node = ngx_queue_next(node)) {
        bn = ngx_queue_data(node, ngx_http_ip_blacklist_t, queue);
        if (bn->blacklist) {
            if (bn->timeout <= ngx_time()) {
                if (bn->ref != 0) {
                    /* wait for request cleanup handler to delete this */
                    bn->timed = 1;
                    bn->blacklist = 0;

                    goto out;
                }
                /* blacklist timed out */
                tmp = node;
                node = ngx_queue_prev(node);

                ngx_rbtree_delete(&blacklist->blacklist, &bn->node);
                ngx_queue_remove(tmp);
                ngx_slab_free_locked(blacklist->shpool, bn);
            }
        } else {
            if (bn->ref == 0) {
                tmp = node;
                node = ngx_queue_prev(node);

                ngx_rbtree_delete(&blacklist->blacklist, &bn->node);
                ngx_queue_remove(tmp);
                ngx_slab_free_locked(blacklist->shpool, bn);
            } else {
                /* wait for request cleanup handler to delete this */
                bn->timed = 1;
            }
        }
    }

out:
    ngx_shmtx_unlock(&blacklist->shpool->mutex);

    return NGX_OK;
}

static ngx_http_ip_blacklist_t *
ngx_http_ip_blacklist_lookup(ngx_rbtree_t *tree, ngx_str_t *addr, uint32_t hash)
{
    ngx_int_t                 rc;
    ngx_rbtree_node_t        *node, *sentinel;
    ngx_http_ip_blacklist_t  *bn;

    node = tree->root;
    sentinel = tree->sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        bn = (ngx_http_ip_blacklist_t *) node;

        rc = ngx_memn2cmp(addr->data, bn->addr, addr->len, bn->len);

        if (rc == 0) {
            return bn;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    /* not found */

    return NULL;
}

static void
ngx_http_ip_blacklist_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t    **p;
    ngx_http_ip_blacklist_t   *bn, *bn_temp;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            bn = (ngx_http_ip_blacklist_t *) node;
            bn_temp = (ngx_http_ip_blacklist_t *) temp;

            p = (ngx_memn2cmp(bn->addr, bn_temp->addr, bn->len, bn_temp->len)
                 < 0) ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}

static ngx_int_t
ngx_http_ip_blacklist_init_shm_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_slab_pool_t                *shpool;
    ngx_http_ip_blacklist_tree_t   *blacklist_tree;
    ngx_rbtree_node_t              *sentinel;

    if (data) {
        shm_zone->data = data;
        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    blacklist_tree = ngx_slab_alloc(shpool,
            sizeof(ngx_http_ip_blacklist_tree_t));
    if (blacklist_tree == NULL) {
        return NGX_ERROR;
    }

    memset(blacklist_tree, 0, sizeof(ngx_http_ip_blacklist_tree_t));

    sentinel = ngx_slab_alloc(shpool, sizeof(ngx_rbtree_node_t));
    if (sentinel == NULL) {
        return NGX_ERROR;
    }

    ngx_rbtree_init(&blacklist_tree->blacklist, sentinel,
                    ngx_http_ip_blacklist_rbtree_insert_value);
    ngx_queue_init(&blacklist_tree->garbage);

    blacklist_tree->shpool = shpool;

    shm_zone->data = blacklist_tree;

    return NGX_OK;
}

static char *
ngx_http_ip_blacklist(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_ip_blacklist_main_conf_t *imcf = conf;
    ngx_str_t                         *value;

    value = cf->args->elts;
    if (!strncmp((char *)(value[1].data), "on", value[1].len)) {
        imcf->enabled = 1;
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_ip_blacklist_timeout(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_ip_blacklist_main_conf_t     *imcf = conf;
    ngx_str_t                             *value;

    value = cf->args->elts;
    imcf->timeout = ngx_atoi(value[1].data, value[1].len);

    if (imcf->timeout == NGX_ERROR) {
        return "Invalid timeout value";
    }

    if (imcf->timeout < 30) {
        return "Invalid timeout value";
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_ip_blacklist_size(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_ip_blacklist_main_conf_t     *imcf = conf;
    ngx_str_t                             *value;

    value = cf->args->elts;
    imcf->size = ngx_atoi(value[1].data, value[1].len);

    if (imcf->size == NGX_ERROR) {
        return "Invalid size value";
    }

    if (imcf->size <= 0) {
        return "ip blacklist size must be larger than 0";
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_ip_blacklist_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_ip_blacklist_loc_conf_t      *ilcf = conf;
    ngx_str_t                   *value;

    value = cf->args->elts;
    if (!strncmp((char *)(value[1].data), "on", value[1].len)) {
        ilcf->log_enabled = 1;
    }
 
    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_ip_blacklist_request_cleanup_init(ngx_http_request_t *r)
{
    ngx_http_cleanup_t             *cln;

    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }

    cln->handler = ngx_http_ip_blacklist_cleanup;
    cln->data = r;

    return NGX_OK;
}

static void
ngx_http_ip_blacklist_cleanup(void *data)
{
    ngx_http_request_t           *r = data;
    ngx_http_ip_blacklist_ctx_t  *ctx;
    ngx_http_ip_blacklist_t      *node;
    ngx_http_ip_blacklist_tree_t *blacklist;

    ctx = ngx_http_get_module_ctx(r, ngx_http_ip_blacklist_module);
    if (!ctx) {
        return;
    }

    if (!ctx->node) {
        return;
    }

    node = ctx->node;

    blacklist = ngx_http_ip_blacklist_shm_zone->data;
    ngx_shmtx_lock(&blacklist->shpool->mutex);

    node->ref--;

    if (node->timed && node->ref == 0) {
        /* this means the node is timed out, delete it */
        ngx_rbtree_delete(&blacklist->blacklist, &node->node);
        ngx_queue_remove(&node->queue);
        ngx_slab_free_locked(blacklist->shpool, node);
    }

    ngx_shmtx_unlock(&blacklist->shpool->mutex);
    return;
}

static void *
ngx_http_ip_blacklist_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_ip_blacklist_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ip_blacklist_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->log_enabled = NGX_CONF_UNSET;

    return conf;
}

static char *
ngx_http_ip_blacklist_merge_loc_conf(ngx_conf_t *cf,
        void *parent, void *child)
{
    ngx_http_ip_blacklist_loc_conf_t  *prev = parent;
    ngx_http_ip_blacklist_loc_conf_t  *conf = child;

    ngx_conf_merge_value(conf->log_enabled, prev->log_enabled, 0);

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_ip_blacklist_show_handler(ngx_http_request_t *r)
{
    ngx_int_t                          rc, j = 0;
    ngx_buf_t                         *b;
    ngx_chain_t                        out;
    ngx_str_t                         *test;
    ngx_http_ip_blacklist_main_conf_t *imcf;
    const char                        *banner = 
        "IP blacklist is not enabled<br>";
    const char                        *empty = 
        "IP blacklist is empty<br>";
    ngx_http_ip_blacklist_tree_t      *blacklist;
    ngx_http_ip_blacklist_t           *bn;
    ngx_queue_t                       *node;
    char                               tmp[NGX_HTTP_IP_BLACKLIST_ADDR_LEN];
    ngx_uint_t                         total = 0;


    imcf = ngx_http_get_module_main_conf(r, ngx_http_ip_blacklist_module);
    
    test = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
    if (!test) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    test->data = ngx_pcalloc(r->pool,
            imcf->size * sizeof(ngx_http_ip_blacklist_t) + 1024);
    if (!test->data) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    if (!imcf->enabled) {
        memcpy(test->data, banner, strlen(banner));
        test->len = strlen(banner);
        
        goto not_enabled;
    } else {
        memcpy(test->data, "Total:                 <br>IP Address(es): <br>",
                strlen("Total:                 <br>IP Address(es): <br>"));
        test->len =
            strlen("Total:                 <br>IP Address(es): <br>");
    }

    blacklist = ngx_http_ip_blacklist_shm_zone->data;
    ngx_shmtx_lock(&blacklist->shpool->mutex);

    if (ngx_queue_empty(&blacklist->garbage)) {
        ngx_shmtx_unlock(&blacklist->shpool->mutex);

        memcpy(test->data, empty, strlen(empty));
        test->len = strlen(empty);

        goto empty;
    }

    for (node = ngx_queue_head(&blacklist->garbage);
            node != ngx_queue_sentinel(&blacklist->garbage);
            node = ngx_queue_next(node)) {
        bn = ngx_queue_data(node, ngx_http_ip_blacklist_t, queue);

        if (bn->blacklist) {
            memset(tmp, 0, NGX_HTTP_IP_BLACKLIST_ADDR_LEN);
            memcpy(tmp,
                    bn->addr,
                    bn->len < NGX_HTTP_IP_BLACKLIST_ADDR_LEN ? bn->len :
                    NGX_HTTP_IP_BLACKLIST_ADDR_LEN - 1);

            j = sprintf((char *)(test->data + test->len), 
                    "addr: %s, timeout: %d, "
                    "timed out: %d, blacklist: %d, ref: %d <br>",
                    tmp, (int)(bn->timeout - ngx_time()),
                    bn->timed, bn->blacklist, (int)bn->ref);

            test->len += j;
            total++;
        }
    }

    sprintf((char *)(test->data + 7), "%u", (unsigned int)total);

    ngx_shmtx_unlock(&blacklist->shpool->mutex);

empty:
not_enabled:
    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
                "Failed to allocate response buffer.");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;

    b->pos = test->data;
    b->last = test->data + test->len;

    b->memory = 1;
    b->last_buf = 1;

    r->headers_out.content_type.len = sizeof("text/html") - 1;
    r->headers_out.content_type.data = (u_char *) "text/html";
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = test->len;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }
    
    return ngx_http_output_filter(r, &out);
}

static char *
ngx_http_ip_blacklist_show(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t          *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_ip_blacklist_show_handler;

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_ip_blacklist_flush_handler(ngx_http_request_t *r)
{
    ngx_http_ip_blacklist_main_conf_t *imcf;
    ngx_http_ip_blacklist_tree_t      *blacklist;
    ngx_http_ip_blacklist_t           *bn;
    ngx_queue_t                       *node;
    ngx_queue_t                       *tmp;

    imcf = ngx_http_get_module_main_conf(r, ngx_http_ip_blacklist_module);

    if (!imcf->enabled) {
        return NGX_HTTP_CLOSE;
    }

    blacklist = ngx_http_ip_blacklist_shm_zone->data;
    ngx_shmtx_lock(&blacklist->shpool->mutex);

    if (ngx_queue_empty(&blacklist->garbage)) {
        ngx_shmtx_unlock(&blacklist->shpool->mutex);
        return NGX_HTTP_CLOSE;
    }

    for (node = ngx_queue_head(&blacklist->garbage);
            node != ngx_queue_sentinel(&blacklist->garbage);
            node = ngx_queue_next(node)) {
        bn = ngx_queue_data(node, ngx_http_ip_blacklist_t, queue);

        if (bn->ref != 0) {
            /* force node to time out */
            bn->timed = 1;
            continue;
        }

        tmp = node;
        node = ngx_queue_prev(node);

        ngx_rbtree_delete(&blacklist->blacklist, &bn->node);
        ngx_queue_remove(tmp);
        ngx_slab_free_locked(blacklist->shpool, bn);
    }

    ngx_shmtx_unlock(&blacklist->shpool->mutex);

    return NGX_HTTP_CLOSE;
}

static char *
ngx_http_ip_blacklist_flush(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t          *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_ip_blacklist_flush_handler;

    return NGX_CONF_OK;
}

static void
ngx_http_ip_blacklist_write_attack_log(ngx_http_request_t *r)
{  
    char                        *addr = NULL;
    char                        *do_action = "running ";
    ngx_connection_t            *connection;
    ngx_log_t                   *log;
    char                        *module_name = "ip_blacklist";

    connection = r->connection;

    log = connection->log;
    log->action = ngx_pcalloc(r->pool, ngx_strlen(do_action) + 
            ngx_strlen(module_name) + 1);
    if (log->action == NULL) {
        return;
    }

    addr = ngx_pcalloc(r->pool, r->connection->addr_text.len + 1);
    if (!addr) {
        return;
    }

    memcpy(addr, r->connection->addr_text.data, r->connection->addr_text.len);

    strcpy(log->action, do_action);
    strcpy(log->action + ngx_strlen(do_action), module_name);

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "%s: Blocked IP address: \"%s\"", 
            "ip_blacklist", addr);
}

/* 
 * ngx_http_ip_blacklist_update
 *
 * This function updates the blacklisting count according to @addr.
 * If the count reaches max threshold, which is indicated by @max, the source
 * IP address will be added to the real blacklist.
 *
 * @addr: IP address of the request
 * @max: threshold of failure number
 * @module: ngx_module_t of the calling module
 *
 * Return values: 
 *     0: not blacklisted
 *     1: blacklisted
 *    -1: error occured
 */
ngx_int_t
ngx_http_ip_blacklist_update(ngx_http_request_t *r,
        ngx_str_t *addr,
        ngx_int_t max,
        ngx_module_t *module)
{
    ngx_http_ip_blacklist_main_conf_t         *imcf;
    ngx_http_ip_blacklist_loc_conf_t          *ilcf;
    ngx_http_ip_blacklist_t                   *node;
    ngx_http_ip_blacklist_tree_t              *blacklist;
    uint32_t                                   hash;
    ngx_int_t                                  i;
    ngx_http_ip_blacklist_ctx_t               *ctx;
    
    imcf = ngx_http_get_module_main_conf(r, ngx_http_ip_blacklist_module);
    ilcf = ngx_http_get_module_loc_conf(r, ngx_http_ip_blacklist_module);
    
    if (!imcf->enabled) {
        return 0;
    }

    if (addr->len > NGX_HTTP_IP_BLACKLIST_ADDR_LEN) {
        return -1;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_ip_blacklist_module);
    if (!ctx) {
        /* ctx should always be prepared by blacklist module */
        return -1;
    }

    blacklist = ngx_http_ip_blacklist_shm_zone->data;
    ngx_shmtx_lock(&blacklist->shpool->mutex);

    if (ctx->node) {
        node = ctx->node;
    } else {
        /* maybe other requests set the node, so let's do a lookup */
        hash = ngx_crc32_short(addr->data, addr->len);

        node = ngx_http_ip_blacklist_lookup(&blacklist->blacklist,
                addr,
                hash);

        if (node == NULL) {
            /* add new rbtree item to record this addr */
            node = ngx_slab_alloc_locked(blacklist->shpool,
                    sizeof(ngx_http_ip_blacklist_t));
            if (node == NULL) {
                ngx_shmtx_unlock(&blacklist->shpool->mutex);
                return -1;
            }

            memset(node, 0, sizeof(ngx_http_ip_blacklist_t));

            memcpy(node->addr, addr->data, addr->len);
            node->len = (u_short)addr->len;

            node->timeout = ngx_time() + imcf->timeout;

            for (i = 0; i < NGX_HTTP_IP_BLACKLIST_MOD_NUM; i++) {
                if (ngx_http_ip_blacklist_modules[i] != NULL) {
                    node->counts[i].module = ngx_http_ip_blacklist_modules[i];

                    if (ngx_http_ip_blacklist_modules[i] == module) {
                        node->counts[i].count++;
                        break;
                    }
                }
            }

            node->node.key = hash;

            ngx_rbtree_insert(&blacklist->blacklist, &node->node);
            ngx_queue_insert_head(&blacklist->garbage, &node->queue);

            ctx->node = node;
            node->ref++;

            ngx_http_ip_blacklist_request_cleanup_init(r);

            ngx_shmtx_unlock(&blacklist->shpool->mutex);
            return 0;
        }
    }

    if (node->blacklist) {
        /* Perhaps other workers set this IP addr to match with max count */
        ngx_shmtx_unlock(&blacklist->shpool->mutex);
        return 1;
    }

    if (node->timed) {
        /* node is timed out, reuse this node, reset the count */
        node->timed = 0;

        for (i = 0; i < NGX_HTTP_IP_BLACKLIST_MOD_NUM; i++) {
            node->counts[i].count = 0;
        }
    }

    /* otherwise, increase the count and check if it matches with max count */
    for (i = 0; i < NGX_HTTP_IP_BLACKLIST_MOD_NUM; i++) {
        if (node->counts[i].module == module) {
            if (++(node->counts[i].count) == max) {
                node->blacklist = 1;

                if (ilcf->log_enabled) {
                    ngx_http_ip_blacklist_write_attack_log(r);
                }

                ngx_shmtx_unlock(&blacklist->shpool->mutex);
                return 1;
            }
            break;
        }
    }

    ngx_shmtx_unlock(&blacklist->shpool->mutex);

    return 0;
}

/* 
 * ngx_http_ip_blacklist_register_mod
 *
 *
 * @module: ngx_module_t of the calling module
 *
 * Return values: 
 *     NGX_OK: registered
 *     NGX_ERROR: error occured
 */
ngx_int_t
ngx_http_ip_blacklist_register_mod(ngx_module_t *mod)
{
    ngx_int_t i;

    for(i = 0; i < NGX_HTTP_IP_BLACKLIST_MOD_NUM; i++) {
        if (ngx_http_ip_blacklist_modules[i] == NULL) {
            ngx_http_ip_blacklist_modules[i] = mod;
            return NGX_OK;
        }
    }

    /* list full */
    return NGX_ERROR;
}
