/*
 * Copyright (c) 2014 Neusoft Corperation., Ltd.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_core_module.h>
#include <ngx_times.h>
#include <ngx_md5.h>
#include <ngx_http_statistics.h>


static char *
ngx_http_statistics_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *
ngx_http_statistics(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *
ngx_http_statistics_create_main_conf(ngx_conf_t *cf);
static char *
ngx_http_statistics_init_main_conf(ngx_conf_t *cf, void *conf);


static ngx_shm_zone_t *statistics_shm_zone = NULL;

static ngx_command_t ngx_http_statistics_commands[] = {

    { ngx_string("statistics_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_statistics_zone,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("statistics"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_statistics,
      0,
      0,
      NULL },

    ngx_null_command,
};

static ngx_http_module_t ngx_http_statistics_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    ngx_http_statistics_create_main_conf,  /* create main configuration */
    ngx_http_statistics_init_main_conf,    /* merge main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};

ngx_module_t ngx_http_statistics_module = {
    NGX_MODULE_V1,
    &ngx_http_statistics_module_ctx,       /* module context */
    ngx_http_statistics_commands,          /* module directives */
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


static ngx_rbtree_node_t *
ngx_http_statistics_lookup(ngx_rbtree_t *tree, ngx_str_t *name,
     uint32_t hash)
{
    ngx_int_t             rc;
    ngx_rbtree_node_t    *node, *sentinel;
    ngx_str_t            *node_name;

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
        fprintf(stderr, "hash == node->key\n");

        node_name = (ngx_str_t *) ((char *)node + sizeof(ngx_rbtree_node_t));

        fprintf(stderr, "hash == node->key, node_name: %p\n", node_name);
        fprintf(stderr, "hash == node->key, node_name->len: %lu\n", node_name->len);
        fprintf(stderr, "hash == node->key, name->len: %lu\n", name->len);

        rc = ngx_memn2cmp(name->data, node_name->data,
                name->len, node_name->len);

        if (rc == 0) {
            return node;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    /* not found */

    return NULL;
}


static void
ngx_http_statistics_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t             **p;
    ngx_str_t                      *name, *name_t;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            name = (ngx_str_t *) ((char *)node + sizeof(ngx_rbtree_node_t));
            name_t = (ngx_str_t *) ((char *)node + sizeof(ngx_rbtree_node_t));

            p = (ngx_memn2cmp(name->data, name_t->data,
                     name->len, name_t->len) < 0)
                ? &temp->left : &temp->right;
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
ngx_http_statistics_init_shm_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_statistics_ctx_t      *octx = data;
    size_t                          len;
    ngx_http_statistics_ctx_t      *ctx;

    ctx = shm_zone->data;

    if (octx) {
        ctx->sh = octx->sh;
        ctx->shpool = octx->shpool;

        return NGX_OK;
    }

    ctx->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        ctx->sh = ctx->shpool->data;

        return NGX_OK;
    }

    ctx->sh = ngx_slab_alloc(ctx->shpool,
              sizeof(ngx_http_statistics_shctx_t));
    if (ctx->sh == NULL) {
        return NGX_ERROR;
    }

    ctx->shpool->data = ctx->sh;

    ngx_rbtree_init(&ctx->sh->server_tree, &ctx->sh->sentinel,
                    ngx_http_statistics_rbtree_insert_value);

    ngx_queue_init(&ctx->sh->server_queue);

    ngx_rbtree_init(&ctx->sh->upstream_tree, &ctx->sh->sentinel,
                    ngx_http_statistics_rbtree_insert_value);

    ngx_queue_init(&ctx->sh->upstream_queue);

    len = sizeof(" in statistics zone \"\"") + shm_zone->shm.name.len;

    ctx->shpool->log_ctx = ngx_slab_alloc(ctx->shpool, len);
    if (ctx->shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(ctx->shpool->log_ctx, " in statistics zone \"%V\"%Z",
                &shm_zone->shm.name);

    return NGX_OK;
}


static char *
ngx_http_statistics_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ssize_t                         size;
    ngx_str_t                      *value, *name;
    ngx_http_statistics_ctx_t      *ctx;
    ngx_http_statistics_conf_t     *smcf = conf;

    value = cf->args->elts;

    size = ngx_parse_size(&value[1]);

    if (size == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "invalid zone size \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (size < (ssize_t) (8 * ngx_pagesize)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "zone \"%V\" is too small", &value[1]);
        return NGX_CONF_ERROR;
    }

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_statistics_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    name = ngx_palloc(cf->pool, sizeof(*name));
    if (name == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_str_set(name, "statistics");

    statistics_shm_zone = ngx_shared_memory_add(cf, name, size,
                                     &ngx_http_statistics_module);
    if (statistics_shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (statistics_shm_zone->data) {
        ctx = statistics_shm_zone->data;

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "%V \"%V\" is duplicated",
                           &cmd->name, &name);
        return NGX_CONF_ERROR;
    }

    statistics_shm_zone->init = ngx_http_statistics_init_shm_zone;
    statistics_shm_zone->data = ctx;

    smcf->enabled = 1;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_statistics_content_handler(ngx_http_request_t *r)
{
    return NGX_HTTP_NOT_FOUND;
#if 0
    ngx_int_t                           rc, j = 0;
    ngx_buf_t                          *b;
    ngx_chain_t                         out;
    ngx_http_statistics_main_conf_t    *smcf;
    ngx_http_statistics_server_t       *server;
    ngx_queue_t                        *node;
    ngx_http_statistics_ctx_t          *ctx;


    smcf = ngx_http_get_module_main_conf(r, ngx_http_statistics_module);

    if (!smcf->enabled) {
        return NGX_HTTP_NOT_FOUND;
    }

    ctx = statistics_shm_zone->data;
    ngx_shmtx_lock(&ctx->shpool->mutex);

    if (ngx_queue_empty(&statistics->garbage)) {
        ngx_shmtx_unlock(&statistics->shpool->mutex);

        memcpy(test->data, empty, strlen(empty));
        test->len = strlen(empty);

        goto empty;
    }

    for (node = ngx_queue_head(&statistics->garbage);
            node != ngx_queue_sentinel(&statistics->garbage);
            node = ngx_queue_next(node)) {
        bn = ngx_queue_data(node, ngx_http_ip_statistics_t, queue);

        if (bn->statistics) {
            memset(tmp, 0, NGX_HTTP_IP_BLACKLIST_ADDR_LEN);
            memcpy(tmp,
                    bn->addr,
                    bn->len < NGX_HTTP_IP_BLACKLIST_ADDR_LEN ? bn->len :
                    NGX_HTTP_IP_BLACKLIST_ADDR_LEN - 1);

            j = sprintf((char *)(test->data + test->len),
                    "addr: %s, timeout: %d, "
                    "timed out: %d, statistics: %d, ref: %d <br>",
                    tmp, (int)(bn->timeout - ngx_time()),
                    bn->timed, bn->statistics, (int)bn->ref);

            test->len += j;
            total++;
        }
    }

    sprintf((char *)(test->data + 7), "%u", (unsigned int)total);

    ngx_shmtx_unlock(&statistics->shpool->mutex);

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
#endif
}


static char *
ngx_http_statistics(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t          *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_statistics_content_handler;

    return NGX_CONF_OK;
}


static void *
ngx_http_statistics_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_statistics_conf_t  *smcf;

    smcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_statistics_conf_t));
    if (smcf == NULL) {
        return NULL;
    }

    return smcf;
}


static char *
ngx_http_statistics_init_main_conf(ngx_conf_t *cf, void *conf)
{
    return NGX_CONF_OK;
}


/* APIs */
ngx_http_statistics_server_t *
ngx_http_statistics_server_add(ngx_cycle_t *cycle, ngx_str_t *name)
{
    ngx_http_statistics_ctx_t       *ctx;
    ngx_http_statistics_conf_t      *smcf;
    ngx_http_statistics_server_t    *server;
    uint32_t                         hash;

    smcf = ngx_http_cycle_get_module_main_conf(cycle,
           ngx_http_statistics_module);

    if (smcf->enabled == 0) {
        return NULL;
    }

    ctx = statistics_shm_zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    hash = ngx_crc32_short(name->data, name->len);
        fprintf(stderr, "server add: hash: %u\n", hash);

    server = (ngx_http_statistics_server_t *) ngx_http_statistics_lookup(
            &ctx->sh->server_tree, name, hash);

        fprintf(stderr, "server add: server: %p\n", server);
    if (server == NULL) {
        /* create a new server node */
        fprintf(stderr, "create new node\n");
        server = ngx_slab_alloc_locked(ctx->shpool,
                sizeof(ngx_http_statistics_server_t));
        if (server == NULL) {
            ngx_shmtx_unlock(&ctx->shpool->mutex);
            return NULL;
        }

        memset(server, 0, sizeof(ngx_http_statistics_server_t));

        server->name.data = ngx_slab_alloc_locked(ctx->shpool, name->len);
        if (server->name.data == NULL) {
            ngx_shmtx_unlock(&ctx->shpool->mutex);
            return NULL;
        }

        memcpy(server->name.data, name->data, name->len);
        server->name.len = name->len;

        server->node.key = hash;

        ngx_rbtree_insert(&ctx->sh->server_tree, &server->node);
        ngx_queue_insert_head(&ctx->sh->server_queue, &server->queue);

        server->ref++;
    } else {
        /* found an exist server node */
        server->ref++;
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return server;
}


void 
ngx_http_statistics_server_del(ngx_cycle_t *cycle, ngx_str_t *name)
{
    ngx_http_statistics_ctx_t       *ctx;
    ngx_http_statistics_conf_t      *smcf;
    ngx_http_statistics_server_t    *server;
    uint32_t                         hash;

    smcf = ngx_http_cycle_get_module_main_conf(cycle,
           ngx_http_statistics_module);

    if (smcf->enabled == 0) {
        return;
    }

    ctx = statistics_shm_zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    hash = ngx_crc32_short(name->data, name->len);

    server = (ngx_http_statistics_server_t *) ngx_http_statistics_lookup(
            &ctx->sh->server_tree, name, hash);

    if (server != NULL) {
        /* find a server node */
        fprintf(stderr, "server->ref: %ld\n", server->ref);
        server->ref--;

        if (server->ref == 0) {
            ngx_rbtree_delete(&ctx->sh->server_tree, &server->node);
            ngx_queue_remove(&server->queue);
            ngx_slab_free_locked(ctx->shpool, server->name.data);
            ngx_slab_free_locked(ctx->shpool, server);
        }
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);
}


void
ngx_http_statistics_inc()
{
}


void
ngx_http_statistics_add()
{
}

void
ngx_http_statistics_dec()
{
}
