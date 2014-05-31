
/*
 * Copyright (c) 2014 Neusoft Corperation., Ltd.
 */


#include "ngx_http_ip_behavior.h"

#if (NGX_HTTP_NETEYE_SECURITY)
#include <ngx_http_neteye_security.h>
#endif


static ngx_int_t ngx_http_ip_behavior_lookup(ngx_http_request_t *r,
    ngx_uint_t hash, ngx_http_ip_behavior_ctx_t *ctx,
    ngx_http_ip_behavior_conf_t *ilcf);
static void ngx_http_ip_behavior_expire(ngx_http_ip_behavior_ctx_t *ctx,
    ngx_uint_t n);
static void *ngx_http_ip_behavior_create_conf(ngx_conf_t *cf);
static char *ngx_http_ip_behavior_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_ip_behavior_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_ip_behavior(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_ip_behavior_sensitive(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_ip_behavior_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_ip_behavior_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_insensitive_percent_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_bad_response_percent_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);


static ngx_command_t  ngx_http_ip_behavior_commands[] = {

    { ngx_string("ip_behavior_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE123,
      ngx_http_ip_behavior_zone,
      0,
      0,
      NULL },

    { ngx_string("ip_behavior"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE2,
      ngx_http_ip_behavior,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("ip_behavior_sensitive"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_ip_behavior_sensitive,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_variable_t  ngx_http_ip_behavior_vars[] = {

    { ngx_string("insensitive_percent"), NULL,
      ngx_http_insensitive_percent_variable, 0,
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("bad_response_percent"), NULL,
      ngx_http_bad_response_percent_variable, 0,
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};


static ngx_http_module_t  ngx_http_ip_behavior_module_ctx = {
    ngx_http_ip_behavior_add_variables,    /* preconfiguration */
    ngx_http_ip_behavior_init,             /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_ip_behavior_create_conf,      /* create location configuration */
    ngx_http_ip_behavior_merge_conf        /* merge location configuration */
};


ngx_module_t  ngx_http_ip_behavior_module = {
    NGX_MODULE_V1,
    &ngx_http_ip_behavior_module_ctx,      /* module context */
    ngx_http_ip_behavior_commands,         /* module directives */
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
ngx_http_ip_behavior_handler(ngx_http_request_t *r)
{
    uint32_t                     hash;
    ngx_int_t                    rc;
    ngx_http_ip_behavior_ctx_t  *ctx;
    ngx_http_ip_behavior_conf_t *ilcf;

    if (r->internal) {
        return NGX_DECLINED;
    }

    ilcf = ngx_http_get_module_loc_conf(r, ngx_http_ip_behavior_module);

    if (!ilcf->enabled) {
        return NGX_DECLINED;
    }

    ctx = ilcf->shm_zone->data;

    rc = NGX_DECLINED;

    hash = ngx_crc32_short(r->connection->addr_text.data,
            r->connection->addr_text.len);

    ngx_shmtx_lock(&ctx->shpool->mutex);

    ngx_http_ip_behavior_expire(ctx, 0);

    rc = ngx_http_ip_behavior_lookup(r, hash, ctx, ilcf);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    if (rc == NGX_OK) {
        return NGX_DECLINED;
    } else {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
}


static void
ngx_http_ip_behavior_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t            **p;
    ngx_http_ip_behavior_node_t   *ibn, *ibnt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            ibn = (ngx_http_ip_behavior_node_t *) &node->color;
            ibnt = (ngx_http_ip_behavior_node_t *) &temp->color;

            p = (ngx_memn2cmp(ibn->addr, ibnt->addr, ibn->len, ibnt->len) < 0)
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
ngx_http_ip_behavior_lookup(ngx_http_request_t *r, ngx_uint_t hash,
    ngx_http_ip_behavior_ctx_t *ctx, ngx_http_ip_behavior_conf_t *ilcf)
{
    size_t                           size;
    ngx_int_t                        rc;
    ngx_time_t                      *tp;
    ngx_msec_t                       now;
    ngx_rbtree_node_t               *node, *sentinel;
    ngx_http_ip_behavior_node_t     *ibn;

    tp = ngx_timeofday();
    now = (ngx_msec_t) (tp->sec * 1000 + tp->msec);

    node = ctx->sh->rbtree.root;
    sentinel = ctx->sh->rbtree.sentinel;
    rc = -1;

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

        ibn = (ngx_http_ip_behavior_node_t *) &node->color;

        rc = ngx_memn2cmp(r->connection->addr_text.data, ibn->addr,
                r->connection->addr_text.len, (size_t) ibn->len);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "ip behavior lookup is : %i", rc);

        if (rc == 0) {
            /* found the node */

            /* check expire */
            if (ngx_abs((ngx_msec_int_t)(now - ibn->last))
                    >= ctx->sample_cycle) {
                /* node is expired, clear counters */
                ibn->insensitive = 0;
                ibn->total = 0;
                ibn->bad_response = 0;
            }

            ngx_queue_remove(&ibn->queue);
            ngx_queue_insert_head(&ctx->sh->queue, &ibn->queue);

            ibn->last = now;

            if (ilcf->type & TYPE_SENSITIVE_URL) {
                if (!ilcf->sensitive) {
                    ibn->insensitive++;
                }
            } else if (ilcf->type & TYPE_BAD_RESPONSE) {
                /* TODO: support bad response behavior */
            } else {
                /* should never be here */
            }

            /* total can be zero when it grows to big,
             * so need to reset all the counters */
            if (++ibn->total == 0) {
                ibn->insensitive = 0;
                ibn->bad_response = 0;

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                        "ip behavior node reset: %V",
                        &r->connection->addr_text);
            }

            if (ibn->total >= (ngx_uint_t)ctx->sample_base) {
                r->insensitive_percent =
                    (float)ibn->insensitive / (float)ibn->total * 100;
                r->bad_response_percent =
                    (float)ibn->bad_response / (float)ibn->total * 100;
            }

            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                          "ip behavior find node: %V, total: %i, insens: %i,"
                          " percent: %i",
                          &r->connection->addr_text, ibn->total,
                          ibn->insensitive, r->insensitive_percent);

            return NGX_OK;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    /* create a new node */
    size = offsetof(ngx_rbtree_node_t, color)
           + offsetof(ngx_http_ip_behavior_node_t, addr)
           + r->connection->addr_text.len;

    node = ngx_slab_alloc_locked(ctx->shpool, size);

    if (node == NULL) {
        ngx_http_ip_behavior_expire(ctx, 1);

        node = ngx_slab_alloc_locked(ctx->shpool, size);
        if (node == NULL) {
            return NGX_ERROR;
        }
    }

    node->key = hash;

    ibn = (ngx_http_ip_behavior_node_t *) &node->color;

    ibn->len = (u_char) r->connection->addr_text.len;

    ngx_memcpy(ibn->addr, r->connection->addr_text.data,
            r->connection->addr_text.len);

    ngx_rbtree_insert(&ctx->sh->rbtree, node);

    ngx_queue_insert_head(&ctx->sh->queue, &ibn->queue);

    ibn->last = now;
    ibn->total = 1;
    ibn->insensitive = !ilcf->sensitive;
    ibn->bad_response = 0;

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ip behavior new node: %V, total: %i, insens: %i,"
            " percent: %i",
            &r->connection->addr_text, ibn->total,
            ibn->insensitive, r->insensitive_percent);

    return NGX_OK;
}


static void
ngx_http_ip_behavior_expire(ngx_http_ip_behavior_ctx_t *ctx, ngx_uint_t force)
{
    ngx_time_t                   *tp;
    ngx_msec_t                    now;
    ngx_msec_int_t                ms;
    ngx_queue_t                  *q;
    ngx_rbtree_node_t            *node;
    ngx_http_ip_behavior_node_t  *ibn;
    ngx_uint_t                    i;
    ngx_uint_t                    n;


    tp = ngx_timeofday();

    now = (ngx_msec_t) (tp->sec * 1000 + tp->msec);

    /* delete at most 2 oldest nodes when a new request comes in
     * or
     * delete 10 oldest nodes ignoring the expires when "force" is set to 1
     */
    if (force) {
        n = 10;
    } else {
        n = 2;
    }

    for (i = 0; i < n; i++) {
        if (ngx_queue_empty(&ctx->sh->queue)) {
            return;
        }

        q = ngx_queue_last(&ctx->sh->queue);

        ibn = ngx_queue_data(q, ngx_http_ip_behavior_node_t, queue);

        if (!force) {
            ms = (ngx_msec_int_t) (now - ibn->last);
            ms = ngx_abs(ms);

            if (ms < ctx->sample_cycle) {
                /* the oldest is not expired, no need to check prev nodes */
                return;
            }
        }

        ngx_queue_remove(q);

        node = (ngx_rbtree_node_t *)
                   ((u_char *) ibn - offsetof(ngx_rbtree_node_t, color));

        ngx_rbtree_delete(&ctx->sh->rbtree, node);

        ngx_slab_free_locked(ctx->shpool, node);
    }
}


static ngx_int_t
ngx_http_ip_behavior_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_ip_behavior_ctx_t      *octx = data;
    size_t                           len;
    ngx_http_ip_behavior_ctx_t      *ctx;

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

    ctx->sh = ngx_slab_alloc(ctx->shpool, sizeof(ngx_http_ip_behavior_shctx_t));
    if (ctx->sh == NULL) {
        return NGX_ERROR;
    }

    ctx->shpool->data = ctx->sh;

    ngx_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
                    ngx_http_ip_behavior_rbtree_insert_value);

    ngx_queue_init(&ctx->sh->queue);

    len = sizeof(" in ip behavior zone \"\"") + shm_zone->shm.name.len;

    ctx->shpool->log_ctx = ngx_slab_alloc(ctx->shpool, len);
    if (ctx->shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(ctx->shpool->log_ctx, " in ip behavior zone \"%V\"%Z",
                &shm_zone->shm.name);

    return NGX_OK;
}


static void *
ngx_http_ip_behavior_create_conf(ngx_conf_t *cf)
{
    ngx_http_ip_behavior_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ip_behavior_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->shm_zone = NGX_CONF_UNSET_PTR;
    conf->enabled = NGX_CONF_UNSET;
    conf->sensitive = NGX_CONF_UNSET;
    conf->type = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_ip_behavior_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_ip_behavior_conf_t *prev = parent;
    ngx_http_ip_behavior_conf_t *conf = child;

    ngx_conf_merge_value(conf->enabled, prev->enabled, 0);
    ngx_conf_merge_value(conf->sensitive, prev->sensitive, 0);
    ngx_conf_merge_value(conf->type, prev->type, TYPE_SENSITIVE_URL);
    ngx_conf_merge_ptr_value(conf->shm_zone, prev->shm_zone, NULL);

    return NGX_CONF_OK;
}


static char *
ngx_http_ip_behavior_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    u_char                         *p;
    size_t                          len;
    ssize_t                         size;
    ngx_str_t                      *value, name, s;
    ngx_shm_zone_t                 *shm_zone;
    ngx_http_ip_behavior_ctx_t     *ctx;
    ngx_uint_t                      i;
    ngx_int_t                       sample_base;
    ngx_int_t                       sample_cycle;
    ngx_int_t                       unit;

    value = cf->args->elts;

    ctx = NULL;
    size = 0;
    name.len = 0;
    sample_base = 50;
    sample_cycle = 5;
    unit = 1;

    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {

            name.data = value[i].data + 5;

            p = (u_char *) ngx_strchr(name.data, ':');

            if (p == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "invalid zone size \"%V\"", &value[1]);
                return NGX_CONF_ERROR;
            }

            name.len = p - name.data;

            s.data = p + 1;
            s.len = value[i].data + value[i].len - s.data;

            size = ngx_parse_size(&s);

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

            continue;
        }

        if (ngx_strncmp(value[i].data, "sample_base=", 12) == 0) {

            sample_base = ngx_atoi(value[i].data + 12, value[i].len - 12);
            if (sample_base <= 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid sample_base \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "sample_cycle=", 13) == 0) {
            len = value[i].len;
            p = value[i].data + len - 1;

            if (ngx_strncmp(p, "s", 1) == 0) {
                unit = 1;
                len--;
            } else if (ngx_strncmp(p, "m", 1) == 0) {
                unit = 60;
                len--;
            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid sample_cycle unit \"%V\"",
                                   &value[i]);
                return NGX_CONF_ERROR;
            }

            sample_cycle = ngx_atoi(value[i].data + 13, len - 13);
            if (sample_cycle <= 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid sample_cycle \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            sample_cycle = sample_cycle * 1000 * unit;

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);

        return NGX_CONF_ERROR;
    }

    if (name.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "\"%V\" must have \"zone\" parameter",
                &cmd->name);
        return NGX_CONF_ERROR;
    }

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_ip_behavior_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    shm_zone = ngx_shared_memory_add(cf, &name, size,
                                     &ngx_http_ip_behavior_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (shm_zone->data) {
        ctx = shm_zone->data;

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "%V \"%V\" is duplicated",
                           &cmd->name, &name);
        return NGX_CONF_ERROR;
    }

    shm_zone->init = ngx_http_ip_behavior_init_zone;
    shm_zone->data = ctx;

    ctx->sample_base = sample_base;
    ctx->sample_cycle = sample_cycle;

    return NGX_CONF_OK;
}


static char *
ngx_http_ip_behavior(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_ip_behavior_conf_t *ilcf = conf;

    ngx_str_t                   *value, s;
    ngx_shm_zone_t              *shm_zone;
    ngx_uint_t                   i;
    ngx_int_t                    type;

    value = cf->args->elts;

    shm_zone = NULL;
    type = 0;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {
            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            shm_zone = ngx_shared_memory_add(cf, &s, 0,
                    &ngx_http_ip_behavior_module);
            if (shm_zone == NULL) {
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "type=", 5) == 0) {

            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            if (ngx_strncmp(s.data, TYPE_SENSITIVE_URL_STR,
                        strlen(TYPE_SENSITIVE_URL_STR)) == 0) {
                type |= TYPE_SENSITIVE_URL;
            } else if (ngx_strncmp(s.data, TYPE_BAD_RESPONSE_STR,
                        strlen(TYPE_BAD_RESPONSE_STR)) == 0) {
                type |= TYPE_BAD_RESPONSE;
            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "invalid type \"%V\"", &value[i]);

                return NGX_CONF_ERROR;
            }

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "invalid parameter \"%V\"", &value[i]);

        return NGX_CONF_ERROR;
    }

    if (shm_zone == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"zone\" parameter",
                           &cmd->name);
        return NGX_CONF_ERROR;
    }

    if (shm_zone->data == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "unknown ip behavior zone \"%V\"",
                           &shm_zone->shm.name);
        return NGX_CONF_ERROR;
    }

    if (type == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"type\" parameter",
                           &cmd->name);
    }

    ilcf->shm_zone = shm_zone;
    ilcf->enabled = 1;
    ilcf->type = type;

    return NGX_CONF_OK;
}


static char *
ngx_http_ip_behavior_sensitive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_ip_behavior_conf_t *ilcf = conf;

    ilcf->sensitive = 1;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_ip_behavior_init(ngx_conf_t *cf)
{
#if (NGX_HTTP_NETEYE_SECURITY)
    return ngx_http_neteye_security_request_register(
           NGX_HTTP_NETEYE_IP_BEHAVIOR, ngx_http_ip_behavior_handler);
#else
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_ip_behavior_handler;

    return NGX_OK;
#endif
}


static ngx_int_t
ngx_http_insensitive_percent_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    if (r->insensitive_percent == -1) {
        /* -1 means no sample availiable */
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ngx_pcalloc(r->pool, 4);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(v->data, "%d", r->insensitive_percent) - v->data;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_bad_response_percent_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    if (r->bad_response_percent == -1) {
        /* -1 means no sample availiable */
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ngx_pcalloc(r->pool, 4);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(v->data, "%d", r->bad_response_percent) - v->data;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_ip_behavior_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_ip_behavior_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}
