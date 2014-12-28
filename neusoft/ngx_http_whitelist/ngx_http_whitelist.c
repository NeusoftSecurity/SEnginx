/**
 * ngx_http_whitelist.c
 *
 * by Paul Yang <y_y@neusoft.com>
 *
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_core_module.h>

#include <ngx_http_whitelist.h>


static ngx_rbtree_t                 ngx_http_wl_dns_rbtree;
static ngx_rbtree_node_t            ngx_http_wl_dns_sentinel;
static ngx_log_t                    ngx_http_wl_timer_log;


#if (NGX_HTTP_NETEYE_SECURITY)
#include <ngx_http_neteye_security.h>
#else
#error "must compile with neteye security module"
#endif

static ngx_int_t
ngx_http_wl_handler(ngx_http_request_t *r);
static char *
ngx_http_wl_ua(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t
ngx_http_wl_init(ngx_conf_t *cf);
static void *
ngx_http_wl_create_main_conf(ngx_conf_t *cf);
static char *
ngx_http_wl_init_main_conf(ngx_conf_t *cf, void *conf);


static ngx_command_t ngx_http_wl_commands[] = {

    { ngx_string("whitelist_ua"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
      ngx_http_wl_ua,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command,
};


static ngx_http_module_t ngx_http_wl_module_ctx = {
    NULL,                                 /* preconfiguration */
    ngx_http_wl_init,                     /* postconfiguration */

    ngx_http_wl_create_main_conf,         /* create main configuration */
    ngx_http_wl_init_main_conf,           /* init main configuration */

    NULL,                                 /* create server configuration */
    NULL,                                 /* merge server configuration */

    NULL,                                 /* create location configuration */
    NULL                                  /* merge location configuration */
};


ngx_module_t ngx_http_whitelist_module = {
    NGX_MODULE_V1,
    &ngx_http_wl_module_ctx,               /* module context */
    ngx_http_wl_commands,                  /* module directives */
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


static void
ngx_http_wl_dns_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t       **p;
    ngx_http_wl_dns_t       *rd, *rd_temp;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            rd = (ngx_http_wl_dns_t *) node;
            rd_temp = (ngx_http_wl_dns_t *) temp;

            p = (ngx_memn2cmp(rd->addr, rd_temp->addr, rd->len, rd_temp->len)
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
ngx_http_wl_init(ngx_conf_t *cf)
{
    ngx_http_wl_timer_log.file = ngx_palloc(cf->pool, sizeof(ngx_open_file_t));
    if (ngx_http_wl_timer_log.file == NULL) {
        return NGX_ERROR;
    }

    ngx_http_wl_timer_log.file->fd = NGX_INVALID_FILE;

    ngx_rbtree_init(&ngx_http_wl_dns_rbtree, &ngx_http_wl_dns_sentinel,
                    ngx_http_wl_dns_rbtree_insert_value);

    return ngx_http_neteye_security_request_register(
            NGX_HTTP_NETEYE_WHITELIST, ngx_http_wl_handler);
}

static ngx_int_t
ngx_http_wl_pattern_parse(ngx_conf_t *cf, ngx_http_regex_t **regex,
    ngx_str_t *pattern, ngx_http_wl_list_t *list)
{
#if (NGX_PCRE)
    ngx_regex_compile_t  rc;
    u_char               errstr[NGX_MAX_CONF_ERRSTR];

    ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

    rc.pattern = *pattern;
    rc.err.len = NGX_MAX_CONF_ERRSTR;
    rc.err.data = errstr;

#if (NGX_HAVE_CASELESS_FILESYSTEM)
    rc.options = NGX_REGEX_CASELESS;
#else
    if (list->caseless) {
        rc.options = NGX_REGEX_CASELESS;
    } else {
        rc.options = 0;
    }
#endif

    *regex = ngx_http_regex_compile(cf, &rc);
    if (*regex == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;

#else

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "using regex \"%V\" requires PCRE library",
                       pattern);
    return NGX_ERROR;

#endif
}

static char *
ngx_http_wl_list_parse(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
{
    ngx_str_t                       *pattern, *domain_name, *value;
    ngx_http_wl_item_t              *item;
    ngx_http_wl_list_t              *list = conf;
    ngx_int_t                        ret;

    value = cf->args->elts;

    if (ngx_strcmp(value[0].data, "include") == 0) {
        if (cf->args->nelts != 2) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid number of arguments"
                               " in \"include\" directive");
            return NGX_CONF_ERROR;
        }

        return ngx_conf_include(cf, dummy, conf);
    }

    if (cf->args->nelts == 1
            && (ngx_strcmp(value[0].data, "caseless") == 0)) {

        list->caseless = 1;

        return NGX_CONF_OK;
    }

    pattern = ngx_palloc(cf->pool, sizeof(ngx_str_t));
    if (pattern == NULL) {
        return NGX_CONF_ERROR;
    }

    *pattern = value[0];

    ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0,
            "http whitelist: ua pattern is \"%V\"", pattern);

    if (list->items == NULL) {
        list->items =
            ngx_array_create(cf->pool, 64, sizeof(ngx_http_wl_item_t));

        if (list->items == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    item = ngx_array_push(list->items);
    if (item == NULL) {
        return NGX_CONF_ERROR;
    }

    memset(item, 0, sizeof(ngx_http_wl_item_t));

    ret = ngx_http_wl_pattern_parse(cf, &item->regex, pattern, list);
    if (ret != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (cf->args->nelts == 2) {
        domain_name = ngx_palloc(cf->pool, sizeof(ngx_str_t));
        if (domain_name == NULL) {
            return NGX_CONF_ERROR;
        }

        *domain_name = value[1];

        ret = ngx_http_wl_pattern_parse(cf, &item->domain_name,
                domain_name, list);
        if (ret != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        item->domain_enable = 1;
        ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0,
                "http whitelist: "
                "domain pattern is \"%V\"", domain_name);
    } else {
        item->domain_name = NULL;
    }

    ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0,
            "http whitelist: "
            "regex pattern is \"%p\"", item->regex);

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_wl_dummy_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    /* in case of no user-agent request */
    v->not_found = 1;

    return NGX_OK;
};

static char *
ngx_http_wl_ua(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_wl_main_conf_t *wmcf = conf;
    ngx_http_wl_list_t      *list;
    ngx_str_t                name, *value;
    ngx_http_variable_t     *var;
    char                    *rv;
    ngx_conf_t               save;


    value = cf->args->elts;

    if (wmcf->whitelists == NULL) {
        wmcf->whitelists =
            ngx_array_create(cf->pool, 8, sizeof(ngx_http_wl_list_t));

        if (wmcf->whitelists == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    list = ngx_array_push(wmcf->whitelists);
    if (list == NULL) {
        return NGX_CONF_ERROR;
    }

    memset(list, 0, sizeof(ngx_http_wl_list_t));

    name = value[1];

    if (name.data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &name);
        return NGX_CONF_ERROR;
    }

    name.len--;
    name.data++;

    var = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_CHANGEABLE);
    if (var == NULL) {
        return NGX_CONF_ERROR;
    }

    var->flags |= NGX_HTTP_VAR_INDEXED;
    var->get_handler = ngx_http_wl_dummy_variable;

    list->name = name;
    list->var_index = ngx_http_get_variable_index(cf, &name);

    save = *cf;
    cf->handler = ngx_http_wl_list_parse;
    cf->handler_conf = (void *)list;

    rv = ngx_conf_parse(cf, NULL);

    *cf = save;

    return rv;
}

static void *
ngx_http_wl_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_wl_main_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_wl_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}

static char *
ngx_http_wl_init_main_conf(ngx_conf_t *cf, void *conf)
{
    return NGX_CONF_OK;
}

static ngx_http_wl_dns_t *
ngx_http_wl_dns_lookup(ngx_rbtree_t *tree, ngx_str_t *addr, uint32_t hash)
{
    ngx_int_t                   rc;
    ngx_rbtree_node_t           *node, *sentinel;
    ngx_http_wl_dns_t           *rn;

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

        rn = (ngx_http_wl_dns_t *) node;

        rc = ngx_memn2cmp(addr->data, rn->addr, addr->len, rn->len);

        if (rc == 0) {
            return rn;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    /* not found */

    return NULL;
}

static void
ngx_http_wl_dns_timeout_handler(ngx_event_t *event)
{
    ngx_http_wl_dns_t               *node;

    node = event->data;

    ngx_rbtree_delete(&ngx_http_wl_dns_rbtree, &node->node);

    free(node->name.data);
    free(node);
}

static void
ngx_http_wl_resolve_addr_handler(ngx_resolver_ctx_t *ctx)
{
    ngx_http_request_t              *r;
    ngx_http_wl_dns_t               *node;
    uint32_t                         hash;


    r = ctx->data;
    r->phase_handler = NGX_HTTP_NETEYE_SECURITY_PHASE;
    r->se_handler = ngx_http_wl_handler;

    hash = ngx_crc32_short(r->connection->addr_text.data,
            r->connection->addr_text.len);
    node = ngx_http_wl_dns_lookup(&ngx_http_wl_dns_rbtree,
            &r->connection->addr_text, hash);

    if (node == NULL) {
        node = calloc(1, sizeof(*node));
        if (node == NULL) {
            goto no_memory;
        }

        if (ctx->name.len > 0) {
            node->name.data = calloc(1, ctx->name.len);
            if (node->name.data == NULL) {
                free(node);
                goto no_memory;
            }

            memcpy(node->name.data, ctx->name.data, ctx->name.len);

        }
        node->name.len = ctx->name.len;

        memcpy(node->addr, r->connection->addr_text.data,
                r->connection->addr_text.len);
        node->len = r->connection->addr_text.len;
        node->timeout_ev.handler = ngx_http_wl_dns_timeout_handler;
        node->timeout_ev.data = node;
        node->timeout_ev.timer_set = 0;
        node->timeout_ev.log = &ngx_http_wl_timer_log;
        ngx_add_timer(&node->timeout_ev, NGX_HTTP_WL_ADDR_TIMEOUT);

        node->node.key = hash;
        ngx_rbtree_insert(&ngx_http_wl_dns_rbtree, &node->node);
    }

    ngx_resolve_addr_done(ctx);
    r->wl_resolve_ctx = NULL;
    ngx_http_core_run_phases(r);

    return;

no_memory:
    ngx_resolve_addr_done(ctx);
    r->wl_resolve_ctx = NULL;
    ngx_http_finalize_request(r, NGX_ERROR);
}

static void
ngx_http_wl_cleanup(void *data)
{
    ngx_http_request_t *r = data;

    if (r->wl_resolve_ctx) {
        ngx_resolve_addr_done(r->wl_resolve_ctx);
        r->wl_resolve_ctx = NULL;
    }
}


static ngx_int_t
ngx_http_wl_match_item(ngx_http_request_t *r, ngx_http_wl_list_t *list)
{
    ngx_http_wl_item_t           *item;
    ngx_str_t                     user_agent;
    ngx_str_t                    *domain_name = NULL;
    ngx_uint_t                    i;
    ngx_int_t                     ret;
    ngx_http_wl_dns_t            *node;
    uint32_t                      hash;
    ngx_resolver_ctx_t           *rctx;
    ngx_http_core_loc_conf_t     *clcf;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

#if (NGX_PCRE)
    if (list->items) {
        user_agent = r->headers_in.user_agent->value;
        item = list->items->elts;

        for (i = 0; i < list->items->nelts; i++) {
            ret = ngx_http_regex_exec(r, item[i].regex, &user_agent);

            if (ret == NGX_OK) {
                /* match */
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                        "http whitelist match item: %V",
                        &user_agent);

                if (item[i].domain_name) {
                    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                        "d name = %p", domain_name);

                    if (domain_name == NULL) {
                        hash = ngx_crc32_short(r->connection->addr_text.data,
                                r->connection->addr_text.len);

                        node = ngx_http_wl_dns_lookup(&ngx_http_wl_dns_rbtree,
                                &r->connection->addr_text, hash);

                        if (node) {
                            ngx_log_debug0(NGX_LOG_DEBUG_HTTP,
                                    r->connection->log, 0,
                                    "found node");

                            if (node->name.len == 0) {
                                ngx_log_debug0(NGX_LOG_DEBUG_HTTP,
                                        r->connection->log, 0,
                                        "found node, but no name");

                                continue;
                            }

                            domain_name = &node->name;
                        }
                    }

                    if (domain_name) {
                        ret = ngx_http_regex_exec(r, item[i].domain_name,
                                domain_name);
                        if (ret == NGX_OK) {
                            ngx_log_debug0(NGX_LOG_DEBUG_HTTP,
                                    r->connection->log, 0,
                                    "domain name matched");

                            return NGX_OK;
                        }

                        if (ret == NGX_ERROR) {
                            return NGX_ERROR;
                        }

                        /* not matched with domain name */
                        ngx_log_debug0(NGX_LOG_DEBUG_HTTP,
                                r->connection->log, 0,
                                "domain name not matched");

                        continue;
                    }

                    ngx_log_debug0(NGX_LOG_DEBUG_HTTP,
                            r->connection->log, 0,
                            "no record in rbtree, query dns server");

                    rctx = ngx_resolve_start(clcf->resolver, NULL);
                    if (rctx == NULL) {
                        return NGX_ERROR;
                    }

                    if (rctx == NGX_NO_RESOLVER) {
                        return NGX_DECLINED;
                    }

                    rctx->addr.sockaddr = r->connection->sockaddr;
                    rctx->addr.socklen = r->connection->socklen;
                    rctx->handler = ngx_http_wl_resolve_addr_handler;
                    rctx->data = r;
                    rctx->timeout = clcf->resolver_timeout;

                    r->wl_resolve_ctx = rctx;

                    ret = ngx_resolve_addr(rctx);
                    if (ret == NGX_ERROR) {
                        r->wl_resolve_ctx = NULL;
                        return NGX_ERROR;
                    }

                    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                            "wait for dns query response");

                    /* Stop request and waiting for the DNS response */
                    return NGX_DONE;
                }

                return NGX_OK;
            }

            if (ret == NGX_ERROR) {
                return NGX_ERROR;
            }

            /* NGX_DECLINED means not macth, we continue search */
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "http whitelist does not match item: %V",
                    &user_agent);
        }
    }
#else
#error "must compile with PCRE"
#endif

    /* nothing is found is this list, go to next list if any */
    return NGX_DECLINED;
}

static ngx_int_t
ngx_http_wl_handler(ngx_http_request_t *r)
{
    ngx_http_wl_list_t           *list;
    ngx_http_wl_main_conf_t      *wmcf;
    ngx_uint_t                    i;
    ngx_int_t                     ret;
    ngx_http_cleanup_t           *cln;
    ngx_http_variable_value_t    *vv;


    wmcf = ngx_http_get_module_main_conf(r, ngx_http_whitelist_module);

    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }

    cln->handler = ngx_http_wl_cleanup;
    cln->data = r;

#if (NGX_PCRE)
    if (r->headers_in.user_agent != NULL && wmcf->whitelists) {
        list = wmcf->whitelists->elts;

        for (i = 0; i < wmcf->whitelists->nelts; i++) {
            vv = &r->variables[list[i].var_index];
            vv->no_cacheable = 0;

            ret = ngx_http_wl_match_item(r, &list[i]);

            if (ret == NGX_OK) {
                /* match */
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                        "http whitelist match: %V", &list[i].name);

                vv->not_found = 0;
                vv->valid = 1;
                vv->data = (u_char *)"1";
                vv->len = 1;

                continue;
            }

            if (ret == NGX_ERROR) {
                return NGX_ERROR;
            }

            if (ret == NGX_DONE) {
                /* waiting for DNS lookup */
                return NGX_DONE;
            }

            /* NGX_DECLINED means not macth, check next list */
            vv->not_found = 1;
            vv->valid = 0;
        }
    }
#else
#error "must compile with PCRE"
#endif

    return NGX_DECLINED;
}

ngx_int_t
ngx_http_wl_check_whitelist(ngx_http_request_t *r,
    ngx_http_wl_variables_t *wl_vars)
{
    ngx_http_variable_value_t    *vv;

    /* check ua whitelist */
    if (wl_vars->ua_var_index != NGX_CONF_UNSET) {
        vv = ngx_http_get_indexed_variable(r, wl_vars->ua_var_index);
        if (vv && vv->valid) {
            return NGX_OK;
        }
    }

    /* check ip whitelist */
    if (wl_vars->ip_var_index != NGX_CONF_UNSET) {
        vv = ngx_http_get_indexed_variable(r, wl_vars->ip_var_index);

        if (vv == NULL || vv->not_found) {
            return NGX_DECLINED;
        }

        if ((vv->len == wl_vars->ip_var_value.len)
             && (ngx_memcmp(vv->data, wl_vars->ip_var_value.data, vv->len)
                 == 0))
        {
            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}

char *
ngx_http_wl_parse_vars(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf, ngx_http_wl_variables_t *wl_vars)
{
    ngx_str_t              *value, s;
    ngx_uint_t              i;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_strncmp(value[i].data, "ip_var_name=", 12) == 0) {

            s.len = value[i].len - 12;
            s.data = value[i].data + 12;

            wl_vars->ip_var_name = s;

            wl_vars->ip_var_index = ngx_http_get_variable_index(cf,
                &wl_vars->ip_var_name);

            if (wl_vars->ip_var_index == NGX_ERROR) {
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "ip_var_value=", 13) == 0) {

            s.len = value[i].len - 13;
            s.data = value[i].data + 13;

            wl_vars->ip_var_value = s;

            continue;
        }

        if (ngx_strncmp(value[i].data, "ua_var_name=", 12) == 0) {

            s.len = value[i].len - 12;
            s.data = value[i].data + 12;

            wl_vars->ua_var_name = s;

            wl_vars->ua_var_index = ngx_http_get_variable_index(cf,
                &wl_vars->ua_var_name);

            if (wl_vars->ua_var_index == NGX_ERROR) {
                return NGX_CONF_ERROR;
            }

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

void ngx_http_wl_init_vars(ngx_http_wl_variables_t *wl_vars)
{
    wl_vars->ip_var_index = NGX_CONF_UNSET;
    wl_vars->ua_var_index = NGX_CONF_UNSET;
}

char *
ngx_http_wl_merge_vars(ngx_http_wl_variables_t *prev,
        ngx_http_wl_variables_t *conf)
{
    ngx_conf_merge_value(conf->ua_var_index, prev->ua_var_index,
                         NGX_CONF_UNSET);

    ngx_conf_merge_value(conf->ip_var_index, prev->ip_var_index,
                         NGX_CONF_UNSET);

    ngx_conf_merge_str_value(conf->ip_var_value, prev->ip_var_value,
                             "");

    return NGX_CONF_OK;
}
