/*
 * Copyright (c) 2013 Neusoft Corperation., Ltd.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_core_module.h>
#include <ngx_connection.h>

#include <ngx_http_neteye_security.h>

#if (NGX_HTTP_BLACKLIST)
#include <ngx_http_blacklist.h>
#endif

#if (NGX_HTTP_STATUS_PAGE)
#include <ngx_http_status_page.h>
#endif

/*XXX: do not insert gap among the rank values */
static ngx_http_neteye_security_module_t ngx_http_neteye_security_modules[] = {
    {NGX_HTTP_NETEYE_WHITELIST,
        "HTTP Whitelist", NULL, NULL, NULL, 1, 0, 0, NULL},
    {NGX_HTTP_NETEYE_SESSION,
        "Session Mechanism", NULL, NULL, NULL,      4, 1, 0, NULL},
    {NGX_HTTP_NETEYE_DYNWHITELIST,
        "Dynamic White list", NULL, NULL,NULL,      3, 0, 0, NULL},
    {NGX_HTTP_NETEYE_ROBOT_MITIGATION,
        "Active/Challenge", NULL, NULL, NULL,       2, 0, 0, NULL},
    {NGX_HTTP_NETEYE_GOOGLE_RECAPTCHA,
        "Google Recaptcha", NULL, NULL, NULL,       5, 0, 0, NULL},
    {NGX_HTTP_NETEYE_LOCAL_CAPTCHA,
        "Local Captcha", NULL, NULL, NULL,          6, 0, 0, NULL},
    {NGX_HTTP_NETEYE_COOKIE_POISONING,
        "Cookie Poisoning", NULL, NULL, NULL,          7, 2, 0, NULL},
    {NGX_HTTP_NETEYE_PAGE_ACL,
        "Page Access Control", NULL, NULL, NULL,    8, 0, 0, NULL},
    {NGX_HTTP_NETEYE_NAXSI,
        "NetEye modified NAXSI", NULL, NULL, NULL,    9, 0, 0, NULL},
    {NGX_HTTP_NETEYE_WEB_DEFACEMENT,
        "Web Defacement", NULL, NULL, NULL,         10, 0, 0, NULL},
    {NGX_HTTP_NETEYE_STATUS_PAGE,
        "Status Page", NULL, NULL, NULL,            0, 3, 0, NULL},
    {NGX_HTTP_NETEYE_LOG_MODULE,
        "NetEye Log", NULL, NULL, NULL,             0, 0, 0, NULL},
};

/*According to enum ngx_http_neteye_security_attack_log_id*/
static char *
ngx_http_neteye_attack_log_str[NGX_HTTP_NETEYE_ATTACK_LOG_ID_MAX] = {
    "Layer 7 DDoS",
    "Cookie Poisoning",
    "Web Defacement",
};

/* The first slot of this array is not used */
static ngx_http_neteye_security_module_t
    *request_chain[NGX_HTTP_NETEYE_SECURITY_MODULE_MAX + 1];
static ngx_int_t max_request_chain;
static ngx_int_t nr_request_chain;

static ngx_http_neteye_security_module_t
    *ns_ctx_chain[NGX_HTTP_NETEYE_SECURITY_MODULE_MAX + 1];
static ngx_int_t nr_ns_ctx_chain;
static ngx_http_neteye_security_module_t
    *response_header_chain[NGX_HTTP_NETEYE_SECURITY_MODULE_MAX + 1];
static ngx_int_t max_response_header_chain;
static ngx_int_t nr_response_header_chain;
static ngx_http_neteye_security_module_t
    *response_body_chain[NGX_HTTP_NETEYE_SECURITY_MODULE_MAX + 1];
static ngx_int_t max_response_body_chain;
static ngx_int_t nr_response_body_chain;


static ngx_int_t ngx_http_ns_request_ctx_not_inited(ngx_http_request_t *r);
static ngx_int_t
ngx_http_neteye_security_init(ngx_conf_t *cf);
static ngx_int_t
ngx_http_neteye_security_request_handler(ngx_http_request_t *r);
ngx_int_t
ngx_http_neteye_security_header_filter(ngx_http_request_t *r);
ngx_int_t
ngx_http_neteye_security_body_filter(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_int_t
ngx_http_ns_ctx_init(ngx_http_request_t *r);
static ngx_int_t
ngx_http_ns_request_ctx_init(ngx_http_request_t *r);
static ngx_int_t
ngx_http_neteye_security_pre_init(ngx_conf_t *cf);
static ngx_http_ns_ctx_t *
ngx_http_ns_get_request_ctx(ngx_http_request_t *r);
static void *
ngx_http_ns_create_loc_conf(ngx_conf_t *cf);
static char *
ngx_http_ns_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static char *
ngx_http_ns_force(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t  ngx_http_ns_commands[] = {

    { ngx_string("ns_layer_force_run"),
        NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
        ngx_http_ns_force,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },

    ngx_null_command,
};


static ngx_http_module_t  ngx_http_neteye_security_module_ctx = {
    ngx_http_neteye_security_pre_init,     /* preconfiguration */
    ngx_http_neteye_security_init,         /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_ns_create_loc_conf,           /* create location configuration */
    ngx_http_ns_merge_loc_conf,            /* merge location configuration */
};


ngx_module_t  ngx_http_neteye_security_module = {
    NGX_MODULE_V1,
    &ngx_http_neteye_security_module_ctx,        /* module context */
    ngx_http_ns_commands,                  /* module directives */
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

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static ngx_int_t
ngx_http_neteye_security_pre_init(ngx_conf_t *cf)
{
    ngx_uint_t         i;


    /* empty all the global vars before other module call the
     * register functions. here is enough from time because
     * other module call the registers at the post-config phase
     *
     * to use global variable in ns module, not the main_conf var
     * is because thus we don't need to care about the build order
     * of the modules.
     */

    for (i = 0; i < NGX_HTTP_NETEYE_SECURITY_MODULE_MAX + 1; i++) {
        request_chain[i] = NULL;
        ns_ctx_chain[i] = NULL;
        response_header_chain[i] = NULL;
        response_body_chain[i] = NULL;
    }

    max_request_chain = 0;
    nr_request_chain = 0;

    nr_ns_ctx_chain = 0;

    max_response_header_chain = 0;
    nr_response_header_chain = 0;

    max_response_body_chain = 0;
    nr_response_body_chain = 0;


    return NGX_OK;
}

static ngx_int_t
ngx_http_neteye_security_init(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t  *cmcf;
    ngx_http_handler_pt        *h;


    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_NETEYE_SECURITY_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_neteye_security_request_handler;

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_neteye_security_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_neteye_security_body_filter;

    return NGX_OK;
}

static ngx_int_t
ngx_http_neteye_security_request_handler(ngx_http_request_t *r)
{
    ngx_int_t i = 1, ret;
    ngx_http_neteye_security_request_pt handler;
    ngx_http_neteye_security_module_t *module;
    ngx_http_ns_loc_conf_t *nlcf;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "neteye security phase begins, handler number: %d",
            nr_request_chain);

    if (ngx_http_ns_test_bypass_all(r)) {
        return NGX_DECLINED;
    }

    if (nr_request_chain == 0) {
        return NGX_DECLINED;
    }

    nlcf = ngx_http_get_module_loc_conf(r, ngx_http_neteye_security_module);

    if (r->internal && !nlcf->force) {
        return NGX_DECLINED;
    }

    if (ngx_http_ns_ctx_init(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_ns_request_ctx_not_inited(r)
            && ngx_http_ns_request_ctx_init(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    while (1) {
        module = request_chain[i];

        if (r->se_handler != NULL) {
            if (module == NULL || r->se_handler != module->request_handler) {
                i++;
                continue;
            }
            r->se_handler = NULL;
        }

        if (module && !ngx_http_ns_jump_bit_is_set(r, module->id)) {
            handler = module->request_handler;
            ret = handler(r);
        } else {
            i++;

            if (i > max_request_chain) {
                /* all handlers have been called */
                break;
            }

            continue;
        }

        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "neteye security handler: %d - %s(ret: %d)",
                module->id, module->name, ret);

        /* terminate current process in nginx */
        if (ret == NGX_DONE) {
            return NGX_DONE;
        }

        /* skip other handlers */
        if (ret == NGX_OK) {
            break;
        }

        if (ret == NGX_ERROR) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "Request denied by handler: %d - %s",
                    module->id, module->name);
            return NGX_ERROR;
        }

        if (ngx_http_ns_test_bypass_all(r)) {
            break;
        }

        /* next handler in the list */
        if (ret == NGX_DECLINED) {
            i++;

            if (i > max_request_chain) {
                /* all handlers have been called */
                break;
            }

            continue;
        }

        if (ret < 0) {
            return ret;
        }

        /* some internal error */
        if (ret >= 400) {
            return ret;
        }

        /* jump to another handler, ret is the new handler id */
        if (ret > max_request_chain) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "jump to unkown handler");

            return NGX_ERROR;
        } else {
            if (request_chain[i] == NULL) {
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                        "jump to unkown handler");

                return NGX_ERROR;
            }

            i = ret;
        }
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "neteye security phase ends without any deny action");

    return NGX_DECLINED;
}

ngx_int_t
ngx_http_neteye_security_request_register(ngx_int_t id,
        ngx_http_neteye_security_request_pt handler)
{
    ngx_int_t i, max_modules;
    ngx_http_neteye_security_module_t *module = NULL;

    if (id >= NGX_HTTP_NETEYE_SECURITY_MODULE_MAX
            || id < 0) {
        return NGX_ERROR;
    }

    if (handler == NULL) {
        return NGX_ERROR;
    }

    max_modules = sizeof(ngx_http_neteye_security_modules)
        / sizeof(ngx_http_neteye_security_module_t);

    for (i = 0; i < max_modules; i++) {
        if (ngx_http_neteye_security_modules[i].id
                == id) {
            /* found this module */
            module = &ngx_http_neteye_security_modules[i];
            if (module->request_rank == 0) {
                fprintf(stderr, "register a no rank module\n");
                return NGX_ERROR;
            }

            /* When reload, the global variable is not cleaned.
            if (module->request_handler) {
                fprintf(stderr, "duplicate module: %d - %s\n",
                        module->id, module->name);
                return NGX_ERROR;
            }
            */
        }
    }

    if (!module) {
        fprintf(stderr, "module not found: %d\n", (int)id);
        return NGX_ERROR;
    }

    module->request_handler = handler;
    request_chain[module->request_rank] = module;

    nr_request_chain++;

    if (module->request_rank > max_request_chain) {
        max_request_chain = module->request_rank;
    }

    return NGX_OK;
}

ngx_int_t
ngx_http_neteye_security_header_register(ngx_int_t id,
        ngx_http_neteye_security_response_header_pt handler)
{
    ngx_int_t i, max_modules;
    ngx_http_neteye_security_module_t *module = NULL;

    if (id >= NGX_HTTP_NETEYE_SECURITY_MODULE_MAX
            || id < 0) {
        return NGX_ERROR;
    }

    if (handler == NULL) {
        return NGX_ERROR;
    }

    max_modules = sizeof(ngx_http_neteye_security_modules)
        / sizeof(ngx_http_neteye_security_module_t);

    for (i = 0; i < max_modules; i++) {
        if (ngx_http_neteye_security_modules[i].id
                == id) {
            /* found this module */
            module = &ngx_http_neteye_security_modules[i];
            if (module->response_header_rank == 0) {
                fprintf(stderr, "register a no rank module\n");
                return NGX_ERROR;
            }

            /* When reload, the global variable is not cleaned.
            if (module->response_header_handler) {
                fprintf(stderr, "duplicate module: %d - %s\n",
                        module->id, module->name);
                return NGX_ERROR;
            }
            */
        }
    }

    if (!module) {
        fprintf(stderr, "module not found: %d\n", (int)id);
        return NGX_ERROR;
    }

    module->response_header_handler = handler;
    response_header_chain[module->response_header_rank] = module;

    nr_response_header_chain++;

    if (module->response_header_rank > max_response_header_chain) {
        max_response_header_chain = module->response_header_rank;
    }

    return NGX_OK;
}

ngx_int_t
ngx_http_neteye_security_body_register(ngx_int_t id,
        ngx_http_neteye_security_response_body_pt handler)
{
    ngx_int_t i, max_modules;
    ngx_http_neteye_security_module_t *module = NULL;

    if (id >= NGX_HTTP_NETEYE_SECURITY_MODULE_MAX
            || id < 0) {
        return NGX_ERROR;
    }

    if (handler == NULL) {
        return NGX_ERROR;
    }

    max_modules = sizeof(ngx_http_neteye_security_modules)
        / sizeof(ngx_http_neteye_security_module_t);

    for (i = 0; i < max_modules; i++) {
        if (ngx_http_neteye_security_modules[i].id
                == id) {
            /* found this module */
            module = &ngx_http_neteye_security_modules[i];
            if (module->response_body_rank == 0) {
                fprintf(stderr, "register a no rank module\n");
                return NGX_ERROR;
            }

            /* When reload, the global variable is not cleaned.
            if (module->response_header_handler) {
                fprintf(stderr, "duplicate module: %d - %s\n",
                        module->id, module->name);
                return NGX_ERROR;
            }
            */
        }
    }

    if (!module) {
        fprintf(stderr, "module not found: %d\n", (int)id);
        return NGX_ERROR;
    }

    module->response_body_handler = handler;
    response_body_chain[module->response_body_rank] = module;

    nr_response_body_chain++;

    if (module->response_body_rank > max_response_body_chain) {
        max_response_body_chain = module->response_body_rank;
    }

    return NGX_OK;
}

ngx_int_t ngx_http_neteye_security_header_filter(ngx_http_request_t *r)
{
    ngx_int_t i = 1, ret;
    ngx_http_neteye_security_response_header_pt handler;
    ngx_http_neteye_security_module_t *module;
    ngx_http_ns_ctx_t           *ctx;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "neteye security response header begins, handler number: %d",
            nr_response_header_chain);

    if (ngx_http_ns_test_bypass_all(r)) {
        return ngx_http_next_header_filter(r);
    }

    if (nr_response_header_chain == 0) {
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_http_ns_get_request_ctx(r);
    if (ctx == NULL) {
        return ngx_http_next_header_filter(r);
    }

    while (1) {
        module = response_header_chain[i];

        if (module
                && !ngx_http_ns_jump_bit_is_set(r, module->id)) {
            handler = module->response_header_handler;
            ret = handler(r);
        } else {
            i++;

            if (i > max_response_header_chain) {
                /* all handlers have been called */
                break;
            }

            continue;
        }

        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "neteye security response header: %d - %s(ret: %d)",
                module->id, module->name, ret);

        /* terminate current process in nginx */
        if (ret == NGX_DONE) {
            return NGX_DONE;
        }

        /* skip other handlers */
        if (ret == NGX_OK) {
            break;
        }

        if (ret == NGX_ERROR) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "Request denied by handler: %d - %s",
                    module->id, module->name);
            return NGX_ERROR;
        }

        /* some internal error */
        if (ret >= 400) {
            return ret;
        }

        if (ngx_http_ns_test_bypass_all(r)) {
            break;
        }

        /* next handler in the list */
        if (ret == NGX_DECLINED) {
            i++;

            if (i > max_response_header_chain) {
                /* all handlers have been called */
                break;
            }

            continue;
        }

        /* jump to another handler, ret is the new handler id */
        if (ret > max_response_header_chain
                || ret < 0) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "jump to unkown handler");

            return NGX_ERROR;
        } else {
            if (response_header_chain[i] == NULL) {
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                        "jump to unkown handler");

                return NGX_ERROR;
            }

            i = ret;
        }
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "neteye security response header ends without any deny action");

    return ngx_http_next_header_filter(r);
}

ngx_int_t ngx_http_neteye_security_body_filter(ngx_http_request_t *r,
        ngx_chain_t *in)
{
    ngx_int_t i = 1, ret;
    ngx_http_neteye_security_response_body_pt handler;
    ngx_http_neteye_security_module_t *module;
    ngx_http_ns_ctx_t           *ctx;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "neteye security response body begins, handler number: %d",
            nr_response_body_chain);

    if (ngx_http_ns_test_bypass_all(r)) {
        return ngx_http_next_body_filter(r, in);
    }

    if (nr_response_body_chain == 0) {
        return ngx_http_next_body_filter(r, in);
    }

    ctx = ngx_http_ns_get_request_ctx(r);
    if (ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    while (1) {
        module = response_body_chain[i];

        if (module
                && !ngx_http_ns_jump_bit_is_set(r, module->id)) {
            handler = module->response_body_handler;
            ret = handler(r, in);
        } else {
            i++;

            if (i > max_response_body_chain) {
                /* all handlers have been called */
                break;
            }

            continue;
        }

        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "neteye security response body: %d - %s(ret: %d)",
                module->id, module->name, ret);

        /* terminate current process in nginx */
        if (ret == NGX_DONE) {
            return NGX_DONE;
        }

        /* skip other handlers */
        if (ret == NGX_OK) {
            break;
        }

        if (ret == NGX_ERROR) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "Request denied by handler: %d - %s",
                    module->id, module->name);
            return NGX_ERROR;
        }

        /* some internal error */
        if (ret >= 400) {
            return ret;
        }

        if (ngx_http_ns_test_bypass_all(r)) {
            break;
        }

        /* next handler in the list */
        if (ret == NGX_DECLINED) {
            i++;

            if (i > max_response_body_chain) {
                /* all handlers have been called */
                break;
            }

            continue;
        }

        /* jump to another handler, ret is the new handler id */
        if (ret > max_response_body_chain || ret < 0) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "jump to unkown handler");

            return NGX_ERROR;
        } else {
            if (response_body_chain[i] == NULL) {
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                        "jump to unkown handler");

                return NGX_ERROR;
            }

            i = ret;
        }
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "neteye security response body ends without any deny action");

    return ngx_http_next_body_filter(r, in);
}

ngx_int_t
ngx_http_neteye_security_ctx_register(ngx_int_t id,
        ngx_http_neteye_security_ctx_pt handler)
{
    ngx_int_t i, max_modules;
    ngx_http_neteye_security_module_t *module = NULL;


    if (id >= NGX_HTTP_NETEYE_SECURITY_MODULE_MAX
            || id < 0) {
        return NGX_ERROR;
    }

    if (handler == NULL) {
        return NGX_ERROR;
    }

    max_modules = sizeof(ngx_http_neteye_security_modules)
        / sizeof(ngx_http_neteye_security_module_t);

    for (i = 0; i < max_modules; i++) {
        if (ngx_http_neteye_security_modules[i].id
                == id) {
            /* found this module */
            module = &ngx_http_neteye_security_modules[i];

            break;
        }
    }

    if (!module) {
        fprintf(stderr, "module not found: %d\n", (int)id);
        return NGX_ERROR;
    }

    module->init_ns_ctx = handler;
    ns_ctx_chain[nr_ns_ctx_chain] = module;

    nr_ns_ctx_chain++;

    return NGX_OK;
}

static ngx_int_t
ngx_http_ns_request_ctx_not_inited(ngx_http_request_t *r)
{
    ngx_http_ns_ctx_t                   *ctx;

    ctx = ngx_http_ns_get_request_ctx(r);
    if (ctx == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "get ns ctx failed");
    }

    return (ctx->ns_ctx_initialed != 1);
}

static ngx_int_t
ngx_http_ns_request_ctx_init(ngx_http_request_t *r)
{
    ngx_int_t                          i, ret;
    ngx_http_neteye_security_module_t *module = NULL;
    ngx_http_ns_ctx_t                   *ctx;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "neteye security request ctx init number: %d", nr_ns_ctx_chain);

    for (i = 0; i < nr_ns_ctx_chain; i++) {
        module = ns_ctx_chain[i];
        if (module) {
            ret = module->init_ns_ctx(r);
            if (ret != NGX_OK) {
                return NGX_ERROR;
            }

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "module %s inited", module->name);
        }
    }

    ctx = ngx_http_ns_get_request_ctx(r);
    if (ctx == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "get ns ctx failed");
    }

    ctx->ns_ctx_initialed = 1;

    return NGX_OK;
}

static ngx_int_t
ngx_http_ns_ctx_init(ngx_http_request_t *r)
{
    ngx_http_ns_ctx_t           *ctx;

    ctx = ngx_http_ns_get_request_ctx(r);
    if (ctx != NULL) {
        return NGX_OK;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_ns_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_http_ns_set_ctx(r, ctx, ngx_http_neteye_security_module);

    return NGX_OK;
}


/**
 *  General action handler
 *
 *  ret: NGX_OK to continue
 *  others to stop
 */
ngx_int_t
ngx_http_ns_do_action(ngx_http_request_t *r,
        ngx_http_ns_action_t *action)
{
    ngx_uint_t                         i;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "neteye security do action: %d", (int)action->action);

    switch (action->action) {
        case NGX_HTTP_NS_ACTION_PASS:
        case NGX_HTTP_NS_ACTION_RECHALLENGE:
            /* do nothing */
            return NGX_OK;
        case NGX_HTTP_NS_ACTION_BLOCK:
#if (NGX_HTTP_STATUS_PAGE)
            if (action->has_redirect) {
                ngx_http_status_page_send_page(r, action->redirect_page,
                        action->in_body, NGX_HTTP_FORBIDDEN);
            }
#endif
            return NGX_ERROR;
        case NGX_HTTP_NS_ACTION_REMOVE_COOKIE:
            for (i = 0; i < action->cookie->len; i++) {
                action->cookie->data[i] = ' ';
            }

            return NGX_OK;
    }

    return NGX_OK;
}

static ngx_http_ns_ctx_t *
ngx_http_ns_get_request_ctx(ngx_http_request_t *r)
{
    ngx_http_ns_ctx_t       *ctx;

    ctx = ngx_http_ns_get_module_ctx(r, ngx_http_neteye_security_module);

    return ctx;
}

void
ngx_http_ns_jump_bit_set(ngx_http_request_t *r, ngx_uint_t mod)
{
    ngx_http_ns_ctx_t           *ctx;

    ctx = ngx_http_ns_get_request_ctx(r);

    ctx->jump_bit |= (1 << mod);
}

void
ngx_http_ns_jump_bit_clr(ngx_http_request_t *r, ngx_uint_t mod)
{
    ngx_http_ns_ctx_t           *ctx;

    ctx = ngx_http_ns_get_request_ctx(r);

    ctx->jump_bit &= ~(1 << mod);
}

void
ngx_http_ns_jump_bit_clr_all(ngx_http_request_t *r)
{
    ngx_http_ns_ctx_t           *ctx;

    ctx = ngx_http_ns_get_request_ctx(r);

    ctx->jump_bit = 0;
}

void
ngx_http_ns_jump_bit_set_all(ngx_http_request_t *r)
{
    ngx_http_ns_ctx_t           *ctx;

    ctx = ngx_http_ns_get_request_ctx(r);

    ctx->jump_bit = (ngx_uint_t)-1;
}

ngx_uint_t
ngx_http_ns_jump_bit_is_set(ngx_http_request_t *r, ngx_uint_t mod)
{
    ngx_http_ns_ctx_t           *ctx;

    ctx = ngx_http_ns_get_request_ctx(r);

    return ((ctx->jump_bit & (1 << mod)) ? 1 : 0);
}

ngx_uint_t
ngx_http_ns_jump_bit_is_set_any(ngx_http_request_t *r)
{
    ngx_http_ns_ctx_t           *ctx;

    ctx = ngx_http_ns_get_request_ctx(r);

    return ((ctx->jump_bit != 0) ? 1 : 0);
}

void ngx_http_ns_set_bypass_all(ngx_http_request_t *r)
{
    ngx_http_ns_ctx_t       *ctx;

    ctx = ngx_http_ns_get_request_ctx(r);
    if (ctx == NULL)
        return;

    ctx->all_security_bypass = 1;
}

void ngx_http_ns_clr_bypass_all(ngx_http_request_t *r)
{
    ngx_http_ns_ctx_t       *ctx;

    ctx = ngx_http_ns_get_request_ctx(r);
    if (ctx == NULL)
        return;

    ctx->all_security_bypass = 0;
}

ngx_uint_t
ngx_http_ns_test_bypass_all(ngx_http_request_t *r)
{
    ngx_http_ns_ctx_t       *ctx;

    ctx = ngx_http_ns_get_request_ctx(r);
    if (ctx == NULL)
        return 0;

    return ctx->all_security_bypass;
}

char *
ngx_http_ns_get_action_str(ngx_int_t action)
{
    switch (action) {
        case NGX_HTTP_NS_ACTION_PASS:
            return "Pass";
        case NGX_HTTP_NS_ACTION_BLOCK:
            return "Block";
        case NGX_HTTP_NS_ACTION_BLACKLIST:
            return "Blacklist";
        case NGX_HTTP_NS_ACTION_REMOVE_COOKIE:
            return "Remove Cookie";
        default:
            return NULL;
    }
}

void ngx_http_neteye_send_attack_log(ngx_http_request_t *r, ngx_uint_t log_id,
        ngx_str_t action, char *module_name, char *string)
{
    char                           *agent = NULL;
    char                           *do_action = "running ";
    ngx_connection_t                *connection;
    ngx_log_t                       *log;

    connection = r->connection;
    if (log_id >= NGX_HTTP_NETEYE_ATTACK_LOG_ID_MAX) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, connection->log, 0,
                "log id is invalid!\n");
        return;
    }

    if (r->headers_in.user_agent != NULL) {
        agent = ngx_pcalloc(r->pool,
                r->headers_in.user_agent->value.len + 1);
        if (!agent) {
            return;
        }

        memcpy(agent, r->headers_in.user_agent->value.data,
                r->headers_in.user_agent->value.len);
    } else {
        agent = "n/a";
    }

    log = connection->log;
    log->action = ngx_pcalloc(r->pool, ngx_strlen(do_action) +
            ngx_strlen(module_name) + 1);
    if (log->action == NULL) {
        return;
    }
    strcpy(log->action, do_action);
    strcpy(log->action + ngx_strlen(do_action), module_name);

    string = (string == NULL) ? " " : string;

    ngx_log_error(NGX_LOG_ERR, connection->log, 0,
            "%s: \"%s\", action: \"%V\", agent: \"%s\", %s, ",
            module_name, ngx_http_neteye_attack_log_str[log_id],
            &action, agent, string);

    return;
}

static void *
ngx_http_ns_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_ns_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ns_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}

static char *
ngx_http_ns_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    return NGX_CONF_OK;
}

static char *
ngx_http_ns_force(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_ns_loc_conf_t *nlcf = conf;

    nlcf->force = 1;

    return NGX_CONF_OK;
}
