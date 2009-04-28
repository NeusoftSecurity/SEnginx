
/*
 * Copyright (C) 2009 Valery Kholodkov
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    ngx_int_t                   variable_index;
    ngx_str_t                   eval_location;
    unsigned int                enabled;
} ngx_http_eval_loc_conf_t;

typedef struct {
    ngx_http_variable_value_t  *value;
    unsigned int                done;
} ngx_http_eval_ctx_t;

static ngx_int_t ngx_http_eval_set_variable(ngx_http_request_t *r, void *data, ngx_int_t rc);

static void *ngx_http_eval_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_eval_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);

static char *ngx_http_eval_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_eval_init(ngx_conf_t *cf);

static ngx_command_t  ngx_http_eval_commands[] = {

    { ngx_string("eval"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1|NGX_CONF_BLOCK,
      ngx_http_eval_block,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};

static ngx_http_module_t  ngx_http_eval_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_eval_init,                    /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_eval_create_loc_conf,  /* create location configuration */
    ngx_http_eval_merge_loc_conf    /* merge location configuration */
};

ngx_module_t  ngx_http_eval_module = {
    NGX_MODULE_V1,
    &ngx_http_eval_module_ctx,      /* module context */
    ngx_http_eval_commands,         /* module directives */
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
ngx_http_eval_handler(ngx_http_request_t *r)
{
    ngx_str_t                   args; 
    ngx_uint_t                  flags;
    ngx_http_eval_loc_conf_t   *ecf;
    ngx_http_eval_ctx_t        *ctx;
    ngx_http_request_t         *sr; 
    ngx_int_t                   rc;
    ngx_http_post_subrequest_t *psr;

    ecf = ngx_http_get_module_loc_conf(r, ngx_http_eval_module);

    if(!ecf->enabled) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_eval_module);

    if(ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_eval_ctx_t));
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_http_set_ctx(r, ctx, ngx_http_eval_module);
    }

    if(ctx->done) {
        return NGX_DECLINED;
    }

    psr = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (psr == NULL) {
        return NGX_ERROR;
    }

    ctx->value = r->variables + ecf->variable_index;

    args.len = 0;
    args.data = NULL;
    flags = 0;

    if (ngx_http_parse_unsafe_uri(r, &ecf->eval_location, &args, &flags) != NGX_OK) {
        return NGX_ERROR;
    }

    psr->handler = ngx_http_eval_set_variable;
    psr->data = ctx;

    flags |= NGX_HTTP_SUBREQUEST_IN_MEMORY|NGX_HTTP_SUBREQUEST_WAITED;

    rc = ngx_http_subrequest(r, &ecf->eval_location, &args, &sr, psr, flags);

    if (rc == NGX_ERROR || rc == NGX_DONE) {
        return rc;
    } 

    /*
     * Wait for subrequest to complete
     */
    return NGX_AGAIN;
}

static ngx_int_t
ngx_http_eval_set_variable(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    ngx_http_eval_ctx_t  *ctx = data;

    ctx->value->valid = 0;
    ctx->value->not_found = 1;

    if (r->upstream) {
        ctx->value->len = r->upstream->buffer.last - r->upstream->buffer.pos;
        ctx->value->data = r->upstream->buffer.pos;
        ctx->value->valid = 1;
        ctx->value->not_found = 0;
    }

    ctx->done = 1;

    return NGX_OK;
}

static void *
ngx_http_eval_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_eval_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_eval_loc_conf_t));

    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    return conf;
}

static char *
ngx_http_eval_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_eval_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data) 
{
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->len = 0;
    v->data = (u_char*)"";

    return NGX_OK;
}

static char *
ngx_http_eval_add_variable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_eval_loc_conf_t            *ecf = conf;

    ngx_int_t                            index;
    ngx_str_t                           *value;
    ngx_http_variable_t                 *v;

    value = cf->args->elts;

    if (value[1].data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    value[1].len--;
    value[1].data++;

    v = ngx_http_add_variable(cf, &value[1], NGX_HTTP_VAR_CHANGEABLE);
    if (v == NULL) {
        return NGX_CONF_ERROR;
    }

    index = ngx_http_get_variable_index(cf, &value[1]);
    if (index == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    if (v->get_handler == NULL)
    {
        v->get_handler = ngx_http_eval_variable;
        v->data = index;
    }

    ecf->variable_index = index;

    return NGX_CONF_OK;
}

static char *
ngx_http_eval_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_eval_loc_conf_t  *ecf, *pecf = conf;

    char                      *rv;
    void                      *mconf;
    ngx_str_t                  name;
    ngx_uint_t                 i;
    ngx_conf_t                 save;
    ngx_http_module_t         *module;
    ngx_http_conf_ctx_t       *ctx, *pctx;
    ngx_http_core_loc_conf_t  *clcf, *pclcf, *rclcf;
    ngx_http_core_srv_conf_t  *cscf;

    if(ngx_http_eval_add_variable(cf, cmd, conf) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    pctx = cf->ctx;
    ctx->main_conf = pctx->main_conf;
    ctx->srv_conf = pctx->srv_conf;

    ctx->loc_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module);
    if (ctx->loc_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = ngx_modules[i]->ctx;

        if (module->create_loc_conf) {

            mconf = module->create_loc_conf(cf);
            if (mconf == NULL) {
                 return NGX_CONF_ERROR;
            }

            ctx->loc_conf[ngx_modules[i]->ctx_index] = mconf;
        }
    }

    ecf = ctx->loc_conf[ngx_http_eval_module.ctx_index];

    pclcf = pctx->loc_conf[ngx_http_core_module.ctx_index];

    clcf = ctx->loc_conf[ngx_http_core_module.ctx_index];

    name.len = sizeof("/eval_") - 1 + NGX_OFF_T_LEN;

    name.data = ngx_palloc(cf->pool, name.len);

    if(name.data == NULL) {
        return NGX_CONF_ERROR;
    }

    name.len = ngx_sprintf(name.data, "/eval_%O", (off_t)(uintptr_t)clcf) - name.data;

    clcf->loc_conf = ctx->loc_conf;
    clcf->name = name;
    clcf->exact_match = 1;
    clcf->noname = 0;
    clcf->internal = 1;
    clcf->noregex = 1;

    cscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_core_module);

    rclcf = cscf->ctx->loc_conf[ngx_http_core_module.ctx_index];

    if (ngx_http_add_location(cf, &rclcf->locations, clcf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    pecf->eval_location = clcf->name;
    pecf->enabled = 1;

    save = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NGX_HTTP_LOC_CONF;

    rv = ngx_conf_parse(cf, NULL);

    *cf = save;

    return rv;
}

static ngx_int_t
ngx_http_eval_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_eval_handler;

    return NGX_OK;
}
