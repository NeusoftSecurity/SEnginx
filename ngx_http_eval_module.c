
/*
 * Copyright (C) 2009 Valery Kholodkov
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    ngx_http_variable_t        *variable;
    ngx_uint_t                  index;
} ngx_http_eval_variable_t;

typedef struct {
    ngx_array_t                *variables;
    ngx_str_t                   eval_location;
    ngx_flag_t                  escalate;
    ngx_str_t                   override_content_type;
} ngx_http_eval_loc_conf_t;

typedef struct {
    ngx_http_eval_loc_conf_t   *base_conf;
    ngx_http_variable_value_t **values;
    unsigned int                done:1;
    unsigned int                in_progress:1;
    ngx_int_t                   status;
} ngx_http_eval_ctx_t;

typedef ngx_int_t (*ngx_http_eval_format_handler_pt)(ngx_http_request_t *r,
    ngx_http_eval_ctx_t *ctx);

typedef struct {
    ngx_str_t                           content_type;
    ngx_http_eval_format_handler_pt     handler;
} ngx_http_eval_format_t;

static ngx_int_t
ngx_http_eval_init_variables(ngx_http_request_t *r, ngx_http_eval_ctx_t *ctx, 
    ngx_http_eval_loc_conf_t *ecf);

static ngx_int_t ngx_http_eval_set_variable(ngx_http_request_t *r, void *data, ngx_int_t rc);

static void *ngx_http_eval_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_eval_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);

static char *ngx_http_eval_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_eval_init(ngx_conf_t *cf);

static ngx_int_t ngx_http_eval_octet_stream(ngx_http_request_t *r, ngx_http_eval_ctx_t *ctx);
static ngx_int_t ngx_http_eval_plain_text(ngx_http_request_t *r, ngx_http_eval_ctx_t *ctx);
static ngx_int_t ngx_http_eval_urlencoded(ngx_http_request_t *r, ngx_http_eval_ctx_t *ctx);

static ngx_http_eval_format_t ngx_http_eval_formats[] = {
    { ngx_string("application/octet-stream"), ngx_http_eval_octet_stream },
    { ngx_string("text/plain"), ngx_http_eval_plain_text },
    { ngx_string("application/x-www-form-urlencoded"), ngx_http_eval_urlencoded },

    { ngx_null_string, ngx_http_eval_plain_text }
};

static ngx_command_t  ngx_http_eval_commands[] = {

    { ngx_string("eval"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE|NGX_CONF_BLOCK,
      ngx_http_eval_block,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("eval_escalate"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_eval_loc_conf_t, escalate),
      NULL },

    { ngx_string("eval_override_content_type"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_eval_loc_conf_t, override_content_type),
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

    ngx_http_eval_create_loc_conf,         /* create location configuration */
    ngx_http_eval_merge_loc_conf           /* merge location configuration */
};

ngx_module_t  ngx_http_eval_module = {
    NGX_MODULE_V1,
    &ngx_http_eval_module_ctx,             /* module context */
    ngx_http_eval_commands,                /* module directives */
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

    if(ecf->variables == NULL || !ecf->variables->nelts) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_eval_module);

    if(ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_eval_ctx_t));
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ctx->base_conf = ecf;

        ngx_http_set_ctx(r, ctx, ngx_http_eval_module);
    }

    if(ctx->done) {
        if(!ecf->escalate || ctx->status == NGX_OK || ctx->status == NGX_HTTP_OK) {
            return NGX_DECLINED;
        }

        return ctx->status;
    }

    if(ctx->in_progress) {
        return NGX_AGAIN;
    }

    psr = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (psr == NULL) {
        return NGX_ERROR;
    }

    if(ngx_http_eval_init_variables(r, ctx, ecf) != NGX_OK) {
        return NGX_ERROR;
    }

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

    sr->discard_body = 1;

    ctx->in_progress = 1;

    /*
     * Wait for subrequest to complete
     */
    return NGX_AGAIN;
}

static ngx_int_t
ngx_http_eval_init_variables(ngx_http_request_t *r, ngx_http_eval_ctx_t *ctx, 
    ngx_http_eval_loc_conf_t *ecf)
{
    ngx_uint_t i;
    ngx_http_eval_variable_t *variable;

    ctx->values = ngx_pcalloc(r->pool, ecf->variables->nelts * sizeof(ngx_http_variable_value_t*));

    if (ctx->values == NULL) {
        return NGX_ERROR;
    }

    variable = ecf->variables->elts;

    for(i = 0;i<ecf->variables->nelts;i++) {
        ctx->values[i] = r->variables + variable[i].index;

        ctx->values[i]->valid = 0;
        ctx->values[i]->not_found = 1;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_eval_set_variable(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    ngx_http_eval_ctx_t     *ctx = data;
    ngx_http_eval_format_t  *f = ngx_http_eval_formats;
    ngx_str_t                content_type;

    if(ctx->base_conf->override_content_type.len) {
        content_type.data = ctx->base_conf->override_content_type.data;
        content_type.len = ctx->base_conf->override_content_type.len;
    }
    else {
        content_type.data = r->headers_out.content_type.data;
        content_type.len = r->headers_out.content_type.len;
    }

    if(!content_type.len) {
        content_type.data = (u_char*)"application/octet-stream";
        content_type.len = sizeof("application/octet-stream") - 1;
    }

    while(f->content_type.len) {

        if(!ngx_strncasecmp(f->content_type.data, content_type.data,
            f->content_type.len))
        {
            f->handler(r, ctx);
            break;
        }

        f++;
    }

    ctx->done = 1;
    ctx->status = rc;

    return NGX_OK;
}

/*
 * The next two evaluation methods assume we have at least one varible.
 *
 * ngx_http_eval_handler must guarantee this *
 */
static ngx_int_t ngx_http_eval_octet_stream(ngx_http_request_t *r, ngx_http_eval_ctx_t *ctx)
{
    ngx_http_variable_value_t *value = ctx->values[0];

    if (r->upstream) {
        value->len = r->upstream->buffer.last - r->upstream->buffer.pos;
        value->data = r->upstream->buffer.pos;
        value->valid = 1;
        value->not_found = 0;
    }

    return NGX_OK;
}

static ngx_int_t ngx_http_eval_plain_text(ngx_http_request_t *r, ngx_http_eval_ctx_t *ctx)
{
//    ngx_http_variable_value_t *value = ctx->values[0];

    ngx_http_eval_octet_stream(r, ctx);

    // TODO: strip the trailing spaces and control characters

    return NGX_OK;
}

static ngx_int_t
ngx_http_eval_parse_param(ngx_http_request_t *r, ngx_str_t *param) {
    u_char                    *p, *src, *dst;

    ngx_str_t                  name;
    ngx_str_t                  value;

    p = (u_char *) ngx_strchr(param->data, '=');

    if(p == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "eval: invalid param \"%V\"", param);
        return NGX_ERROR;
    }

    name.data = param->data;
    name.len = p - param->data;

    value.data = p + 1;
    value.len = param->len - (p - param->data) - 1;

    src = dst = value.data;

    ngx_unescape_uri(&dst, &src, value.len, NGX_UNESCAPE_URI);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "eval param: \"%V\"=\"%V\"", &name, &value);

    return NGX_OK;
}

static ngx_int_t
ngx_http_eval_urlencoded(ngx_http_request_t *r, ngx_http_eval_ctx_t *ctx)
{
    u_char *pos, *last;
    ngx_str_t param;
    ngx_int_t rc;

    if (!r->upstream || r->upstream->buffer.last == r->upstream->buffer.pos) {
        return NGX_OK;
    }

    pos = r->upstream->buffer.pos;
    last = r->upstream->buffer.last;

    param.data = pos;
    param.len = 0;

    while (pos != last && *pos != LF) {
        if (*pos == '&' || *pos == CR) {
            if(param.len != 0) {
                rc = ngx_http_eval_parse_param(r, &param);

                if(rc != NGX_OK) {
                    return rc;
                }

                pos++;

                param.data = pos;
                param.len = 0;
            }

            if(*pos == CR) {
                break;
            }
            else {
                continue;
            }
        }

        param.len++;
        pos++;
    }

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

    conf->escalate = NGX_CONF_UNSET;

    return conf;
}

static char *
ngx_http_eval_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_eval_loc_conf_t *prev = parent;
    ngx_http_eval_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->escalate, prev->escalate, 0);
    ngx_conf_merge_str_value(conf->override_content_type, prev->override_content_type, "");

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
ngx_http_eval_add_variables(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_eval_loc_conf_t            *ecf = conf;

    ngx_uint_t                           i;
    ngx_int_t                            index;
    ngx_str_t                           *value;
    ngx_http_variable_t                 *v;
    ngx_http_eval_variable_t            *variable;

    value = cf->args->elts;

    ecf->variables = ngx_array_create(cf->pool,
        cf->args->nelts, sizeof(ngx_http_eval_variable_t));

    if(ecf->variables == NULL) {
        return NGX_CONF_ERROR;
    }

    variable = ecf->variables->elts;

    for(i = 1;i<cf->args->nelts;i++) {
        if (value[i].data[0] != '$') {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid variable name \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }

        value[i].len--;
        value[i].data++;

        v = ngx_http_add_variable(cf, &value[i], NGX_HTTP_VAR_CHANGEABLE);
        if (v == NULL) {
            return NGX_CONF_ERROR;
        }

        index = ngx_http_get_variable_index(cf, &value[i]);
        if (index == NGX_ERROR) {
            return NGX_CONF_ERROR;
        }

        if (v->get_handler == NULL)
        {
            v->get_handler = ngx_http_eval_variable;
            v->data = index;
        }

        variable[i].variable = v;
        variable[i].index = index;
    }

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

    if(ngx_http_eval_add_variables(cf, cmd, conf) != NGX_CONF_OK) {
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
