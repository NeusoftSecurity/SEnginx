
/*
 * Copyright (C) 2009 Valery Kholodkov
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>

typedef struct {
    ngx_http_variable_t        *variable;
    ngx_uint_t                  index;
} ngx_http_eval_variable_t;

typedef struct {
    ngx_array_t                *variables;
    ngx_str_t                   eval_location;
} ngx_http_eval_block_t;

typedef struct {
    ngx_array_t                *blocks;
    ngx_flag_t                  escalate;
    ngx_flag_t                  inherit_body;
    ngx_str_t                   override_content_type;
} ngx_http_eval_loc_conf_t;

typedef struct {
    ngx_http_eval_loc_conf_t   *base_conf;
    ngx_http_variable_value_t **values;
    ngx_int_t                   status;
    ngx_http_eval_block_t      *current_block;
    ngx_http_eval_block_t      *last_block;

    unsigned int                done:1;
    unsigned int                in_progress:1;
} ngx_http_eval_ctx_t;

typedef ngx_int_t (*ngx_http_eval_format_handler_pt)(ngx_http_request_t *r,
    ngx_http_eval_ctx_t *ctx);

typedef struct {
    ngx_str_t                           content_type;
    ngx_http_eval_format_handler_pt     handler;
} ngx_http_eval_format_t;

static ngx_int_t
ngx_http_eval_init_variables(ngx_http_request_t *r, ngx_http_eval_ctx_t *ctx, 
    ngx_http_eval_block_t *block);

static ngx_int_t ngx_http_eval_post_subrequest_handler(ngx_http_request_t *r, void *data, ngx_int_t rc);

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

    { ngx_string("eval_inherit_body"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_eval_loc_conf_t, inherit_body),
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
    size_t                      loc_len;
    ngx_str_t                   args; 
    ngx_str_t                   subrequest_uri;
    ngx_uint_t                  flags;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_http_eval_loc_conf_t   *ecf;
    ngx_http_eval_ctx_t        *ctx;
    ngx_http_request_t         *sr; 
    ngx_int_t                   rc;
    ngx_http_post_subrequest_t *psr;
    ngx_http_eval_block_t      *block;
    u_char                     *p;

    if(r != r->main && r->uri.len > 6 && r->uri.data[0] == '/' && r->uri.data[1] == 'e'
        && r->uri.data[2] == 'v' && r->uri.data[3] == 'a' && r->uri.data[4] == 'l'
        && r->uri.data[5] == '_')
    {
        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        loc_len = r->valid_location ? clcf->name.len : 0;

        if(r->uri.len != loc_len) {
            r->uri.data += loc_len;
            r->uri.len -= loc_len;
        }
        else {
            r->uri.len = 1;
        }
    }

    ecf = ngx_http_get_module_loc_conf(r, ngx_http_eval_module);

    if(ecf->blocks == NULL || !ecf->blocks->nelts) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_eval_module);

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "eval module: r=%p, ctx=%p, uri=%p", r, ctx, &r->uri);

    if(ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_eval_ctx_t));
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ctx->base_conf = ecf;

        ctx->current_block = ecf->blocks->elts;
        ctx->last_block = ctx->current_block + ecf->blocks->nelts - 1;

        ngx_http_set_ctx(r, ctx, ngx_http_eval_module);
    }

    if (ecf != ctx->base_conf) {
        ngx_memzero(ctx, sizeof(ngx_http_eval_ctx_t));

        ctx->base_conf = ecf;

        ctx->current_block = ecf->blocks->elts;
        ctx->last_block = ctx->current_block + ecf->blocks->nelts - 1;
    }
        
    if(ctx->done) {
        ctx->in_progress = 0;

        if(ctx->current_block == ctx->last_block) {
            if(!ecf->escalate || ctx->status == NGX_OK || ctx->status == NGX_HTTP_OK) {
                return NGX_DECLINED;
            }

            return ctx->status;
        }

        ctx->current_block++;
    }

    if(ctx->in_progress) {
#if defined nginx_version && nginx_version >= 8042
        return NGX_DONE;
#else
        return NGX_AGAIN;
#endif
    }

    /*
     * Advance to block which has at least one variable
     */
    while(ctx->current_block->variables == NULL || ctx->current_block->variables->nelts == 0) {
        if(ctx->current_block == ctx->last_block) {
            return NGX_DECLINED;
        }

        ctx->current_block++;
    }

    block = ctx->current_block;

    psr = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (psr == NULL) {
        return NGX_ERROR;
    }

    if(ngx_http_eval_init_variables(r, ctx, block) != NGX_OK) {
        return NGX_ERROR;
    }

    args.len = r->args.len;
    args.data = r->args.data;
    flags = 0;

    subrequest_uri.len = block->eval_location.len + r->uri.len;

    p = subrequest_uri.data = ngx_palloc(r->pool, subrequest_uri.len);

    if(p == NULL) {
        return NGX_ERROR;
    }

    p = ngx_copy(p, block->eval_location.data, block->eval_location.len);
    p = ngx_copy(p, r->uri.data, r->uri.len);

    if (ngx_http_parse_unsafe_uri(r, &subrequest_uri, &args, &flags) != NGX_OK) {
        return NGX_ERROR;
    }

    psr->handler = ngx_http_eval_post_subrequest_handler;
    psr->data = ctx;

    flags |= NGX_HTTP_SUBREQUEST_IN_MEMORY|NGX_HTTP_SUBREQUEST_WAITED;

    rc = ngx_http_subrequest(r, &subrequest_uri, &args, &sr, psr, flags);

    if (rc == NGX_ERROR || rc == NGX_DONE) {
        return rc;
    }

    if (!ecf->inherit_body) {
        /*
         * create a fake request body instead of discarding the real one
         * in order to avoid attempts to read it
         */
        sr->request_body = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
        if (sr->request_body == NULL) {
            return NGX_ERROR;
        }
    }
    else {
        sr->request_body = r->request_body;
        sr->header_in = r->header_in;
        sr->headers_in.content_length_n = r->headers_in.content_length_n;
        sr->headers_in.content_length = r->headers_in.content_length;

        r->headers_in.content_length_n = 0;
        r->headers_in.content_length = NULL;
    }

    ctx->in_progress = 1;
    ctx->done = 0;

    /*
     * Wait for subrequest to complete
     */

#if defined nginx_version && nginx_version >= 8011 && nginx_version < 8054
    r->main->count++;
#endif

#if defined nginx_version && nginx_version >= 8042
    return NGX_DONE;
#else
    return NGX_AGAIN;
#endif
}

static ngx_int_t
ngx_http_eval_init_variables(ngx_http_request_t *r, ngx_http_eval_ctx_t *ctx, 
    ngx_http_eval_block_t *block)
{
    ngx_uint_t i;
    ngx_http_eval_variable_t *variable;

    ctx->values = ngx_pcalloc(r->pool, block->variables->nelts * sizeof(ngx_http_variable_value_t*));

    if (ctx->values == NULL) {
        return NGX_ERROR;
    }

    variable = block->variables->elts;

    for(i = 0;i<block->variables->nelts;i++) {
        ctx->values[i] = r->variables + variable[i].index;

        ctx->values[i]->valid = 0;
        ctx->values[i]->not_found = 1;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_eval_post_subrequest_handler(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    ngx_http_eval_ctx_t     *ctx = data;
    ngx_http_eval_format_t  *f = ngx_http_eval_formats;
    ngx_str_t                content_type;

    if(ctx->base_conf->override_content_type.len) {
        content_type.data = ctx->base_conf->override_content_type.data;
        content_type.len = ctx->base_conf->override_content_type.len;
    }
    else if(r->headers_out.content_type.len) {
        content_type.data = r->headers_out.content_type.data;
        content_type.len = r->headers_out.content_type.len;
    }
    else {
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
 * ngx_http_eval_handler must guarantee this. *
 */
static ngx_int_t
ngx_http_eval_octet_stream(ngx_http_request_t *r, ngx_http_eval_ctx_t *ctx)
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

static ngx_int_t
ngx_http_eval_plain_text(ngx_http_request_t *r, ngx_http_eval_ctx_t *ctx)
{
    ngx_int_t rc;
    u_char *p;
    ngx_http_variable_value_t *value = ctx->values[0];

    rc = ngx_http_eval_octet_stream(r, ctx);

    if(rc != NGX_OK) {
        return rc;
    }

    /*
     * Remove trailing spaces and control characters
     */
    if(value->valid) {
        p = value->data + value->len;

        while(p != value->data) {
            p--;

            if(*p != CR && *p != LF && *p != '\t' && *p != ' ')
                break;

            value->len--;
        }
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_eval_set_variable_value(ngx_http_request_t *r, ngx_http_eval_ctx_t *ctx,
    ngx_str_t *name, ngx_str_t *value)
{
    ngx_uint_t i;
    ngx_http_eval_variable_t *variable;

    variable = ctx->current_block->variables->elts;

    for(i = 0;i<ctx->current_block->variables->nelts;i++) {
        if(variable[i].variable->name.len != name->len) {
            continue;
        }

        if(!ngx_strncasecmp(variable[i].variable->name.data, name->data, variable[i].variable->name.len)) {
            ctx->values[i]->len = value->len;
            ctx->values[i]->data = value->data;
            ctx->values[i]->valid = 1;
            ctx->values[i]->not_found = 0;

            return NGX_OK;
        }
    }

    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
        "eval: ignored undefined variable \"%V\"", value);

    return NGX_OK;
}

static ngx_int_t
ngx_http_eval_parse_param(ngx_http_request_t *r, ngx_http_eval_ctx_t *ctx, ngx_str_t *param) {
    u_char                    *p, *src, *dst;

    ngx_str_t                  name;
    ngx_str_t                  value;

    p = (u_char *) ngx_strlchr(param->data, param->data + param->len, '=');

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

    value.len = dst - value.data;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "eval param: \"%V\"=\"%V\"", &name, &value);

    return ngx_http_eval_set_variable_value(r, ctx, &name, &value);
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

    do {
        param.data = pos;
        param.len = 0;

        while (pos != last) {
            if (*pos == '&') {
                pos++;
                break;
            }

            if (*pos == CR || *pos == LF) {
                pos = last;
                break;
            }

            param.len++;
            pos++;
        }

        if(param.len != 0) {
            rc = ngx_http_eval_parse_param(r, ctx, &param);

            if(rc != NGX_OK) {
                return rc;
            }
        }
    }while(pos != last);

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
    conf->inherit_body = NGX_CONF_UNSET;

    return conf;
}

static char *
ngx_http_eval_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_eval_loc_conf_t *prev = parent;
    ngx_http_eval_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->escalate, prev->escalate, 0);
    ngx_conf_merge_value(conf->inherit_body, prev->inherit_body, 0);
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
ngx_http_eval_add_variables(ngx_conf_t *cf, ngx_http_eval_block_t *block)
{
    ngx_uint_t                           i;
    ngx_int_t                            index;
    ngx_str_t                           *value;
    ngx_http_variable_t                 *v;
    ngx_http_eval_variable_t            *variable;

    value = cf->args->elts;

    block->variables = ngx_array_create(cf->pool,
        cf->args->nelts, sizeof(ngx_http_eval_variable_t));

    if(block->variables == NULL) {
        return NGX_CONF_ERROR;
    }

    for(i = 1;i<cf->args->nelts;i++) {
        if (value[i].data[0] != '$') {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid variable name \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }

        variable = ngx_array_push(block->variables);
        if(variable == NULL) {
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

        variable->variable = v;
        variable->index = index;
    }

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_eval_add_block(ngx_conf_t *cf, ngx_http_eval_loc_conf_t *conf, ngx_str_t *name) {
    ngx_http_eval_block_t *block;

    if(conf->blocks == NULL) {
        conf->blocks = ngx_array_create(cf->pool, 1, sizeof(ngx_http_eval_block_t));

        if(conf->blocks == NULL) {
            return NGX_ERROR;
        }
    }

    block = ngx_array_push(conf->blocks);

    if(block == NULL) {
        return NGX_ERROR;
    }

    block->eval_location = *name;

    if(ngx_http_eval_add_variables(cf, block) != NGX_CONF_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
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
    clcf->exact_match = 0;
    clcf->noname = 0;
    clcf->internal = 1;
    clcf->noregex = 1;

    cscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_core_module);

    rclcf = cscf->ctx->loc_conf[ngx_http_core_module.ctx_index];

    if (ngx_http_add_location(cf, &rclcf->locations, clcf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if(ngx_http_eval_add_block(cf, pecf, &clcf->name) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

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
