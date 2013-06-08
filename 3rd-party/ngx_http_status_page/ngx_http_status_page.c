/**
 * ngx_http_status_page.c
 *
 * by Paul Yang <y_y@neusoft.com>
 *
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_core_module.h>
#include <ngx_times.h>

#include <ngx_http_status_page.h>

#if (NGX_HTTP_NETEYE_SECURITY)
#include <ngx_http_neteye_security.h>
#else
#error "must compile with neteye security module"
#endif

static ngx_int_t 
ngx_http_status_page_filter_init(ngx_conf_t *cf);

static ngx_int_t
ngx_http_status_page_request_ctx_init(ngx_http_request_t *r);
    
static ngx_http_module_t  ngx_http_status_page_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_status_page_filter_init,          /* postconfiguration */
    
    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */
    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */
    NULL,                                   /* create location configuration */
    NULL,                                   /* merge location configuration */
};

ngx_module_t  ngx_http_status_page_module = {
    NGX_MODULE_V1,
    &ngx_http_status_page_module_ctx,      /* module context */
    NULL,                                   /* module directives */
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
ngx_http_status_page_filter_init(ngx_conf_t *cf)
{
    return ngx_http_neteye_security_ctx_register(NGX_HTTP_NETEYE_STATUS_PAGE, 
            ngx_http_status_page_request_ctx_init);
}

/**
 * ngx_http_status_page_send_page
 * @r: request
 * @page: error page to send
 * @in_body: 1 for body filters, 0 for phases & header filters
 *
 * return: NGX_DONE
 *
 */
ngx_int_t
ngx_http_status_page_send_page(ngx_http_request_t *r, ngx_str_t *page, 
        ngx_int_t in_body, ngx_uint_t status)
{
    ngx_list_part_t *part;
   
#if (NGX_HTTP_SESSION)
    ngx_http_ns_jump_bit_set(r, NGX_HTTP_NETEYE_SESSION);
#endif
    ngx_http_status_page_set_bypass(r);
    ngx_http_ns_set_bypass_all(r);
    
    if (status != 0) {
        ngx_http_status_page_set_change_status(r);
        ngx_http_status_page_set_status(r, status);
    }

    r->headers_out.content_length = NULL;
    r->headers_out.date = NULL;
    r->headers_out.content_type.len = 0;
    r->headers_out.server = NULL;
    r->headers_out.location = NULL;
    r->headers_out.last_modified = NULL;
    r->headers_out.status_line.len = 0;

    part = &r->headers_out.headers.part;
    part->nelts = 0;

    if (in_body) {
	    ngx_http_status_page_set_old_header(r);
    }

    /* to bypass the method check in http_static_module */
    if (r->method & NGX_HTTP_POST) {
        r->method &= ~NGX_HTTP_POST;
        r->method |= NGX_HTTP_GET;
    }
    
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
            "in status page filter, redirect to %V", page);

    ngx_http_internal_redirect(r, page, NULL);

    return NGX_DONE;
}

static ngx_http_status_page_ctx_t *
ngx_http_status_page_get_ctx(ngx_http_request_t *r)
{
    ngx_http_status_page_ctx_t       *ctx;

    ctx = ngx_http_ns_get_module_ctx(r, ngx_http_status_page_module);

    return ctx;
}

static ngx_int_t
ngx_http_status_page_request_ctx_init(ngx_http_request_t *r)
{
    ngx_http_status_page_ctx_t    *ctx;

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_status_page_ctx_t));
    if (ctx == NULL)
        return NGX_ERROR;

    ngx_http_ns_set_ctx(r, ctx, ngx_http_status_page_module);

    return NGX_OK;
}

void ngx_http_status_page_set_bypass(ngx_http_request_t *r)
{
    ngx_http_status_page_ctx_t       *ctx;
   
    ctx = ngx_http_status_page_get_ctx(r);
    if (ctx == NULL)
        return;

    ctx->bypass = 1;
}

void ngx_http_status_page_set_change_status(ngx_http_request_t *r)
{
    ngx_http_status_page_ctx_t       *ctx;
   
    ctx = ngx_http_status_page_get_ctx(r);
    if (ctx == NULL)
        return;

    ctx->change_status = 1;
}

void ngx_http_status_page_set_status(ngx_http_request_t *r, 
        ngx_uint_t status)
{
    ngx_http_status_page_ctx_t       *ctx;
   
    ctx = ngx_http_status_page_get_ctx(r);
    if (ctx == NULL)
        return;

    ctx->status = status;
}

void ngx_http_status_page_set_old_header(ngx_http_request_t *r)
{
    ngx_http_status_page_ctx_t       *ctx;
   
    ctx = ngx_http_status_page_get_ctx(r);
    if (ctx == NULL)
        return;

    ctx->old_header = 1;
}

void ngx_http_status_page_clr_bypass(ngx_http_request_t *r)
{
    ngx_http_status_page_ctx_t       *ctx;
   
    ctx = ngx_http_status_page_get_ctx(r);
    if (ctx == NULL)
        return;

    ctx->bypass = 0;
}

void ngx_http_status_page_clr_change_status(ngx_http_request_t *r)
{
    ngx_http_status_page_ctx_t       *ctx;
   
    ctx = ngx_http_status_page_get_ctx(r);
    if (ctx == NULL)
        return;

    ctx->change_status = 0;
}

void ngx_http_status_page_clr_status(ngx_http_request_t *r)
{
    ngx_http_status_page_ctx_t       *ctx;
   
    ctx = ngx_http_status_page_get_ctx(r);
    if (ctx == NULL)
        return;

    ctx->status = 0;
}

void ngx_http_status_page_clr_old_header(ngx_http_request_t *r)
{
    ngx_http_status_page_ctx_t       *ctx;
   
    ctx = ngx_http_status_page_get_ctx(r);
    if (ctx == NULL)
        return;

    ctx->old_header = 0;
}

ngx_uint_t 
ngx_http_status_page_test_bypass(ngx_http_request_t *r)
{
    ngx_http_status_page_ctx_t       *ctx;
   
    ctx = ngx_http_status_page_get_ctx(r);
    if (ctx == NULL)
        return 0;

    return ctx->bypass;
}

ngx_uint_t
ngx_http_status_page_test_change_status(ngx_http_request_t *r)
{
    ngx_http_status_page_ctx_t       *ctx;
   
    ctx = ngx_http_status_page_get_ctx(r);
    if (ctx == NULL)
        return 0;

    return ctx->change_status;
}

ngx_uint_t 
ngx_http_status_page_get_status(ngx_http_request_t *r)
{
    ngx_http_status_page_ctx_t       *ctx;
   
    ctx = ngx_http_status_page_get_ctx(r);
    if (ctx == NULL)
        return 0;

    return ctx->status;
}

ngx_uint_t 
ngx_http_status_page_test_old_header(ngx_http_request_t *r)
{
    ngx_http_status_page_ctx_t       *ctx;
   
    ctx = ngx_http_status_page_get_ctx(r);
    if (ctx == NULL)
        return 0;

    return ctx->old_header;
}


