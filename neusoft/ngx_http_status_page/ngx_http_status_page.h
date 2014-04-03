#ifndef _NGX_HTTP_STATUS_PAGE_H_INCLUDED_
#define _NGX_HTTP_STATUS_PAGE_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define NGX_HTTP_STATUS_PAGE_PATH "/neteye_adsg_special_status_page"

typedef struct {
    ngx_uint_t code;
    ngx_str_t page;
} ngx_http_status_page_t;

typedef struct {
    ngx_array_t  *status_pages; /* array of ngx_http_status_page_t */
    ngx_flag_t    enabled;
} ngx_http_status_page_loc_conf_t;

typedef struct {
    u_char      bypass:1;
    u_char      change_status:1;
    ngx_uint_t  status;
    u_char      old_header:1;
} ngx_http_status_page_ctx_t;

ngx_int_t
ngx_http_status_page_send_page(ngx_http_request_t *r, ngx_str_t *page, 
        ngx_int_t in_body, ngx_uint_t status);

void ngx_http_status_page_set_bypass(ngx_http_request_t *r);
void ngx_http_status_page_set_change_status(ngx_http_request_t *r);
void ngx_http_status_page_set_status(ngx_http_request_t *r, ngx_uint_t status);
void ngx_http_status_page_set_old_header(ngx_http_request_t *r);

void ngx_http_status_page_clr_bypass(ngx_http_request_t *r);
void ngx_http_status_page_clr_change_status(ngx_http_request_t *r);
void ngx_http_status_page_clr_status(ngx_http_request_t *r);
void ngx_http_status_page_clr_old_header(ngx_http_request_t *r);

ngx_uint_t ngx_http_status_page_test_bypass(ngx_http_request_t *r);
ngx_uint_t ngx_http_status_page_test_change_status(ngx_http_request_t *r);
ngx_uint_t ngx_http_status_page_get_status(ngx_http_request_t *r);
ngx_uint_t ngx_http_status_page_test_old_header(ngx_http_request_t *r);

#endif
