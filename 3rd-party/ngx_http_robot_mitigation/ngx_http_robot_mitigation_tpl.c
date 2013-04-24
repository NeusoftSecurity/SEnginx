#include <ngx_http_robot_mitigation.h>

const char *ngx_http_rm_get_js_tpls[] = {
#include "get_js.tpls"
};

const ngx_uint_t ngx_http_rm_get_js_tpls_nr = sizeof(ngx_http_rm_get_js_tpls)
    / sizeof(char *);

const char *ngx_http_rm_post_js_tpls[] = {
#include "post_js.tpls"
};

const ngx_uint_t ngx_http_rm_post_js_tpls_nr = sizeof(ngx_http_rm_post_js_tpls)
    / sizeof(char *);
