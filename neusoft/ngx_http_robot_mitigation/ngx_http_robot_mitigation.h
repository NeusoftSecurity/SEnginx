/*
 * Copyright (c) 2013 Neusoft Corperation., Ltd.
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ngx_md5.h>
#include <ngx_string.h>

#define NGX_HTTP_RECAPTCHA_DEFAULT_MAX_VERIFY_TIMES 10

#include <ngx_times.h>

#if (NGX_HTTP_IP_BLACKLIST)
#include <ngx_http_ip_blacklist.h>
#endif

#if (NGX_HTTP_STATUS_PAGE)
#include <ngx_http_status_page.h>
#endif

#include <ngx_http_whitelist.h>

#define NGX_HTTP_RM_DEFAULT_URI NGX_HTTP_STATUS_PAGE_PATH"/403.html"

#define NGX_HTTP_RM_GET_SWF_URI "NetEye-ADSG-AC-GET-"
#define NGX_HTTP_RM_POST_SWF_URI "NetEye-ADSG-AC-POST-"

#define NGX_HTTP_RM_DEFAULT_COOKIE_LEN 40
#define NGX_HTTP_RM_DEFAULT_COOKIE_NAME_LEN 40

#define NGX_HTTP_RM_COOKIE_NAME "SENGINX-ROBOT-MITIGATION"
#define NGX_HTTP_RM_COOKIE_NAME_C "SENGINX-ROBOT-MITIGATION        "
#define NGX_HTTP_RM_MAX_COOKIE_NAME_LEN 32

#define NGX_HTTP_RM_RET_INVALID_COOKIE 1
#define NGX_HTTP_RM_RET_NO_COOKIE 2

#define NGX_HTTP_RM_MODE_JS 1
#define NGX_HTTP_RM_MODE_SWF 2

#define NGX_HTTP_RM_DEFAULT_TIMEOUT 600
#define NGX_HTTP_RM_DEFAULT_TIMEOUT_C "600 "
#define NGX_HTTP_RM_MAX_TIMEOUT 3600
#define NGX_HTTP_RM_MAX_TIMEOUT_STR_LEN 4

#define NGX_HTTP_RM_SWF_FILENAME_PREFIX "neteye-adsg-swf-"

#define NGX_HTTP_RM_SWF_PLACEHOLDER_COOKIE_NAME "Roboo_name_0"
#define NGX_HTTP_RM_SWF_PLACEHOLDER_COOKIE_VALUE "Roboo_value_0"
#define NGX_HTTP_RM_SWF_PLACEHOLDER_TIMEOUT "Roboo_validity_0"


#define NGX_HTTP_RM_POST_TYPE "application/x-www-form-urlencoded"
#define NGX_HTTP_RM_FORM_VARIABLES \
    "<input type=\"hidden\" name=\"%s\" value=\"%s\">\n"

#define NGX_HTTP_RM_FORM_VARIABLES_1 "<input type=\"hidden\" name=\""
#define NGX_HTTP_RM_FORM_VARIABLES_2 "\" value=\""
#define NGX_HTTP_RM_FORM_VARIABLES_3 "\">\n"

#define NGX_HTTP_RM_AJAX_KEY "X-Requested-With"
#define NGX_HTTP_RM_AJAX_KEY_LEN 16
#define NGX_HTTP_RM_AJAX_VALUE "XMLHttpRequest"
#define NGX_HTTP_RM_AJAX_VALUE_LEN 14

#define NGX_HTTP_RM_ADDR_LEN 64
#define NGX_HTTP_RM_ADDR_TIMEOUT (5*1000)  //5s

typedef struct {
    ngx_http_regex_t  *regex;
    ngx_http_regex_t  *domain_name;
} ngx_http_rm_whitelist_item_t;

typedef struct {
    in_addr_t start_addr;
    in_addr_t end_addr;
} ngx_http_rm_ip_whitelist_item_t;

typedef struct {
    ngx_int_t                   failed_count;
    ngx_uint_t                  mode;

    ngx_flag_t                  enabled;
    ngx_flag_t                  ip_whitelist_x_forwarded_for;
    ngx_flag_t                  pass_ajax;
    ngx_flag_t                  wl_caseless;
    ngx_flag_t                  no_expires;
    ngx_str_t                   cookie_name;
    ngx_str_t                   cookie_name_c;
    ngx_str_t                   timeout_c;
    time_t                      timeout;

    ngx_array_t                 *whitelist_items;
    ngx_array_t                 *ip_whitelist_items;

    /* global whitelists */
    ngx_http_wl_variables_t     global_wl;
} ngx_http_rm_loc_conf_t;

typedef struct {
    ngx_msec_t                  resolver_timeout;      /* resolver_timeout */
    ngx_resolver_t              *resolver;             /* resolver */
    ngx_uint_t                  wl_domain_enable:1;
} ngx_http_rm_main_conf_t;


typedef struct {
    ngx_uint_t                 failed_count;
    /* 0 for first, 1 for not first */
    ngx_uint_t                 request_type;
    ngx_int_t                  generate_time;
} ngx_http_rm_session_ctx_t;

typedef struct {
    ngx_http_request_t    *request;
    ngx_str_t              cookie;

    ngx_str_t              cookie_f1;
    ngx_str_t              cookie_f2;

    ngx_int_t              blacklist;
} ngx_http_rm_req_ctx_t;

typedef struct {
    ngx_rbtree_node_t               node;
    u_char                          addr[NGX_HTTP_RM_ADDR_LEN];
    size_t                          len;
    ngx_str_t                       name;
    ngx_event_t                     timeout_ev;
} ngx_http_rm_dns_t;

typedef struct {
    char                  *data;
    uint16_t               m;
    uint16_t               n;
    uint16_t               o;
    uint16_t               x;
    uint16_t               y;
    uint16_t               z;
    uint16_t               len;
} ngx_http_rm_tpl_t;

#define NGX_HTTP_RM_ATTACK_LOG_ID               1201001
#define NGX_HTTP_RM_EVENT_VERIFYDO              2030001


#define NGX_HTTP_RM_LOG_TEMPLATE_v4         \
    "%s\a"

#define NGX_HTTP_RM_EVENT_LOG_TEMPLATE_v4         \
    "%d.%d.%d.%d\a%d\a%s\a%d.%d.%d.%d\a%d\a"

#define NGX_HTTP_RM_SET_STATUS            0
#define NGX_HTTP_RM_CLEAR_STATUS          1
#define NGX_HTTP_RM_GET_STATUS            2
#define NGX_HTTP_RM_RECORD_TIME           3
#define NGX_HTTP_RM_GET_TIME              4

#define NGX_HTTP_RM_STATUS_NEW            0
#define NGX_HTTP_RM_STATUS_CHALLENGING    1
#define NGX_HTTP_RM_STATUS_PASSED         2
