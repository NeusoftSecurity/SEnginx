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

#define NGX_HTTP_RM_DEFAULT_URI NGX_HTTP_STATUS_PAGE_PATH"/403.html"

#define NGX_HTTP_RM_GET_SWF_URI "NetEye-ADSG-AC-GET-"
#define NGX_HTTP_RM_POST_SWF_URI "NetEye-ADSG-AC-POST-"  

#define NGX_HTTP_RM_DEFAULT_COOKIE_LEN 40
#define NGX_HTTP_RM_DEFAULT_COOKIE_NAME_LEN 40

#define NGX_HTTP_RM_COOKIE_NAME "SENGINX-ROBOT-MITIGATION"

#define NGX_HTTP_RM_RET_INVALID_COOKIE 1
#define NGX_HTTP_RM_RET_NO_COOKIE 2

#define NGX_HTTP_RM_MODE_JS 1
#define NGX_HTTP_RM_MODE_SWF 2

#define NGX_HTTP_RM_DEFAULT_TIMEOUT 600

#define NGX_HTTP_RM_SWF_FILENAME_PREFIX "neteye-adsg-swf-"

#define NGX_HTTP_RM_SWF_PLACEHOLDER_COOKIE_NAME "Roboo_name_0"
#define NGX_HTTP_RM_SWF_PLACEHOLDER_COOKIE_VALUE "Roboo_value_0"
#define NGX_HTTP_RM_SWF_PLACEHOLDER_TIMEOUT "Roboo_validity_0"


#define NGX_HTTP_RM_FORM_VARIABLES \
    "<input type=\"hidden\" name=\"%s\" value=\"%s\">\n"

#define NGX_HTTP_RM_FORM_VARIABLES_1 "<input type=\"hidden\" name=\""
#define NGX_HTTP_RM_FORM_VARIABLES_2 "\" value=\""
#define NGX_HTTP_RM_FORM_VARIABLES_3 "\">\n"

#define NGX_HTTP_RM_AJAX_KEY "X-Requested-With"
#define NGX_HTTP_RM_AJAX_KEY_LEN 16
#define NGX_HTTP_RM_AJAX_VALUE "XMLHttpRequest"
#define NGX_HTTP_RM_AJAX_VALUE_LEN 14


typedef struct {
    ngx_str_t *name;
#if (NGX_PCRE)
    ngx_http_regex_t  *regex;
#endif
} ngx_http_rm_whitelist_item_t;

typedef struct {
    in_addr_t start_addr;
    in_addr_t end_addr;
} ngx_http_rm_ip_whitelist_item_t;

typedef struct {
    ngx_int_t                  failed_count;
    ngx_int_t                  mode;

    ngx_uint_t                 enabled:1;
    ngx_uint_t                 ip_whitelist_x_forwarded_for:1;
    ngx_uint_t                 whitelist_any:1;
    ngx_uint_t                 wl_caseless:1;
    ngx_uint_t                 log:1;
    ngx_uint_t                 no_expires:1;
    ngx_uint_t                 pass_ajax:1;
    ngx_str_t                  cookie_name;
    time_t                     timeout;

    ngx_array_t               *whitelist_items;
    ngx_array_t               *ip_whitelist_items;
} ngx_http_rm_loc_conf_t;

typedef struct {
    ngx_uint_t                 failed_count;
    ngx_uint_t                 request_type;    /* 0 for first, 1 for not first */
    ngx_int_t                  generate_time;
} ngx_http_rm_session_ctx_t;

typedef struct {
    ngx_http_request_t    *request;
    ngx_str_t              cookie;
    
    ngx_str_t              cookie_f1;
    ngx_str_t              cookie_f2;

    ngx_int_t              blacklist;
} ngx_http_rm_req_ctx_t;


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
