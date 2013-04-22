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

#if (NGX_NETEYE_LOG)
#include <ngx_neteye_log.h>
#endif

#if (NGX_HTTP_BLACKLIST)
#include <ngx_http_blacklist.h>
#endif

#if (NGX_HTTP_STATUS_PAGE)
#include <ngx_http_status_page.h>
#endif

#if (NGX_HTTP_SESSION)
#include <ngx_http_session.h>
#endif

#define NGX_HTTP_AC_DEFAULT_URI NGX_HTTP_STATUS_PAGE_PATH"/403.html"

#define NGX_HTTP_AC_GET_SWF_URI "NetEye-ADSG-AC-GET-"
#define NGX_HTTP_AC_POST_SWF_URI "NetEye-ADSG-AC-POST-"  

#define NGX_HTTP_AC_DEFAULT_COOKIE_LEN 40
#define NGX_HTTP_AC_DEFAULT_COOKIE_NAME_LEN 40

#define NGX_HTTP_AC_COOKIE_NAME "NetEye-ADSG-AC"

#define NGX_HTTP_AC_RET_INVALID_COOKIE 1
#define NGX_HTTP_AC_RET_NO_COOKIE 2

#define NGX_HTTP_AC_MODE_JS 1
#define NGX_HTTP_AC_MODE_SWF 2

#define NGX_HTTP_AC_DEFAULT_TIMEOUT 600

#define NGX_HTTP_AC_SWF_FILENAME_PREFIX "neteye-adsg-swf-"

#define NGX_HTTP_AC_SWF_PLACEHOLDER_COOKIE_NAME "Roboo_name_0"
#define NGX_HTTP_AC_SWF_PLACEHOLDER_COOKIE_VALUE "Roboo_value_0"
#define NGX_HTTP_AC_SWF_PLACEHOLDER_TIMEOUT "Roboo_validity_0"


#define NGX_HTTP_AC_FORM_VARIABLES \
    "<input type=\"hidden\" name=\"%s\" value=\"%s\">\n"

#define NGX_HTTP_AC_FORM_VARIABLES_1 "<input type=\"hidden\" name=\""
#define NGX_HTTP_AC_FORM_VARIABLES_2 "\" value=\""
#define NGX_HTTP_AC_FORM_VARIABLES_3 "\">\n"

typedef struct {
    ngx_str_t *name;
#if (NGX_PCRE)
    ngx_http_regex_t  *regex;
#endif
} ngx_http_ac_whitelist_item_t;

typedef struct {
    ngx_int_t                  failed_count;
    ngx_int_t                  blacktime;
    
    ngx_int_t                  enabled;
    ngx_int_t                  action;
    ngx_int_t                  mode;
    ngx_int_t                  log;
    ngx_str_t                  error_page;
    time_t                     timeout;
    ngx_int_t                  no_expires;

    ngx_array_t               *whitelist_items;
} ngx_http_ac_loc_conf_t;

typedef struct {
    ngx_uint_t                 failed_count;
    ngx_uint_t                 request_type;    /* 0 for first, 1 for not first */
} ngx_http_ac_session_ctx_t;

typedef struct {
    ngx_http_request_t    *request;
    ngx_str_t              cookie;
    
    ngx_str_t              cookie_f1;
    ngx_str_t              cookie_f2;
} ngx_http_ac_req_ctx_t;


#define NGX_HTTP_AC_ATTACK_LOG_ID               1201001
#define NGX_HTTP_AC_EVENT_VERIFYDO              2030001


#define NGX_HTTP_AC_LOG_TEMPLATE_v4         \
    "%s\a"

#define NGX_HTTP_AC_EVENT_LOG_TEMPLATE_v4         \
    "%d.%d.%d.%d\a%d\a%s\a%d.%d.%d.%d\a%d\a"

#define NGX_HTTP_AC_SET_STATUS            0
#define NGX_HTTP_AC_CLEAR_STATUS          1
#define NGX_HTTP_AC_GET_STATUS            2

#define NGX_HTTP_AC_STATUS_NEW            0
#define NGX_HTTP_AC_STATUS_CHALLENGING    1
#define NGX_HTTP_AC_STATUS_PASSED         2
