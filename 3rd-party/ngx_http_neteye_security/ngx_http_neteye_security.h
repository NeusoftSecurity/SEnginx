/*
 * Copyright (c) 2013 Neusoft Corperation., Ltd. 
 */
#ifndef _NGX_HTTP_NETEYE_SECURITY_H_INCLUDED_
#define _NGX_HTTP_NETEYE_SECURITY_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef ngx_int_t (*ngx_http_neteye_security_request_pt)(ngx_http_request_t *r);
typedef ngx_int_t (*ngx_http_neteye_security_response_header_pt)(ngx_http_request_t *r);
typedef ngx_int_t (*ngx_http_neteye_security_response_body_pt)(ngx_http_request_t *r, 
        ngx_chain_t *in);

typedef ngx_int_t (*ngx_http_neteye_security_ctx_pt)(ngx_http_request_t *r);

typedef struct ngx_http_neteye_security_module_s {
    ngx_int_t id;
    char *name;
    ngx_http_neteye_security_request_pt request_handler;
    ngx_http_neteye_security_response_header_pt response_header_handler;
    ngx_http_neteye_security_response_body_pt response_body_handler;
    ngx_int_t request_rank;
    ngx_int_t response_header_rank;
    ngx_int_t response_body_rank;

    ngx_http_neteye_security_ctx_pt init_ns_ctx;
} ngx_http_neteye_security_module_t;

enum ngx_http_neteye_security_module_ids {
    NGX_HTTP_NETEYE_SECURITY_MODULE_START = 0,  

    NGX_HTTP_NETEYE_WHITELIST,
    NGX_HTTP_NETEYE_FRIENDLY_BOTSLIST,
    NGX_HTTP_NETEYE_SESSION,
    NGX_HTTP_NETEYE_DYNWHITELIST,
    NGX_HTTP_NETEYE_ROBOT_MITIGATION,
    NGX_HTTP_NETEYE_GOOGLE_RECAPTCHA,
    NGX_HTTP_NETEYE_LOCAL_CAPTCHA,
    NGX_HTTP_NETEYE_COOKIE_POISONING,
    NGX_HTTP_NETEYE_PAGE_ACL,
    NGX_HTTP_NETEYE_NAXSI,
    NGX_HTTP_NETEYE_STATUS_PAGE,
    NGX_HTTP_NETEYE_LOG_MODULE,

    NGX_HTTP_NETEYE_SECURITY_MODULE_MAX
};

enum ngx_http_neteye_security_attack_log_id {
    NGX_HTTP_NETEYE_ATTACK_LOG_ID_AC,
    NGX_HTTP_NETEYE_ATTACK_LOG_ID_CP,
    NGX_HTTP_NETEYE_ATTACK_LOG_ID_MAX
};

typedef struct ngx_http_ns_ctx_s {
    ngx_uint_t       jump_bit;
    
    u_char           all_security_bypass:1;
    u_char           ns_ctx_initialed:1;
} ngx_http_ns_ctx_t;

#define NGX_HTTP_NETEYE_SECURITY_MODULE_LIMIT sizeof(ngx_uint_t)

#define NGX_NS_RET_DO_ACTION     -50

#define NGX_HTTP_NS_ACTION_PASS         0
#define NGX_HTTP_NS_ACTION_BLOCK        1
#define NGX_HTTP_NS_ACTION_BLACKLIST    2
#define NGX_HTTP_NS_ACTION_WHITELIST    3
#define NGX_HTTP_NS_ACTION_REMOVE_COOKIE 4
#define NGX_HTTP_NS_ACTION_RECHALLENGE  5

#define ngx_http_ns_get_module_ctx(r, module)  (r)->ns_ctx[module.ctx_index]
#define ngx_http_ns_set_ctx(r, c, module)      r->ns_ctx[module.ctx_index] = c;

#if (NGX_HTTP_SESSION) 
#include <ngx_http_session.h>

typedef ngx_uint_t *(*ngx_http_ns_get_bl_count_t)(ngx_http_session_ctx_t *ctx);
#endif

typedef struct ngx_http_neteye_security_action_s {
    ngx_int_t                               action;

    /* session & blacklist group */
#if (NGX_HTTP_SESSION) 
    u_char                                 *session_name;
    ngx_http_ns_get_bl_count_t              get_bl_count;
    ngx_uint_t                              bl_max;
#endif

    /* redirect url group */
    ngx_uint_t                              in_body;
    ngx_str_t                              *redirect_page;

    /* remove cookie group */
    ngx_str_t                              *cookie;
    /* block group */

    /* pass group */

    /* other stuffs */
    ngx_uint_t                              has_redirect:1;
} ngx_http_ns_action_t;

ngx_int_t
ngx_http_neteye_security_request_register(ngx_int_t id, 
        ngx_http_neteye_security_request_pt handler);
ngx_int_t
ngx_http_neteye_security_header_register(ngx_int_t id, 
        ngx_http_neteye_security_response_header_pt handler);
ngx_int_t
ngx_http_neteye_security_body_register(ngx_int_t id, 
        ngx_http_neteye_security_response_body_pt handler);
ngx_int_t
ngx_http_ns_do_action(ngx_http_request_t *r, 
        ngx_http_ns_action_t *action);

ngx_int_t
ngx_http_neteye_security_ctx_register(ngx_int_t id, 
        ngx_http_neteye_security_ctx_pt handler);

void
ngx_http_ns_jump_bit_set(ngx_http_request_t *r, ngx_uint_t mod);
void
ngx_http_ns_jump_bit_clr(ngx_http_request_t *r, ngx_uint_t mod);
void
ngx_http_ns_jump_bit_clr_all(ngx_http_request_t *r);
ngx_uint_t
ngx_http_ns_jump_bit_is_set(ngx_http_request_t *r, ngx_uint_t mod);
void
ngx_http_ns_jump_bit_set_all(ngx_http_request_t *r);
ngx_uint_t
ngx_http_ns_jump_bit_is_set_any(ngx_http_request_t *r);
void ngx_http_ns_set_bypass_all(ngx_http_request_t *r);
void ngx_http_ns_clr_bypass_all(ngx_http_request_t *r);
ngx_uint_t ngx_http_ns_test_bypass_all(ngx_http_request_t *r);

char *
ngx_http_ns_get_action_str(ngx_int_t action);
void ngx_http_neteye_send_attack_log(ngx_http_request_t *r, ngx_uint_t log_id, 
        ngx_str_t action, char *module_name, char *string);
#endif
