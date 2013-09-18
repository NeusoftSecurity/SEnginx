/**
 * ngx_http_cookie_poison.c
 *
 * by Paul Yang <y_y@neusoft.com>
 *
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_core_module.h>

#include <ngx_http_cookie_poisoning.h>
#include <ngx_md5.h>

#if (NGX_NETEYE_LOG)
#include <ngx_neteye_log.h>
#endif

#if (NGX_HTTP_BLACKLIST)
#include <ngx_http_blacklist.h>
#endif


#if (NGX_HTTP_SESSION)
#include <ngx_http_session.h>
#else
#error "must compile with session module"
#endif

#if (NGX_HTTP_NETEYE_SECURITY)
#include <ngx_http_neteye_security.h>
#else
#error "must compile with neteye security module"
#endif

static void
ngx_http_cp_create_session_ctx(ngx_http_session_t *session);
static char *
ngx_http_cp(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *
ngx_http_cp_action(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *
ngx_http_cp_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t
ngx_http_cp_filter_init(ngx_conf_t *cf);
static void *
ngx_http_cp_create_loc_conf(ngx_conf_t *cf);
static char *
ngx_http_cp_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
ngx_int_t ngx_http_cp_header_handler(ngx_http_request_t *r);
static ngx_int_t
ngx_http_cp_handler(ngx_http_request_t *r);

static ngx_command_t  ngx_http_cp_commands[] = {

    { ngx_string("cookie_poisoning"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_http_cp,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },

    { ngx_string("cookie_poisoning_action"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
        ngx_http_cp_action,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },

    { ngx_string("cookie_poisoning_log"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_http_cp_log,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },

    ngx_null_command,
};


static ngx_http_module_t  ngx_http_cp_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_cp_filter_init,              /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_cp_create_loc_conf,          /* create location configuration */
    ngx_http_cp_merge_loc_conf            /* merge location configuration */
};


ngx_module_t  ngx_http_cookie_poisoning_module = {
    NGX_MODULE_V1,
    &ngx_http_cp_module_ctx, /* module context */
    ngx_http_cp_commands,    /* module directives */
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
ngx_http_cp_filter_init(ngx_conf_t *cf)
{
    ngx_int_t ret;

    ret = ngx_http_neteye_security_header_register(
            NGX_HTTP_NETEYE_COOKIE_POISONING, ngx_http_cp_header_handler);

    if (ret == NGX_ERROR) {
        return NGX_ERROR;
    }
    
    ngx_http_session_register_create_ctx_handler(
            ngx_http_cp_create_session_ctx);
    
    return ngx_http_neteye_security_request_register(
            NGX_HTTP_NETEYE_COOKIE_POISONING, ngx_http_cp_handler);
}

static char *
ngx_http_cp(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cp_loc_conf_t *cplcf = conf;
    ngx_str_t        *value;

    value = cf->args->elts;
    if (!strncmp((char *)(value[1].data), "on", value[1].len)) {
        cplcf->enabled = 1;
    }
    
    return NGX_CONF_OK;
}

static char *
ngx_http_cp_action(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cp_loc_conf_t *cplcf = conf;
    ngx_str_t        *value;
    u_char *tmp;

    value = cf->args->elts;
    
    if (!ngx_strcmp(value[1].data, "block")) {
        cplcf->action = NGX_HTTP_NS_ACTION_BLOCK;
    } else if (!ngx_strcmp(value[1].data, "remove")) {
        cplcf->action = NGX_HTTP_NS_ACTION_REMOVE_COOKIE;
    } else if (!ngx_strcmp(value[1].data, "pass")) {
        cplcf->action = NGX_HTTP_NS_ACTION_PASS;
    } else if (!ngx_strncmp(value[1].data, "blacklist", strlen("blacklist"))) {
        cplcf->action = NGX_HTTP_NS_ACTION_BLACKLIST;
        tmp = value[1].data;

        if (((u_char *)tmp + strlen("blacklist"))
                == (value[1].data + value[1].len)) {
            cplcf->bl_times = 5;
        } else {
            cplcf->bl_times = ngx_atoi((u_char *)tmp + strlen("blacklist,"), 
                    value[1].len - strlen("blacklist,"));
            if (cplcf->bl_times == NGX_ERROR) {
                return "blacklist times error";
            }
        }
    } else {
        return "invalid action";
    }
 
#if (NGX_HTTP_STATUS_PAGE)
    if (cf->args->nelts == 3) {
        if (!ngx_strncmp(value[2].data, "notify=", strlen("notify="))) {
            if (value[2].len == strlen("notify=")) {
                cplcf->error_page.len = 0;
                cplcf->error_page.data = NULL;

                return "invalid notification page, use \"off\" tho turn off";
            } else {
                cplcf->error_page.data = value[2].data + strlen("notify=");
                cplcf->error_page.len = value[2].len - strlen("notify=");
                if (cplcf->error_page.len == strlen("off")) {
                    if (!ngx_strncmp(cplcf->error_page.data,
                                "off", strlen("off"))) {
                        cplcf->error_page.len = 0;
                        cplcf->error_page.data = NULL;
                    }
                }
            }
        } else {
            return "invalid notification page, use notify= to define it";
        }
    }
#endif

    return NGX_CONF_OK;
}

static char *
ngx_http_cp_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t        *value;
    ngx_http_cp_loc_conf_t  *cplcf = conf;

    value = cf->args->elts;

    if (!strncmp((char *)(value[1].data), "on", value[1].len)) {
        cplcf->log_enabled = 1;
    }

    return NGX_CONF_OK;
}

static void *
ngx_http_cp_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_cp_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_cp_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}

static char *
ngx_http_cp_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_cp_gen_cookie_data(ngx_http_request_t *r, 
        ngx_str_t *cookie, ngx_str_t *neteye_cookie,
        ngx_uint_t magic)
{
    ngx_md5_t                        md5_ctx;
    u_char                           md5_digest[16];
    u_char                          *hex_output, *source;
    ngx_uint_t                       di;

    source = ngx_pcalloc(r->pool, cookie->len + sizeof(magic));
    if (!source) {
        return NGX_ERROR;
    }

    hex_output = ngx_pcalloc(r->pool, NGX_HTTP_CP_MD5_LEN + 1);
    if (!hex_output) {
        return NGX_ERROR;
    }
    
    memcpy(source, cookie->data, cookie->len);
    memcpy(source + cookie->len, &magic, sizeof(magic));

    ngx_md5_init(&md5_ctx);
    ngx_md5_update(&md5_ctx, (void *)source, strlen((char *)source));
    ngx_md5_final(md5_digest, &md5_ctx);

    for (di = 0; di < 16; di++) {
        sprintf((char *)hex_output + di * 2, "%02x", md5_digest[di]);
    }

    neteye_cookie->data = hex_output;
    neteye_cookie->len = NGX_HTTP_CP_MD5_LEN;

    return NGX_OK;
}

static void 
ngx_http_cp_send_log(ngx_http_request_t *r, 
        ngx_str_t *cookie,
        ngx_str_t *cookie_value)
{
    ngx_http_cp_loc_conf_t      *cplcf;
    ngx_str_t                    action;
    char                        *string;
    char                        *prefix = "cookie: ";
    ngx_int_t                    prefix_len = strlen(prefix);

    cplcf = ngx_http_get_module_loc_conf(r, ngx_http_cookie_poisoning_module);
    action.data = (u_char *)ngx_http_ns_get_action_str(cplcf->action);
    action.len = ngx_strlen(action.data);

    string = ngx_pcalloc(r->pool, cookie->len 
            + 2
            + prefix_len
            + cookie_value->len);
    if (string) {
        memcpy(string, prefix, prefix_len);
        memcpy(string + prefix_len, cookie->data, cookie->len);
        memcpy(string + prefix_len + cookie->len, ":", 1);
        memcpy(string + prefix_len + cookie->len + 1, 
                cookie_value->data, cookie_value->len);
    }

    ngx_http_neteye_send_attack_log(r, NGX_HTTP_NETEYE_ATTACK_LOG_ID_CP, 
            action, "cookie poisoning", string);
}

static void 
ngx_http_cp_destroy_session_ctx_handler(void *ctx)
{
    ngx_http_session_ctx_t *session_ctx;

    session_ctx = (ngx_http_session_ctx_t *)ctx;

    return ngx_http_session_shm_free_nolock(session_ctx->data);
}

static ngx_int_t
ngx_http_cp_init_session_ctx_handler(void *ctx)
{
    ngx_http_session_ctx_t           *session_ctx;

    session_ctx = (ngx_http_session_ctx_t *)ctx;
    
    /* initial session ctx */
    session_ctx->data = ngx_http_session_shm_alloc_nolock(
            sizeof(ngx_http_cp_session_ctx_t));
    if (!session_ctx->data) {
        fprintf(stderr, "create cp session ctx error\n");
        return NGX_ERROR;
    }
   
    return NGX_OK;
}

static ngx_uint_t
ngx_http_cp_hash_key(ngx_http_cp_hash_t *hash, ngx_str_t *cookie_name)
{
    ngx_uint_t i, key = 0;

    for (i = 0; i < cookie_name->len; i++) {
        key = ngx_hash(key, cookie_name->data[i]);
    }

    return key % hash->nr_buckets;
}

static ngx_http_cp_monitored_cookie_t *
__ngx_http_cp_hash_find(ngx_http_cp_hash_t *hash, ngx_str_t *cookie_name,
        ngx_uint_t key)
{
    ngx_http_cp_monitored_cookie_t *m_cookie;

    m_cookie = hash->buckets[key];

    if (!m_cookie) {
        return NULL;
    }

    for (; m_cookie != NULL; m_cookie = m_cookie->next) {
        if (m_cookie->cookie_name.len != cookie_name->len) {
            continue;
        }

        if (!memcmp(m_cookie->cookie_name.data,
                    cookie_name->data,
                    cookie_name->len)) {
            return m_cookie;
        }
    }

    return NULL;
}

static ngx_http_cp_monitored_cookie_t *
ngx_http_cp_hash_find(ngx_http_cp_hash_t *hash, ngx_str_t *cookie_name)
{
    ngx_uint_t key = 0;

    key = ngx_http_cp_hash_key(hash, cookie_name);

    return __ngx_http_cp_hash_find(hash, cookie_name, key);
}

static ngx_int_t
__ngx_http_cp_hash_insert(ngx_http_cp_hash_t *hash,
        ngx_http_cp_monitored_cookie_t *monitored_cookie,
        ngx_uint_t key)
{
    ngx_http_cp_monitored_cookie_t *m_cookie;

    m_cookie = hash->buckets[key];

    if (!m_cookie) {
        hash->buckets[key] = monitored_cookie;
        return NGX_OK;
    }

    for (; m_cookie->next != NULL; m_cookie = m_cookie->next) { }

    m_cookie->next = monitored_cookie;

    return NGX_OK;
}

static ngx_int_t
ngx_http_cp_hash_delete(ngx_http_cp_hash_t *hash, ngx_str_t *cookie_name)
{
    ngx_uint_t key = 0;
    ngx_http_cp_monitored_cookie_t *m_cookie, *prev;

    key = ngx_http_cp_hash_key(hash, cookie_name);

    prev = m_cookie = hash->buckets[key];
    for (; m_cookie != NULL; prev = m_cookie, m_cookie = m_cookie->next) {
        if (m_cookie->cookie_name.len != cookie_name->len) {
            continue;
        }

        if (!memcmp(m_cookie->cookie_name.data,
                    cookie_name->data,
                    cookie_name->len)) {
            /* found the cookie */
            if (prev == m_cookie) {
                /*the first one*/
                hash->buckets[key] = m_cookie->next;
            } else {
                prev->next = m_cookie->next;
            }

            /* free the memory */
            ngx_http_session_shm_free_nolock(m_cookie->cookie_name.data);
            ngx_http_session_shm_free_nolock(m_cookie);

            return NGX_OK;
        }
    }

    return NGX_ERROR;
}

static ngx_int_t
ngx_http_cp_hash_init(ngx_http_cp_hash_t *hash, size_t size)
{
    hash->nr_buckets = size;
    hash->buckets = ngx_http_session_shm_alloc_nolock(
                sizeof(ngx_http_cp_monitored_cookie_t *) * size);
    if (!hash->buckets) {
        return NGX_ERROR;
    }

    memset(hash->buckets, 0, sizeof(ngx_http_cp_monitored_cookie_t *) * size);

    return NGX_OK;
}

static ngx_int_t
ngx_http_cp_delete_monitored_cookies(ngx_http_request_t *r,
        ngx_str_t *cookie_name)
{
    ngx_http_session_t               *session;
    ngx_http_session_ctx_t           *session_ctx;
    ngx_http_cp_session_ctx_t        *cp_ctx;

    session = ngx_http_session_get(r);
    if (!session) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                "cp get session failed when update monitored cookies");
        return NGX_ERROR;
    }

    ngx_shmtx_lock(&session->mutex);

    session_ctx = ngx_http_session_find_ctx(session, (u_char *)"cookie_poisoning");
    if (!session_ctx) {
        ngx_shmtx_unlock(&session->mutex);
        ngx_http_session_put(r);
        
        return NGX_ERROR;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
            "found session ctx\n");

    cp_ctx = session_ctx->data;

    ngx_http_cp_hash_delete(&cp_ctx->monitored_cookies, cookie_name);

    ngx_shmtx_unlock(&session->mutex);
    ngx_http_session_put(r);

    return NGX_OK;
}

static ngx_int_t
ngx_http_cp_update_monitored_cookies(ngx_http_request_t *r,
        ngx_str_t *cookie_name,
        ngx_str_t *neteye_cookie,
        ngx_uint_t magic)
{
    ngx_http_session_t               *session;
    ngx_http_session_ctx_t           *session_ctx;
    ngx_http_cp_session_ctx_t        *cp_ctx;
    ngx_http_cp_monitored_cookie_t   *m_cookie;
    ngx_uint_t                        key;

    session = ngx_http_session_get(r);
    if (!session) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                "cp get session failed when update monitored cookies");
        return NGX_ERROR;
    }

    ngx_shmtx_lock(&session->mutex);

    session_ctx = ngx_http_session_find_ctx(session, (u_char *)"cookie_poisoning");
    if (!session_ctx) {
        ngx_shmtx_unlock(&session->mutex);
        ngx_http_session_put(r);
        
        return NGX_ERROR;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
            "found session ctx\n");

    cp_ctx = session_ctx->data;

    key = ngx_http_cp_hash_key(&cp_ctx->monitored_cookies, cookie_name);

    m_cookie = __ngx_http_cp_hash_find(&cp_ctx->monitored_cookies,
            cookie_name, key);
    if (m_cookie != NULL) {
        /* update, 32 is the length of md5 value */
        memcpy(m_cookie->cookie_magic, neteye_cookie->data, NGX_HTTP_CP_MD5_LEN);
        m_cookie->magic = magic;
    } else {
        /* insert */
        m_cookie = ngx_http_session_shm_alloc_nolock(
                sizeof(ngx_http_cp_monitored_cookie_t));
        if (!m_cookie) {
            ngx_shmtx_unlock(&session->mutex);
            ngx_http_session_put(r);
 
            return NGX_ERROR;
        }

        m_cookie->cookie_name.data = ngx_http_session_shm_alloc_nolock(
                cookie_name->len);
        if (!m_cookie->cookie_name.data) {
            ngx_shmtx_unlock(&session->mutex);
            ngx_http_session_put(r);
 
            return NGX_ERROR;
        }

        memcpy(m_cookie->cookie_name.data, cookie_name->data, cookie_name->len);
        m_cookie->cookie_name.len = cookie_name->len;
        memcpy(m_cookie->cookie_magic, neteye_cookie->data, NGX_HTTP_CP_MD5_LEN);

        m_cookie->magic = magic;
        m_cookie->next = NULL;

        __ngx_http_cp_hash_insert(&cp_ctx->monitored_cookies, m_cookie, key);
    }

    ngx_shmtx_unlock(&session->mutex);
    ngx_http_session_put(r);

    return NGX_OK;
}

static ngx_uint_t *
ngx_http_cp_get_bl_count(ngx_http_session_ctx_t *ctx)
{
    ngx_http_cp_session_ctx_t         *cp_ctx;
    
    cp_ctx = ctx->data;

    return (ngx_uint_t *)(&(cp_ctx->bl_times));
}

static ngx_int_t
ngx_http_cp_do_action(ngx_http_request_t *r,
        ngx_str_t *cookie_name,
        ngx_str_t *cookie_value)
{
    ngx_http_cp_loc_conf_t           *cplcf;
    ngx_uint_t                        i;
    ngx_http_ns_action_t             *action;
    u_char                           *cp_name = (u_char *)"cookie_poisoning";

    cplcf = ngx_http_get_module_loc_conf(r, ngx_http_cookie_poisoning_module);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "cookie poisoning do action: %d", cplcf->action);

    if (cplcf->log_enabled) {
        ngx_http_cp_send_log(r, cookie_name, cookie_value);
    }

    if (cplcf->action == NGX_HTTP_NS_ACTION_REMOVE_COOKIE) {
        for (i = 0; i < cookie_value->len; i++) {
            cookie_value->data[i] = ' ';
        }

        return NGX_OK;
    }

    action = ngx_pcalloc(r->pool, sizeof(ngx_http_ns_action_t));
    if (action == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    action->action = cplcf->action;
    action->session_name = cp_name;
    action->get_bl_count = ngx_http_cp_get_bl_count;
    action->bl_max = cplcf->bl_times;

    if (cplcf->error_page.data != NULL) {
        action->has_redirect = 1;
        action->redirect_page = &cplcf->error_page;
        action->in_body = 0;
    }
    
    return ngx_http_ns_do_action(r, action);
}

static ngx_http_cp_monitored_cookie_t *
ngx_http_cp_check_cookie(ngx_http_request_t *r, ngx_str_t *cookie_name)
{
    ngx_http_session_t               *session;
    ngx_http_session_ctx_t           *session_ctx;
    ngx_http_cp_session_ctx_t        *cp_ctx;
    ngx_http_cp_monitored_cookie_t   *m_cookie;
    
    session = ngx_http_session_get(r);
    if (!session) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                "cp get session failed when update monitored cookies");
        return NULL;
    }
    
    ngx_shmtx_lock(&session->mutex);

    session_ctx = ngx_http_session_find_ctx(session,
            (u_char *)"cookie_poisoning");
    if (!session_ctx) {
        ngx_shmtx_unlock(&session->mutex);
        ngx_http_session_put(r);
        
        return NULL;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
            "found session ctx\n");

    cp_ctx = session_ctx->data;
    
    m_cookie = ngx_http_cp_hash_find(&cp_ctx->monitored_cookies, cookie_name);

    ngx_shmtx_unlock(&session->mutex);
    ngx_http_session_put(r);
   
    return m_cookie;
}

static ngx_int_t
ngx_http_cp_handler(ngx_http_request_t *r)
{
    ngx_http_cp_loc_conf_t           *cplcf;
    ngx_str_t                        cookie, cookie_name;
    ngx_str_t                        neteye_cookie;
#if (NGX_DEBUG)
    ngx_str_t                        cookie_magic;
#endif
    ngx_int_t                        ret;
    ngx_uint_t                       i, j;
    ngx_table_elt_t                  **h;
    u_char                           *start, *end, *p;
    ngx_http_cp_monitored_cookie_t   *m_cookie;
    
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
            "cookie poison handler begin");
    
    if (ngx_http_session_test_create(r)
            || ngx_http_session_test_bypass(r)) {
        return NGX_DECLINED;
    }

    cplcf = ngx_http_get_module_loc_conf(r, ngx_http_cookie_poisoning_module);
    
    if (!cplcf->enabled) {
        return NGX_DECLINED;
    }

    if (ngx_http_ns_test_bypass_all(r)) {
        return NGX_DECLINED;
    }
    
    memset(&cookie, 0, sizeof(ngx_str_t));
    memset(&cookie_name, 0, sizeof(ngx_str_t));
    memset(&neteye_cookie, 0, sizeof(ngx_str_t));
                
    h = r->headers_in.cookies.elts;

    for (i = 0; i < r->headers_in.cookies.nelts; i++) {
        start = p = h[i]->value.data;
        end = start + h[i]->value.len;
       
        /* skip the spaces at head */
        for (; start < end && *start == ' '; start++) { }

        if (start == end) {
            /* no more in this value */
            continue;
        }

        for (j = 0; j < h[i]->value.len; j++, p++) {
            if (*p == '=') {
                cookie_name.data = start;
                cookie_name.len = p - start;

                if (cookie_name.len == strlen(NGX_HTTP_SESSION_DEFAULT_COOKIE)) {
                    if (!memcmp(cookie_name.data,
                                NGX_HTTP_SESSION_DEFAULT_COOKIE,
                                strlen(NGX_HTTP_SESSION_DEFAULT_COOKIE))) {
                        goto next;
                    }
                }

                /* store this cookie's value to cookie */
                ret = ngx_http_parse_multi_header_lines(&r->headers_in.cookies,
                        &cookie_name, &cookie);
                if (ret == NGX_DECLINED 
                        || cookie.len == 0) {
                    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                            "BIG ERROR!");

                    goto next;
                }

                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                        "cookie_name: %V, cookie_data: %V",
                        &cookie_name, &cookie);

                m_cookie = ngx_http_cp_check_cookie(r, &cookie_name);
                if (m_cookie != NULL) {
                    /* this cookie is monitored */
                    if (ngx_http_cp_gen_cookie_data(r, &cookie,
                                &neteye_cookie, m_cookie->magic) != NGX_OK) {
                        return NGX_HTTP_INTERNAL_SERVER_ERROR;
                    }

#if (NGX_DEBUG)
                    cookie_magic.data = m_cookie->cookie_magic;
                    cookie_magic.len = NGX_HTTP_CP_MD5_LEN;

                    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                            "neteye_cookie_data: %V, expected: %V", 
                            &neteye_cookie, &cookie_magic);
#endif
                    
                    if (memcmp(m_cookie->cookie_magic, neteye_cookie.data,
                                NGX_HTTP_CP_MD5_LEN)) {
                        /* not matched, do action */
                        ret = ngx_http_cp_do_action(r, &cookie_name, &cookie);
                        if (ret != NGX_OK) {
                            return ret;
                        }
                    }
                } else {
                    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                            "cookie is not monitored");
                }

next:
                for (; start < end && *start != ';'; start++) { }

                if (start == end) {
                    /* no more in this value */
                    break;
                }

                /* *start == ';' */

                start++;
                for (; start < end && *start == ' '; start++) { }

                if (start == end) {
                    /* no more in this value */
                    break;
                }

                p = start;
            }
        }
    }

    return NGX_DECLINED;
}

ngx_int_t ngx_http_cp_header_handler(ngx_http_request_t *r)
{
    ngx_table_elt_t              *h;
    ngx_list_part_t              *part;
    ngx_http_upstream_t          *u;
    ngx_uint_t                   i, j, cmp_len;
    u_char                       *start, *end, *p;
    ngx_str_t                    cookie, cookie_name;
    ngx_str_t                    neteye_cookie;
    ngx_http_cp_loc_conf_t       *cplcf;
    ngx_uint_t                   magic;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 
            0, "cookie poison header handler");
    
    if (ngx_http_session_test_create(r)
            || ngx_http_session_test_bypass(r)) {
        return NGX_DECLINED;
    }

    if (ngx_http_ns_test_bypass_all(r)) {
        return NGX_DECLINED;
    }
    
    cplcf = ngx_http_get_module_loc_conf(r, ngx_http_cookie_poisoning_module);
    
    if (cplcf->enabled != 1) {
        /* Cookie Poison not enabled */
        return NGX_DECLINED;
    }

    u = r->upstream;
    if (u) {
        part = &u->headers_in.headers.part;
    } else {
	    /* response from local */
        part = &r->headers_out.headers.part;
    }

    if (part == NULL) {
        /* Have no headers */
        return NGX_DECLINED;
    }

    memset(&cookie, 0, sizeof(ngx_str_t));
    memset(&cookie_name, 0, sizeof(ngx_str_t));
    memset(&neteye_cookie, 0, sizeof(ngx_str_t));

    h = part->elts;

    for (i = 0; ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].key.len != strlen("Set-Cookie")) {
            continue;
        }

        if (!memcmp(h[i].key.data, "Set-Cookie", h[i].key.len)) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                    "found set cookie");

            start = p = h[i].value.data;
            end = h[i].value.data + h[i].value.len;
            
            for (j = 0; j < h[i].value.len; j++, p++) {
                if (*p == ' ' || *p == '=') {
                    cookie_name.data = start;
                    cookie_name.len = p - start;

                    /* store this cookie's value to cookie */
                    if (*p == ' ') {
                        for (; *p != '='; p++) ;
                    }

                    p++;

                    cookie.data = p;

                    for (; *p != ';' && p < end; p++) ;

                    cookie.len = p - cookie.data;

                    if (cookie.len == 0) {
                        break;
                    }

                    cmp_len = cookie.len >= strlen("deleted") ? 
                        strlen("deleted") : cookie.len;

                    if (!strncmp((char *)cookie.data, "deleted", cmp_len)) {
                        /* update monitored cookies in session*/
                        ngx_http_cp_delete_monitored_cookies(r, &cookie_name);
                        break;
                    }

                    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                            "cookie_name: %V, cookie_data: %V", 
                            &cookie_name, &cookie);
                    
                    /* md5 the cookie_data, and add it to the header */
                   
                    magic = ngx_random();
                    if (ngx_http_cp_gen_cookie_data(r, &cookie,
                                &neteye_cookie, magic)
                            != NGX_OK) {
                        return NGX_HTTP_INTERNAL_SERVER_ERROR;
                    }

                    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                            "neteye_cookie_data: %V",
                            &neteye_cookie);
                    
                    /* update monitored cookies in session*/
                    ngx_http_cp_update_monitored_cookies(r,
                            &cookie_name, &neteye_cookie, magic);

                    break;
                }
            }
        }
    }

    return NGX_DECLINED;
}

static void
ngx_http_cp_create_session_ctx(ngx_http_session_t *session)
{
    ngx_http_session_ctx_t           *session_ctx;
    ngx_http_cp_session_ctx_t        *cp_ctx;
    
    session_ctx = ngx_http_session_create_ctx(session,
            (u_char *)"cookie_poisoning",
            ngx_http_cp_init_session_ctx_handler,
            ngx_http_cp_destroy_session_ctx_handler);
    if (!session_ctx) {
        return;
    }

    /* init cp_ctx */
    cp_ctx = session_ctx->data;

    cp_ctx->bl_times = 0;
    ngx_http_cp_hash_init(&cp_ctx->monitored_cookies,
            NGX_HTTP_CP_DEFAULT_BUCKETS_NUM);
}
