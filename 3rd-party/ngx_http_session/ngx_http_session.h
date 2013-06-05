/*
 * Copyright (c) 2013 Neusoft Corperation., Ltd.
 */
#ifndef _NGX_HTTP_SESSION_H_INCLUDED_
#define _NGX_HTTP_SESSION_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define NGX_HTTP_SESSION_DEFAULT_TMOUT              60 * 1000
#define NGX_HTTP_SESSION_DEFAULT_REDIRECT_TMOUT     5 * 1000
#define NGX_HTTP_SESSION_DEFAULT_NUMBER             50000
#define NGX_HTTP_SESSION_DEFAULT_COOKIE             "NetEye-ADSG-SID"
#define NGX_HTTP_SESSION_CTX_SIZE                   512
#define NGX_HTTP_SESSION_MAX_CTX                    32
#define NGX_HTTP_SESSION_CTX_NAME_LEN               32
#define MD5_LEN                                     32
#define NGX_HTTP_SESSION_DEFAULT_SID_LEN            MD5_LEN

typedef struct {
    ngx_int_t in_use;
    u_char name[NGX_HTTP_SESSION_CTX_NAME_LEN];

    void *data;
    void (*destroy)(void *ctx);
    
    ngx_shmtx_t       mutex;
    ngx_atomic_t      lock;
} ngx_http_session_ctx_t;

typedef struct {
    u_char     found:1;
    u_char     create:1;
    u_char     bypass:1;
    u_char     local:1;
    void      *session;
} ngx_http_session_request_ctx_t;

typedef ngx_int_t (*ngx_http_session_init_ctx_t)(void *ctx);
typedef void (*ngx_http_session_destroy_ctx_t)(void *data);

typedef struct {
    char                    id[NGX_HTTP_SESSION_DEFAULT_SID_LEN];                  /* session id */
    
    void                    *next;
    void                    *prev;

    void                    *new_chain_next;
    ngx_queue_t             redirect_queue_node;
    
    void                    **slot;                    /* point to sessions list, only the first node has this */

    int                     ref;                        /* ref count */
    int                     des;                        /* should be destroyed or not */
    int                     timed;                      /* should be destroyed or not */
    int                     reset;                      /* need to reset timer */
    int                     wait;                       /* on the new session chain */
    
    time_t                  est;                     /* time of creating/reseting */
    
    ngx_int_t               timeout;              /* session timeout */
    ngx_int_t               bl_timeout;           /* timeout of blacklist */
    ngx_event_t             ev;                 /* ngx_event, used to establish timer */

    ngx_http_session_ctx_t  ctx[NGX_HTTP_SESSION_MAX_CTX];    /* store other modules' ctx */
    ngx_shmtx_t             mutex;
    ngx_atomic_t            lock;
} ngx_http_session_t;

typedef struct {
    ngx_slab_pool_t        *shpool;
    ngx_log_t              *log;
    
    ngx_http_session_t     *sessions[NGX_HTTP_SESSION_DEFAULT_NUMBER]; /* the hash table */
    ngx_http_session_t     *new_chain_head, *new_chain_tail;
    ngx_queue_t             redirect_queue_head;
    ngx_int_t               redirect_num;           /* the number of redirecting session */
} ngx_http_session_list_t;

typedef struct {
    ngx_int_t              enabled;
    ngx_int_t              timeout;  /* in seconds */
    ngx_int_t              bl_timeout;  /* in seconds */
    ngx_int_t              redirect_timeout;  /* in seconds */
    ngx_str_t              keyword;
    ngx_int_t              session_show_enabled;
} ngx_http_session_conf_t;

/* APIs */
ngx_int_t 
ngx_http_session_delete(ngx_http_request_t *r);

void * ngx_http_session_shm_alloc(size_t size);
void ngx_http_session_shm_free(void *);

void * ngx_http_session_shm_alloc_nolock(size_t size);
void ngx_http_session_shm_free_nolock(void *);

ngx_http_session_ctx_t * 
ngx_http_session_create_ctx(ngx_http_session_t *session, u_char *name, 
        ngx_int_t (*init)(void *ctx), void (*destroy)(void *data));

ngx_http_session_ctx_t * 
ngx_http_session_find_ctx(ngx_http_session_t *session, u_char *name);

void
ngx_http_session_destroy_ctx(ngx_http_session_t *session, u_char *name);

ngx_http_session_t * ngx_http_session_get(ngx_http_request_t *r);
void ngx_http_session_put(ngx_http_request_t *r);


void 
ngx_http_session_set_request_session(ngx_http_request_t *r, 
        ngx_http_session_t *session);
ngx_http_session_t * 
ngx_http_session_get_request_session(ngx_http_request_t *r);
void 
ngx_http_session_clr_request_session(ngx_http_request_t *r);

void ngx_http_session_set_found(ngx_http_request_t *r);
void ngx_http_session_set_create(ngx_http_request_t *r);
void ngx_http_session_set_bypass(ngx_http_request_t *r);
void ngx_http_session_set_local(ngx_http_request_t *r);

void ngx_http_session_clr_found(ngx_http_request_t *r);
void ngx_http_session_clr_create(ngx_http_request_t *r);
void ngx_http_session_clr_bypass(ngx_http_request_t *r);
void ngx_http_session_clr_local(ngx_http_request_t *r);

ngx_uint_t ngx_http_session_test_found(ngx_http_request_t *r);
ngx_uint_t ngx_http_session_test_create(ngx_http_request_t *r);
ngx_uint_t ngx_http_session_test_bypass(ngx_http_request_t *r);
ngx_uint_t ngx_http_session_test_local(ngx_http_request_t *r);

ngx_int_t
ngx_http_session_is_enabled(ngx_http_request_t *r);

ngx_int_t
ngx_http_session_get_bl_timeout(ngx_http_request_t *r);

#endif
