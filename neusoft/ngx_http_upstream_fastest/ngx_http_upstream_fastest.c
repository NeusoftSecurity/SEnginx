/*
 * Copyright (c) 2013 Neusoft Corperation., Ltd.
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#if (NGX_HTTP_PERSISTENCE)
#include <ngx_http_upstream_persistence.h>
#endif

#define NGX_HTTP_FASTEST_VALID_TIME_LENGTH          (60*1000)      //ms

typedef struct {
    ngx_uint_t                          response_msec;
    ngx_uint_t                          last_access_msec;
} ngx_http_upstream_fastest_access_t;

typedef struct {
    ngx_http_upstream_fastest_access_t  *conns;
} ngx_http_upstream_fastest_conf_t;


typedef struct {
    /* the round robin data must be first */
    ngx_http_upstream_rr_peer_data_t   rrp;

    ngx_http_upstream_fastest_access_t *conns;
    ngx_uint_t                         accessed_msec;
    ngx_uint_t                         current;

    ngx_event_get_peer_pt              get_rr_peer;
    ngx_event_free_peer_pt             free_rr_peer;
} ngx_http_upstream_ft_peer_data_t;


static ngx_int_t ngx_http_upstream_init_fastest_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_get_fastest_peer(
    ngx_peer_connection_t *pc, void *data);
static void ngx_http_upstream_free_fastest_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t state);
static void *ngx_http_upstream_fastest_create_conf(ngx_conf_t *cf);
static char *ngx_http_upstream_fastest(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_http_upstream_fastest_commands[] = {

    { ngx_string("fastest"),
      NGX_HTTP_UPS_CONF|NGX_CONF_NOARGS,
      ngx_http_upstream_fastest,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_upstream_fastest_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_upstream_fastest_create_conf, /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_upstream_fastest_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_fastest_module_ctx, /* module context */
    ngx_http_upstream_fastest_commands, /* module directives */
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
ngx_http_upstream_reinit_fastest(ngx_http_request_t *r, ngx_pool_t *pool,
    ngx_http_upstream_srv_conf_t *us, void *data)
{
    ngx_uint_t                            n;
    ngx_http_upstream_rr_peers_t         *peers;
    ngx_http_upstream_fastest_conf_t  *lcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "reinit fastest");

    peers = data;

    n = peers->number;

    if (peers->next) {
        n += peers->next->number;
    }

    lcf = ngx_http_conf_upstream_srv_conf(us,
                                          ngx_http_upstream_fastest_module);

    if (lcf->conns) {
        ngx_pfree(pool, lcf->conns);
    }

    lcf->conns = ngx_pcalloc(pool,
            sizeof(ngx_http_upstream_fastest_access_t) * n);
    if (lcf->conns == NULL) {
        return NGX_ERROR;
    }

    if (us->peer.init(r, us) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_init_fastest(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_uint_t                            n;
    ngx_http_upstream_rr_peers_t         *peers;
    ngx_http_upstream_fastest_conf_t  *lcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                   "init fastest");

    if (ngx_http_upstream_init_round_robin(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }

    peers = us->peer.data;

    n = peers->number;

    if (peers->next) {
        n += peers->next->number;
    }

    lcf = ngx_http_conf_upstream_srv_conf(us,
                                          ngx_http_upstream_fastest_module);

    lcf->conns = ngx_pcalloc(cf->pool,
            sizeof(ngx_http_upstream_fastest_access_t) * n);
    if (lcf->conns == NULL) {
        return NGX_ERROR;
    }

    us->peer.init = ngx_http_upstream_init_fastest_peer;
    us->peer.reinit_upstream = ngx_http_upstream_reinit_fastest;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_init_fastest_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_http_upstream_ft_peer_data_t     *fp;
    ngx_http_upstream_fastest_conf_t  *fcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "init fastest peer");

    fcf = ngx_http_conf_upstream_srv_conf(us,
                                          ngx_http_upstream_fastest_module);

    fp = ngx_palloc(r->pool, sizeof(ngx_http_upstream_ft_peer_data_t));
    if (fp == NULL) {
        return NGX_ERROR;
    }

    fp->conns = fcf->conns;

    r->upstream->peer.data = &fp->rrp;
    fp->rrp.dyn_peers = NULL;

    if (ngx_http_upstream_init_round_robin_peer(r, us) != NGX_OK) {
        return NGX_ERROR;
    }

    r->upstream->peer.get = ngx_http_upstream_get_fastest_peer;
    r->upstream->peer.free = ngx_http_upstream_free_fastest_peer;

    fp->get_rr_peer = ngx_http_upstream_get_round_robin_peer;
    fp->free_rr_peer = ngx_http_upstream_free_round_robin_peer;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_get_fastest_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_ft_peer_data_t  *fp = data;

    time_t                         now;
    uintptr_t                      m;
    ngx_int_t                      rc;
    ngx_uint_t                     i, n, p;
    ngx_uint_t                     elapsed;
    ngx_http_upstream_rr_peer_t   *peer, *best;
    ngx_http_upstream_rr_peers_t  *peers;
#if (NGX_HTTP_PERSISTENCE)
    ngx_int_t                      persist_index;
#endif

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "get fastest peer, try: %ui", pc->tries);

    if (fp->rrp.peers->single) {
        return fp->get_rr_peer(pc, &fp->rrp);
    }

    pc->cached = 0;
    pc->connection = NULL;

    now = ngx_time();

    peers = fp->rrp.peers;

    best = NULL;

    p = 0;

#if (NGX_HTTP_PERSISTENCE)
    persist_index = ngx_http_upstream_ps_get(fp->rrp.request,
        fp->rrp.peers->number, fp->rrp.group);
#endif
    for (i = 0; i < peers->number; i++) {
#if (NGX_HTTP_PERSISTENCE)
        if(persist_index >= 0) {
            i = persist_index;
        }
#endif
        n = i / (8 * sizeof(uintptr_t));
        m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));

        if (fp->rrp.tried[n] & m) {
#if (NGX_HTTP_PERSISTENCE)
            if(persist_index >= 0) {
                persist_index = -1;
                i = 0;
            }
#endif
            continue;
        }

        peer = &peers->peer[i];

        if (peer->down) {
#if (NGX_HTTP_PERSISTENCE)
            if(persist_index >= 0) {
                persist_index = -1;
                i = 0;
            }
#endif
            continue;
        }

#if (NGX_HTTP_UPSTREAM_CHECK)
        if (ngx_http_upstream_check_peer_down(peer->check_index)) {
            continue;
        }
#endif

        if (peer->max_fails
            && peer->fails >= peer->max_fails
            && now - peer->checked <= peer->fail_timeout)
        {
#if (NGX_HTTP_PERSISTENCE)
            if(persist_index >= 0) {
                persist_index = -1;
                i = 0;
            }
#endif
            continue;
        }

#if (NGX_HTTP_PERSISTENCE)
        if(persist_index >= 0) {
            best = peer;
            break;
        }
#endif
        elapsed = ngx_current_msec - fp->conns[i].last_access_msec;
        if (elapsed > NGX_HTTP_FASTEST_VALID_TIME_LENGTH) {
            fp->conns[i].response_msec = 0;
        }

        if (best == NULL
            || fp->conns[i].response_msec < fp->conns[p].response_msec) {
            best = peer;
            p = i;
        }
    }

    if (best == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "get fastest peer, no peer found");

        goto failed;
    }

    best->checked = now;

    pc->sockaddr = best->sockaddr;
    pc->socklen = best->socklen;
    pc->name = &best->name;
    pc->host = &best->host;
    pc->dyn_resolve = best->dyn_resolve;

    fp->rrp.current = best;
    fp->current = p;

    n = p / (8 * sizeof(uintptr_t));
    m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));

    fp->rrp.tried[n] |= m;

    if (pc->tries == 1 && peers->next) {
        pc->tries += peers->next->number;
    }

    fp->accessed_msec = ngx_current_msec;

#if (NGX_HTTP_PERSISTENCE)
    ngx_http_upstream_ps_set(fp->rrp.request, p,
            fp->rrp.group);
#endif
    return NGX_OK;

failed:

    if (peers->next) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "get fastest peer, backup servers");

        fp->conns += peers->number;

        fp->rrp.peers = peers->next;
        pc->tries = fp->rrp.peers->number;

        n = (fp->rrp.peers->number + (8 * sizeof(uintptr_t) - 1))
                / (8 * sizeof(uintptr_t));

        for (i = 0; i < n; i++) {
             fp->rrp.tried[i] = 0;
        }

        rc = ngx_http_upstream_get_fastest_peer(pc, fp);

        if (rc != NGX_BUSY) {
            return rc;
        }
    }

    /* all peers failed, mark them as live for quick recovery */

    for (i = 0; i < peers->number; i++) {
        peers->peer[i].fails = 0;
    }

    pc->name = peers->name;

    return NGX_BUSY;
}


static void
ngx_http_upstream_free_fastest_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t state)
{
    ngx_http_upstream_ft_peer_data_t    *fp = data;
    ngx_uint_t                          elapsed;
    ngx_http_upstream_fastest_access_t  *peer;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "free fastest peer %ui %ui", pc->tries, state);

    if (fp->rrp.peers->single) {
        fp->free_rr_peer(pc, &fp->rrp, state);
        return;
    }

    if (state == 0 && pc->tries == 0) {
        return;
    }

    elapsed = ngx_current_msec - fp->accessed_msec;
    peer = &fp->conns[fp->current];

    if (elapsed == 0) {
        elapsed = 1;
    }

    if (elapsed < peer->response_msec || peer->response_msec == 0) {
        peer->response_msec = elapsed;
    } else {
        peer->response_msec = (elapsed + peer->response_msec * 7) / 8;
    }

    peer->last_access_msec = ngx_current_msec;

    fp->free_rr_peer(pc, &fp->rrp, state);
}


static void *
ngx_http_upstream_fastest_create_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_fastest_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool,
                       sizeof(ngx_http_upstream_fastest_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->conns = NULL;
     */

    return conf;
}


static char *
ngx_http_upstream_fastest(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upstream_srv_conf_t  *uscf;

    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

    uscf->peer.init_upstream = ngx_http_upstream_init_fastest;

    uscf->flags = NGX_HTTP_UPSTREAM_CREATE
                  |NGX_HTTP_UPSTREAM_MAX_FAILS
                  |NGX_HTTP_UPSTREAM_FAIL_TIMEOUT
                  |NGX_HTTP_UPSTREAM_DOWN
                  |NGX_HTTP_UPSTREAM_BACKUP;

    return NGX_CONF_OK;
}
