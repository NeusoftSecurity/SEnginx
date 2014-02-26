/**
 * ngx_http_web_defacement.c
 *
 * by Paul Yang <y_y@neusoft.com>
 *
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_core_module.h>

#include <ngx_http_web_defacement.h>
#include <ngx_md5.h>


static ngx_int_t
ngx_http_wd_add_variables(ngx_conf_t *cf);
#if (NGX_HTTP_NETEYE_SECURITY)
static ngx_int_t
ngx_http_wd_request_ctx_init(ngx_http_request_t *r);
#endif
static ngx_int_t
ngx_http_wd_file_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t
ngx_http_wd_deface_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t
ngx_http_wd_handler(ngx_http_request_t *r);
static char *
ngx_http_wd(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *
ngx_http_wd_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *
ngx_http_wd_original(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *
ngx_http_wd_hash_data(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *
ngx_http_wd_index(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t
ngx_http_wd_init(ngx_conf_t *cf);
static void *
ngx_http_wd_create_loc_conf(ngx_conf_t *cf);
static char *
ngx_http_wd_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static char *
ngx_http_wd_whitelist(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t ngx_http_wd_commands[] = {

    { ngx_string("web_defacement"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_http_wd,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },

    { ngx_string("web_defacement_log"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_http_wd_log,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },

    { ngx_string("web_defacement_original"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_http_wd_original,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },

    { ngx_string("web_defacement_hash_data"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_http_wd_hash_data,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },

    { ngx_string("web_defacement_index"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_http_wd_index,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },

    { ngx_string("web_defacement_whitelist"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
        ngx_http_wd_whitelist,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },

    ngx_null_command,
};

static ngx_http_variable_t  ngx_http_wd_vars[] = {

    { ngx_string("web_defacement"), NULL, ngx_http_wd_deface_variable, 0,
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("web_defacement_file"), NULL, ngx_http_wd_file_variable, 0,
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};



static ngx_http_module_t ngx_http_wd_module_ctx = {
    ngx_http_wd_add_variables,            /* preconfiguration */
    ngx_http_wd_init,                     /* postconfiguration */

    NULL,                                 /* create main configuration */
    NULL,                                 /* init main configuration */

    NULL,                                 /* create server configuration */
    NULL,                                 /* merge server configuration */

    ngx_http_wd_create_loc_conf,          /* create location configuration */
    ngx_http_wd_merge_loc_conf            /* merge location configuration */
};


ngx_module_t ngx_http_web_defacement_module = {
    NGX_MODULE_V1,
    &ngx_http_wd_module_ctx,               /* module context */
    ngx_http_wd_commands,                  /* module directives */
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
ngx_http_wd_init(ngx_conf_t *cf)
{
#if (NGX_HTTP_NETEYE_SECURITY)
    ngx_int_t ret;

    ret = ngx_http_neteye_security_ctx_register(NGX_HTTP_NETEYE_WEB_DEFACEMENT,
            ngx_http_wd_request_ctx_init);

    if (ret != NGX_OK) {
        return ret;
    }

    return ngx_http_neteye_security_request_register(
            NGX_HTTP_NETEYE_WEB_DEFACEMENT, ngx_http_wd_handler);
#else
    ngx_http_handler_pt         *h;
    ngx_http_core_main_conf_t   *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
    if (h == NULL)
        return NGX_ERROR;

    *h = ngx_http_wd_handler;

    return NGX_OK;
#endif
}

static char *
ngx_http_wd(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_wd_loc_conf_t *wdlcf = conf;
    ngx_str_t              *value;

    value = cf->args->elts;
    if (!strncmp((char *)(value[1].data), "on", value[1].len)) {
        wdlcf->enabled = 1;
    }
    
    return NGX_CONF_OK;
}

static char *
ngx_http_wd_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_wd_loc_conf_t      *wdlcf = conf;
    ngx_str_t                   *value;

    value = cf->args->elts;
    if (!strncmp((char *)(value[1].data), "on", value[1].len)) {
        wdlcf->log_enabled = 1;
    }
 
    return NGX_CONF_OK;
}

static char *
ngx_http_wd_parse_path(ngx_conf_t *cf, ngx_str_t *conf_path)
{
    ngx_str_t               *value;
    ngx_str_t               path;
    size_t                  i;
    int                     label;

    value = cf->args->elts;
    path = value[1];

    if (ngx_conf_full_name(cf->cycle, &path, 1) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    while (conf_path->len > 1) {
        if (conf_path->data[conf_path->len - 1] != '/') {
            break;
        }
        conf_path->len--;
    }

    conf_path->data = ngx_pcalloc(cf->pool, path.len);
    if (conf_path->data == NULL) {
        return NGX_CONF_ERROR;
    }

    conf_path->len = 0;
    for (i = 0, label = 0; i < path.len; i++) {
        if (path.data[i] == '/') {
            if (label == 0) {
                label = 1;
                conf_path->data[conf_path->len] = path.data[i];
                conf_path->len++;
            } else {
                continue;
            }
        } else {
            label = 0;
            conf_path->data[conf_path->len] = path.data[i];
            conf_path->len++;
        }
    }

    if (conf_path->data[conf_path->len - 1] == '/') {
        conf_path->len--;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_wd_original(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_wd_loc_conf_t  *wdlcf = conf;

    return ngx_http_wd_parse_path(cf, &wdlcf->orig_path);
}

static void 
htoi(unsigned char *output, char *hex) 
{
    int count = 0;
    char *s;

    for(s = hex; strlen(s) > 0 && count < 16; s += 2) {
        if(*s >= '0' && *s <= '9') {
            output[count] = *s - '0';
        } else if(*s >= 'A' && *s <= 'F') {
            output[count] = *s -'A' + 10;
        } else if(*s >= 'a' && *s <= 'f') {
            output[count] = *s -'a' + 10;
        }

        if(strlen(s) > 1) {
            output[count] <<= 4;
            if(*(s + 1) >= '0' && *(s + 1) <= '9') {
                output[count++] += (*(s + 1) - '0');
            } else if(*(s + 1) >= 'A'&& *(s + 1) <= 'F') {
                output[count++] += (*(s + 1) - 'A' + 10);
            } else if(*(s + 1) >= 'a'&& *(s + 1) <= 'f') {
                output[count++] += (*(s + 1) - 'a' + 10);
            }
        }
    }
}

#define NGX_HASH_ELT_SIZE(name)                                               \
    (sizeof(void *) + ngx_align((name)->key.len + 2, sizeof(void *)))

static ngx_int_t
ngx_wd_hash_init(ngx_hash_init_t *hinit, ngx_hash_key_t *names, ngx_uint_t nelts)
{
    u_char          *elts;
    size_t           len;
    u_short         *test;
    ngx_uint_t       i, n, key, size, start, bucket_size;
    ngx_hash_elt_t  *elt, **buckets;

    for (n = 0; n < nelts; n++) {
        if (hinit->bucket_size < NGX_HASH_ELT_SIZE(&names[n]) + sizeof(void *))
        {
            ngx_log_error(NGX_LOG_EMERG, hinit->pool->log, 0,
                          "could not build the %s, you should "
                          "increase %s_bucket_size: %i",
                          hinit->name, hinit->name, hinit->bucket_size);
            return NGX_ERROR;
        }
    }

    test = ngx_alloc(hinit->max_size * sizeof(u_short), hinit->pool->log);
    if (test == NULL) {
        return NGX_ERROR;
    }

    bucket_size = hinit->bucket_size - sizeof(void *);

    start = nelts / (bucket_size / (2 * sizeof(void *)));
    start = start ? start : 1;

    if (hinit->max_size > 10000 && nelts && hinit->max_size / nelts < 100) {
        start = hinit->max_size - 1000;
    }

    for (size = start; size < hinit->max_size; size++) {

        ngx_memzero(test, size * sizeof(u_short));

        for (n = 0; n < nelts; n++) {
            if (names[n].key.data == NULL) {
                continue;
            }

            key = names[n].key_hash % size;
            test[key] = (u_short) (test[key] + NGX_HASH_ELT_SIZE(&names[n]));

            if (test[key] > (u_short) bucket_size) {
                goto next;
            }
        }

        goto found;

    next:

        continue;
    }

    ngx_log_error(NGX_LOG_EMERG, hinit->pool->log, 0,
                  "could not build the %s, you should increase "
                  "either %s_max_size: %i or %s_bucket_size: %i",
                  hinit->name, hinit->name, hinit->max_size,
                  hinit->name, hinit->bucket_size);

    ngx_free(test);

    return NGX_ERROR;

found:

    for (i = 0; i < size; i++) {
        test[i] = sizeof(void *);
    }

    for (n = 0; n < nelts; n++) {
        if (names[n].key.data == NULL) {
            continue;
        }

        key = names[n].key_hash % size;
        test[key] = (u_short) (test[key] + NGX_HASH_ELT_SIZE(&names[n]));
    }

    len = 0;

    for (i = 0; i < size; i++) {
        if (test[i] == sizeof(void *)) {
            continue;
        }

        test[i] = (u_short) (ngx_align(test[i], ngx_cacheline_size));

        len += test[i];
    }

    if (hinit->hash == NULL) {
        hinit->hash = ngx_pcalloc(hinit->pool, sizeof(ngx_hash_wildcard_t)
                                             + size * sizeof(ngx_hash_elt_t *));
        if (hinit->hash == NULL) {
            ngx_free(test);
            return NGX_ERROR;
        }

        buckets = (ngx_hash_elt_t **)
                      ((u_char *) hinit->hash + sizeof(ngx_hash_wildcard_t));

    } else {
        buckets = ngx_pcalloc(hinit->pool, size * sizeof(ngx_hash_elt_t *));
        if (buckets == NULL) {
            ngx_free(test);
            return NGX_ERROR;
        }
    }

    elts = ngx_palloc(hinit->pool, len + ngx_cacheline_size);
    if (elts == NULL) {
        ngx_free(test);
        return NGX_ERROR;
    }

    elts = ngx_align_ptr(elts, ngx_cacheline_size);

    for (i = 0; i < size; i++) {
        if (test[i] == sizeof(void *)) {
            continue;
        }

        buckets[i] = (ngx_hash_elt_t *) elts;
        elts += test[i];

    }

    for (i = 0; i < size; i++) {
        test[i] = 0;
    }

    for (n = 0; n < nelts; n++) {
        if (names[n].key.data == NULL) {
            continue;
        }

        key = names[n].key_hash % size;
        elt = (ngx_hash_elt_t *) ((u_char *) buckets[key] + test[key]);

        elt->value = names[n].value;
        elt->len = (u_short) names[n].key.len;

        strncpy((char *)elt->name, (char *)names[n].key.data, names[n].key.len);

        test[key] = (u_short) (test[key] + NGX_HASH_ELT_SIZE(&names[n]));
    }

    for (i = 0; i < size; i++) {
        if (buckets[i] == NULL) {
            continue;
        }

        elt = (ngx_hash_elt_t *) ((u_char *) buckets[i] + test[i]);

        elt->value = NULL;
    }

    ngx_free(test);

    hinit->hash->buckets = buckets;
    hinit->hash->size = size;

    return NGX_OK;
}


static char *
ngx_http_wd_hash_data(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t               *value, file;
    FILE                    *stream;
    ngx_array_t             file_names;
    ngx_hash_key_t          *fk;
    ngx_hash_init_t         file_hash;
    struct stat             fstat;
    int                     size;
    char                    *buf, *data_file, *hash;
    char                    *ret = NGX_CONF_OK;
    const char              *split = "\001";
    int                     line_num = 0;
    ngx_http_wd_loc_conf_t  *wdlcf = conf;

    value = cf->args->elts;
    file = value[1];

    if (ngx_conf_full_name(cf->cycle, &file, 1) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    size = stat((char *)file.data, &fstat);
    if (size < 0) {
        return NGX_CONF_ERROR;
    }

    if (fstat.st_size == 0) {
        return NGX_CONF_ERROR;
    }

    buf = malloc(fstat.st_size);
    if (buf == NULL) {
        return NGX_CONF_ERROR;
    }

    stream = fopen((char *)file.data, "r");
    if (stream == NULL) {
        free(buf);
        return NGX_CONF_ERROR;
    }

    /* Get the total line number of hash file */
    while (fgets(buf, fstat.st_size, stream)) {
        line_num++;
    }

    if (fseek(stream, 0, SEEK_SET) < 0) {
        ret = NGX_CONF_ERROR;
        goto out;
    }

    if (ngx_array_init(&file_names, cf->pool, line_num, 
                sizeof(ngx_hash_key_t)) != NGX_OK) {
        ret = NGX_CONF_ERROR;
        goto out;
    }

    while (fgets(buf, fstat.st_size, stream)) {
        data_file = strtok(buf, split);
        if (data_file == NULL) {
            ret = "Invalid hash file";
            goto out;
        }

        hash = strtok(NULL, split);
        if (hash == NULL) {
            ret = "Invalid hash file";
            goto out;
        }

        fk = ngx_array_push(&file_names);
        if (fk == NULL) {
            ret = NGX_CONF_ERROR;
            goto out;
        }

        fk->key.len = strlen(data_file);
        fk->key.data = ngx_pcalloc(cf->pool, fk->key.len);
        if (fk->key.data == NULL) {
            ret = NGX_CONF_ERROR;
            goto out;
        }

        memcpy(fk->key.data, data_file, fk->key.len);
        fk->key_hash = ngx_hash_key_lc(fk->key.data, fk->key.len);
        fk->value = ngx_pcalloc(cf->pool, 16);
        if (fk->value == NULL) {
            ret = NGX_CONF_ERROR;
            goto out;
        }
        htoi(fk->value, hash);
    }

    file_hash.hash = &wdlcf->file_name_hash;
    file_hash.key = ngx_hash_key_lc;
    file_hash.max_size = 10000;
    file_hash.bucket_size = 512;
    file_hash.name = "web_defacement_file_hash";
    file_hash.pool = cf->pool;
    file_hash.temp_pool = NULL;
    
    if (ngx_wd_hash_init(&file_hash, file_names.elts, 
                file_names.nelts) != NGX_OK) {
        ret = NGX_CONF_ERROR;
    }

out:
    free(buf);
    fclose(stream);

    return ret;
}

static char *
ngx_http_wd_index(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_wd_loc_conf_t *wdlcf = conf;
    ngx_str_t              *value;

    value = cf->args->elts;
    wdlcf->index_file = value[1];
 
    return NGX_CONF_OK;
}

static void *
ngx_http_wd_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_wd_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_wd_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enabled = NGX_CONF_UNSET;
    conf->log_enabled = NGX_CONF_UNSET;
    memset(&conf->file_name_hash, 0 , sizeof(conf->file_name_hash));

    ngx_http_wl_init_vars(&conf->whitelist);

    return conf;
}

static char *
ngx_http_wd_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_wd_loc_conf_t  *prev = parent;
    ngx_http_wd_loc_conf_t  *conf = child;

    ngx_conf_merge_value(conf->enabled, prev->enabled, 0);
    ngx_conf_merge_value(conf->log_enabled, prev->log_enabled, 0);
    ngx_conf_merge_str_value(conf->orig_path, prev->orig_path, "");
    ngx_conf_merge_str_value(conf->index_file, prev->index_file, "");

    if (conf->file_name_hash.buckets == NULL && 
            prev->file_name_hash.buckets != NULL) {
        conf->file_name_hash = prev->file_name_hash;
    }

    ngx_http_wl_merge_vars(&prev->whitelist, &conf->whitelist);

    return NGX_CONF_OK;
}

static void
ngx_http_wd_write_attack_log(ngx_http_request_t *r)
{  
#ifndef NGX_HTTP_NETEYE_SECURITY
    char                        *agent = NULL;
    char                        *do_action = "running ";
    ngx_connection_t            *connection;
    ngx_log_t                   *log;
    char                        *module_name = "web_defacement";
#endif

#if (NGX_HTTP_NETEYE_SECURITY)
    ngx_http_neteye_send_attack_log(r, NGX_HTTP_NETEYE_ATTACK_LOG_ID_WD, 
            ngx_string(""), "web_defacement", NULL);
#else
    connection = r->connection;
    if (r->headers_in.user_agent != NULL) {
        agent = ngx_pcalloc(r->pool, 
                r->headers_in.user_agent->value.len + 1);
        if (!agent) {
            return;
        }

        memcpy(agent, r->headers_in.user_agent->value.data, 
                r->headers_in.user_agent->value.len);
    } else {
        agent = "n/a";
    }

    log = connection->log;
    log->action = ngx_pcalloc(r->pool, ngx_strlen(do_action) + 
            ngx_strlen(module_name) + 1);
    if (log->action == NULL) {
        return;
    }
    strcpy(log->action, do_action);
    strcpy(log->action + ngx_strlen(do_action), module_name);

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "%s: agent: \"%s\"", 
            "web_defacement", agent);
#endif
}

#if (NGX_HTTP_NETEYE_SECURITY)
static ngx_int_t
ngx_http_wd_request_ctx_init(ngx_http_request_t *r)
{
    ngx_http_wd_ctx_t    *ctx;

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_wd_ctx_t));
    if (ctx == NULL)
        return NGX_ERROR;

    ngx_http_ns_set_ctx(r, ctx, ngx_http_web_defacement_module);

    return NGX_OK;
}
#endif

static ngx_int_t
ngx_http_wd_handler(ngx_http_request_t *r)
{
    ngx_http_wd_loc_conf_t              *wdlcf;
    ngx_str_t                           file_path;
    u_char                              *p, *n;
    u_char                              *hash_value;
    u_char                              buf[1024] = {};
    u_char                              md5_digest[16];
    ngx_md5_t                           md5;
    int                                 fd, uri_len;
    ngx_uint_t                          key;
    ssize_t                             rlen;
    ngx_http_wd_ctx_t                  *ctx;
    
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
            "web defacement handler begin");
    
    wdlcf = ngx_http_get_module_loc_conf(r, ngx_http_web_defacement_module);
    
    if (!wdlcf->enabled || wdlcf->file_name_hash.buckets == NULL) {
        return NGX_DECLINED;
    }

    if (ngx_http_wl_check_whitelist(r, &wdlcf->whitelist) == NGX_OK) {
        return NGX_DECLINED;
    }

#if (NGX_HTTP_NETEYE_SECURITY)
    ctx = ngx_http_ns_get_module_ctx(r, ngx_http_web_defacement_module);
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
#else
    ctx = ngx_http_get_module_ctx(r, ngx_http_web_defacement_module);

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "web defacement module: r=%p, ctx=%p, uri=%p",
                   r, ctx, &r->uri);

    if(ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_wd_ctx_t));
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_http_set_ctx(r, ctx, ngx_http_web_defacement_module);
    }
#endif

    uri_len = r->uri.len;
    // Get dir
    if (r->uri.data[r->uri.len - 1] == '/') {
        uri_len += wdlcf->index_file.len;
    }
    n = ngx_pnalloc(r->pool, wdlcf->orig_path.len + uri_len + 1);
    if (n == NULL) {
        return NGX_ERROR;
    }

    p = ngx_cpymem(n, wdlcf->orig_path.data, wdlcf->orig_path.len);
    if (r->uri.data[r->uri.len - 1] == '/' && wdlcf->index_file.len > 0) {
        p = ngx_cpymem(p, r->uri.data, r->uri.len);
        ngx_cpystrn(p, wdlcf->index_file.data, wdlcf->index_file.len + 1);
    } else {
        ngx_cpystrn(p, r->uri.data, r->uri.len + 1);
    }

    file_path.len = wdlcf->orig_path.len + uri_len;
    file_path.data = n;

    key = ngx_hash_key_lc(file_path.data, file_path.len);
    hash_value = ngx_hash_find(&wdlcf->file_name_hash, key, 
            file_path.data, file_path.len);
    if (hash_value == NULL) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                "In hash, can't find file %V, pass", &file_path);
        return NGX_DECLINED;
    } else {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "Find file %s", (char *)file_path.data);
    }

    fd = open((const char *)file_path.data, O_RDONLY);
    if (fd < 0) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "Can't open file: %V", &file_path);
do_action:
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "The uri is defaced, set variables");
        ctx->defaced = 1;
        ctx->file.data = r->uri.data;
        ctx->file.len = r->uri.len;

        if (wdlcf->log_enabled) {
            ngx_http_wd_write_attack_log(r);
        }

        return NGX_DECLINED;
    }

    ngx_md5_init(&md5);

    while (1) {
        rlen = read(fd, buf, sizeof(buf));
        if (rlen < 0) {
            close(fd);
            goto do_action;
        }

        if (rlen == 0) {
            break;
        }

        ngx_md5_update(&md5, (void *)buf, rlen);
    }

    close(fd);
    ngx_md5_final(md5_digest, &md5);

    if (memcmp(hash_value, md5_digest, sizeof(md5_digest)) != 0) {
        goto do_action;
    }

    return NGX_DECLINED;
}

static ngx_int_t
ngx_http_wd_deface_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_wd_ctx_t  *ctx;

#if (NGX_HTTP_NETEYE_SECURITY)
    ctx = ngx_http_ns_get_module_ctx(r, ngx_http_web_defacement_module);
#else
    ctx = ngx_http_get_module_ctx(r, ngx_http_web_defacement_module);
#endif

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (ctx->defaced) {
        v->data = (u_char *)"defaced";
        v->len = strlen("defaced");
    } else {
        v->data = NULL;
        v->len = 0;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_http_wd_file_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_wd_ctx_t  *ctx;

#if (NGX_HTTP_NETEYE_SECURITY)
    ctx = ngx_http_ns_get_module_ctx(r, ngx_http_web_defacement_module);
#else
    ctx = ngx_http_get_module_ctx(r, ngx_http_web_defacement_module);
#endif

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = ctx->file.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = ctx->file.data;

    return NGX_OK;
}

static ngx_int_t
ngx_http_wd_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_wd_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}

static char *
ngx_http_wd_whitelist(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_wd_loc_conf_t *wlcf = conf;

    return ngx_http_wl_parse_vars(cf, cmd, conf, &wlcf->whitelist);
}
