/*
 * NAXSI, a web application firewall for NGINX
 * 
 * This file is a helper to help naxsi to be integrated into neteye
 * security product.
 *
 * Copyright (C) 2013, Neusoft Corp.
 * Author: y_y@neusoft.com (Paul Yang)
 *  
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 * 
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "naxsi.h"

#if (NGX_HTTP_NAXSI_NETEYE_HELPER)
char *
ngx_http_naxsi_action_loc_conf(ngx_conf_t *cf, ngx_command_t *cmd,
			   void *conf)
{
    ngx_http_dummy_loc_conf_t	    *alcf = conf;
    ngx_http_naxsi_neteye_action_t  *neteye_action;
    ngx_str_t                        action_str;
    ngx_str_t                       *value;

    value = cf->args->elts;

    if (!alcf->neteye_actions) {
        alcf->neteye_actions = ngx_array_create(cf->pool, 6, 
                sizeof(ngx_http_naxsi_neteye_action_t));
    }

    if (!alcf->neteye_actions)
        return NGX_CONF_ERROR;

    neteye_action = ngx_array_push(alcf->neteye_actions);
    if (!neteye_action)
        return NGX_CONF_ERROR;

    /* parse tag */
    if (ngx_strstr(value[1].data, "tag=") != NULL) {
        if ((value[1].len - strlen("tag=")) == 0) {
            return "not valid tag name";
        } else {
            neteye_action->tag.data = value[1].data + strlen("tag=");
            neteye_action->tag.len = value[1].len - strlen("tag=");
        }
    } else {
        return "no tag presented in the directive";
    }

    /* parse action */
    if (ngx_strstr(value[2].data, "action=") != NULL) {
        if ((value[2].len - strlen("action=")) == 0) {
            return "not valid action content";
        } else {
            action_str.data = value[2].data + strlen("action=");
            action_str.len = value[2].len - strlen("action=");

            if (ngx_strstr(action_str.data, "block") != NULL) {
                neteye_action->action = NGX_HTTP_NS_ACTION_BLOCK;
            } else if (ngx_strstr(action_str.data, "pass") != NULL) {
                neteye_action->action = NGX_HTTP_NS_ACTION_PASS;
            } else {
                return "not valid action";
            }
        }
    } else {
        return "no action presented in the directive";
    }

    /* parse notify */
    if (ngx_strstr(value[3].data, "notify=") != NULL) {
#if (NGX_HTTP_STATUS_PAGE)
        if ((value[3].len - strlen("notify=")) == 0) { 
            neteye_action->error_page.len = 0;
            neteye_action->error_page.data = NULL;
        } else {
            neteye_action->error_page.data = value[3].data + strlen("notify=");
            neteye_action->error_page.len = value[3].len - strlen("notify=");

            if (neteye_action->error_page.len == 3) {
                if (!ngx_memcmp(neteye_action->error_page.data, "off", 3)) {
                    neteye_action->error_page.len = 0;
                    neteye_action->error_page.data = NULL;
                }
            }
        }
#else
        neteye_action->error_page.len = 0;
        neteye_action->error_page.data = NULL;
#endif
    } else {
        return "not valid notify page";
    }

#if 0
    fprintf(stderr, "neteye action: tag: %s, action: %ld, "
            "notify: %s, log: %d\n", 
            neteye_action->tag.data, 
            neteye_action->action, 
            neteye_action->error_page.data, 
            (int)neteye_action->log);
#endif

    return NGX_CONF_OK;
}

ngx_int_t
ngx_http_naxsi_do_action(ngx_http_request_t *r, 
        ngx_http_request_ctx_t *ctx, char *fmt)
{
    ngx_http_ns_action_t              *action;
    ngx_int_t                          ret;
    ngx_uint_t                         i;
    ngx_http_dummy_loc_conf_t         *nlcf;
    ngx_http_naxsi_neteye_action_t    *neteye_action;
    u_char                            *tag;
  
    nlcf = ngx_http_get_module_loc_conf(r, ngx_http_naxsi_module);
   
    if (nlcf->neteye_actions == NULL) {
        /* no neteye actions defined, treat as BLOCK without logging */
        return NGX_ERROR;
    }

    if (ctx->matched_tag == NULL) {
        /* something strange hanpped, treat as internal rules */
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "naxsi ctx matched no tag, treat as internal rules");

        tag = (u_char *)"internal";
    } else {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                "naxsi ctx matched tag: %V", ctx->matched_tag);

        tag = ctx->matched_tag->data;
    }
    
    neteye_action = nlcf->neteye_actions->elts;
    for (i = 0; i < nlcf->neteye_actions->nelts; i++) {
	if (!ngx_strcmp(tag, neteye_action[i].tag.data)) {
            break;
        }
    }

    if (i == nlcf->neteye_actions->nelts) {
        /* not found matched action, fallback to block silently */
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                "no defined actions matched with ctx tag");
        return NGX_ERROR;
    }

    action = ngx_pcalloc(r->pool, sizeof(ngx_http_ns_action_t));
    if (action == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    action->action = neteye_action[i].action;
    if (neteye_action[i].error_page.data != NULL) {
        action->has_redirect = 1;
        action->redirect_page = &neteye_action[i].error_page;
        action->in_body = 0;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
            "naxsi do action: %d", action->action);

    if (neteye_action[i].log) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "naxsi log fmt: %s", fmt);
    }

    ret = ngx_http_ns_do_action(r, action);
    
    return ret;
}
#endif
