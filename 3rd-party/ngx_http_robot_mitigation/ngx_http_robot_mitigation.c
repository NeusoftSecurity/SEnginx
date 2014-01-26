/*
 * Copyright (c) 2013 Neusoft Corperation., Ltd.
 */

#include <ngx_http_robot_mitigation.h>

#if (NGX_HTTP_NETEYE_SECURITY)
#include <ngx_http_neteye_security.h>
#endif

#include <ngx_sha1.h>
#include <ngx_resolver.h>

#include <zlib.h>

extern const ngx_http_rm_tpl_t ngx_http_rm_get_js_tpls[];
extern const ngx_uint_t ngx_http_rm_get_js_tpls_nr;
extern const ngx_http_rm_tpl_t ngx_http_rm_post_js_tpls[];
extern const ngx_uint_t ngx_http_rm_post_js_tpls_nr;

static ngx_rbtree_t                 ngx_http_rm_dns_rbtree;
static ngx_rbtree_node_t            ngx_http_rm_dns_sentinel;
static ngx_log_t                    ngx_http_rm_timer_log;
          
#define NGX_HTTP_RM_GET_SWF \
    "<html>\n<body>\n" \
    "<OBJECT classid=\"clsid:D27CDB6E-AE6D-11cf-96B8-444553540000\"" \
    "codebase=\"http://download.macromedia.com/pub/shockwave/" \
    "cabs/flash/swflash.cab#version=6,0,40,0\"" \
    " WIDTH=\"100\" HEIGHT=\"100\" " \
    "id=\"%s\">" \
    "<PARAM NAME=movie VALUE=\"%s.swf\">" \
    "<PARAM NAME=quality VALUE=high><PARAM NAME=bgcolor VALUE=#FFFFFF>" \
    "<EMBED src=\"/%s.swf\" " \
    "quality=high bgcolor=#FFFFFF WIDTH=\"100\" HEIGHT=\"100\" " \
    "NAME=\"%s\" " \
    "ALIGN=\"\" TYPE=\"application/x-shockwave-flash\" " \
    "PLUGINSPAGE=\"http://www.macromedia.com/go/getflashplayer\">" \
    "</EMBED></OBJECT>\n</body>\n</html>\n"

#define NGX_HTTP_RM_POST_JS_2 \
    "</form>\n</body>\n</html>\n"

#define NGX_HTTP_RM_POST_JS_2_LEN 24

#define NGX_HTTP_RM_POST_SWF_1 \
    "<html>\n<body>\n" \
    "<OBJECT classid=\"clsid:D27CDB6E-AE6D-11cf-96B8-444553540000\"" \
    "codebase=\"http://download.macromedia.com/pub/shockwave/" \
    "cabs/flash/swflash.cab#version=6,0,40,0\"" \
    " WIDTH=\"100\" HEIGHT=\"100\" " \
    "id=\"%s\">" \
    "<PARAM NAME=movie VALUE=\"%s.swf\">" \
    "<PARAM NAME=quality VALUE=high><PARAM NAME=bgcolor VALUE=#FFFFFF>" \
    "<EMBED src=\"/%s.swf\" " \
    "quality=high bgcolor=#FFFFFF WIDTH=\"100\" HEIGHT=\"100\" " \
    "NAME=\"%s\" " \
    "ALIGN=\"\" TYPE=\"application/x-shockwave-flash\" " \
    "PLUGINSPAGE=\"http://www.macromedia.com/go/getflashplayer\">" \
    "</EMBED></OBJECT>\n" \
    "<form name=\"response\" method=\"post\">\n"

#define NGX_HTTP_RM_POST_SWF_2 \
    "</form>\n" \
    "</body>\n</html>\n"

static const char ngx_http_rm_get_swf[] = "\x0a\xf3\x05\x00\x00\x60\x00\x3e\x80\x00\x3e\x80\x00\x1e\x01\x00\x44\x11\x18\x00\x00\x00\x7f\x13\xcb\x01\x00\x00\x3c\x72\x64\x66\x3a\x52\x44\x46\x20\x78\x6d\x6c\x6e\x73\x3a\x72\x64\x66\x3d\x27\x68\x74\x74\x70\x3a\x2f\x2f\x77\x77\x77\x2e\x77\x33\x2e\x6f\x72\x67\x2f\x31\x39\x39\x39\x2f\x30\x32\x2f\x32\x32\x2d\x72\x64\x66\x2d\x73\x79\x6e\x74\x61\x78\x2d\x6e\x73\x23\x27\x3e\x3c\x72\x64\x66\x3a\x44\x65\x73\x63\x72\x69\x70\x74\x69\x6f\x6e\x20\x72\x64\x66\x3a\x61\x62\x6f\x75\x74\x3d\x27\x27\x20\x78\x6d\x6c\x6e\x73\x3a\x64\x63\x3d\x27\x68\x74\x74\x70\x3a\x2f\x2f\x70\x75\x72\x6c\x2e\x6f\x72\x67\x2f\x64\x63\x2f\x65\x6c\x65\x6d\x65\x6e\x74\x73\x2f\x31\x2e\x31\x27\x3e\x3c\x64\x63\x3a\x66\x6f\x72\x6d\x61\x74\x3e\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x2f\x78\x2d\x73\x68\x6f\x63\x6b\x77\x61\x76\x65\x2d\x66\x6c\x61\x73\x68\x3c\x2f\x64\x63\x3a\x66\x6f\x72\x6d\x61\x74\x3e\x3c\x64\x63\x3a\x74\x69\x74\x6c\x65\x3e\x41\x64\x6f\x62\x65\x20\x46\x6c\x65\x78\x20\x34\x20\x41\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x3c\x2f\x64\x63\x3a\x74\x69\x74\x6c\x65\x3e\x3c\x64\x63\x3a\x64\x65\x73\x63\x72\x69\x70\x74\x69\x6f\x6e\x3e\x68\x74\x74\x70\x3a\x2f\x2f\x77\x77\x77\x2e\x61\x64\x6f\x62\x65\x2e\x63\x6f\x6d\x2f\x70\x72\x6f\x64\x75\x63\x74\x73\x2f\x66\x6c\x65\x78\x3c\x2f\x64\x63\x3a\x64\x65\x73\x63\x72\x69\x70\x74\x69\x6f\x6e\x3e\x3c\x64\x63\x3a\x70\x75\x62\x6c\x69\x73\x68\x65\x72\x3e\x75\x6e\x6b\x6e\x6f\x77\x6e\x3c\x2f\x64\x63\x3a\x70\x75\x62\x6c\x69\x73\x68\x65\x72\x3e\x3c\x64\x63\x3a\x63\x72\x65\x61\x74\x6f\x72\x3e\x75\x6e\x6b\x6e\x6f\x77\x6e\x3c\x2f\x64\x63\x3a\x63\x72\x65\x61\x74\x6f\x72\x3e\x3c\x64\x63\x3a\x6c\x61\x6e\x67\x75\x61\x67\x65\x3e\x45\x4e\x3c\x2f\x64\x63\x3a\x6c\x61\x6e\x67\x75\x61\x67\x65\x3e\x3c\x64\x63\x3a\x64\x61\x74\x65\x3e\x46\x65\x62\x20\x31\x32\x2c\x20\x32\x30\x31\x31\x3c\x2f\x64\x63\x3a\x64\x61\x74\x65\x3e\x3c\x2f\x72\x64\x66\x3a\x44\x65\x73\x63\x72\x69\x70\x74\x69\x6f\x6e\x3e\x3c\x2f\x72\x64\x66\x3a\x52\x44\x46\x3e\x00\x44\x10\xe8\x03\x3c\x00\x43\x02\xff\xff\xff\x5a\x0a\x03\x00\x00\x00\x06\x00\x00\x00\x04\x00\x4f\x37\x00\x00\x00\x00\x00\x00\x1d\xf7\x17\x1b\x2e\x01\x00\x00\xc4\x0a\x47\x45\x54\x00\xbf\x14\xc8\x03\x00\x00\x01\x00\x00\x00\x66\x72\x61\x6d\x65\x31\x00\x10\x00\x2e\x00\x00\x00\x00\x1e\x00\x04\x76\x6f\x69\x64\x0c\x66\x6c\x61\x73\x68\x2e\x65\x76\x65\x6e\x74\x73\x05\x45\x76\x65\x6e\x74\x03\x47\x45\x54\x0d\x66\x6c\x61\x73\x68\x2e\x64\x69\x73\x70\x6c\x61\x79\x06\x53\x70\x72\x69\x74\x65\x0b\x43\x4f\x4f\x4b\x49\x45\x5f\x4e\x41\x4d\x45\x06\x53\x74\x72\x69\x6e\x67\x28\x52\x6f\x62\x6f\x6f\x5f\x6e\x61\x6d\x65\x5f\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x50\x4c\x41\x43\x45\x48\x4f\x4c\x44\x45\x52\x0c\x43\x4f\x4f\x4b\x49\x45\x5f\x56\x41\x4c\x55\x45\x28\x52\x6f\x62\x6f\x6f\x5f\x76\x61\x6c\x75\x65\x5f\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x50\x4c\x41\x43\x45\x48\x4f\x4c\x44\x45\x52\x0f\x43\x4f\x4f\x4b\x49\x45\x5f\x56\x41\x4c\x49\x44\x49\x54\x59\x28\x52\x6f\x62\x6f\x6f\x5f\x76\x61\x6c\x69\x64\x69\x74\x79\x5f\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x50\x4c\x41\x43\x45\x48\x4f\x4c\x44\x45\x52\x04\x69\x6e\x69\x74\x05\x73\x74\x61\x67\x65\x10\x61\x64\x64\x45\x76\x65\x6e\x74\x4c\x69\x73\x74\x65\x6e\x65\x72\x0e\x41\x44\x44\x45\x44\x5f\x54\x4f\x5f\x53\x54\x41\x47\x45\x13\x72\x65\x6d\x6f\x76\x65\x45\x76\x65\x6e\x74\x4c\x69\x73\x74\x65\x6e\x65\x72\x03\x58\x4d\x4c\x86\x02\x3c\x73\x63\x72\x69\x70\x74\x3e\x0d\x0a\x09\x09\x09\x09\x09\x3c\x21\x5b\x43\x44\x41\x54\x41\x5b\x0d\x0a\x09\x09\x09\x09\x09\x09\x66\x75\x6e\x63\x74\x69\x6f\x6e\x20\x28\x63\x6f\x6f\x6b\x69\x65\x5f\x6e\x61\x6d\x65\x2c\x20\x63\x6f\x6f\x6b\x69\x65\x5f\x76\x61\x6c\x75\x65\x2c\x20\x63\x6f\x6f\x6b\x69\x65\x5f\x76\x61\x6c\x69\x64\x69\x74\x79\x29\x20\x7b\x20\x0d\x0a\x09\x09\x09\x09\x09\x09\x09\x09\x64\x6f\x63\x75\x6d\x65\x6e\x74\x2e\x63\x6f\x6f\x6b\x69\x65\x3d\x63\x6f\x6f\x6b\x69\x65\x5f\x6e\x61\x6d\x65\x20\x2b\x20\x27\x3d\x27\x20\x2b\x20\x63\x6f\x6f\x6b\x69\x65\x5f\x76\x61\x6c\x75\x65\x20\x2b\x20\x27\x3b\x20\x6d\x61\x78\x2d\x61\x67\x65\x3d\x27\x20\x2b\x20\x63\x6f\x6f\x6b\x69\x65\x5f\x76\x61\x6c\x69\x64\x69\x74\x79\x20\x2b\x20\x27\x3b\x20\x70\x61\x74\x68\x3d\x2f\x27\x3b\x0d\x0a\x09\x09\x09\x09\x09\x09\x09\x09\x77\x69\x6e\x64\x6f\x77\x2e\x6c\x6f\x63\x61\x74\x69\x6f\x6e\x2e\x72\x65\x6c\x6f\x61\x64\x28\x29\x3b\x0d\x0a\x09\x09\x09\x09\x09\x09\x7d\x0d\x0a\x09\x09\x09\x09\x09\x5d\x5d\x3e\x0d\x0a\x09\x09\x09\x09\x3c\x2f\x73\x63\x72\x69\x70\x74\x3e\x0e\x66\x6c\x61\x73\x68\x2e\x65\x78\x74\x65\x72\x6e\x61\x6c\x11\x45\x78\x74\x65\x72\x6e\x61\x6c\x49\x6e\x74\x65\x72\x66\x61\x63\x65\x04\x63\x61\x6c\x6c\x06\x4f\x62\x6a\x65\x63\x74\x0f\x45\x76\x65\x6e\x74\x44\x69\x73\x70\x61\x74\x63\x68\x65\x72\x0d\x44\x69\x73\x70\x6c\x61\x79\x4f\x62\x6a\x65\x63\x74\x11\x49\x6e\x74\x65\x72\x61\x63\x74\x69\x76\x65\x4f\x62\x6a\x65\x63\x74\x16\x44\x69\x73\x70\x6c\x61\x79\x4f\x62\x6a\x65\x63\x74\x43\x6f\x6e\x74\x61\x69\x6e\x65\x72\x07\x16\x01\x16\x03\x16\x06\x18\x05\x05\x00\x16\x16\x00\x16\x07\x01\x02\x07\x02\x04\x07\x01\x05\x07\x03\x07\x07\x01\x08\x07\x01\x09\x07\x01\x0b\x07\x01\x0d\x07\x05\x0f\x07\x01\x10\x07\x01\x11\x07\x01\x12\x07\x01\x13\x07\x01\x14\x07\x06\x17\x07\x01\x18\x07\x01\x19\x07\x02\x1a\x07\x03\x1b\x07\x03\x1c\x07\x03\x1d\x04\x00\x00\x00\x00\x00\x01\x00\x00\x01\x01\x02\x00\x08\x01\x0c\x0c\x00\x00\x00\x00\x00\x01\x03\x04\x09\x04\x00\x01\x04\x05\x06\x00\x06\x0a\x01\x07\x06\x00\x06\x0c\x01\x08\x06\x00\x06\x0e\x01\x09\x01\x00\x02\x00\x00\x01\x03\x01\x03\x04\x01\x00\x04\x00\x01\x01\x08\x09\x03\xd0\x30\x47\x00\x00\x01\x03\x01\x09\x0a\x20\xd0\x30\xd0\x49\x00\x60\x0a\x12\x08\x00\x00\xd0\x4f\x09\x00\x10\x0c\x00\x00\x5d\x0b\x60\x02\x66\x0c\xd0\x66\x09\x4f\x0b\x02\x47\x00\x00\x02\x05\x03\x09\x0a\x27\xd0\x30\x5d\x0d\x60\x02\x66\x0c\xd0\x66\x09\x4f\x0d\x02\x60\x0e\x2c\x15\x42\x01\x80\x0e\xd6\x60\x0f\xd2\xd0\x66\x05\xd0\x66\x07\xd0\x66\x08\x4f\x10\x04\x47\x00\x00\x03\x02\x01\x01\x08\x23\xd0\x30\x65\x00\x60\x11\x30\x60\x12\x30\x60\x13\x30\x60\x14\x30\x60\x15\x30\x60\x04\x30\x60\x04\x58\x00\x1d\x1d\x1d\x1d\x1d\x1d\x68\x03\x47\x00\x00\x08\x13\x01\x00\x00\x00\x47\x45\x54\x00\x40\x00\x00\x00";

char ngx_http_rm_post_swf[]="\x0a\x4c\x06\x00\x00\x30\x0a\x00\xa0\x00\x01\x01\x00\x44\x11\x18\x00\x00\x00\x7f\x13\xcb\x01\x00\x00\x3c\x72\x64\x66\x3a\x52\x44\x46\x20\x78\x6d\x6c\x6e\x73\x3a\x72\x64\x66\x3d\x27\x68\x74\x74\x70\x3a\x2f\x2f\x77\x77\x77\x2e\x77\x33\x2e\x6f\x72\x67\x2f\x31\x39\x39\x39\x2f\x30\x32\x2f\x32\x32\x2d\x72\x64\x66\x2d\x73\x79\x6e\x74\x61\x78\x2d\x6e\x73\x23\x27\x3e\x3c\x72\x64\x66\x3a\x44\x65\x73\x63\x72\x69\x70\x74\x69\x6f\x6e\x20\x72\x64\x66\x3a\x61\x62\x6f\x75\x74\x3d\x27\x27\x20\x78\x6d\x6c\x6e\x73\x3a\x64\x63\x3d\x27\x68\x74\x74\x70\x3a\x2f\x2f\x70\x75\x72\x6c\x2e\x6f\x72\x67\x2f\x64\x63\x2f\x65\x6c\x65\x6d\x65\x6e\x74\x73\x2f\x31\x2e\x31\x27\x3e\x3c\x64\x63\x3a\x66\x6f\x72\x6d\x61\x74\x3e\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x2f\x78\x2d\x73\x68\x6f\x63\x6b\x77\x61\x76\x65\x2d\x66\x6c\x61\x73\x68\x3c\x2f\x64\x63\x3a\x66\x6f\x72\x6d\x61\x74\x3e\x3c\x64\x63\x3a\x74\x69\x74\x6c\x65\x3e\x41\x64\x6f\x62\x65\x20\x46\x6c\x65\x78\x20\x34\x20\x41\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x3c\x2f\x64\x63\x3a\x74\x69\x74\x6c\x65\x3e\x3c\x64\x63\x3a\x64\x65\x73\x63\x72\x69\x70\x74\x69\x6f\x6e\x3e\x68\x74\x74\x70\x3a\x2f\x2f\x77\x77\x77\x2e\x61\x64\x6f\x62\x65\x2e\x63\x6f\x6d\x2f\x70\x72\x6f\x64\x75\x63\x74\x73\x2f\x66\x6c\x65\x78\x3c\x2f\x64\x63\x3a\x64\x65\x73\x63\x72\x69\x70\x74\x69\x6f\x6e\x3e\x3c\x64\x63\x3a\x70\x75\x62\x6c\x69\x73\x68\x65\x72\x3e\x75\x6e\x6b\x6e\x6f\x77\x6e\x3c\x2f\x64\x63\x3a\x70\x75\x62\x6c\x69\x73\x68\x65\x72\x3e\x3c\x64\x63\x3a\x63\x72\x65\x61\x74\x6f\x72\x3e\x75\x6e\x6b\x6e\x6f\x77\x6e\x3c\x2f\x64\x63\x3a\x63\x72\x65\x61\x74\x6f\x72\x3e\x3c\x64\x63\x3a\x6c\x61\x6e\x67\x75\x61\x67\x65\x3e\x45\x4e\x3c\x2f\x64\x63\x3a\x6c\x61\x6e\x67\x75\x61\x67\x65\x3e\x3c\x64\x63\x3a\x64\x61\x74\x65\x3e\x4a\x75\x6e\x20\x32\x39\x2c\x20\x32\x30\x31\x31\x3c\x2f\x64\x63\x3a\x64\x61\x74\x65\x3e\x3c\x2f\x72\x64\x66\x3a\x44\x65\x73\x63\x72\x69\x70\x74\x69\x6f\x6e\x3e\x3c\x2f\x72\x64\x66\x3a\x52\x44\x46\x3e\x00\x44\x10\xe8\x03\x3c\x00\x43\x02\xff\xff\xff\x5a\x0a\x03\x00\x00\x00\x06\x00\x00\x00\x04\x00\x4f\x37\x00\x00\x00\x00\x00\x00\x94\x69\xd6\xda\x30\x01\x00\x00\xc5\x0a\x50\x4f\x53\x54\x00\xbf\x14\x22\x04\x00\x00\x01\x00\x00\x00\x66\x72\x61\x6d\x65\x31\x00\x10\x00\x2e\x00\x00\x00\x00\x1e\x00\x04\x76\x6f\x69\x64\x0c\x66\x6c\x61\x73\x68\x2e\x65\x76\x65\x6e\x74\x73\x05\x45\x76\x65\x6e\x74\x04\x50\x4f\x53\x54\x0d\x66\x6c\x61\x73\x68\x2e\x64\x69\x73\x70\x6c\x61\x79\x06\x53\x70\x72\x69\x74\x65\x0b\x43\x4f\x4f\x4b\x49\x45\x5f\x4e\x41\x4d\x45\x06\x53\x74\x72\x69\x6e\x67\x28\x52\x6f\x62\x6f\x6f\x5f\x6e\x61\x6d\x65\x5f\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x50\x4c\x41\x43\x45\x48\x4f\x4c\x44\x45\x52\x0c\x43\x4f\x4f\x4b\x49\x45\x5f\x56\x41\x4c\x55\x45\x28\x52\x6f\x62\x6f\x6f\x5f\x76\x61\x6c\x75\x65\x5f\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x50\x4c\x41\x43\x45\x48\x4f\x4c\x44\x45\x52\x0f\x43\x4f\x4f\x4b\x49\x45\x5f\x56\x41\x4c\x49\x44\x49\x54\x59\x28\x52\x6f\x62\x6f\x6f\x5f\x76\x61\x6c\x69\x64\x69\x74\x79\x5f\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x50\x4c\x41\x43\x45\x48\x4f\x4c\x44\x45\x52\x04\x69\x6e\x69\x74\x05\x73\x74\x61\x67\x65\x10\x61\x64\x64\x45\x76\x65\x6e\x74\x4c\x69\x73\x74\x65\x6e\x65\x72\x0e\x41\x44\x44\x45\x44\x5f\x54\x4f\x5f\x53\x54\x41\x47\x45\x13\x72\x65\x6d\x6f\x76\x65\x45\x76\x65\x6e\x74\x4c\x69\x73\x74\x65\x6e\x65\x72\x03\x58\x4d\x4c\xdf\x02\x3c\x73\x63\x72\x69\x70\x74\x3e\x0d\x0a\x09\x09\x09\x09\x09\x3c\x21\x5b\x43\x44\x41\x54\x41\x5b\x0d\x0a\x09\x09\x09\x09\x09\x09\x66\x75\x6e\x63\x74\x69\x6f\x6e\x20\x28\x63\x6f\x6f\x6b\x69\x65\x5f\x6e\x61\x6d\x65\x2c\x20\x63\x6f\x6f\x6b\x69\x65\x5f\x76\x61\x6c\x75\x65\x2c\x20\x63\x6f\x6f\x6b\x69\x65\x5f\x76\x61\x6c\x69\x64\x69\x74\x79\x29\x20\x7b\x20\x0d\x0a\x09\x09\x09\x09\x09\x09\x09\x09\x64\x6f\x63\x75\x6d\x65\x6e\x74\x2e\x63\x6f\x6f\x6b\x69\x65\x3d\x63\x6f\x6f\x6b\x69\x65\x5f\x6e\x61\x6d\x65\x20\x2b\x20\x27\x3d\x27\x20\x2b\x20\x63\x6f\x6f\x6b\x69\x65\x5f\x76\x61\x6c\x75\x65\x20\x2b\x20\x27\x3b\x20\x6d\x61\x78\x2d\x61\x67\x65\x3d\x27\x20\x2b\x20\x63\x6f\x6f\x6b\x69\x65\x5f\x76\x61\x6c\x69\x64\x69\x74\x79\x20\x2b\x20\x27\x3b\x20\x70\x61\x74\x68\x3d\x2f\x27\x3b\x0d\x0a\x09\x09\x09\x09\x09\x09\x09\x09\x64\x6f\x63\x75\x6d\x65\x6e\x74\x2e\x72\x65\x73\x70\x6f\x6e\x73\x65\x2e\x61\x63\x74\x69\x6f\x6e\x20\x3d\x20\x77\x69\x6e\x64\x6f\x77\x2e\x6c\x6f\x63\x61\x74\x69\x6f\x6e\x2e\x70\x61\x74\x68\x6e\x61\x6d\x65\x20\x2b\x20\x77\x69\x6e\x64\x6f\x77\x2e\x6c\x6f\x63\x61\x74\x69\x6f\x6e\x2e\x73\x65\x61\x72\x63\x68\x3b\x0d\x0a\x09\x09\x09\x09\x09\x09\x09\x09\x64\x6f\x63\x75\x6d\x65\x6e\x74\x2e\x66\x6f\x72\x6d\x73\x5b\x30\x5d\x2e\x73\x75\x62\x6d\x69\x74\x28\x29\x3b\x0d\x0a\x09\x09\x09\x09\x09\x09\x7d\x0d\x0a\x09\x09\x09\x09\x09\x5d\x5d\x3e\x0d\x0a\x09\x09\x09\x09\x3c\x2f\x73\x63\x72\x69\x70\x74\x3e\x0e\x66\x6c\x61\x73\x68\x2e\x65\x78\x74\x65\x72\x6e\x61\x6c\x11\x45\x78\x74\x65\x72\x6e\x61\x6c\x49\x6e\x74\x65\x72\x66\x61\x63\x65\x04\x63\x61\x6c\x6c\x06\x4f\x62\x6a\x65\x63\x74\x0f\x45\x76\x65\x6e\x74\x44\x69\x73\x70\x61\x74\x63\x68\x65\x72\x0d\x44\x69\x73\x70\x6c\x61\x79\x4f\x62\x6a\x65\x63\x74\x11\x49\x6e\x74\x65\x72\x61\x63\x74\x69\x76\x65\x4f\x62\x6a\x65\x63\x74\x16\x44\x69\x73\x70\x6c\x61\x79\x4f\x62\x6a\x65\x63\x74\x43\x6f\x6e\x74\x61\x69\x6e\x65\x72\x07\x16\x01\x16\x03\x16\x06\x18\x05\x05\x00\x16\x16\x00\x16\x07\x01\x02\x07\x02\x04\x07\x01\x05\x07\x03\x07\x07\x01\x08\x07\x01\x09\x07\x01\x0b\x07\x01\x0d\x07\x05\x0f\x07\x01\x10\x07\x01\x11\x07\x01\x12\x07\x01\x13\x07\x01\x14\x07\x06\x17\x07\x01\x18\x07\x01\x19\x07\x02\x1a\x07\x03\x1b\x07\x03\x1c\x07\x03\x1d\x04\x00\x00\x00\x00\x00\x01\x00\x00\x01\x01\x02\x00\x08\x01\x0c\x0c\x00\x00\x00\x00\x00\x01\x03\x04\x09\x04\x00\x01\x04\x05\x06\x00\x06\x0a\x01\x07\x06\x00\x06\x0c\x01\x08\x06\x00\x06\x0e\x01\x09\x01\x00\x02\x00\x00\x01\x03\x01\x03\x04\x01\x00\x04\x00\x01\x01\x08\x09\x03\xd0\x30\x47\x00\x00\x01\x03\x01\x09\x0a\x20\xd0\x30\xd0\x49\x00\x60\x0a\x12\x08\x00\x00\xd0\x4f\x09\x00\x10\x0c\x00\x00\x5d\x0b\x60\x02\x66\x0c\xd0\x66\x09\x4f\x0b\x02\x47\x00\x00\x02\x05\x03\x09\x0a\x27\xd0\x30\x5d\x0d\x60\x02\x66\x0c\xd0\x66\x09\x4f\x0d\x02\x60\x0e\x2c\x15\x42\x01\x80\x0e\xd6\x60\x0f\xd2\xd0\x66\x05\xd0\x66\x07\xd0\x66\x08\x4f\x10\x04\x47\x00\x00\x03\x02\x01\x01\x08\x23\xd0\x30\x65\x00\x60\x11\x30\x60\x12\x30\x60\x13\x30\x60\x14\x30\x60\x15\x30\x60\x04\x30\x60\x04\x58\x00\x1d\x1d\x1d\x1d\x1d\x1d\x68\x03\x47\x00\x00\x09\x13\x01\x00\x00\x00\x50\x4f\x53\x54\x00\x40\x00\x00\x00";

static ngx_str_t 
ngx_http_rm_type_swf = ngx_string("application/x-shockwave-flash");

static ngx_str_t ngx_http_rm_type_html = ngx_string("text/html");

static char *
ngx_http_rm_challenge_ajax(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t
ngx_http_rm_add_variables(ngx_conf_t *cf);
static ngx_int_t
ngx_http_rm_blacklist_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static char *
ngx_http_rm_whitelist_caseless(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *
ngx_http_rm_mode(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *
ngx_http_rm(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *
ngx_http_rm_cookie_name(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *
ngx_http_rm_timeout(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t
ngx_http_rm_content_handler(ngx_http_request_t *r);
static ngx_int_t
ngx_http_rm_request_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_rm_init(ngx_conf_t *cf);
static void *ngx_http_rm_create_loc_conf(ngx_conf_t *cf);
static char *
ngx_http_rm_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t
ngx_http_rm_challenge_get_js_handler(ngx_http_request_t *r);
static ngx_int_t
ngx_http_rm_challenge_get_swf_handler(ngx_http_request_t *r);
ngx_int_t ngx_http_rm_special_swf_uri(ngx_http_request_t *r);
static ngx_int_t 
ngx_http_rm_send_swf_file_handler(ngx_http_request_t *r, ngx_uint_t method);
static ngx_int_t 
ngx_http_rm_send_swf_handler(ngx_http_request_t *r);
static ngx_int_t
ngx_http_rm_send_response(ngx_http_request_t *r, ngx_uint_t status,
    ngx_str_t *ct, ngx_str_t val);
static ngx_int_t
ngx_http_rm_challenge_post_js_handler(ngx_http_request_t *r);
static ngx_int_t
ngx_http_rm_challenge_post_swf_handler(ngx_http_request_t *r);
static u_char * 
ngx_http_rm_post_body_to_form(ngx_http_request_t *r, 
        u_char *body, ngx_uint_t len, 
        ngx_uint_t *post_args_len);
static u_char * 
ngx_http_rm_post_data_decode(ngx_http_request_t *r,
        u_char *string, ngx_uint_t len, 
        ngx_uint_t *decoded_len);
static ngx_http_rm_dns_t *
ngx_http_rm_dns_lookup(ngx_rbtree_t *tree, ngx_str_t *addr, uint32_t hash);
static void *
ngx_http_rm_create_main_conf(ngx_conf_t *cf);

static ngx_int_t
ngx_http_rm_request_ctx_init(ngx_http_request_t *r);

static ngx_http_rm_req_ctx_t *
ngx_http_rm_get_request_ctx(ngx_http_request_t *r);

static char *
ngx_http_rm_whitelist(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char *
ngx_http_rm_ip_whitelist(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char *
ngx_http_rm_resolver(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

#if (NGX_HTTP_X_FORWARDED_FOR)
static char *
ngx_http_rm_ip_whitelist_x_forwarded_for(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
#endif

static char *
ngx_http_rm_blacklist(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t
ngx_http_rm_test_content_type(ngx_http_request_t *r, u_char *type);


static ngx_command_t  ngx_http_robot_mitigation_commands[] = {

    { ngx_string("robot_mitigation"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
        ngx_http_rm,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },
    
    { ngx_string("robot_mitigation_cookie_name"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_http_rm_cookie_name,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },
  
    { ngx_string("robot_mitigation_mode"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_http_rm_mode,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },
    
    { ngx_string("robot_mitigation_blacklist"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_http_rm_blacklist,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },
    
    { ngx_string("robot_mitigation_timeout"),
        NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
        ngx_http_rm_timeout,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },

    { ngx_string("robot_mitigation_whitelist_caseless"),
        NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
        ngx_http_rm_whitelist_caseless,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },

    { ngx_string("robot_mitigation_resolver"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_1MORE,
      ngx_http_rm_resolver,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("robot_mitigation_resolver_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_rm_main_conf_t, resolver_timeout),
      NULL },

    { ngx_string("robot_mitigation_whitelist"),
        NGX_HTTP_LOC_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
        ngx_http_rm_whitelist,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },
 
    { ngx_string("robot_mitigation_ip_whitelist"),
        NGX_HTTP_LOC_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
        ngx_http_rm_ip_whitelist,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },

#if (NGX_HTTP_X_FORWARDED_FOR)
    { ngx_string("robot_mitigation_ip_whitelist_x_forwarded_for"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_http_rm_ip_whitelist_x_forwarded_for,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },
#endif

    { ngx_string("robot_mitigation_challenge_ajax"),
        NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
        ngx_http_rm_challenge_ajax,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },

    ngx_null_command
};

static ngx_http_variable_t  ngx_http_rm_vars[] = {

    { ngx_string("robot_mitigation_blacklist"),
        NULL, ngx_http_rm_blacklist_variable, 0,
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};


static ngx_http_module_t
ngx_http_robot_mitigation_module_ctx = {
    ngx_http_rm_add_variables,               /* preconfiguration */
    ngx_http_rm_init,                        /* postconfiguration */

    ngx_http_rm_create_main_conf,            /* create main configuration */
    NULL,                                    /* init main configuration */

    NULL,                                    /* create server configuration */
    NULL,                                    /* merge server configuration */

    ngx_http_rm_create_loc_conf,             /* create location configuration */
    ngx_http_rm_merge_loc_conf,              /* merge location configuration */
};


ngx_module_t  ngx_http_robot_mitigation_module = {
    NGX_MODULE_V1,                           /* module context */
    &ngx_http_robot_mitigation_module_ctx,   /* module directives */
    ngx_http_robot_mitigation_commands,      /* module type */
    NGX_HTTP_MODULE,                         /* init master */
    NULL,                                    /* init module */
    NULL,                                    /* init process */
    NULL,                                    /* init thread */
    NULL,                                    /* exit thread */
    NULL,                                    /* exit process */
    NULL,                                    /* exit master */
    NULL,                                    
    NGX_MODULE_V1_PADDING
};


static u_char
ngx_http_rm_ascii_to_hex(u_char a)
{
    if (a >= '0' && a <= '9') {
        a = a - 48;
    } else if (a >= 'a' && a <= 'f') {
        a = a - 87;
    } else if (a >= 'A' && a <= 'F') {
        a = a - 55;
    } else {
        a = 0;
    }

    return a;
}

static u_char
ngx_http_rm_change_to_hex(u_char a, u_char b)
{
    u_char sum;

    a = ngx_http_rm_ascii_to_hex(a);
    b = ngx_http_rm_ascii_to_hex(b);

    sum = a * 16 + b;

    return sum;
}

/**
 * decode the post body
 *
 * $data =~ tr/+/ /;
 * $data =~ s/%([a-fA-F0-9]{2})/pack("C", hex($1))/eg; 
 * $data =~ s/\x22/&quot;/g;
 */
typedef struct {
    ngx_uint_t                 offset;
    
    /* type 1: +
     * type 2: %HH
     * type 3: \x22
     * */
    ngx_uint_t                 type;
    ngx_uint_t                 delta;
    u_char                     hex;
} ngx_http_rm_decode_helper_t;

static ngx_int_t
ngx_http_rm_is_ascii_hex(u_char a)
{
    if ((a <= '9' && a >= '0')
                || (a <= 'F' && a >= 'A')
                || (a <= 'f' && a >= 'a')) {
        return 1;
    }

    return 0;
}

static u_char * 
ngx_http_rm_post_data_decode(ngx_http_request_t *r,
        u_char *string, ngx_uint_t len, 
        ngx_uint_t *decoded_len)
{
    u_char                           *decoded;
    ngx_http_rm_decode_helper_t      *helper;
    ngx_uint_t                        nr_helper = 0;
    ngx_uint_t                        pos = 0, src_pos = 0;
    ngx_uint_t                        i, new_len = 0, nr_b = 0, nr_c = 0;
    ngx_uint_t                        last_sub, delta;

    helper = ngx_pcalloc(r->pool, sizeof(ngx_http_rm_decode_helper_t) * len);
    if (helper == NULL) {
        return NULL;
    }

    for (i = 0; i < len; i++) {
        if (string[i] == '+') {
            /* find a + */
            helper[nr_helper].offset = i;
            helper[nr_helper].type = 1;
            helper[nr_helper].delta = 1;

            nr_helper++;
        }

        if (string[i] == '%') {
            if (i + 2 < len) {
                if (ngx_http_rm_is_ascii_hex(string[i + 1])
                        && ngx_http_rm_is_ascii_hex(string[i + 2])) {
                    /* find a %HH */
                    helper[nr_helper].offset = i;
                    helper[nr_helper].type = 2;

                    helper[nr_helper].hex = 
                        ngx_http_rm_change_to_hex(string[i + 1], 
                                string[i + 2]);
                    
                    helper[nr_helper].delta = 3;
                    
                    nr_helper++;
                    nr_b++;
                }
            }
        }

        if (string[i] == '\x22') {
            helper[nr_helper].offset = i;
            helper[nr_helper].type = 3;

            helper[nr_helper].delta = 1;
            
            nr_helper++;
            nr_c++;
        }
    }

    if (nr_helper == 0) {
        /* nothing to be substituted */
        *decoded_len = len;
        return string;
    } else {
        /* -2 means %HH to a char */
        /* 5 means \x22 to &quot; */
        new_len = len + (-2) * nr_b + 5 * nr_c;

        decoded = ngx_pcalloc(r->pool, new_len);
        if (decoded == NULL) {
            return NULL;
        }

        pos = 0;
        for (i = 0; i < nr_helper; i++) {
            if (i != 0) {
                src_pos = helper[i - 1].offset + helper[i - 1].delta;
                ngx_memcpy(decoded + pos, 
                        string + src_pos, 
                        helper[i].offset - src_pos);

                pos += (helper[i].offset - src_pos);
            } else {
                if (helper[i].offset != 0) {
                    ngx_memcpy(decoded, string, helper[i].offset);
                    pos += helper[i].offset;
                }
            }

            switch (helper[i].type) {
                case 1:
                    /* sub + to ' ' */
                    decoded[pos] = ' ';
                    pos++;
                    break;
                case 2:
                    decoded[pos] = helper[i].hex;
                    pos++;
                    break;
                case 3:
                    ngx_memcpy(decoded + pos, 
                            "&quot;", 
                            strlen("&quot;"));
                    pos += strlen("&quot;");
                    break;
            }
        }

        
        last_sub = helper[nr_helper - 1].offset;
        delta = helper[nr_helper - 1].delta;

        if (last_sub + delta != len) {
            /* copy the remaining chars into decoded */
            ngx_memcpy(decoded + pos, 
                    string + last_sub + delta, 
                    len - (last_sub + delta)
                    );
        }
    }

    *decoded_len = new_len;

#if 0
    ngx_uint_t k;

    for (k = 0; k < *decoded_len; k++) {
        fprintf(stderr, "%c", decoded[k]);
    }
    fprintf(stderr, "\n");
#endif

    return decoded;
}

/* obtaine request body and recover POST data */
static u_char * 
ngx_http_rm_post_body_to_form(ngx_http_request_t *r, 
        u_char *body, ngx_uint_t body_len, 
        ngx_uint_t *post_vars_len)
{ 
    u_char              *post_vars = NULL;
    ngx_uint_t           i, j, start, found = 0;
    u_char              *variable, *varname = NULL, *varvalue = NULL;
    u_char              *varname_e, *varvalue_e;
    ngx_uint_t           varname_len = 0, varvalue_len = 0;
    u_char              *decoded_name, *decoded_value;
    ngx_uint_t           decoded_name_len, decoded_value_len;
    ngx_uint_t           form_len = 0, inc_form_len = 0, offset;
    u_char              *buf_a, *buf_b;

    start = 0;
    *post_vars_len = 0;

    for (i = 0; i < body_len; i++) {
        if (body[i] == '&') {
            /* find a varname=varvalue pattern */
            
            variable = body + start;

            for (j = start; j < i; j++) {
                if (body[j] == '=') {
                    /* find a = */
                    varname = variable;
                    varname_e = body + j;
                    varname_len = varname_e - varname;

                    if (j == i - 1) {
                        /* null value for this variable */
                        varvalue = varvalue_e = NULL;
                        varvalue_len = 0;
                    } else {
                        varvalue = body + j + 1;
                        varvalue_e = body + i;
                        varvalue_len = varvalue_e - varvalue;
                    }

                    found = 1;
                }
            }
            
            start = i + 1;
        }

        /* only once, the last variable */
        if (i == body_len - 1) {
            /* find the last varname=varvalue pattern */

            variable = body + start;

            for (j = start; j <= i; j++) {
                if (body[j] == '=') {
                    /* find a = */
                    varname = variable;
                    varname_e = body + j;
                    varname_len = varname_e - varname;

                    if (j == i) {
                        varvalue = varvalue_e = NULL;
                        varvalue_len = 0;
                    } else {
                        varvalue = body + j + 1;
                        varvalue_e = body + i + 1;
                        varvalue_len = varvalue_e - varvalue;
                    }

                    found = 1;
                }
            }
        }
       
        if (found == 1) {
            found = 0;
            
            decoded_name = ngx_http_rm_post_data_decode(r, 
                    varname, varname_len, &decoded_name_len);
            if (decoded_name == NULL) {
                return NULL;
            }

            if (varvalue_len != 0) {
                decoded_value = ngx_http_rm_post_data_decode(r, 
                        varvalue, varvalue_len, &decoded_value_len);
                if (decoded_value == NULL) {
                    return NULL;
                }
            } else {
                decoded_value = NULL;
                decoded_value_len = 0;
            }

            inc_form_len = strlen(NGX_HTTP_RM_FORM_VARIABLES_1) 
                + strlen(NGX_HTTP_RM_FORM_VARIABLES_2)
                + strlen(NGX_HTTP_RM_FORM_VARIABLES_3)
                + decoded_name_len
                + decoded_value_len;

            buf_a = ngx_pcalloc(r->pool, form_len + inc_form_len);
            if (buf_a == NULL) {
                return NULL;
            }

            /* points buf_b to post_vars */
            buf_b = post_vars;
            
            /* copy post_vars to buf_a and add new stuffs */
            if (post_vars != NULL) {
                /* copy old stuffs here */
                memcpy(buf_a, post_vars, form_len);
            }

            /* initial offset */
            offset = form_len;

            /* copy part 1 */
            ngx_memcpy(buf_a + offset, 
                    NGX_HTTP_RM_FORM_VARIABLES_1, 
                    strlen(NGX_HTTP_RM_FORM_VARIABLES_1));

            offset += strlen(NGX_HTTP_RM_FORM_VARIABLES_1);

            /* copy vairiable name */
            ngx_memcpy(buf_a + offset, 
                    decoded_name, 
                    decoded_name_len);

            offset += decoded_name_len;

            /* copy part 2 */
            ngx_memcpy(buf_a + offset, 
                    NGX_HTTP_RM_FORM_VARIABLES_2, 
                    strlen(NGX_HTTP_RM_FORM_VARIABLES_2));

            offset += strlen(NGX_HTTP_RM_FORM_VARIABLES_2);

            /* copy variable value if not 0 */
            if (decoded_value_len != 0) {
                ngx_memcpy(buf_a + offset, 
                        decoded_value, 
                        decoded_value_len);

                offset += decoded_value_len;
            }

            /* copy part 3 */
            ngx_memcpy(buf_a + offset, 
                    NGX_HTTP_RM_FORM_VARIABLES_3, 
                    strlen(NGX_HTTP_RM_FORM_VARIABLES_3));

            /* points post_vars to buf_a and free buf_b */
            post_vars = buf_a;

            ngx_pfree(r->pool, buf_b);
            
            form_len += inc_form_len;
        }
    }

    *post_vars_len = form_len;

#if 0
    ngx_uint_t k;

    for (k = 0; k < *post_vars_len; k++) {
        fprintf(stderr, "%c", post_vars[k]);
    }
    fprintf(stderr, "\n");
#endif

    return post_vars;
}

static ngx_int_t
ngx_http_rm_generate_fake_cookie(ngx_http_request_t *r, 
        ngx_str_t *fake_1, ngx_str_t *fake_2)
{
    ngx_sha1_t                       sha1_state;
    u_char                           sha1_digest[20];
    u_char                           hex_output[20 * 2 + 1], source[512];
    ngx_uint_t                       di, source_len = 0;
    ngx_int_t                        t;
    ngx_int_t                        ra;

    t = ngx_time();
    ra = ngx_random();
    
    /* generate fake cookies */
    if (fake_1 != NULL) {
        memset(source, 0, 512);
        source_len = snprintf((char *)source, 512, "%d", (int)(ra + t));
        
        ngx_sha1_init(&sha1_state);
        ngx_sha1_update(&sha1_state, source, source_len);
        ngx_sha1_final(sha1_digest, &sha1_state);
        
        for (di = 0; di < 20; di++) {
            sprintf((char *)hex_output + di * 2, "%02x", sha1_digest[di]);
        }

        memcpy(fake_1->data, hex_output, NGX_HTTP_RM_DEFAULT_COOKIE_LEN);
        fake_1->data[NGX_HTTP_RM_DEFAULT_COOKIE_LEN] = 0;
        fake_1->len = NGX_HTTP_RM_DEFAULT_COOKIE_LEN;
    }
    
    if (fake_2 != NULL) {
        memset(source, 0, 512);
        source_len = snprintf((char *)source, 512, "%d", (int)(ra - t));
        
        ngx_sha1_init(&sha1_state);
        ngx_sha1_update(&sha1_state, source, source_len);
        ngx_sha1_final(sha1_digest, &sha1_state);
        
        for (di = 0; di < 20; di++) {
            sprintf((char *)hex_output + di * 2, "%02x", sha1_digest[di]);
        }

        memcpy(fake_2->data, hex_output, NGX_HTTP_RM_DEFAULT_COOKIE_LEN);
        fake_2->data[NGX_HTTP_RM_DEFAULT_COOKIE_LEN] = 0;
        fake_2->len = NGX_HTTP_RM_DEFAULT_COOKIE_LEN;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_rm_generate_cookie(ngx_http_request_t *r, ngx_str_t *cookie, 
        ngx_int_t timeout)
{
    ngx_sha1_t                       sha1_state;
    u_char                           sha1_digest[20];
    u_char                           hex_output[20 * 2 + 1], source[512];
    ngx_uint_t                       di, source_len = 0;
    /* XXX: only src addr is considered to form the cookie value */
#if 0
    u_char                           sa[NGX_SOCKADDRLEN];
    struct sockaddr_in              *peer_addr;
    socklen_t                        peer_len = NGX_SOCKADDRLEN;
    ngx_int_t                        ret = 0;
#endif
    ngx_uint_t                       port_time_len;

    memset(source, 0, 512);

    memcpy(source, r->connection->addr_text.data, r->connection->addr_text.len);
    source_len += r->connection->addr_text.len;
#if 0    
    ret = getpeername(r->connection->fd, (struct sockaddr *)&sa, &peer_len);
    if (ret < 0) {
        return NGX_ERROR;
    }

    time = ngx_timeofday();
    if (!time) {
        return NGX_ERROR;
    }

    peer_addr = (struct sockaddr_in *)sa;
    port_time_len = sprintf((char *)source + source_len, ":%u %ld.%lu", 
            peer_addr->sin_port, (ngx_int_t)ngx_time(), time->msec);

    if (port_time_len <= 0) {
        return NGX_ERROR;
    }

    source_len += port_time_len;
#endif
    port_time_len = sprintf((char *)source + source_len, "@%ld", 
                                        (unsigned long)timeout);

    if (port_time_len <= 0) {
        return NGX_ERROR;
    }

    source_len += port_time_len;

    ngx_sha1_init(&sha1_state);
    ngx_sha1_update(&sha1_state, source, source_len);
    ngx_sha1_final(sha1_digest, &sha1_state);

    for (di = 0; di < 20; di++) {
        sprintf((char *)hex_output + di * 2, "%02x", sha1_digest[di]);
    }

    memcpy(cookie->data, hex_output, NGX_HTTP_RM_DEFAULT_COOKIE_LEN);
    cookie->data[NGX_HTTP_RM_DEFAULT_COOKIE_LEN] = 0;
    cookie->len = NGX_HTTP_RM_DEFAULT_COOKIE_LEN;

    return NGX_OK;
}

static char *
ngx_http_rm_strstr(ngx_http_request_t *r, 
        ngx_str_t *haystack, ngx_str_t *needle)
{
    char *a, *b;

    a = ngx_pcalloc(r->pool, haystack->len + 1);
    if (a == NULL) {
        return NULL;
    }

    memcpy(a, haystack->data, haystack->len);

    b = ngx_pcalloc(r->pool, needle->len + 1);
    if (b == NULL) {
        return NULL;
    }
    
    memcpy(b, needle->data, needle->len);

    return ngx_strstr(a, b);
}

static ngx_int_t
ngx_http_rm_valid_cookie(ngx_http_request_t *r, ngx_str_t *gen_cookie)
{
    ngx_http_rm_loc_conf_t              *rlcf;  
    ngx_int_t                           ret;
    ngx_str_t                           cookie;

    rlcf = ngx_http_get_module_loc_conf(r, ngx_http_robot_mitigation_module);

    ret = ngx_http_parse_multi_header_lines(&r->headers_in.cookies, 
            &rlcf->cookie_name, &cookie);

    if (ret == NGX_DECLINED 
            || cookie.len == 0) {
        return NGX_HTTP_RM_RET_INVALID_COOKIE;
    }

    /* find a cookie, check the value then */
    if (!ngx_http_rm_strstr(r, &cookie, gen_cookie)) {
        return NGX_HTTP_RM_RET_INVALID_COOKIE;
    }

    return NGX_OK; 
}

ngx_int_t ngx_http_rm_special_swf_uri(ngx_http_request_t *r)
{
    if (r->uri.len > sizeof(NGX_HTTP_RM_SWF_FILENAME_PREFIX)
            && ngx_strstr(r->uri.data, 
                NGX_HTTP_RM_SWF_FILENAME_PREFIX)) {
        return 1;
    }
 
    return 0;
}

static ngx_int_t
ngx_http_rm_check_ajax_request(ngx_http_request_t *r)
{
    ngx_table_elt_t             *h;
    ngx_list_part_t             *part;
    ngx_uint_t                   i;

    part = &r->headers_in.headers.part;
    h = part->elts;

    for (i = 0; i < part->nelts; i++) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "ajax_request_check: %V %V", &h[i].key, &h[i].value);
        if (h[i].key.len != NGX_HTTP_RM_AJAX_KEY_LEN) {
            continue;
        }

        if (!ngx_strncasecmp(h[i].key.data, (u_char *)NGX_HTTP_RM_AJAX_KEY,
                NGX_HTTP_RM_AJAX_KEY_LEN)) {
            /* key matched, check value */
            if (h[i].value.len != NGX_HTTP_RM_AJAX_VALUE_LEN) {
                continue;
            }

            if (!ngx_strncasecmp(h[i].value.data,
                        (u_char *)NGX_HTTP_RM_AJAX_VALUE,
                        NGX_HTTP_RM_AJAX_VALUE_LEN)) {
                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                        "ajax_request_match: %V %V", &h[i].key, &h[i].value);
                return 1;
            }
        }
    }

    return 0;
}

static void 
ngx_http_rm_dns_timeout_handler(ngx_event_t *event) 
{
    ngx_http_rm_dns_t               *node;

    node = event->data;

    ngx_rbtree_delete(&ngx_http_rm_dns_rbtree, &node->node);

    free(node->name.data);
    free(node);
}

static void
ngx_http_rm_resolve_addr_handler(ngx_resolver_ctx_t *ctx)
{
    ngx_http_request_t              *r;
    ngx_http_rm_dns_t               *node;
    uint32_t                        hash;

    r = ctx->data;
    r->phase_handler = NGX_HTTP_NETEYE_SECURITY_PHASE;
    r->se_handler = ngx_http_rm_request_handler;

    hash = ngx_crc32_short(r->connection->addr_text.data, 
            r->connection->addr_text.len);
    node = ngx_http_rm_dns_lookup(&ngx_http_rm_dns_rbtree,
            &r->connection->addr_text, hash);

    if (node == NULL) {
        node = calloc(1, sizeof(*node));
        if (node == NULL) {
            goto no_memory;
        }
        
        if (ctx->name.len > 0) {
            node->name.data = calloc(1, ctx->name.len);
            if (node->name.data == NULL) {
                goto no_memory;
            }

            memcpy(node->name.data, ctx->name.data, ctx->name.len);

        }
        node->name.len = ctx->name.len;

        memcpy(node->addr, r->connection->addr_text.data, 
                r->connection->addr_text.len);
        node->len = r->connection->addr_text.len;
        node->timeout_ev.handler = ngx_http_rm_dns_timeout_handler;
        node->timeout_ev.data = node;
        node->timeout_ev.timer_set = 0;
        node->timeout_ev.log = &ngx_http_rm_timer_log;
        ngx_add_timer(&node->timeout_ev, NGX_HTTP_RM_ADDR_TIMEOUT);

        node->node.key = hash;
        ngx_rbtree_insert(&ngx_http_rm_dns_rbtree, &node->node);
    }

    ngx_resolve_addr_done(ctx);
    r->wl_resolve_ctx = NULL;
    ngx_http_core_run_phases(r);

    return;

no_memory:
    ngx_resolve_addr_done(ctx);
    r->wl_resolve_ctx = NULL;
    ngx_http_finalize_request(r, NGX_ERROR);
}

static void
ngx_http_rm_cleanup(void *data)
{
    ngx_http_request_t *r = data;

    if (r->wl_resolve_ctx) {
        ngx_resolve_addr_done(r->wl_resolve_ctx);
        r->wl_resolve_ctx = NULL;
    }
}

static ngx_int_t
ngx_http_rm_request_handler(ngx_http_request_t *r)
{
    ngx_http_rm_loc_conf_t            *rlcf;  
    ngx_http_rm_main_conf_t           *rmcf;
    ngx_resolver_ctx_t                *rctx;
    ngx_http_rm_req_ctx_t             *ctx;
    ngx_str_t                          cookie, user_agent;
    ngx_str_t                          cookie_f1, cookie_f2;
    ngx_str_t                          src_addr_text;
    ngx_str_t                         *domain_name = NULL;
    ngx_int_t                          ret;
    ngx_http_rm_whitelist_item_t      *item;
    ngx_http_rm_ip_whitelist_item_t   *ip_item;
    ngx_uint_t                         i;
    ngx_int_t                          gen_time;
    in_addr_t                          src_addr;
    ngx_http_rm_dns_t                 *node;
    uint32_t                           hash;
    ngx_http_cleanup_t                 *cln;
#if (NGX_HTTP_X_FORWARDED_FOR)
    ngx_array_t                       *xfwd;
    ngx_table_elt_t                  **h;
#endif

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
            "robot mitigation request handler begin");
    
    rlcf = ngx_http_get_module_loc_conf(r, ngx_http_robot_mitigation_module);

    if (rlcf->enabled != 1) {
        return NGX_DECLINED;
    }

    if (rlcf->pass_ajax) {
        if (ngx_http_rm_check_ajax_request(r)) {
            return NGX_DECLINED;
        }
    }

    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }

    cln->handler = ngx_http_rm_cleanup;
    cln->data = r;

    if (rlcf->ip_whitelist_items) {
#if (NGX_HTTP_X_FORWARDED_FOR)
        if (rlcf->ip_whitelist_x_forwarded_for && 
                r->headers_in.x_forwarded_for.nelts > 0) {
            xfwd = &r->headers_in.x_forwarded_for;
            h = xfwd->elts;
            src_addr = ngx_inet_addr(h[0]->value.data, 
                    h[0]->value.len);
        } else 
#endif
            src_addr = ngx_inet_addr(r->connection->addr_text.data, 
                    r->connection->addr_text.len);

        ip_item = rlcf->ip_whitelist_items->elts;

        src_addr = ntohl(src_addr);
        /* check ip whitelist */
        for (i = 0; i < rlcf->ip_whitelist_items->nelts; i++) {
            if (ip_item[i].start_addr <= src_addr &&
                    ip_item[i].end_addr >= src_addr) {
                break;
            }
        }

        /* Matched */
        if (i != rlcf->ip_whitelist_items->nelts) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                    "ip whitelist matched\n");
            return NGX_DECLINED;
        } 
    }

#if (NGX_PCRE)
    /* -1: check whitelist */
    if (r->headers_in.user_agent != NULL && rlcf->whitelist_items) {
        user_agent = r->headers_in.user_agent->value;
        item = rlcf->whitelist_items->elts;

        for (i = 0; i < rlcf->whitelist_items->nelts; i++) {
            ret = ngx_http_regex_exec(r, item[i].regex, &user_agent);

            if (ret == NGX_OK) {
                /* match */
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                        "robot mitigation match whitelist: %V", 
                        &user_agent);

                if (item[i].domain_name) {
                    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                        "d name = %p\n", domain_name);
                    if (domain_name == NULL) {
                        hash = ngx_crc32_short(r->connection->addr_text.data, 
                                r->connection->addr_text.len);
                        node = ngx_http_rm_dns_lookup(&ngx_http_rm_dns_rbtree,
                                &r->connection->addr_text, hash);

                        if (node) {
                            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, 
                                    r->connection->log, 0, 
                                    "found node\n");
                            if (node->name.len == 0) {
                                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, 
                                        r->connection->log, 0, 
                                        "found node, but no name\n");
                                continue;
                            }
                            domain_name = &node->name;
                        }
                    }

                    if (domain_name) {
                        ret = ngx_http_regex_exec(r, item[i].domain_name, domain_name);
                        if (ret == NGX_OK) {
                            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                                    "matched\n");
                            return NGX_DECLINED;
                        }

                        if (ret == NGX_ERROR) {
                            return NGX_ERROR;
                        }

                        continue;
                    }

                    rmcf = ngx_http_get_module_main_conf(r, 
                            ngx_http_robot_mitigation_module);
                    if (rmcf->resolver == NULL) {
                        continue;
                    }
                    rctx = ngx_resolve_start(rmcf->resolver, NULL);
                    if (rctx == NULL) {
                        return NGX_ERROR;
                    }
                    rctx->addr.sockaddr = r->connection->sockaddr;
                    rctx->addr.socklen = r->connection->socklen;
                    rctx->handler = ngx_http_rm_resolve_addr_handler;
                    rctx->data = r;
                    rctx->timeout = rmcf->resolver_timeout;

                    ret = ngx_resolve_addr(rctx);
                    r->wl_resolve_ctx = rctx;

                    if (ret == NGX_ERROR) {
                        r->wl_resolve_ctx = NULL;
                        return NGX_ERROR;
                    }

                    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                            "wait for query\n");
                    /* Stop request and waiting for the DNS respoonse */
                    return NGX_DONE;
                }

                return NGX_DECLINED;
            }

            if (ret == NGX_ERROR) {
                return NGX_ERROR;
            }

            /* NGX_DECLINED means not macth, we continue search */
        }
    }
#else
#error "must compile with PCRE"
#endif

    /* 0: check special active-challenge urls ignoring the location */
    if (ngx_http_rm_special_swf_uri(r)) {
        ngx_http_ns_set_bypass_all(r);

        r->write_event_handler = ngx_http_request_empty_handler;
        ngx_http_finalize_request(r, ngx_http_rm_send_swf_handler(r));

        return NGX_DONE;
    }

    /* 1: check special cookie */
    cookie.data = ngx_pcalloc(r->pool, NGX_HTTP_RM_DEFAULT_COOKIE_LEN + 1);
    if (cookie.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    gen_time = ngx_time();
    gen_time = gen_time - (gen_time % rlcf->timeout);

    ret = ngx_http_rm_generate_cookie(r, &cookie, gen_time);
    if (ret != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
            "real cookie generated: %V", &cookie);
    
    ret = ngx_http_rm_valid_cookie(r, &cookie);
    if (ret == NGX_OK) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                "robot mitigation passed");

        return NGX_DECLINED;
    }
 
    if (ret == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
            "robot mitgation failed, re-challenge");

#if NGX_HTTP_IP_BLACKLIST
#if (NGX_HTTP_X_FORWARDED_FOR)
        if (r->headers_in.x_forwarded_for.nelts > 0) {
            xfwd = &r->headers_in.x_forwarded_for;
            h = xfwd->elts;
            src_addr_text = h[0]->value;
        } else
#endif
        {
            src_addr_text = r->connection->addr_text;
        }
 
    if (rlcf->failed_count > 0) {
        ret = ngx_http_ip_blacklist_update(r,
                    &src_addr_text,
                    rlcf->failed_count + 1,
                    &ngx_http_robot_mitigation_module);
        if (ret == 1) {
            return NGX_ERROR;
        }
    }
#endif

    if ((r->method != NGX_HTTP_GET)
            && (r->method != NGX_HTTP_POST)) {
        return NGX_DECLINED;
    }

    /* currently we only support application/x-www-form-urlencoded style post
     * TODO: support it
     */
    if (r->method == NGX_HTTP_POST) {
        if (!ngx_http_rm_test_content_type(r, (u_char *)NGX_HTTP_RM_POST_TYPE)) {
                return NGX_DECLINED;
        }
    }

    cookie_f1.data = ngx_pcalloc(r->pool, NGX_HTTP_RM_DEFAULT_COOKIE_LEN + 1);
    if (cookie_f1.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cookie_f2.data = ngx_pcalloc(r->pool, NGX_HTTP_RM_DEFAULT_COOKIE_LEN + 1);
    if (cookie_f2.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ret = ngx_http_rm_generate_fake_cookie(r, &cookie_f1, &cookie_f2);
    if (ret != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
            "fake cookie generated: %V/%V", &cookie_f1, &cookie_f2);

    ctx = ngx_http_rm_get_request_ctx(r);
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->request = r;
    ctx->cookie.data = cookie.data;
    ctx->cookie.len = cookie.len;
    ctx->cookie_f1.data = cookie_f1.data;
    ctx->cookie_f1.len = cookie_f1.len;
    ctx->cookie_f2.data = cookie_f2.data;
    ctx->cookie_f2.len = cookie_f2.len;

    ngx_http_ns_set_bypass_all(r);

    r->write_event_handler = ngx_http_request_empty_handler;
    ngx_http_finalize_request(r, ngx_http_rm_content_handler(r));

    return NGX_DONE;
}

static ngx_http_rm_dns_t *
ngx_http_rm_dns_lookup(ngx_rbtree_t *tree, ngx_str_t *addr, uint32_t hash)
{
    ngx_int_t                   rc;
    ngx_rbtree_node_t           *node, *sentinel;
    ngx_http_rm_dns_t           *rn;

    node = tree->root;
    sentinel = tree->sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        rn = (ngx_http_rm_dns_t *) node;

        rc = ngx_memn2cmp(addr->data, rn->addr, addr->len, rn->len);

        if (rc == 0) {
            return rn;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    /* not found */

    return NULL;
}

static void
ngx_http_rm_dns_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t       **p;
    ngx_http_rm_dns_t       *rd, *rd_temp;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            rd = (ngx_http_rm_dns_t *) node;
            rd_temp = (ngx_http_rm_dns_t *) temp;

            p = (ngx_memn2cmp(rd->addr, rd_temp->addr, rd->len, rd_temp->len)
                 < 0) ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


static ngx_int_t ngx_http_rm_init(ngx_conf_t *cf)
{
    ngx_http_rm_main_conf_t     *rmcf;
    ngx_int_t                   ret;

    rmcf = ngx_http_conf_get_module_main_conf(cf, 
            ngx_http_robot_mitigation_module);

    if (rmcf->wl_domain_enable && rmcf->resolver == NULL) {
        fprintf(stderr, "robot_mitigation_resolver not configured\n");
        return NGX_ERROR;
    } else if (rmcf->wl_domain_enable && 
            rmcf->resolver_timeout == NGX_CONF_UNSET_MSEC) {
        rmcf->resolver_timeout = 3000; //3s
    }

    ret = ngx_http_neteye_security_ctx_register(NGX_HTTP_NETEYE_ROBOT_MITIGATION, 
            ngx_http_rm_request_ctx_init);

    if (ret != NGX_OK) {
        return ret;
    }

    ret = ngx_http_ip_blacklist_register_mod(&ngx_http_robot_mitigation_module);
    if (ret != NGX_OK) {
        return ret;
    }

    ngx_http_rm_timer_log.file = ngx_palloc(cf->pool, sizeof(ngx_open_file_t));
    if (ngx_http_rm_timer_log.file == NULL) {
        return NGX_ERROR;
    }

    ngx_http_rm_timer_log.file->fd = NGX_INVALID_FILE;

    ngx_rbtree_init(&ngx_http_rm_dns_rbtree, &ngx_http_rm_dns_sentinel,
                    ngx_http_rm_dns_rbtree_insert_value);

    /* we only a request handler for this feature */
    return ngx_http_neteye_security_request_register(
            NGX_HTTP_NETEYE_ROBOT_MITIGATION,
            ngx_http_rm_request_handler);
}

static char *ngx_http_rm(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_rm_loc_conf_t  *rlcf = conf;
    ngx_str_t               *value = NULL;

    value = cf->args->elts;

    if (!strncmp((char *)(value[1].data), "on", value[1].len)) {
        rlcf->enabled = 1;
    }

    return NGX_CONF_OK;
}

static void *
ngx_http_rm_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_rm_main_conf_t  *rmcf;

    rmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_rm_main_conf_t));
    if (rmcf == NULL) {
        return NULL;
    }

    memset(rmcf, 0, sizeof(*rmcf));
    rmcf->resolver_timeout = NGX_CONF_UNSET_MSEC;

    return rmcf;
}


static char *
ngx_http_rm_resolver(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_rm_main_conf_t  *rmcf = conf;
    ngx_str_t               *value;

    if (rmcf->resolver) {
        return "is duplicate";
    }

    value = cf->args->elts;

    rmcf->resolver = ngx_resolver_create(cf, &value[1], cf->args->nelts - 1);
    if (rmcf->resolver == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

#if (NGX_HTTP_X_FORWARDED_FOR)
static char *ngx_http_rm_ip_whitelist_x_forwarded_for(ngx_conf_t *cf, 
        ngx_command_t *cmd, void *conf)
{
    ngx_http_rm_loc_conf_t  *rlcf = conf;
    ngx_str_t               *value = NULL;

    value = cf->args->elts;

    if (!strncmp((char *)(value[1].data), "on", value[1].len)) {
        rlcf->ip_whitelist_x_forwarded_for = 1;
    }

    return NGX_CONF_OK;
}
#endif

static char *ngx_http_rm_cookie_name(ngx_conf_t *cf,
        ngx_command_t *cmd, void *conf)
{
    ngx_http_rm_loc_conf_t  *rlcf = conf;
    ngx_str_t               *value = NULL;
    ngx_str_t               *name = NULL;

    value = cf->args->elts;

    if (value[1].len > NGX_HTTP_RM_MAX_COOKIE_NAME_LEN) {
        return "must not be longer than 32 characters";
    }

    if (value[1].len != NGX_HTTP_RM_MAX_COOKIE_NAME_LEN) {
        /* append space to cookie name */
        rlcf->cookie_name = value[1];
        name = &rlcf->cookie_name_c;

        name->data = ngx_pcalloc(cf->pool, NGX_HTTP_RM_MAX_COOKIE_NAME_LEN + 1);
        if (!name->data) {
            return NGX_CONF_ERROR;
        }

        memset(name->data, ' ', NGX_HTTP_RM_MAX_COOKIE_NAME_LEN);
        memcpy(name->data, value[1].data, value[1].len);
        name->len = NGX_HTTP_RM_MAX_COOKIE_NAME_LEN;
    } else {
        /* value[1].len == MAX_COOKIE_NAME_LEN */
        rlcf->cookie_name_c = rlcf->cookie_name = value[1];
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_rm_mode(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_rm_loc_conf_t     *rlcf = conf;
    ngx_str_t                  *value;
    
    value = cf->args->elts;

    if ((ngx_strstr(value[1].data, "JS") != NULL)
            || (ngx_strstr(value[1].data, "js") != NULL)) {
        rlcf->mode = NGX_HTTP_RM_MODE_JS;
    } else if ((ngx_strstr(value[1].data, "SWF") != NULL) 
            || (ngx_strstr(value[1].data, "swf") != NULL)) {
        rlcf->mode = NGX_HTTP_RM_MODE_SWF;
    } else {
        return "Unknow robot_mitigation_modes type";
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_rm_blacklist(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_rm_loc_conf_t     *rlcf = conf;
    ngx_str_t                  *value;

    value = cf->args->elts;

    rlcf->failed_count = ngx_atoi(value[1].data, value[1].len);
    if (rlcf->failed_count == NGX_ERROR) {
        return "Invalid blacklist count";
    }

    if (rlcf->failed_count <= 0) {
        return "Invalid blacklist count";
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_rm_timeout(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_rm_loc_conf_t     *rlcf = conf;
    ngx_str_t                  *value;
    ngx_str_t                  *tmp;
    ngx_int_t                   timeout;

    value = cf->args->elts;

    timeout = ngx_atoi(value[1].data, value[1].len);
    if (timeout == NGX_ERROR) {
        return "Invalid timeout value";
    }

    if (timeout == 0) {
        rlcf->no_expires = 1;
    }

    if (timeout > NGX_HTTP_RM_MAX_TIMEOUT) {
        return "can not be bigger than 3600s";
    }

    rlcf->timeout = timeout;

    if (value[1].len < NGX_HTTP_RM_MAX_TIMEOUT_STR_LEN) {
        tmp = &rlcf->timeout_c;

        tmp->data = ngx_pcalloc(cf->pool, NGX_HTTP_RM_MAX_TIMEOUT_STR_LEN + 1);
        if (!tmp->data) {
            return NGX_CONF_ERROR;
        }

        memset(tmp->data, ' ', NGX_HTTP_RM_MAX_TIMEOUT_STR_LEN);
        memcpy(tmp->data, value[1].data, value[1].len);
        tmp->len = NGX_HTTP_RM_MAX_TIMEOUT_STR_LEN;
    } else {
        /* equal */
        rlcf->timeout_c = value[1];
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_rm_challenge_ajax(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_rm_loc_conf_t     *rlcf = conf;
    ngx_str_t                  *value;

    value = cf->args->elts;

    if (!strncmp((char *)(value[1].data), "on", value[1].len)) {
        rlcf->pass_ajax = 0;
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_rm_whitelist_caseless(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_rm_loc_conf_t     *rlcf = conf;
    ngx_str_t                  *value;

    value = cf->args->elts;

    if (!strncmp((char *)(value[1].data), "on", value[1].len)) {
        rlcf->wl_caseless = 1;
    }

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_rm_whitelist_pattern_parse(ngx_conf_t *cf, ngx_http_regex_t **regex,
    ngx_str_t *pattern, ngx_http_rm_loc_conf_t *rlcf)
{
#if (NGX_PCRE)
    ngx_regex_compile_t  rc;
    u_char               errstr[NGX_MAX_CONF_ERRSTR];

    ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

    rc.pattern = *pattern;
    rc.err.len = NGX_MAX_CONF_ERRSTR;
    rc.err.data = errstr;

#if (NGX_HAVE_CASELESS_FILESYSTEM)
    rc.options = NGX_REGEX_CASELESS;
#else
    if (rlcf->wl_caseless) {
        rc.options = NGX_REGEX_CASELESS;
    } else {
        rc.options = 0;
    }
#endif

    *regex = ngx_http_regex_compile(cf, &rc);
    if (*regex == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;

#else

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "using regex \"%V\" requires PCRE library",
                       pattern);
    return NGX_ERROR;

#endif
}

static char *
ngx_http_rm_whitelist_parse(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
{
    ngx_http_rm_loc_conf_t          *rlcf = conf;
    ngx_str_t                       *pattern, *domain_name, *value;
    ngx_http_rm_whitelist_item_t    *item;
    ngx_int_t                       ret;
    ngx_http_rm_main_conf_t         *rmcf;

    value = cf->args->elts;

    if (ngx_strcmp(value[0].data, "include") == 0) {
        if (cf->args->nelts != 2) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid number of arguments"
                               " in \"include\" directive");
            return NGX_CONF_ERROR;
        }

        return ngx_conf_include(cf, dummy, conf);
    }

    pattern = ngx_palloc(cf->pool, sizeof(ngx_str_t));
    if (pattern == NULL) {
        return NGX_CONF_ERROR;
    }

    *pattern = value[0];

    ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, 
            "robot mitigation: original pattern is \"%V\"", pattern);

    item = ngx_array_push(rlcf->whitelist_items);
    if (item == NULL) {
        return NGX_CONF_ERROR;
    }

    ret = ngx_http_rm_whitelist_pattern_parse(cf, &item->regex, pattern, rlcf);
    if (ret != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (cf->args->nelts == 2) {
        domain_name = ngx_palloc(cf->pool, sizeof(ngx_str_t));
        if (domain_name == NULL) {
            return NGX_CONF_ERROR;
        }

        *domain_name = value[1];

        ret = ngx_http_rm_whitelist_pattern_parse(cf, &item->domain_name, 
                domain_name, rlcf);
        if (ret != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        rmcf = ngx_http_conf_get_module_main_conf(cf, 
            ngx_http_robot_mitigation_module);

        rmcf->wl_domain_enable = 1;
        ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0,
                "robot mitigation: "
                "original pattern is \"%V\"", domain_name);
    } else {
        item->domain_name = NULL;
    }

    ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, 
            "robot mitigation: "
            "regex pattern is \"%p\"", item->regex);
    
    return NGX_CONF_OK;
}

static char *
ngx_http_rm_whitelist(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_rm_loc_conf_t *rlcf = conf;

    char        *rv;
    ngx_conf_t   save;

    if (rlcf->whitelist_items == NULL) {
        rlcf->whitelist_items = 
            ngx_array_create(cf->pool, 64, sizeof(ngx_http_rm_whitelist_item_t));
        
        if (rlcf->whitelist_items == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    save = *cf;
    cf->handler = ngx_http_rm_whitelist_parse;
    cf->handler_conf = conf;

    rv = ngx_conf_parse(cf, NULL);

    *cf = save;

    return rv;
}

static char *
ngx_http_rm_ip_whitelist_parse(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
{
    ngx_http_rm_loc_conf_t  			*rlcf = conf;
    ngx_str_t               			*value;	
	in_addr_t							start, end;
    ngx_http_rm_ip_whitelist_item_t  	*item;

    value = cf->args->elts;

    if (ngx_strcmp(value[0].data, "include") == 0) {
        if (cf->args->nelts != 2) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid number of arguments"
                               " in \"include\" directive");
            return NGX_CONF_ERROR;
        }

        return ngx_conf_include(cf, dummy, conf);
    }

    if (cf->args->nelts == 0 || cf->args->nelts > 2) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "invalid number of arguments"
                " in a name-pattern pair");
        
        return NGX_CONF_ERROR;
    }

    start = ngx_inet_addr(value[0].data, value[0].len);
	if (start == INADDR_NONE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "invalid ip address");
        return NGX_CONF_ERROR;
	}

	if (cf->args->nelts == 2) {
    	end = ngx_inet_addr(value[1].data, value[1].len);
		if (end == INADDR_NONE) {
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
					"invalid ip address");
			return NGX_CONF_ERROR;
		}
		if (ntohl(start) >= ntohl(end)) {
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
					"start ip less or eq end ip");
			return NGX_CONF_ERROR;
		}
	} else {
		end = start;
	}

    item = ngx_array_push(rlcf->ip_whitelist_items);
    if (item == NULL) {
        return NGX_CONF_ERROR;
    }

    item->start_addr = ntohl(start);
    item->end_addr = ntohl(end);

    return NGX_CONF_OK;
}

static char *
ngx_http_rm_ip_whitelist(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_rm_loc_conf_t *rlcf = conf;

    char        *rv;
    ngx_conf_t   save;

    if (rlcf->ip_whitelist_items == NULL) {
        rlcf->ip_whitelist_items = 
            ngx_array_create(cf->pool, 64, sizeof(ngx_http_rm_ip_whitelist_item_t));
        
        if (rlcf->ip_whitelist_items == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    save = *cf;
    cf->handler = ngx_http_rm_ip_whitelist_parse;
    cf->handler_conf = conf;

    rv = ngx_conf_parse(cf, NULL);

    *cf = save;

    return rv;
}

static void
ngx_http_rm_handle_no_expires(u_char *data, ngx_uint_t len) 
{
    ngx_uint_t                    i;

    for (i = 0; i < len; i++) {
        if (i + 2 < len
                && data[i] == 'm'
                && data[i + 1] == 'a'
                && data[i + 2] == 'x') {
            data[i] = 't';
        }
    }
}

/* for a GET request, 
 * respond with a js challenge
 * triggering an automatic reload of the page */
static ngx_int_t 
ngx_http_rm_challenge_get_js_handler(ngx_http_request_t *r)
{
    ngx_http_complex_value_t      cv;
    u_char                       *challenge_ct;
    ngx_http_rm_loc_conf_t       *rlcf;
    ngx_http_rm_req_ctx_t        *ctx;
    ngx_int_t                     random_tpl;
    const ngx_http_rm_tpl_t      *tpl;


    rlcf = ngx_http_get_module_loc_conf(r, ngx_http_robot_mitigation_module);

    ctx = ngx_http_rm_get_request_ctx(r);
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memzero(&cv, sizeof(ngx_http_complex_value_t)); 

    /* get template randomly */
    random_tpl = ngx_random() % ngx_http_rm_get_js_tpls_nr;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "get random js-get template, tpl id: %d", random_tpl);

    tpl = &ngx_http_rm_get_js_tpls[random_tpl];

    challenge_ct = ngx_pcalloc(r->pool, tpl->len + 1);
    if (challenge_ct == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    memcpy(challenge_ct, tpl->data, tpl->len);

    memcpy(challenge_ct + tpl->x,
            (u_char *)rlcf->cookie_name_c.data,
            rlcf->cookie_name_c.len);

    memcpy(challenge_ct + tpl->y,
            ctx->cookie.data,
            ctx->cookie.len);

    memcpy(challenge_ct + tpl->z,
            (u_char *)rlcf->timeout_c.data,
            rlcf->timeout_c.len);

    memcpy(challenge_ct + tpl->m,
            (u_char *)rlcf->cookie_name_c.data,
            rlcf->cookie_name_c.len);

    memcpy(challenge_ct + tpl->n,
            ctx->cookie_f1.data,
            ctx->cookie_f1.len);

    memcpy(challenge_ct + tpl->o,
            (u_char *)rlcf->timeout_c.data,
            rlcf->timeout_c.len);

    if (rlcf->no_expires == 1) {
        ngx_http_rm_handle_no_expires(challenge_ct, tpl->len);
    }

    cv.value.data = challenge_ct;
    cv.value.len = tpl->len;

    return ngx_http_send_response(r, NGX_HTTP_OK, &ngx_http_rm_type_html, &cv);
}

/* 
 * for a GET request, 
 * respond with a html that can trigger a GET request for a flash file
 */
static ngx_int_t
ngx_http_rm_challenge_get_swf_handler(ngx_http_request_t *r)
{
    ngx_http_complex_value_t      cv;
    u_char                       *challenge_ct;
    u_char                       *swf_filename;
    ngx_uint_t                    swf_filename_len;
    ngx_http_rm_req_ctx_t        *ctx;

    ctx = ngx_http_rm_get_request_ctx(r);
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memzero(&cv, sizeof(ngx_http_complex_value_t));

    /* + 5 means '-GET-' */
    swf_filename_len = strlen(NGX_HTTP_RM_SWF_FILENAME_PREFIX)
        + ctx->cookie.len
        + 5;

    swf_filename = ngx_pcalloc(r->pool, swf_filename_len + 1);
    if (swf_filename == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_sprintf(swf_filename, 
            NGX_HTTP_RM_SWF_FILENAME_PREFIX"%V-GET-", 
            &ctx->cookie);
    
    /* -8 means 4 %s in NGX_HTTP_RM_GET_SWF 
     * filename length * 4 means we need to replace 4 %s */
    cv.value.len = strlen(NGX_HTTP_RM_GET_SWF) 
            + (swf_filename_len * 4)
            - 8;
    
    challenge_ct = ngx_pcalloc(r->pool, cv.value.len);
    if (challenge_ct == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
   
    ngx_sprintf(challenge_ct, NGX_HTTP_RM_GET_SWF, 
            swf_filename, swf_filename, swf_filename, swf_filename);

    cv.value.data = challenge_ct;
    
    return ngx_http_send_response(r, NGX_HTTP_OK, &ngx_http_rm_type_html, &cv);
}

static void
ngx_http_rm_dummy_post_handler(ngx_http_request_t *r)
{
    return;
}

static ngx_int_t
ngx_http_rm_read_request_body(ngx_http_request_t *r, 
    ngx_http_client_body_handler_pt post_handler)
{
    r->request_body_in_single_buf = 1;
    r->request_body_in_persistent_file = 1;
    r->request_body_in_clean_file = 1;

    if (r->request_body_in_file_only) {
        r->request_body_file_log_level = 0;
    }

    return ngx_http_read_client_request_body(r, post_handler);
}

/* for a POST request, 
 * respond with a js challenge 
 * triggering an automatic resubmission of the form */
static ngx_int_t
ngx_http_rm_challenge_post_js_handler(ngx_http_request_t *r)
{
    ngx_http_complex_value_t      cv;
    u_char                       *challenge_ct;
    ngx_http_rm_loc_conf_t       *rlcf;
    ngx_http_rm_req_ctx_t        *ctx;
    u_char                       *post_vars = NULL;
    ngx_uint_t                    post_vars_len = 0;
    ngx_http_request_body_t      *rb;
    ngx_uint_t                    body_len, offset;
    ngx_int_t                     rc;
    ngx_int_t                     random_tpl;
    const ngx_http_rm_tpl_t      *tpl;

    rlcf = ngx_http_get_module_loc_conf(r, ngx_http_robot_mitigation_module);

    ctx = ngx_http_rm_get_request_ctx(r);
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memzero(&cv, sizeof(ngx_http_complex_value_t)); 

    rb = r->request_body;

    if (rb == NULL
        || rb->temp_file
        || rb->bufs == NULL
        || (body_len = rb->bufs->buf->last - rb->bufs->buf->pos) == 0
        || r->headers_in.content_length_n <= 0) {
        /* no request body */
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "no request body when ac post js\n");

        post_vars = NULL;
        post_vars_len = 0;
    } else {
        post_vars = ngx_http_rm_post_body_to_form(
                r,
                rb->bufs->buf->pos,
                body_len,
                &post_vars_len);
    }

    /* get template randomly */
    random_tpl = ngx_random() % ngx_http_rm_post_js_tpls_nr;
    tpl = &ngx_http_rm_post_js_tpls[random_tpl];

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "get random js-post template, tpl id: %d", random_tpl);

    cv.value.len = tpl->len
            + NGX_HTTP_RM_POST_JS_2_LEN
            + post_vars_len;

    challenge_ct = ngx_pcalloc(r->pool, cv.value.len + 1);
    if (challenge_ct == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
  
    memcpy(challenge_ct, tpl->data, tpl->len);

    memcpy(challenge_ct + tpl->x,
            (u_char *)rlcf->cookie_name_c.data,
            rlcf->cookie_name_c.len);

    memcpy(challenge_ct + tpl->y,
            ctx->cookie.data,
            ctx->cookie.len);

    memcpy(challenge_ct + tpl->z,
            (u_char *)rlcf->timeout_c.data,
            rlcf->timeout_c.len);

    memcpy(challenge_ct + tpl->m,
            (u_char *)rlcf->cookie_name_c.data,
            rlcf->cookie_name_c.len);

    memcpy(challenge_ct + tpl->n,
            ctx->cookie_f1.data,
            ctx->cookie_f1.len);

    /* add post vars */
    offset = strlen((const char *)challenge_ct); 

    if (post_vars_len != 0) {
        ngx_memcpy(challenge_ct + offset, 
                post_vars,
                post_vars_len);

        offset += post_vars_len;
    }

    /* copy part 2 */
    ngx_memcpy(challenge_ct + offset, 
            NGX_HTTP_RM_POST_JS_2, 
            strlen(NGX_HTTP_RM_POST_JS_2));

    if (rlcf->no_expires == 1) {
        ngx_http_rm_handle_no_expires(challenge_ct, cv.value.len); 
    }

    cv.value.data = challenge_ct;

    rc = ngx_http_send_response(r, NGX_HTTP_OK, &ngx_http_rm_type_html, &cv);

    /* we have to finalize the request by ourselves, 
     * that is because we use the "read client body" API */
    ngx_http_finalize_request(r, rc);

    return NGX_OK;
}

/* 
 * for a POST request, 
 * respond with a html that can trigger a GET request for a flash file
 */
static ngx_int_t 
ngx_http_rm_challenge_post_swf_handler(ngx_http_request_t *r)
{
    ngx_http_complex_value_t      cv;
    u_char                       *challenge_ct;
    u_char                       *swf_filename;
    ngx_uint_t                    swf_filename_len;
    ngx_http_rm_req_ctx_t        *ctx;
    u_char                       *post_vars = NULL;
    ngx_uint_t                    post_vars_len = 0;
    ngx_http_request_body_t      *rb;
    ngx_uint_t                    body_len, offset;
    ngx_int_t                     rc;


    ctx = ngx_http_rm_get_request_ctx(r);
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memzero(&cv, sizeof(ngx_http_complex_value_t));

    /* + 6 means '-POST-' */
    swf_filename_len = strlen(NGX_HTTP_RM_SWF_FILENAME_PREFIX)
        + ctx->cookie.len
        + 6;

    swf_filename = ngx_pcalloc(r->pool, swf_filename_len + 1);
    if (swf_filename == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_sprintf(swf_filename, 
            NGX_HTTP_RM_SWF_FILENAME_PREFIX"%V-POST-", 
            &ctx->cookie);
   
    rb = r->request_body;

    if (rb == NULL
        || rb->temp_file
        || rb->bufs == NULL
        || (body_len = rb->bufs->buf->last - rb->bufs->buf->pos) == 0
        || r->headers_in.content_length_n <= 0) {
        /* no request body */
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "no request body when ac post js\n");

        post_vars = NULL;
        post_vars_len = 0;
    } else {
        post_vars = ngx_http_rm_post_body_to_form(
                r, 
                rb->bufs->buf->pos, 
                body_len, 
                &post_vars_len);
    }

    /* -8 means 4 %s in NGX_HTTP_RM_POST_SWF_1 
     * filename length * 4 means we need to replace 4 %s */
    cv.value.len = strlen(NGX_HTTP_RM_POST_SWF_1) 
            + post_vars_len
            + strlen(NGX_HTTP_RM_POST_SWF_2)
            + (swf_filename_len * 4)
            - 8;
   
    challenge_ct = ngx_pcalloc(r->pool, cv.value.len);
    if (challenge_ct == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
   
    ngx_sprintf(challenge_ct, NGX_HTTP_RM_POST_SWF_1, 
            swf_filename, swf_filename, swf_filename, swf_filename);

    offset = strlen(NGX_HTTP_RM_POST_SWF_1) 
        + (swf_filename_len * 4)
        - 8;

    if (post_vars_len != 0) {
        ngx_memcpy(challenge_ct + offset, 
                post_vars,
                post_vars_len);

        offset += post_vars_len;
    }

    /* copy part 2 */
    ngx_memcpy(challenge_ct + offset, 
            NGX_HTTP_RM_POST_SWF_2, 
            strlen(NGX_HTTP_RM_POST_SWF_2));

    cv.value.data = challenge_ct;
    
    rc = ngx_http_send_response(r, NGX_HTTP_OK, &ngx_http_rm_type_html, &cv);

    /* we have to finalize the request by ourselves, 
     * that is because we use the "read client body" API */
    ngx_http_finalize_request(r, rc);
    
    return NGX_OK;
}

static ngx_int_t
ngx_http_rm_send_response(ngx_http_request_t *r, ngx_uint_t status,
    ngx_str_t *ct, ngx_str_t val)
{
    ngx_int_t     rc;
    ngx_buf_t    *b;
    ngx_chain_t   out;

    if (ngx_http_discard_request_body(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.status = status;

    if (status == NGX_HTTP_MOVED_PERMANENTLY
        || status == NGX_HTTP_MOVED_TEMPORARILY
        || status == NGX_HTTP_SEE_OTHER
        || status == NGX_HTTP_TEMPORARY_REDIRECT)
    {
        ngx_http_clear_location(r);

        r->headers_out.location = ngx_list_push(&r->headers_out.headers);
        if (r->headers_out.location == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        r->headers_out.location->hash = 1;
        ngx_str_set(&r->headers_out.location->key, "Location");
        r->headers_out.location->value = val;

        return status;
    }

    r->headers_out.content_length_n = val.len;

    if (ct) {
        r->headers_out.content_type_len = ct->len;
        r->headers_out.content_type = *ct;

    } else {
        if (ngx_http_set_content_type(r) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    if (r->method == NGX_HTTP_HEAD || (r != r->main && val.len == 0)) {
        return ngx_http_send_header(r);
    }

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->pos = val.data;
    b->last = val.data + val.len;
    b->memory = val.len ? 1 : 0;
    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}

static ngx_int_t 
ngx_http_rm_send_swf_file_handler(ngx_http_request_t *r, ngx_uint_t method)
{
    ngx_str_t                     val;
    u_char                       *challenge_ct, *final_ct;
    u_char                        cookie_name[40], cookie_value[40];
    u_char                        timeout[40];
    u_char                       *uri;
    ngx_http_rm_loc_conf_t       *rlcf;
    ngx_uint_t                    i, tmp_len, final_len;
    int                           ret;

    rlcf = ngx_http_get_module_loc_conf(r, ngx_http_robot_mitigation_module);
 
    /* replace the placeholder in flash file 
     * each placeholder in ngx_http_rm_get_swf is 40 bytes long
     * and we replace them with a 40 bytes long data, using \x20
     * to fill the gap.
     */
   
    ngx_memset(timeout, '\x20', 40);
    ngx_memset(cookie_name, '\x20', 40);
    ngx_memset(cookie_value, '\x20', 40);

    /* fetch timeout value */
    ngx_snprintf(timeout, 40, "%d", rlcf->timeout);

    /* fetch cookie value */
    uri = ngx_pcalloc(r->pool, r->uri.len + 1);
    if (uri == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    memcpy(uri, r->uri.data, r->uri.len);

    if (method == 0) {
        sscanf((char *)uri, "/"NGX_HTTP_RM_SWF_FILENAME_PREFIX"%40s-GET-.swf", 
                (char *)cookie_value);
    } else {
        sscanf((char *)uri, "/"NGX_HTTP_RM_SWF_FILENAME_PREFIX"%40s-POST-.swf", 
                (char *)cookie_value);
    }
   
    /* fetch cookie name */
    memcpy(cookie_name, rlcf->cookie_name.data, rlcf->cookie_name.len); 

    /* replace them into the flash file */
    if (method == 0) {
        val.len = sizeof(ngx_http_rm_get_swf) - 1;
    } else {
        val.len = sizeof(ngx_http_rm_post_swf) - 1;
    }

    challenge_ct = ngx_pcalloc(r->pool, val.len);
    if (challenge_ct == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (method == 0) {
        memcpy(challenge_ct, ngx_http_rm_get_swf, val.len);
    } else {
        memcpy(challenge_ct, ngx_http_rm_post_swf, val.len);
    }

    for (i = 0; i < val.len; i++) {
        /* replace cookie name */
        if (!memcmp(challenge_ct + i, 
                    NGX_HTTP_RM_SWF_PLACEHOLDER_COOKIE_NAME, 
                    strlen(NGX_HTTP_RM_SWF_PLACEHOLDER_COOKIE_NAME))) {
            memcpy(challenge_ct + i, cookie_name, 40);
        }
        
        /* replace cookie value */
        if (!memcmp(challenge_ct + i, 
                    NGX_HTTP_RM_SWF_PLACEHOLDER_COOKIE_VALUE, 
                    strlen(NGX_HTTP_RM_SWF_PLACEHOLDER_COOKIE_VALUE))) {
            memcpy(challenge_ct + i, cookie_value, 40);
        }
        
        /* replace timeout */
        if (!memcmp(challenge_ct + i, 
                    NGX_HTTP_RM_SWF_PLACEHOLDER_TIMEOUT, 
                    strlen(NGX_HTTP_RM_SWF_PLACEHOLDER_TIMEOUT))) {
            memcpy(challenge_ct + i, timeout, 40);
        }
    }

    if (rlcf->no_expires == 1) {
        ngx_http_rm_handle_no_expires(challenge_ct, val.len); 
    }

    /* build a final content by: 
     * 1) add a 'CWS' prefix 
     * 2) keep the original 5 chars
     * 3) compress the other chars by using zlib
     */

    /* read zlib.h to find out the zlib APIs usage */
    final_len = tmp_len = compressBound(val.len);

    /* 5 means the first 5 chars of challenge_ct */
    tmp_len += strlen("CWS") + 5;
    
    final_ct = ngx_pcalloc(r->pool, tmp_len);
    if (final_ct == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
   
    memcpy(final_ct, "CWS", strlen("CWS"));
    memcpy(final_ct + strlen("CWS"), challenge_ct, 5);

    ret = compress(final_ct + strlen("CWS") + 5, (uLongf *)&final_len, 
            challenge_ct + 5, val.len - 5);
    if (ret != Z_OK) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                "compress flash file failed: %d\n", ret);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    val.len = final_len + strlen("CWS") + 5;
    val.data = final_ct;
    
    return ngx_http_rm_send_response(r, NGX_HTTP_OK, 
            &ngx_http_rm_type_swf, val);
}

static ngx_int_t 
ngx_http_rm_send_swf_handler(ngx_http_request_t *r)
{
    u_char *uri;

    uri = ngx_pcalloc(r->pool, r->uri.len + 1);
    if (uri == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    memcpy(uri, r->uri.data, r->uri.len);

    if (r->method == NGX_HTTP_GET) {
        if (ngx_strstr(uri, "-GET-")) {
            return ngx_http_rm_send_swf_file_handler(r, 0);
        } else if (ngx_strstr(uri, "-POST-")) {
            return ngx_http_rm_send_swf_file_handler(r, 1);
        } else {
            /* invalid uri */
            return NGX_HTTP_FORBIDDEN;
        }
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_rm_test_content_type(ngx_http_request_t *r, u_char *type)
{
    ngx_table_elt_t       *content_type;

    content_type = r->headers_in.content_type;
    
    if (content_type == NULL) {
        return 0;
    }

    if (content_type->value.len != ngx_strlen(type)) {
        return 0;
    }

    if (ngx_memcmp(content_type->value.data, 
                type, content_type->value.len)) {
        return 0;
    }

    return 1;
}

static ngx_int_t 
ngx_http_rm_content_handler(ngx_http_request_t *r)
{
    ngx_http_rm_loc_conf_t          *rlcf;
    ngx_int_t                       rc;
    ngx_table_elt_t                 *cc, **ccp;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
            "in robot mitigation's content handler");

    ccp = r->headers_out.cache_control.elts;

    if (ccp == NULL) {

        if (ngx_array_init(&r->headers_out.cache_control, r->pool,
                           1, sizeof(ngx_table_elt_t *))
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    ccp = ngx_array_push(&r->headers_out.cache_control);
    if (ccp == NULL) {
        return NGX_ERROR;
    }

    cc = ngx_list_push(&r->headers_out.headers);
    if (cc == NULL) {
        return NGX_ERROR;
    }

    cc->hash = 1;
    ngx_str_set(&cc->key, "Cache-Control");
    ngx_str_set(&cc->value, "no-cache, no-store");

    *ccp = cc;
    
    rlcf = ngx_http_get_module_loc_conf(r, ngx_http_robot_mitigation_module);
    
    if (r->method == NGX_HTTP_GET) {
        if (rlcf->mode == NGX_HTTP_RM_MODE_JS) {
            return ngx_http_rm_challenge_get_js_handler(r);
        } else {
            return ngx_http_rm_challenge_get_swf_handler(r);
        }
    } else if (r->method == NGX_HTTP_POST){
        rc = ngx_http_rm_read_request_body(r, ngx_http_rm_dummy_post_handler);
        
        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }

        if (rlcf->mode == NGX_HTTP_RM_MODE_JS) {
            return ngx_http_rm_challenge_post_js_handler(r);
        } else {
            return ngx_http_rm_challenge_post_swf_handler(r);
        }
    }

    return NGX_OK;
}

#if 0
static void
ngx_http_rm_write_attack_log(ngx_http_request_t *r)
{  
    ngx_http_rm_loc_conf_t      *rlcf;
    ngx_str_t                   action;

    rlcf = ngx_http_get_module_loc_conf(r, ngx_http_robot_mitigation_module);
    action.data = (u_char *)ngx_http_ns_get_action_str(rlcf->action);
    action.len = ngx_strlen(action.data);

    ngx_http_neteye_send_attack_log(r, NGX_HTTP_NETEYE_ATTACK_LOG_ID_AC, 
            action, "robot_mitigation", NULL);
}

static ngx_int_t
ngx_http_rm_do_action(ngx_http_request_t *r)
{
    ngx_http_rm_loc_conf_t            *rlcf;
    ngx_http_ns_action_t              *action;
    ngx_int_t                          ret;

    rlcf = ngx_http_get_module_loc_conf(r, ngx_http_robot_mitigation_module);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
            "robot mitigation do action: %d", (int)rlcf->action);

    action = ngx_pcalloc(r->pool, sizeof(ngx_http_ns_action_t));
    if (action == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    action->action = rlcf->action;
    if (rlcf->error_page.data != NULL) {
        action->has_redirect = 1;
        action->redirect_page = &rlcf->error_page;
        action->in_body = 0;
    }
    
    ret = ngx_http_ns_do_action(r, action);
    if (ret != NGX_OK) {
        ngx_http_rm_write_attack_log(r);
    }

    return ret;
}
#endif

static void* ngx_http_rm_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_rm_loc_conf_t  *conf;
    ngx_str_t           cookie_name = ngx_string(NGX_HTTP_RM_COOKIE_NAME);
    ngx_str_t           cookie_name_c = ngx_string(NGX_HTTP_RM_COOKIE_NAME_C);
    ngx_str_t           timeout_c = ngx_string(NGX_HTTP_RM_DEFAULT_TIMEOUT_C);

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_rm_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->mode = NGX_HTTP_RM_MODE_JS;
    conf->enabled = 0;
#if (NGX_HTTP_X_FORWARDED_FOR)
    conf->ip_whitelist_x_forwarded_for = 0;
#endif
    conf->failed_count = -1;
    conf->timeout = NGX_HTTP_RM_DEFAULT_TIMEOUT;
    conf->cookie_name = cookie_name;
    conf->no_expires = 0;
    conf->whitelist_items = NULL;
    conf->pass_ajax = 1;

    conf->cookie_name_c = cookie_name_c;
    conf->timeout_c = timeout_c;

    return conf;
}

static char *
ngx_http_rm_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_rm_request_ctx_init(ngx_http_request_t *r)
{
    ngx_http_rm_req_ctx_t    *ctx;

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_rm_req_ctx_t));
    if (ctx == NULL)
        return NGX_ERROR;

    ngx_http_ns_set_ctx(r, ctx, ngx_http_robot_mitigation_module);

    return NGX_OK;
}

static ngx_http_rm_req_ctx_t *
ngx_http_rm_get_request_ctx(ngx_http_request_t *r)
{
    ngx_http_rm_req_ctx_t       *ctx;

    ctx = ngx_http_ns_get_module_ctx(r, ngx_http_robot_mitigation_module);

    return ctx;
}

static ngx_int_t
ngx_http_rm_blacklist_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_rm_req_ctx_t  *ctx;

    ctx = ngx_http_rm_get_request_ctx(r);

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (ctx->blacklist) {
        ngx_str_set(v, "true");
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
ngx_http_rm_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_rm_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}
