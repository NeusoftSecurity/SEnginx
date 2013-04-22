/*
 * Copyright (c) 2013 Neusoft Corperation., Ltd.
 */

#include <ngx_http_active_challenge.h>

#if (NGX_HTTP_NETEYE_SECURITY)
#include <ngx_http_neteye_security.h>
#else
#error "must compile with neteye security module"
#endif

#include <ngx_sha1.h>

#include <zlib.h>

extern const char *ngx_http_ac_get_js_tpls[];
extern const ngx_uint_t ngx_http_ac_get_js_tpls_nr;
extern const char *ngx_http_ac_post_js_tpls[];
extern const ngx_uint_t ngx_http_ac_post_js_tpls_nr;

#define NGX_HTTP_AC_GET_SWF \
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

#define NGX_HTTP_AC_POST_JS_2 \
    "</form>\n</body>\n</html>\n"

#define NGX_HTTP_AC_POST_SWF_1 \
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

#define NGX_HTTP_AC_POST_SWF_2 \
    "</form>\n" \
    "</body>\n</html>\n"

static const char ngx_http_ac_get_swf[] = "\x0a\xf3\x05\x00\x00\x60\x00\x3e\x80\x00\x3e\x80\x00\x1e\x01\x00\x44\x11\x18\x00\x00\x00\x7f\x13\xcb\x01\x00\x00\x3c\x72\x64\x66\x3a\x52\x44\x46\x20\x78\x6d\x6c\x6e\x73\x3a\x72\x64\x66\x3d\x27\x68\x74\x74\x70\x3a\x2f\x2f\x77\x77\x77\x2e\x77\x33\x2e\x6f\x72\x67\x2f\x31\x39\x39\x39\x2f\x30\x32\x2f\x32\x32\x2d\x72\x64\x66\x2d\x73\x79\x6e\x74\x61\x78\x2d\x6e\x73\x23\x27\x3e\x3c\x72\x64\x66\x3a\x44\x65\x73\x63\x72\x69\x70\x74\x69\x6f\x6e\x20\x72\x64\x66\x3a\x61\x62\x6f\x75\x74\x3d\x27\x27\x20\x78\x6d\x6c\x6e\x73\x3a\x64\x63\x3d\x27\x68\x74\x74\x70\x3a\x2f\x2f\x70\x75\x72\x6c\x2e\x6f\x72\x67\x2f\x64\x63\x2f\x65\x6c\x65\x6d\x65\x6e\x74\x73\x2f\x31\x2e\x31\x27\x3e\x3c\x64\x63\x3a\x66\x6f\x72\x6d\x61\x74\x3e\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x2f\x78\x2d\x73\x68\x6f\x63\x6b\x77\x61\x76\x65\x2d\x66\x6c\x61\x73\x68\x3c\x2f\x64\x63\x3a\x66\x6f\x72\x6d\x61\x74\x3e\x3c\x64\x63\x3a\x74\x69\x74\x6c\x65\x3e\x41\x64\x6f\x62\x65\x20\x46\x6c\x65\x78\x20\x34\x20\x41\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x3c\x2f\x64\x63\x3a\x74\x69\x74\x6c\x65\x3e\x3c\x64\x63\x3a\x64\x65\x73\x63\x72\x69\x70\x74\x69\x6f\x6e\x3e\x68\x74\x74\x70\x3a\x2f\x2f\x77\x77\x77\x2e\x61\x64\x6f\x62\x65\x2e\x63\x6f\x6d\x2f\x70\x72\x6f\x64\x75\x63\x74\x73\x2f\x66\x6c\x65\x78\x3c\x2f\x64\x63\x3a\x64\x65\x73\x63\x72\x69\x70\x74\x69\x6f\x6e\x3e\x3c\x64\x63\x3a\x70\x75\x62\x6c\x69\x73\x68\x65\x72\x3e\x75\x6e\x6b\x6e\x6f\x77\x6e\x3c\x2f\x64\x63\x3a\x70\x75\x62\x6c\x69\x73\x68\x65\x72\x3e\x3c\x64\x63\x3a\x63\x72\x65\x61\x74\x6f\x72\x3e\x75\x6e\x6b\x6e\x6f\x77\x6e\x3c\x2f\x64\x63\x3a\x63\x72\x65\x61\x74\x6f\x72\x3e\x3c\x64\x63\x3a\x6c\x61\x6e\x67\x75\x61\x67\x65\x3e\x45\x4e\x3c\x2f\x64\x63\x3a\x6c\x61\x6e\x67\x75\x61\x67\x65\x3e\x3c\x64\x63\x3a\x64\x61\x74\x65\x3e\x46\x65\x62\x20\x31\x32\x2c\x20\x32\x30\x31\x31\x3c\x2f\x64\x63\x3a\x64\x61\x74\x65\x3e\x3c\x2f\x72\x64\x66\x3a\x44\x65\x73\x63\x72\x69\x70\x74\x69\x6f\x6e\x3e\x3c\x2f\x72\x64\x66\x3a\x52\x44\x46\x3e\x00\x44\x10\xe8\x03\x3c\x00\x43\x02\xff\xff\xff\x5a\x0a\x03\x00\x00\x00\x06\x00\x00\x00\x04\x00\x4f\x37\x00\x00\x00\x00\x00\x00\x1d\xf7\x17\x1b\x2e\x01\x00\x00\xc4\x0a\x47\x45\x54\x00\xbf\x14\xc8\x03\x00\x00\x01\x00\x00\x00\x66\x72\x61\x6d\x65\x31\x00\x10\x00\x2e\x00\x00\x00\x00\x1e\x00\x04\x76\x6f\x69\x64\x0c\x66\x6c\x61\x73\x68\x2e\x65\x76\x65\x6e\x74\x73\x05\x45\x76\x65\x6e\x74\x03\x47\x45\x54\x0d\x66\x6c\x61\x73\x68\x2e\x64\x69\x73\x70\x6c\x61\x79\x06\x53\x70\x72\x69\x74\x65\x0b\x43\x4f\x4f\x4b\x49\x45\x5f\x4e\x41\x4d\x45\x06\x53\x74\x72\x69\x6e\x67\x28\x52\x6f\x62\x6f\x6f\x5f\x6e\x61\x6d\x65\x5f\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x50\x4c\x41\x43\x45\x48\x4f\x4c\x44\x45\x52\x0c\x43\x4f\x4f\x4b\x49\x45\x5f\x56\x41\x4c\x55\x45\x28\x52\x6f\x62\x6f\x6f\x5f\x76\x61\x6c\x75\x65\x5f\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x50\x4c\x41\x43\x45\x48\x4f\x4c\x44\x45\x52\x0f\x43\x4f\x4f\x4b\x49\x45\x5f\x56\x41\x4c\x49\x44\x49\x54\x59\x28\x52\x6f\x62\x6f\x6f\x5f\x76\x61\x6c\x69\x64\x69\x74\x79\x5f\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x50\x4c\x41\x43\x45\x48\x4f\x4c\x44\x45\x52\x04\x69\x6e\x69\x74\x05\x73\x74\x61\x67\x65\x10\x61\x64\x64\x45\x76\x65\x6e\x74\x4c\x69\x73\x74\x65\x6e\x65\x72\x0e\x41\x44\x44\x45\x44\x5f\x54\x4f\x5f\x53\x54\x41\x47\x45\x13\x72\x65\x6d\x6f\x76\x65\x45\x76\x65\x6e\x74\x4c\x69\x73\x74\x65\x6e\x65\x72\x03\x58\x4d\x4c\x86\x02\x3c\x73\x63\x72\x69\x70\x74\x3e\x0d\x0a\x09\x09\x09\x09\x09\x3c\x21\x5b\x43\x44\x41\x54\x41\x5b\x0d\x0a\x09\x09\x09\x09\x09\x09\x66\x75\x6e\x63\x74\x69\x6f\x6e\x20\x28\x63\x6f\x6f\x6b\x69\x65\x5f\x6e\x61\x6d\x65\x2c\x20\x63\x6f\x6f\x6b\x69\x65\x5f\x76\x61\x6c\x75\x65\x2c\x20\x63\x6f\x6f\x6b\x69\x65\x5f\x76\x61\x6c\x69\x64\x69\x74\x79\x29\x20\x7b\x20\x0d\x0a\x09\x09\x09\x09\x09\x09\x09\x09\x64\x6f\x63\x75\x6d\x65\x6e\x74\x2e\x63\x6f\x6f\x6b\x69\x65\x3d\x63\x6f\x6f\x6b\x69\x65\x5f\x6e\x61\x6d\x65\x20\x2b\x20\x27\x3d\x27\x20\x2b\x20\x63\x6f\x6f\x6b\x69\x65\x5f\x76\x61\x6c\x75\x65\x20\x2b\x20\x27\x3b\x20\x6d\x61\x78\x2d\x61\x67\x65\x3d\x27\x20\x2b\x20\x63\x6f\x6f\x6b\x69\x65\x5f\x76\x61\x6c\x69\x64\x69\x74\x79\x20\x2b\x20\x27\x3b\x20\x70\x61\x74\x68\x3d\x2f\x27\x3b\x0d\x0a\x09\x09\x09\x09\x09\x09\x09\x09\x77\x69\x6e\x64\x6f\x77\x2e\x6c\x6f\x63\x61\x74\x69\x6f\x6e\x2e\x72\x65\x6c\x6f\x61\x64\x28\x29\x3b\x0d\x0a\x09\x09\x09\x09\x09\x09\x7d\x0d\x0a\x09\x09\x09\x09\x09\x5d\x5d\x3e\x0d\x0a\x09\x09\x09\x09\x3c\x2f\x73\x63\x72\x69\x70\x74\x3e\x0e\x66\x6c\x61\x73\x68\x2e\x65\x78\x74\x65\x72\x6e\x61\x6c\x11\x45\x78\x74\x65\x72\x6e\x61\x6c\x49\x6e\x74\x65\x72\x66\x61\x63\x65\x04\x63\x61\x6c\x6c\x06\x4f\x62\x6a\x65\x63\x74\x0f\x45\x76\x65\x6e\x74\x44\x69\x73\x70\x61\x74\x63\x68\x65\x72\x0d\x44\x69\x73\x70\x6c\x61\x79\x4f\x62\x6a\x65\x63\x74\x11\x49\x6e\x74\x65\x72\x61\x63\x74\x69\x76\x65\x4f\x62\x6a\x65\x63\x74\x16\x44\x69\x73\x70\x6c\x61\x79\x4f\x62\x6a\x65\x63\x74\x43\x6f\x6e\x74\x61\x69\x6e\x65\x72\x07\x16\x01\x16\x03\x16\x06\x18\x05\x05\x00\x16\x16\x00\x16\x07\x01\x02\x07\x02\x04\x07\x01\x05\x07\x03\x07\x07\x01\x08\x07\x01\x09\x07\x01\x0b\x07\x01\x0d\x07\x05\x0f\x07\x01\x10\x07\x01\x11\x07\x01\x12\x07\x01\x13\x07\x01\x14\x07\x06\x17\x07\x01\x18\x07\x01\x19\x07\x02\x1a\x07\x03\x1b\x07\x03\x1c\x07\x03\x1d\x04\x00\x00\x00\x00\x00\x01\x00\x00\x01\x01\x02\x00\x08\x01\x0c\x0c\x00\x00\x00\x00\x00\x01\x03\x04\x09\x04\x00\x01\x04\x05\x06\x00\x06\x0a\x01\x07\x06\x00\x06\x0c\x01\x08\x06\x00\x06\x0e\x01\x09\x01\x00\x02\x00\x00\x01\x03\x01\x03\x04\x01\x00\x04\x00\x01\x01\x08\x09\x03\xd0\x30\x47\x00\x00\x01\x03\x01\x09\x0a\x20\xd0\x30\xd0\x49\x00\x60\x0a\x12\x08\x00\x00\xd0\x4f\x09\x00\x10\x0c\x00\x00\x5d\x0b\x60\x02\x66\x0c\xd0\x66\x09\x4f\x0b\x02\x47\x00\x00\x02\x05\x03\x09\x0a\x27\xd0\x30\x5d\x0d\x60\x02\x66\x0c\xd0\x66\x09\x4f\x0d\x02\x60\x0e\x2c\x15\x42\x01\x80\x0e\xd6\x60\x0f\xd2\xd0\x66\x05\xd0\x66\x07\xd0\x66\x08\x4f\x10\x04\x47\x00\x00\x03\x02\x01\x01\x08\x23\xd0\x30\x65\x00\x60\x11\x30\x60\x12\x30\x60\x13\x30\x60\x14\x30\x60\x15\x30\x60\x04\x30\x60\x04\x58\x00\x1d\x1d\x1d\x1d\x1d\x1d\x68\x03\x47\x00\x00\x08\x13\x01\x00\x00\x00\x47\x45\x54\x00\x40\x00\x00\x00";

char ngx_http_ac_post_swf[]="\x0a\x4c\x06\x00\x00\x30\x0a\x00\xa0\x00\x01\x01\x00\x44\x11\x18\x00\x00\x00\x7f\x13\xcb\x01\x00\x00\x3c\x72\x64\x66\x3a\x52\x44\x46\x20\x78\x6d\x6c\x6e\x73\x3a\x72\x64\x66\x3d\x27\x68\x74\x74\x70\x3a\x2f\x2f\x77\x77\x77\x2e\x77\x33\x2e\x6f\x72\x67\x2f\x31\x39\x39\x39\x2f\x30\x32\x2f\x32\x32\x2d\x72\x64\x66\x2d\x73\x79\x6e\x74\x61\x78\x2d\x6e\x73\x23\x27\x3e\x3c\x72\x64\x66\x3a\x44\x65\x73\x63\x72\x69\x70\x74\x69\x6f\x6e\x20\x72\x64\x66\x3a\x61\x62\x6f\x75\x74\x3d\x27\x27\x20\x78\x6d\x6c\x6e\x73\x3a\x64\x63\x3d\x27\x68\x74\x74\x70\x3a\x2f\x2f\x70\x75\x72\x6c\x2e\x6f\x72\x67\x2f\x64\x63\x2f\x65\x6c\x65\x6d\x65\x6e\x74\x73\x2f\x31\x2e\x31\x27\x3e\x3c\x64\x63\x3a\x66\x6f\x72\x6d\x61\x74\x3e\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x2f\x78\x2d\x73\x68\x6f\x63\x6b\x77\x61\x76\x65\x2d\x66\x6c\x61\x73\x68\x3c\x2f\x64\x63\x3a\x66\x6f\x72\x6d\x61\x74\x3e\x3c\x64\x63\x3a\x74\x69\x74\x6c\x65\x3e\x41\x64\x6f\x62\x65\x20\x46\x6c\x65\x78\x20\x34\x20\x41\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x3c\x2f\x64\x63\x3a\x74\x69\x74\x6c\x65\x3e\x3c\x64\x63\x3a\x64\x65\x73\x63\x72\x69\x70\x74\x69\x6f\x6e\x3e\x68\x74\x74\x70\x3a\x2f\x2f\x77\x77\x77\x2e\x61\x64\x6f\x62\x65\x2e\x63\x6f\x6d\x2f\x70\x72\x6f\x64\x75\x63\x74\x73\x2f\x66\x6c\x65\x78\x3c\x2f\x64\x63\x3a\x64\x65\x73\x63\x72\x69\x70\x74\x69\x6f\x6e\x3e\x3c\x64\x63\x3a\x70\x75\x62\x6c\x69\x73\x68\x65\x72\x3e\x75\x6e\x6b\x6e\x6f\x77\x6e\x3c\x2f\x64\x63\x3a\x70\x75\x62\x6c\x69\x73\x68\x65\x72\x3e\x3c\x64\x63\x3a\x63\x72\x65\x61\x74\x6f\x72\x3e\x75\x6e\x6b\x6e\x6f\x77\x6e\x3c\x2f\x64\x63\x3a\x63\x72\x65\x61\x74\x6f\x72\x3e\x3c\x64\x63\x3a\x6c\x61\x6e\x67\x75\x61\x67\x65\x3e\x45\x4e\x3c\x2f\x64\x63\x3a\x6c\x61\x6e\x67\x75\x61\x67\x65\x3e\x3c\x64\x63\x3a\x64\x61\x74\x65\x3e\x4a\x75\x6e\x20\x32\x39\x2c\x20\x32\x30\x31\x31\x3c\x2f\x64\x63\x3a\x64\x61\x74\x65\x3e\x3c\x2f\x72\x64\x66\x3a\x44\x65\x73\x63\x72\x69\x70\x74\x69\x6f\x6e\x3e\x3c\x2f\x72\x64\x66\x3a\x52\x44\x46\x3e\x00\x44\x10\xe8\x03\x3c\x00\x43\x02\xff\xff\xff\x5a\x0a\x03\x00\x00\x00\x06\x00\x00\x00\x04\x00\x4f\x37\x00\x00\x00\x00\x00\x00\x94\x69\xd6\xda\x30\x01\x00\x00\xc5\x0a\x50\x4f\x53\x54\x00\xbf\x14\x22\x04\x00\x00\x01\x00\x00\x00\x66\x72\x61\x6d\x65\x31\x00\x10\x00\x2e\x00\x00\x00\x00\x1e\x00\x04\x76\x6f\x69\x64\x0c\x66\x6c\x61\x73\x68\x2e\x65\x76\x65\x6e\x74\x73\x05\x45\x76\x65\x6e\x74\x04\x50\x4f\x53\x54\x0d\x66\x6c\x61\x73\x68\x2e\x64\x69\x73\x70\x6c\x61\x79\x06\x53\x70\x72\x69\x74\x65\x0b\x43\x4f\x4f\x4b\x49\x45\x5f\x4e\x41\x4d\x45\x06\x53\x74\x72\x69\x6e\x67\x28\x52\x6f\x62\x6f\x6f\x5f\x6e\x61\x6d\x65\x5f\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x50\x4c\x41\x43\x45\x48\x4f\x4c\x44\x45\x52\x0c\x43\x4f\x4f\x4b\x49\x45\x5f\x56\x41\x4c\x55\x45\x28\x52\x6f\x62\x6f\x6f\x5f\x76\x61\x6c\x75\x65\x5f\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x50\x4c\x41\x43\x45\x48\x4f\x4c\x44\x45\x52\x0f\x43\x4f\x4f\x4b\x49\x45\x5f\x56\x41\x4c\x49\x44\x49\x54\x59\x28\x52\x6f\x62\x6f\x6f\x5f\x76\x61\x6c\x69\x64\x69\x74\x79\x5f\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x50\x4c\x41\x43\x45\x48\x4f\x4c\x44\x45\x52\x04\x69\x6e\x69\x74\x05\x73\x74\x61\x67\x65\x10\x61\x64\x64\x45\x76\x65\x6e\x74\x4c\x69\x73\x74\x65\x6e\x65\x72\x0e\x41\x44\x44\x45\x44\x5f\x54\x4f\x5f\x53\x54\x41\x47\x45\x13\x72\x65\x6d\x6f\x76\x65\x45\x76\x65\x6e\x74\x4c\x69\x73\x74\x65\x6e\x65\x72\x03\x58\x4d\x4c\xdf\x02\x3c\x73\x63\x72\x69\x70\x74\x3e\x0d\x0a\x09\x09\x09\x09\x09\x3c\x21\x5b\x43\x44\x41\x54\x41\x5b\x0d\x0a\x09\x09\x09\x09\x09\x09\x66\x75\x6e\x63\x74\x69\x6f\x6e\x20\x28\x63\x6f\x6f\x6b\x69\x65\x5f\x6e\x61\x6d\x65\x2c\x20\x63\x6f\x6f\x6b\x69\x65\x5f\x76\x61\x6c\x75\x65\x2c\x20\x63\x6f\x6f\x6b\x69\x65\x5f\x76\x61\x6c\x69\x64\x69\x74\x79\x29\x20\x7b\x20\x0d\x0a\x09\x09\x09\x09\x09\x09\x09\x09\x64\x6f\x63\x75\x6d\x65\x6e\x74\x2e\x63\x6f\x6f\x6b\x69\x65\x3d\x63\x6f\x6f\x6b\x69\x65\x5f\x6e\x61\x6d\x65\x20\x2b\x20\x27\x3d\x27\x20\x2b\x20\x63\x6f\x6f\x6b\x69\x65\x5f\x76\x61\x6c\x75\x65\x20\x2b\x20\x27\x3b\x20\x6d\x61\x78\x2d\x61\x67\x65\x3d\x27\x20\x2b\x20\x63\x6f\x6f\x6b\x69\x65\x5f\x76\x61\x6c\x69\x64\x69\x74\x79\x20\x2b\x20\x27\x3b\x20\x70\x61\x74\x68\x3d\x2f\x27\x3b\x0d\x0a\x09\x09\x09\x09\x09\x09\x09\x09\x64\x6f\x63\x75\x6d\x65\x6e\x74\x2e\x72\x65\x73\x70\x6f\x6e\x73\x65\x2e\x61\x63\x74\x69\x6f\x6e\x20\x3d\x20\x77\x69\x6e\x64\x6f\x77\x2e\x6c\x6f\x63\x61\x74\x69\x6f\x6e\x2e\x70\x61\x74\x68\x6e\x61\x6d\x65\x20\x2b\x20\x77\x69\x6e\x64\x6f\x77\x2e\x6c\x6f\x63\x61\x74\x69\x6f\x6e\x2e\x73\x65\x61\x72\x63\x68\x3b\x0d\x0a\x09\x09\x09\x09\x09\x09\x09\x09\x64\x6f\x63\x75\x6d\x65\x6e\x74\x2e\x66\x6f\x72\x6d\x73\x5b\x30\x5d\x2e\x73\x75\x62\x6d\x69\x74\x28\x29\x3b\x0d\x0a\x09\x09\x09\x09\x09\x09\x7d\x0d\x0a\x09\x09\x09\x09\x09\x5d\x5d\x3e\x0d\x0a\x09\x09\x09\x09\x3c\x2f\x73\x63\x72\x69\x70\x74\x3e\x0e\x66\x6c\x61\x73\x68\x2e\x65\x78\x74\x65\x72\x6e\x61\x6c\x11\x45\x78\x74\x65\x72\x6e\x61\x6c\x49\x6e\x74\x65\x72\x66\x61\x63\x65\x04\x63\x61\x6c\x6c\x06\x4f\x62\x6a\x65\x63\x74\x0f\x45\x76\x65\x6e\x74\x44\x69\x73\x70\x61\x74\x63\x68\x65\x72\x0d\x44\x69\x73\x70\x6c\x61\x79\x4f\x62\x6a\x65\x63\x74\x11\x49\x6e\x74\x65\x72\x61\x63\x74\x69\x76\x65\x4f\x62\x6a\x65\x63\x74\x16\x44\x69\x73\x70\x6c\x61\x79\x4f\x62\x6a\x65\x63\x74\x43\x6f\x6e\x74\x61\x69\x6e\x65\x72\x07\x16\x01\x16\x03\x16\x06\x18\x05\x05\x00\x16\x16\x00\x16\x07\x01\x02\x07\x02\x04\x07\x01\x05\x07\x03\x07\x07\x01\x08\x07\x01\x09\x07\x01\x0b\x07\x01\x0d\x07\x05\x0f\x07\x01\x10\x07\x01\x11\x07\x01\x12\x07\x01\x13\x07\x01\x14\x07\x06\x17\x07\x01\x18\x07\x01\x19\x07\x02\x1a\x07\x03\x1b\x07\x03\x1c\x07\x03\x1d\x04\x00\x00\x00\x00\x00\x01\x00\x00\x01\x01\x02\x00\x08\x01\x0c\x0c\x00\x00\x00\x00\x00\x01\x03\x04\x09\x04\x00\x01\x04\x05\x06\x00\x06\x0a\x01\x07\x06\x00\x06\x0c\x01\x08\x06\x00\x06\x0e\x01\x09\x01\x00\x02\x00\x00\x01\x03\x01\x03\x04\x01\x00\x04\x00\x01\x01\x08\x09\x03\xd0\x30\x47\x00\x00\x01\x03\x01\x09\x0a\x20\xd0\x30\xd0\x49\x00\x60\x0a\x12\x08\x00\x00\xd0\x4f\x09\x00\x10\x0c\x00\x00\x5d\x0b\x60\x02\x66\x0c\xd0\x66\x09\x4f\x0b\x02\x47\x00\x00\x02\x05\x03\x09\x0a\x27\xd0\x30\x5d\x0d\x60\x02\x66\x0c\xd0\x66\x09\x4f\x0d\x02\x60\x0e\x2c\x15\x42\x01\x80\x0e\xd6\x60\x0f\xd2\xd0\x66\x05\xd0\x66\x07\xd0\x66\x08\x4f\x10\x04\x47\x00\x00\x03\x02\x01\x01\x08\x23\xd0\x30\x65\x00\x60\x11\x30\x60\x12\x30\x60\x13\x30\x60\x14\x30\x60\x15\x30\x60\x04\x30\x60\x04\x58\x00\x1d\x1d\x1d\x1d\x1d\x1d\x68\x03\x47\x00\x00\x09\x13\x01\x00\x00\x00\x50\x4f\x53\x54\x00\x40\x00\x00\x00";

static ngx_str_t 
ngx_http_ac_type_swf = ngx_string("application/x-shockwave-flash");

static ngx_str_t ngx_http_ac_type_html = ngx_string("text/html");

static char *
ngx_http_ac_mode(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *
ngx_http_ac_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *
ngx_http_ac(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
#if (NGX_HTTP_SESSION) 
static char *
ngx_http_ac_action(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
#endif
static char *
ngx_http_ac_timeout(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t
ngx_http_ac_content_handler(ngx_http_request_t *r);
static ngx_int_t
ngx_http_ac_request_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_ac_init(ngx_conf_t *cf);
static void *ngx_http_ac_create_loc_conf(ngx_conf_t *cf);
static char *
ngx_http_ac_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t
ngx_http_ac_challenge_get_js_handler(ngx_http_request_t *r);
static ngx_int_t
ngx_http_ac_challenge_get_swf_handler(ngx_http_request_t *r);
ngx_int_t ngx_http_ac_special_swf_uri(ngx_http_request_t *r);
static ngx_int_t 
ngx_http_ac_send_swf_file_handler(ngx_http_request_t *r, ngx_uint_t method);
static ngx_int_t 
ngx_http_ac_send_swf_handler(ngx_http_request_t *r);
static ngx_int_t
ngx_http_ac_send_response(ngx_http_request_t *r, ngx_uint_t status,
    ngx_str_t *ct, ngx_str_t val);
static ngx_int_t
ngx_http_ac_challenge_post_js_handler(ngx_http_request_t *r);
static ngx_int_t
ngx_http_ac_challenge_post_swf_handler(ngx_http_request_t *r);
static u_char * 
ngx_http_ac_post_body_to_form(ngx_http_request_t *r, 
        u_char *body, ngx_uint_t len, 
        ngx_uint_t *post_args_len);
static u_char * 
ngx_http_ac_post_data_decode(ngx_http_request_t *r,
        u_char *string, ngx_uint_t len, 
        ngx_uint_t *decoded_len);

static ngx_int_t
ngx_http_ac_do_action(ngx_http_request_t *r);

static char *
ngx_http_ac_redirect(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

#if (NGX_HTTP_SESSION)
static ngx_int_t
ngx_http_ac_request_type(ngx_http_request_t *r, 
        ngx_uint_t op, ngx_uint_t value);
#endif

static ngx_int_t
ngx_http_ac_request_ctx_init(ngx_http_request_t *r);

static ngx_http_ac_req_ctx_t *
ngx_http_ac_get_request_ctx(ngx_http_request_t *r);

static char *
ngx_http_ac_whitelist(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

#if (NGX_HTTP_SESSION)
static void 
ngx_http_ac_destroy_ctx_handler(void *ctx);
static ngx_int_t 
ngx_http_ac_init_ctx_handler(void *ctx);
#endif

static ngx_command_t  ngx_http_active_challenge_commands[] = {

    { ngx_string("active_challenge"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
        ngx_http_ac,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },
    
    { ngx_string("active_challenge_modes"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_http_ac_mode,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },
    
#if (NGX_HTTP_SESSION) 
    { ngx_string("active_challenge_action"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234,
        ngx_http_ac_action,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },
#endif
    
    { ngx_string("active_challenge_log"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_http_ac_log,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },
    
    { ngx_string("active_challenge_validity_windows"),
        NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
        ngx_http_ac_timeout,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },

    { ngx_string("active_challenge_redirect"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_http_ac_redirect,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },
 
    { ngx_string("active_challenge_whitelist"),
        NGX_HTTP_LOC_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
        ngx_http_ac_whitelist,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },
 
    ngx_null_command
};

static ngx_http_module_t 
ngx_http_active_challenge_module_ctx = {
    NULL,                                    /* preconfiguration */
    ngx_http_ac_init,                        /* postconfiguration */

    NULL,                                    /* create main configuration */
    NULL,                                    /* init main configuration */

    NULL,                                    /* create server configuration */
    NULL,                                    /* merge server configuration */

    ngx_http_ac_create_loc_conf,             /* create location configuration */
    ngx_http_ac_merge_loc_conf,              /* merge location configuration */
};


ngx_module_t  ngx_http_active_challenge_module = {
    NGX_MODULE_V1,                           /* module context */
    &ngx_http_active_challenge_module_ctx,   /* module directives */
    ngx_http_active_challenge_commands,      /* module type */
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
ngx_http_ac_ascii_to_hex(u_char a)
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
ngx_http_ac_change_to_hex(u_char a, u_char b)
{
    u_char sum;

    a = ngx_http_ac_ascii_to_hex(a);
    b = ngx_http_ac_ascii_to_hex(b);

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
} ngx_http_ac_decode_helper_t;

static ngx_int_t
ngx_http_ac_is_ascii_hex(u_char a)
{
    if ((a <= '9' && a >= '0')
                || (a <= 'F' && a >= 'A')
                || (a <= 'f' && a >= 'a')) {
        return 1;
    }

    return 0;
}

static u_char * 
ngx_http_ac_post_data_decode(ngx_http_request_t *r,
        u_char *string, ngx_uint_t len, 
        ngx_uint_t *decoded_len)
{
    u_char                           *decoded;
    ngx_http_ac_decode_helper_t      *helper;
    ngx_uint_t                        nr_helper = 0;
    ngx_uint_t                        pos = 0, src_pos = 0;
    ngx_uint_t                        i, new_len = 0, nr_b = 0, nr_c = 0;
    ngx_uint_t                        last_sub, delta;

    helper = ngx_pcalloc(r->pool, sizeof(ngx_http_ac_decode_helper_t) * len);
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
                if (ngx_http_ac_is_ascii_hex(string[i + 1])
                        && ngx_http_ac_is_ascii_hex(string[i + 2])) {
                    /* find a %HH */
                    helper[nr_helper].offset = i;
                    helper[nr_helper].type = 2;

                    helper[nr_helper].hex = 
                        ngx_http_ac_change_to_hex(string[i + 1], 
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
ngx_http_ac_post_body_to_form(ngx_http_request_t *r, 
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
            
            decoded_name = ngx_http_ac_post_data_decode(r, 
                    varname, varname_len, &decoded_name_len);
            if (decoded_name == NULL) {
                return NULL;
            }

            if (varvalue_len != 0) {
                decoded_value = ngx_http_ac_post_data_decode(r, 
                        varvalue, varvalue_len, &decoded_value_len);
                if (decoded_value == NULL) {
                    return NULL;
                }
            } else {
                decoded_value = NULL;
                decoded_value_len = 0;
            }

            inc_form_len = strlen(NGX_HTTP_AC_FORM_VARIABLES_1) 
                + strlen(NGX_HTTP_AC_FORM_VARIABLES_2)
                + strlen(NGX_HTTP_AC_FORM_VARIABLES_3)
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
                    NGX_HTTP_AC_FORM_VARIABLES_1, 
                    strlen(NGX_HTTP_AC_FORM_VARIABLES_1));

            offset += strlen(NGX_HTTP_AC_FORM_VARIABLES_1);

            /* copy vairiable name */
            ngx_memcpy(buf_a + offset, 
                    decoded_name, 
                    decoded_name_len);

            offset += decoded_name_len;

            /* copy part 2 */
            ngx_memcpy(buf_a + offset, 
                    NGX_HTTP_AC_FORM_VARIABLES_2, 
                    strlen(NGX_HTTP_AC_FORM_VARIABLES_2));

            offset += strlen(NGX_HTTP_AC_FORM_VARIABLES_2);

            /* copy variable value if not 0 */
            if (decoded_value_len != 0) {
                ngx_memcpy(buf_a + offset, 
                        decoded_value, 
                        decoded_value_len);

                offset += decoded_value_len;
            }

            /* copy part 3 */
            ngx_memcpy(buf_a + offset, 
                    NGX_HTTP_AC_FORM_VARIABLES_3, 
                    strlen(NGX_HTTP_AC_FORM_VARIABLES_3));

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
ngx_http_ac_generate_fake_cookie(ngx_http_request_t *r, 
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

        memcpy(fake_1->data, hex_output, NGX_HTTP_AC_DEFAULT_COOKIE_LEN);
        fake_1->data[NGX_HTTP_AC_DEFAULT_COOKIE_LEN] = 0;
        fake_1->len = NGX_HTTP_AC_DEFAULT_COOKIE_LEN;
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

        memcpy(fake_2->data, hex_output, NGX_HTTP_AC_DEFAULT_COOKIE_LEN);
        fake_2->data[NGX_HTTP_AC_DEFAULT_COOKIE_LEN] = 0;
        fake_2->len = NGX_HTTP_AC_DEFAULT_COOKIE_LEN;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_ac_generate_cookie(ngx_http_request_t *r, ngx_str_t *cookie, 
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
    ngx_int_t                        t;
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

    t = ngx_time();
    
    if (timeout == 0) {
        t = 1;
    } else {
        t = t - (t % timeout);
    }

    port_time_len = sprintf((char *)source + source_len, "@%ld", t);

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

    memcpy(cookie->data, hex_output, NGX_HTTP_AC_DEFAULT_COOKIE_LEN);
    cookie->data[NGX_HTTP_AC_DEFAULT_COOKIE_LEN] = 0;
    cookie->len = NGX_HTTP_AC_DEFAULT_COOKIE_LEN;

    return NGX_OK;
}

static char *
ngx_http_ac_strstr(ngx_http_request_t *r, 
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
ngx_http_ac_valid_cookie(ngx_http_request_t *r, ngx_str_t *gen_cookie)
{
    ngx_int_t ret;
    ngx_str_t cookie, cookie_name;

    memset(&cookie, 0, sizeof(ngx_str_t));

    cookie_name.data = ngx_pcalloc(r->pool, strlen(NGX_HTTP_AC_COOKIE_NAME));
    if (cookie_name.data == NULL) {
        return NGX_ERROR;
    }

    memcpy(cookie_name.data, NGX_HTTP_AC_COOKIE_NAME, 
            strlen(NGX_HTTP_AC_COOKIE_NAME));
    cookie_name.len = strlen(NGX_HTTP_AC_COOKIE_NAME);
    
    ret = ngx_http_parse_multi_header_lines(&r->headers_in.cookies, 
            &cookie_name, &cookie);

    if (ret == NGX_DECLINED 
            || cookie.len == 0) {
        return NGX_HTTP_AC_RET_INVALID_COOKIE;
    }

    /* find a cookie, check the value then */
    if (!ngx_http_ac_strstr(r, &cookie, gen_cookie)) {
        return NGX_HTTP_AC_RET_INVALID_COOKIE;
    }

    return NGX_OK; 
}

ngx_int_t ngx_http_ac_special_swf_uri(ngx_http_request_t *r)
{
    if (r->uri.len > sizeof(NGX_HTTP_AC_SWF_FILENAME_PREFIX)
            && ngx_strstr(r->uri.data, 
                NGX_HTTP_AC_SWF_FILENAME_PREFIX)) {
        return 1;
    }
 
    return 0;
}

static ngx_int_t
ngx_http_ac_request_handler(ngx_http_request_t *r)
{
    ngx_http_ac_loc_conf_t            *alcf;  
    ngx_http_ac_req_ctx_t             *ctx;
    ngx_str_t                          cookie, user_agent;
    ngx_str_t                          cookie_f1, cookie_f2;
    ngx_int_t                          ret;
    ngx_int_t                          req_type = NGX_HTTP_AC_STATUS_NEW;
    ngx_http_ac_whitelist_item_t      *item;
    ngx_uint_t                         i;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
            "active challenge request handler begin");
    
    alcf = ngx_http_get_module_loc_conf(r, ngx_http_active_challenge_module);

#if 0
    if (!ngx_http_session_is_enabled(r)) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                "session mechanism is not enabled, skip");
        return NGX_DECLINED;
    }
#endif

#if (NGX_HTTP_SESSION)
    if (ngx_http_session_test_create(r) 
            || ngx_http_session_test_bypass(r)) {
        return NGX_DECLINED;
    }
#endif

    if (alcf->enabled != 1) {
        return NGX_DECLINED;
    }
 
#if (NGX_PCRE)
    /* -1: check whitelist */
    if (r->headers_in.user_agent != NULL
            && alcf->whitelist_items) {
        user_agent = r->headers_in.user_agent->value;
        item = alcf->whitelist_items->elts;

        for (i = 0; i < alcf->whitelist_items->nelts; i++) {
            ret = ngx_http_regex_exec(r, item[i].regex, &user_agent);

            if (ret == NGX_OK) {
                /* match */
                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                        "active challenge match whitelist: %V with %V", 
                        item[i].name, &user_agent);
                
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
    if (ngx_http_ac_special_swf_uri(r)) {
        r->content_handler = ngx_http_ac_send_swf_handler;
        goto out;
    }

    /* 1: check special cookie */
    cookie.data = ngx_pcalloc(r->pool, NGX_HTTP_AC_DEFAULT_COOKIE_LEN + 1);
    if (cookie.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ret = ngx_http_ac_generate_cookie(r, &cookie, alcf->timeout);
    if (ret != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
            "real cookie generated: %V", &cookie);
    
    ret = ngx_http_ac_valid_cookie(r, &cookie);
    if (ret == NGX_OK) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                "active challenge passed");

#if (NGX_HTTP_SESSION)
        ngx_http_ac_request_type(r, 
                NGX_HTTP_AC_SET_STATUS, 
                NGX_HTTP_AC_STATUS_PASSED);
#endif

        return NGX_DECLINED;
    }
 
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
            "cookie valid: %d", (int)ret);
   
    if (ret == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* 2: if failed and reason is no cookie value, 
     * try to find session 
     * and record the blacklist failure count 
     */

#if (NGX_HTTP_SESSION)
    req_type = ngx_http_ac_request_type(r, NGX_HTTP_AC_GET_STATUS, 0);
    if (req_type == NGX_ERROR) {
        return NGX_ERROR;
    }
#endif
    
    /* timeout or cookie lost */
    if (req_type == NGX_HTTP_AC_STATUS_PASSED) {
#if (NGX_HTTP_SESSION)
        ngx_http_ac_request_type(r, 
                NGX_HTTP_AC_SET_STATUS, 
                NGX_HTTP_AC_STATUS_NEW);
#endif
    }

    if (ret == NGX_HTTP_AC_RET_INVALID_COOKIE
            && req_type == NGX_HTTP_AC_STATUS_CHALLENGING) {
        if ((ret = ngx_http_ac_do_action(r)) != NGX_OK) {
#if (NGX_HTTP_SESSION)
            /* set status to NEW, thus next time will rechallenge */ 
            ngx_http_ac_request_type(r, 
                    NGX_HTTP_AC_SET_STATUS, 
                    NGX_HTTP_AC_STATUS_NEW);
#endif
            return ret;
        }

        /* pass to next ns checker */
        if (ret == NGX_OK) {
#if (NGX_HTTP_SESSION)
            /* set status to NEW, thus next time will rechallenge */ 
            ngx_http_ac_request_type(r, 
                    NGX_HTTP_AC_SET_STATUS, 
                    NGX_HTTP_AC_STATUS_NEW);
#endif
            return NGX_DECLINED;
        }
    }

    /*
     * 3: record cookie value to ctx, and begin challenge 
     */
    if ((r->method != NGX_HTTP_GET)
            && (r->method != NGX_HTTP_POST)) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_ac_get_request_ctx(r);
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
   
    cookie_f1.data = ngx_pcalloc(r->pool, NGX_HTTP_AC_DEFAULT_COOKIE_LEN + 1);
    if (cookie_f1.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    cookie_f2.data = ngx_pcalloc(r->pool, NGX_HTTP_AC_DEFAULT_COOKIE_LEN + 1);
    if (cookie_f2.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ret = ngx_http_ac_generate_fake_cookie(r, &cookie_f1, &cookie_f2);
    if (ret != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
            "fake cookie generated: %V/%V", &cookie_f1, &cookie_f2);

    ctx->request = r;
    ctx->cookie.data = cookie.data;
    ctx->cookie.len = cookie.len;
    ctx->cookie_f1.data = cookie_f1.data;
    ctx->cookie_f1.len = cookie_f1.len;
    ctx->cookie_f2.data = cookie_f2.data;
    ctx->cookie_f2.len = cookie_f2.len;

    r->content_handler = ngx_http_ac_content_handler;

#if (NGX_HTTP_SESSION)
    if (req_type == NGX_HTTP_AC_STATUS_NEW) {
        ngx_http_ac_request_type(r, NGX_HTTP_AC_SET_STATUS, 
                NGX_HTTP_AC_STATUS_CHALLENGING);
    }
#endif

out:
    ngx_http_ns_set_bypass_all(r);
#if (NGX_HTTP_SESSION)
    ngx_http_session_set_bypass(r);
#endif

    return NGX_DECLINED;
}

static ngx_int_t ngx_http_ac_init(ngx_conf_t *cf)
{
    ngx_int_t ret;

    ret = ngx_http_neteye_security_ctx_register(NGX_HTTP_NETEYE_ACTIVE_CHALLENGE, 
            ngx_http_ac_request_ctx_init);
    
    if (ret != NGX_OK) {
        return ret;
    }

    /* we only a request handler for this feature */
    return ngx_http_neteye_security_request_register(
            NGX_HTTP_NETEYE_ACTIVE_CHALLENGE, 
            ngx_http_ac_request_handler);
}

static char *ngx_http_ac(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_ac_loc_conf_t *sscf = conf;
    ngx_str_t               *value = NULL;
    ngx_str_t               page;
    value = cf->args->elts;

    if (!strncmp((char *)(value[1].data), "on", value[1].len)) {
        sscf->enabled = 1;
    }

    if (cf->args->nelts != 3) {
#if (NGX_HTTP_STATUS_PAGE)
        page.len = strlen(NGX_HTTP_AC_DEFAULT_URI) + 1;

        page.data = ngx_pcalloc(cf->pool, page.len);
        if (!page.data) {
            return NGX_CONF_ERROR;
        }

        memcpy(page.data, NGX_HTTP_AC_DEFAULT_URI, page.len);
        page.len--;
#else
        page.len = 0;
        page.data = NULL;
#endif
    } else {
        page = value[2];
    }

    sscf->error_page = page;

    return NGX_CONF_OK;
}

static char *
ngx_http_ac_mode(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_ac_loc_conf_t     *alcf = conf;
    ngx_str_t                  *value;
    
    value = cf->args->elts;

    if ((ngx_strstr(value[1].data, "JS") != NULL)
            || (ngx_strstr(value[1].data, "js") != NULL)) {
        alcf->mode = NGX_HTTP_AC_MODE_JS;
    } else if ((ngx_strstr(value[1].data, "SWF") != NULL) 
            || (ngx_strstr(value[1].data, "swf") != NULL)) {
        alcf->mode = NGX_HTTP_AC_MODE_SWF;
    } else {
        return "Unknow active_challenge_modes type";
    }

    return NGX_CONF_OK;
}

#if (NGX_HTTP_SESSION) 
static char *
ngx_http_ac_action(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_ac_loc_conf_t     *alcf = conf;
    ngx_str_t                  *value;
    
    value = cf->args->elts;

    if (ngx_strstr(value[1].data, "pass") != NULL) {
        alcf->action = NGX_HTTP_NS_ACTION_PASS;
    } else if (ngx_strstr(value[1].data, "block") != NULL) {
        alcf->action = NGX_HTTP_NS_ACTION_BLOCK;
#if (NGX_HTTP_BLACKLIST)
    } else if (ngx_strstr(value[1].data, "blacklist") != NULL) {
        alcf->action = NGX_HTTP_NS_ACTION_BLACKLIST;

        if (cf->args->nelts == 3) {
            alcf->failed_count = ngx_atoi(value[2].data, value[2].len);
            if (alcf->failed_count == NGX_ERROR) {
                return "Invalid blacklist count";
            }
        } else {
            alcf->failed_count = 5;
        }

        if (cf->args->nelts == 4) {
            alcf->blacktime = ngx_atoi(value[3].data, value[3].len);
            if (alcf->blacktime == NGX_ERROR) {
                return NGX_CONF_ERROR;
            }
        } else { 
            alcf->blacktime = 0;
        }
#endif
    } else {
        return "Unknow active_challenge_action type";
    }

    return NGX_CONF_OK;
}
#endif

static char *
ngx_http_ac_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_ac_loc_conf_t    *alcf = conf;
    ngx_str_t                 *value;

    value = cf->args->elts;
    if (!strncmp((char *)(value[1].data), "on", value[1].len)) {
        alcf->log = 1;
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_ac_timeout(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_ac_loc_conf_t     *alcf = conf;
    ngx_str_t                  *value;
    ngx_int_t                   timeout;
    
    value = cf->args->elts;
    alcf->timeout = ngx_atoi(value[1].data, value[1].len);

    timeout = ngx_atoi(value[1].data, value[1].len);
    if (timeout == NGX_ERROR) {
        return "Invalid timeout value";
    }

    if (timeout == 0) {
        alcf->no_expires = 1;
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_ac_redirect(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_ac_loc_conf_t     *sscf = conf;
    ngx_str_t                  *value;

    value = cf->args->elts;
    if (!strncmp((char *)(value[1].data), "off", value[1].len)) {
        sscf->error_page.data = NULL;
    } else {
        sscf->error_page.data = value[1].data;
        sscf->error_page.len = value[1].len;
    }

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_ac_whitelist_pattern_parse(ngx_conf_t *cf, ngx_http_regex_t **regex,
    ngx_str_t *pattern)
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
    rc.options = 0;
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
ngx_http_ac_whitelist_parse(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
{
    ngx_http_ac_loc_conf_t  *alcf = conf;
    ngx_str_t               *name, *pattern, *value;
    ngx_http_ac_whitelist_item_t  *item;
    ngx_int_t                      ret;

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

    if (cf->args->nelts != 2) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "invalid number of arguments"
                " in a name-pattern pair");
        
        return NGX_CONF_ERROR;
    }

    name = ngx_palloc(cf->pool, sizeof(ngx_str_t));
    if (name == NULL) {
        return NGX_CONF_ERROR;
    }

    *name = value[0];

    pattern = ngx_palloc(cf->pool, sizeof(ngx_str_t));
    if (pattern == NULL) {
        return NGX_CONF_ERROR;
    }

    *pattern = value[1];

    ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, 
            "active challenge: "
            "original pattern name is \"%V\", pattern is \"%V\"", 
            name, pattern);

    item = ngx_array_push(alcf->whitelist_items);
    if (item == NULL) {
        return NGX_CONF_ERROR;
    }

    item->name = name;
    ret = ngx_http_ac_whitelist_pattern_parse(cf, &item->regex, pattern);
    if (ret != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, 
            "active challenge: "
            "regex pattern name is \"%V\", pattern is \"%p\"", 
            item->name, item->regex);
    
    return NGX_CONF_OK;
}

static char *
ngx_http_ac_whitelist(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_ac_loc_conf_t *alcf = conf;

    char        *rv;
    ngx_conf_t   save;

    if (alcf->whitelist_items == NULL) {
        alcf->whitelist_items = 
            ngx_array_create(cf->pool, 64, sizeof(ngx_http_ac_whitelist_item_t));
        
        if (alcf->whitelist_items == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    save = *cf;
    cf->handler = ngx_http_ac_whitelist_parse;
    cf->handler_conf = conf;

    rv = ngx_conf_parse(cf, NULL);

    *cf = save;

    return rv;
}

static void
ngx_http_ac_handle_no_expires(u_char *data, ngx_uint_t len) 
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

/* Caution:
 * buf should big enough to include "after" string
 */
static ngx_int_t
ngx_http_ac_replace_string(ngx_http_request_t *r, 
        u_char *buf, size_t len, u_char *before, u_char *after)
{
    u_char *p, *q, *buf2;
    ngx_uint_t buf_len, move_len, after_len;

    buf_len = strlen((const char *)buf);

    /* p points to start character */
    p = (u_char *)ngx_strstr(buf, before);
    if (p == NULL)
        return NGX_ERROR;

    /* q points to end-edge */
    q = p + strlen((const char *)before);

    move_len = buf_len - (q -buf);
    buf2 = ngx_pcalloc(r->pool, move_len);
    if (buf2 == NULL)
        return NGX_ERROR;

    after_len = strlen((const char *)after);

    memcpy(buf2, q, move_len);
    memcpy(p, after, after_len);
    memcpy(p + after_len, buf2, move_len);

#if 0
    fprintf(stderr,
            "buf %s \nlen %ld, buf_len: %lu\n", buf, len, buf_len);
    fprintf(stderr,
            "replace %s to %s\n", before, after);
#endif

    return NGX_OK;
}

/* for a GET request, 
 * respond with a js challenge
 * triggering an automatic reload of the page */
static ngx_int_t 
ngx_http_ac_challenge_get_js_handler(ngx_http_request_t *r)
{
    ngx_http_complex_value_t      cv;
    u_char                       *challenge_ct, timeout[32];
    ngx_http_ac_loc_conf_t       *alcf;
    ngx_http_ac_req_ctx_t        *ctx;
    ngx_int_t                     random_tpl;


    alcf = ngx_http_get_module_loc_conf(r, ngx_http_active_challenge_module);
    
    ctx = ngx_http_ac_get_request_ctx(r);
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memzero(&cv, sizeof(ngx_http_complex_value_t)); 
    ngx_memzero(timeout, sizeof(timeout)); 

    sprintf((char *)timeout, "%d", (int)alcf->timeout);

    /* get template randomly */
    random_tpl = ngx_random() % ngx_http_ac_get_js_tpls_nr;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "get random js-get template, tpl id: %d", random_tpl);
    
    /* -6 means 3 XX in NGX_HTTP_AC_GET_JS */
    cv.value.len = strlen(ngx_http_ac_get_js_tpls[random_tpl]) 
            + NGX_HTTP_AC_DEFAULT_COOKIE_LEN * 2
            + strlen(NGX_HTTP_AC_COOKIE_NAME) * 2
            + strlen((char *)timeout) * 2
            - 6
            - 6;
    
    challenge_ct = ngx_pcalloc(r->pool, cv.value.len + 1);
    if (challenge_ct == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    memcpy(challenge_ct, ngx_http_ac_get_js_tpls[random_tpl], 
            strlen(ngx_http_ac_get_js_tpls[random_tpl]));

    if (ngx_http_ac_replace_string(r, challenge_ct, cv.value.len + 1,
                (u_char *)"XX", 
                (u_char *)NGX_HTTP_AC_COOKIE_NAME) != NGX_OK)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;

    if (ngx_http_ac_replace_string(r, challenge_ct, cv.value.len + 1,
                (u_char *)"YY", 
                ctx->cookie.data) != NGX_OK)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
   
    if (ngx_http_ac_replace_string(r, challenge_ct, cv.value.len + 1,
                (u_char *)"ZZ", 
                timeout) != NGX_OK)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    
    if (ngx_http_ac_replace_string(r, challenge_ct, cv.value.len + 1,
                (u_char *)"MM", 
                (u_char *)NGX_HTTP_AC_COOKIE_NAME) != NGX_OK)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;

    if (ngx_http_ac_replace_string(r, challenge_ct, cv.value.len + 1,
                (u_char *)"NN", 
                ctx->cookie_f1.data) != NGX_OK)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
   
    if (ngx_http_ac_replace_string(r, challenge_ct, cv.value.len + 1,
                (u_char *)"OO", 
                timeout) != NGX_OK)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    
    if (alcf->no_expires == 1) {
        ngx_http_ac_handle_no_expires(challenge_ct, cv.value.len); 
    }

    cv.value.data = challenge_ct;
    
    return ngx_http_send_response(r, NGX_HTTP_OK, &ngx_http_ac_type_html, &cv);
}

/* 
 * for a GET request, 
 * respond with a html that can trigger a GET request for a flash file
 */
static ngx_int_t
ngx_http_ac_challenge_get_swf_handler(ngx_http_request_t *r)
{
    ngx_http_complex_value_t      cv;
    u_char                       *challenge_ct;
    u_char                       *swf_filename;
    ngx_uint_t                    swf_filename_len;
    ngx_http_ac_req_ctx_t        *ctx;

    ctx = ngx_http_ac_get_request_ctx(r);
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memzero(&cv, sizeof(ngx_http_complex_value_t));

    /* + 5 means '-GET-' */
    swf_filename_len = strlen(NGX_HTTP_AC_SWF_FILENAME_PREFIX)
        + ctx->cookie.len
        + 5;

    swf_filename = ngx_pcalloc(r->pool, swf_filename_len + 1);
    if (swf_filename == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_sprintf(swf_filename, 
            NGX_HTTP_AC_SWF_FILENAME_PREFIX"%V-GET-", 
            &ctx->cookie);
    
    /* -8 means 4 %s in NGX_HTTP_AC_GET_SWF 
     * filename length * 4 means we need to replace 4 %s */
    cv.value.len = strlen(NGX_HTTP_AC_GET_SWF) 
            + (swf_filename_len * 4)
            - 8;
    
    challenge_ct = ngx_pcalloc(r->pool, cv.value.len);
    if (challenge_ct == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
   
    ngx_sprintf(challenge_ct, NGX_HTTP_AC_GET_SWF, 
            swf_filename, swf_filename, swf_filename, swf_filename);

    cv.value.data = challenge_ct;
    
    return ngx_http_send_response(r, NGX_HTTP_OK, &ngx_http_ac_type_html, &cv);
}

static void
ngx_http_ac_dummy_post_handler(ngx_http_request_t *r)
{
    return;
}

static ngx_int_t
ngx_http_ac_read_request_body(ngx_http_request_t *r, 
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
ngx_http_ac_challenge_post_js_handler(ngx_http_request_t *r)
{
    ngx_http_complex_value_t      cv;
    u_char                       *challenge_ct, timeout[32];
    ngx_http_ac_loc_conf_t       *alcf;
    ngx_http_ac_req_ctx_t        *ctx;
    u_char                       *post_vars = NULL;
    ngx_uint_t                    post_vars_len = 0;
    ngx_http_request_body_t      *rb;
    ngx_uint_t                    body_len, offset;
    ngx_int_t                     rc;
    ngx_int_t                     random_tpl;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_active_challenge_module);
    
    ctx = ngx_http_ac_get_request_ctx(r);
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memzero(&cv, sizeof(ngx_http_complex_value_t)); 
    ngx_memzero(timeout, sizeof(timeout)); 

    sprintf((char *)timeout, "%d", (int)alcf->timeout);

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
        post_vars = ngx_http_ac_post_body_to_form(
                r, 
                rb->bufs->buf->pos, 
                body_len, 
                &post_vars_len);
    }

    /* get template randomly */
    random_tpl = ngx_random() % ngx_http_ac_post_js_tpls_nr;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "get random js-post template, tpl id: %d", random_tpl);
    
    /* -6 means 3 %s in NGX_HTTP_AC_POST_JS_1 */
    cv.value.len = strlen(ngx_http_ac_post_js_tpls[random_tpl]) 
            + strlen(NGX_HTTP_AC_POST_JS_2)
            + NGX_HTTP_AC_DEFAULT_COOKIE_LEN * 2
            + strlen(NGX_HTTP_AC_COOKIE_NAME) * 2
            + strlen((char *)timeout) 
            + post_vars_len
            - 6
            - 4;
    
    challenge_ct = ngx_pcalloc(r->pool, cv.value.len + 1);
    if (challenge_ct == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
  
    memcpy(challenge_ct, ngx_http_ac_post_js_tpls[random_tpl], 
            strlen(ngx_http_ac_post_js_tpls[random_tpl]));

    if (ngx_http_ac_replace_string(r, challenge_ct, cv.value.len + 1,
                (u_char *)"XX", 
                (u_char *)NGX_HTTP_AC_COOKIE_NAME) != NGX_OK)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;

    if (ngx_http_ac_replace_string(r, challenge_ct, cv.value.len + 1,
                (u_char *)"YY", 
                ctx->cookie.data) != NGX_OK)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
   
    if (ngx_http_ac_replace_string(r, challenge_ct, cv.value.len + 1,
                (u_char *)"ZZ", 
                timeout) != NGX_OK)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    
    if (ngx_http_ac_replace_string(r, challenge_ct, cv.value.len + 1,
                (u_char *)"MM", 
                (u_char *)NGX_HTTP_AC_COOKIE_NAME) != NGX_OK)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;

    if (ngx_http_ac_replace_string(r, challenge_ct, cv.value.len + 1,
                (u_char *)"NN", 
                ctx->cookie_f1.data) != NGX_OK)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
   
 
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
            NGX_HTTP_AC_POST_JS_2, 
            strlen(NGX_HTTP_AC_POST_JS_2));

    if (alcf->no_expires == 1) {
        ngx_http_ac_handle_no_expires(challenge_ct, cv.value.len); 
    }

    cv.value.data = challenge_ct;
    
    rc = ngx_http_send_response(r, NGX_HTTP_OK, &ngx_http_ac_type_html, &cv);

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
ngx_http_ac_challenge_post_swf_handler(ngx_http_request_t *r)
{
    ngx_http_complex_value_t      cv;
    u_char                       *challenge_ct;
    u_char                       *swf_filename;
    ngx_uint_t                    swf_filename_len;
    ngx_http_ac_req_ctx_t        *ctx;
    u_char                       *post_vars = NULL;
    ngx_uint_t                    post_vars_len = 0;
    ngx_http_request_body_t      *rb;
    ngx_uint_t                    body_len, offset;
    ngx_int_t                     rc;


    ctx = ngx_http_ac_get_request_ctx(r);
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memzero(&cv, sizeof(ngx_http_complex_value_t));

    /* + 6 means '-POST-' */
    swf_filename_len = strlen(NGX_HTTP_AC_SWF_FILENAME_PREFIX)
        + ctx->cookie.len
        + 6;

    swf_filename = ngx_pcalloc(r->pool, swf_filename_len + 1);
    if (swf_filename == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_sprintf(swf_filename, 
            NGX_HTTP_AC_SWF_FILENAME_PREFIX"%V-POST-", 
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
        post_vars = ngx_http_ac_post_body_to_form(
                r, 
                rb->bufs->buf->pos, 
                body_len, 
                &post_vars_len);
    }

    /* -8 means 4 %s in NGX_HTTP_AC_POST_SWF_1 
     * filename length * 4 means we need to replace 4 %s */
    cv.value.len = strlen(NGX_HTTP_AC_POST_SWF_1) 
            + post_vars_len
            + strlen(NGX_HTTP_AC_POST_SWF_2)
            + (swf_filename_len * 4)
            - 8;
   
    challenge_ct = ngx_pcalloc(r->pool, cv.value.len);
    if (challenge_ct == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
   
    ngx_sprintf(challenge_ct, NGX_HTTP_AC_POST_SWF_1, 
            swf_filename, swf_filename, swf_filename, swf_filename);

    offset = strlen(NGX_HTTP_AC_POST_SWF_1) 
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
            NGX_HTTP_AC_POST_SWF_2, 
            strlen(NGX_HTTP_AC_POST_SWF_2));

    cv.value.data = challenge_ct;
    
    rc = ngx_http_send_response(r, NGX_HTTP_OK, &ngx_http_ac_type_html, &cv);

    /* we have to finalize the request by ourselves, 
     * that is because we use the "read client body" API */
    ngx_http_finalize_request(r, rc);
    
    return NGX_OK;
}

static ngx_int_t
ngx_http_ac_send_response(ngx_http_request_t *r, ngx_uint_t status,
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
ngx_http_ac_send_swf_file_handler(ngx_http_request_t *r, ngx_uint_t method)
{
    ngx_str_t                     val;
    u_char                       *challenge_ct, *final_ct;
    u_char                        cookie_name[40], cookie_value[40];
    u_char                        timeout[40];
    u_char                       *uri;
    ngx_http_ac_loc_conf_t       *alcf;
    ngx_uint_t                    i, tmp_len, final_len;
    int                           ret;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_active_challenge_module);
 
    /* replace the placeholder in flash file 
     * each placeholder in ngx_http_ac_get_swf is 40 bytes long
     * and we replace them with a 40 bytes long data, using \x20
     * to fill the gap.
     */
   
    ngx_memset(timeout, '\x20', 40);
    ngx_memset(cookie_name, '\x20', 40);
    ngx_memset(cookie_value, '\x20', 40);

    /* fetch timeout value */
    ngx_snprintf(timeout, 40, "%d", alcf->timeout);

    /* fetch cookie value */
    uri = ngx_pcalloc(r->pool, r->uri.len + 1);
    if (uri == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    memcpy(uri, r->uri.data, r->uri.len);

    if (method == 0) {
        sscanf((char *)uri, "/"NGX_HTTP_AC_SWF_FILENAME_PREFIX"%40s-GET-.swf", 
                (char *)cookie_value);
    } else {
        sscanf((char *)uri, "/"NGX_HTTP_AC_SWF_FILENAME_PREFIX"%40s-POST-.swf", 
                (char *)cookie_value);
    }
   
    /* fetch cookie name */
    memcpy(cookie_name, NGX_HTTP_AC_COOKIE_NAME, 
            strlen(NGX_HTTP_AC_COOKIE_NAME));

    /* replace them into the flash file */
    if (method == 0) {
        val.len = sizeof(ngx_http_ac_get_swf) - 1;
    } else {
        val.len = sizeof(ngx_http_ac_post_swf) - 1;
    }

    challenge_ct = ngx_pcalloc(r->pool, val.len);
    if (challenge_ct == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (method == 0) {
        memcpy(challenge_ct, ngx_http_ac_get_swf, val.len);
    } else {
        memcpy(challenge_ct, ngx_http_ac_post_swf, val.len);
    }

    for (i = 0; i < val.len; i++) {
        /* replace cookie name */
        if (!memcmp(challenge_ct + i, 
                    NGX_HTTP_AC_SWF_PLACEHOLDER_COOKIE_NAME, 
                    strlen(NGX_HTTP_AC_SWF_PLACEHOLDER_COOKIE_NAME))) {
            memcpy(challenge_ct + i, cookie_name, 40);
        }
        
        /* replace cookie value */
        if (!memcmp(challenge_ct + i, 
                    NGX_HTTP_AC_SWF_PLACEHOLDER_COOKIE_VALUE, 
                    strlen(NGX_HTTP_AC_SWF_PLACEHOLDER_COOKIE_VALUE))) {
            memcpy(challenge_ct + i, cookie_value, 40);
        }
        
        /* replace timeout */
        if (!memcmp(challenge_ct + i, 
                    NGX_HTTP_AC_SWF_PLACEHOLDER_TIMEOUT, 
                    strlen(NGX_HTTP_AC_SWF_PLACEHOLDER_TIMEOUT))) {
            memcpy(challenge_ct + i, timeout, 40);
        }
    }

    if (alcf->no_expires == 1) {
        ngx_http_ac_handle_no_expires(challenge_ct, val.len); 
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

    ret = compress(final_ct + strlen("CWS") + 5, &final_len, 
            challenge_ct + 5, val.len - 5);
    if (ret != Z_OK) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                "compress flash file failed: %d\n", ret);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    val.len = final_len + strlen("CWS") + 5;
    val.data = final_ct;
    
    return ngx_http_ac_send_response(r, NGX_HTTP_OK, 
            &ngx_http_ac_type_swf, val);
}

static ngx_int_t 
ngx_http_ac_send_swf_handler(ngx_http_request_t *r)
{
    u_char *uri;

    uri = ngx_pcalloc(r->pool, r->uri.len + 1);
    if (uri == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    memcpy(uri, r->uri.data, r->uri.len);

    if (r->method == NGX_HTTP_GET) {
        if (ngx_strstr(uri, "-GET-")) {
            return ngx_http_ac_send_swf_file_handler(r, 0);
        } else if (ngx_strstr(uri, "-POST-")) {
            return ngx_http_ac_send_swf_file_handler(r, 1);
        } else {
            /* invalid uri */
            return NGX_HTTP_FORBIDDEN;
        }
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_ac_test_content_type(ngx_http_request_t *r, u_char *type)
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
ngx_http_ac_content_handler(ngx_http_request_t *r)
{
    ngx_http_ac_loc_conf_t       *alcf;
    ngx_int_t                     rc;
    
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
            "in active challenge's content handler");
    
    alcf = ngx_http_get_module_loc_conf(r, ngx_http_active_challenge_module);
    
    if (r->method == NGX_HTTP_GET) {
        if (alcf->mode == NGX_HTTP_AC_MODE_JS) {
            return ngx_http_ac_challenge_get_js_handler(r);
        } else {
            return ngx_http_ac_challenge_get_swf_handler(r);
        }
    } else if (r->method == NGX_HTTP_POST){
        /* consider upload file as GET */
        if (ngx_http_ac_test_content_type(r, 
                    (u_char *)"multipart/form-data")) {
            if (alcf->mode == NGX_HTTP_AC_MODE_JS) {
                return ngx_http_ac_challenge_get_js_handler(r);
            } else {
                return ngx_http_ac_challenge_get_swf_handler(r);
            }
        }

        rc = ngx_http_ac_read_request_body(r, ngx_http_ac_dummy_post_handler);
        
        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }

        if (alcf->mode == NGX_HTTP_AC_MODE_JS) {
            return ngx_http_ac_challenge_post_js_handler(r);
        } else {
            return ngx_http_ac_challenge_post_swf_handler(r);
        }
    }

    return NGX_OK;
}

#if (NGX_HTTP_SESSION)
static void 
ngx_http_ac_destroy_ctx_handler(void *ctx)
{
    ngx_http_session_ctx_t *session_ctx;

    session_ctx = (ngx_http_session_ctx_t *)ctx;

    return ngx_http_session_shm_free_nolock(session_ctx->data);
}

static ngx_int_t 
ngx_http_ac_init_ctx_handler(void *ctx)
{
    ngx_http_session_ctx_t *session_ctx;

    session_ctx = (ngx_http_session_ctx_t *)ctx;

    /* initial session ctx */
    session_ctx->data = 
        ngx_http_session_shm_alloc_nolock(sizeof(ngx_http_ac_session_ctx_t));
    if (!session_ctx->data) {
        fprintf(stderr, "create ac ctx error\n");
        return NGX_ERROR;
    }

    memset(session_ctx->data, 0, sizeof(ngx_http_ac_session_ctx_t));

    return NGX_OK;
}

static ngx_uint_t *
ngx_http_ac_get_bl_count(ngx_http_session_ctx_t *ctx)
{
    ngx_http_ac_session_ctx_t         *ac_ctx;
    
    ac_ctx = ctx->data;

    return &(ac_ctx->failed_count);
}

/*
 * set:
 * 0 for get the request_type
 * 1 for set the request_type to 1
 *
 * ret:
 * 0
 * 1
 * -1 for error occurred.
 */
static ngx_int_t
ngx_http_ac_request_type(ngx_http_request_t *r, ngx_uint_t op, ngx_uint_t value)
{
    ngx_http_session_t                *session;
    ngx_http_session_ctx_t            *session_ctx;
    ngx_int_t                          ret;
    ngx_http_ac_session_ctx_t         *ac_ctx;
    u_char                            *session_name = (u_char *)"a/challenge";
    
    session = ngx_http_session_get(r);
    if (!session) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                "get session failed, treat this session as new\n");
        return NGX_HTTP_AC_STATUS_NEW;
    }

    ngx_shmtx_lock(&session->mutex);
    session_ctx = ngx_http_session_find_ctx(session, 
            session_name);

    if (!session_ctx) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                "create %s session ctx", session_name);

        session_ctx = ngx_http_session_create_ctx(session, 
                session_name, 
                ngx_http_ac_init_ctx_handler,
                ngx_http_ac_destroy_ctx_handler);

        if (!session_ctx) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                    "create session ctx error");
            ngx_shmtx_unlock(&session->mutex);
            ngx_http_session_put(r);
            return -1;
        }

        ac_ctx = session_ctx->data;
    } else {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                "found session ctx\n");
        ac_ctx = session_ctx->data;
    }
    
    if (op == NGX_HTTP_AC_SET_STATUS) {
        ac_ctx->request_type = value;
    } else if (op == NGX_HTTP_AC_GET_STATUS) {
        /* do nothing */
    } else if (op == NGX_HTTP_AC_CLEAR_STATUS) {
        ac_ctx->request_type = NGX_HTTP_AC_STATUS_NEW;
    } else {
        return NGX_ERROR;
    }

    ret = ac_ctx->request_type;
    
    ngx_shmtx_unlock(&session->mutex);
    ngx_http_session_put(r);

    return ret;
}
#endif

static ngx_int_t
ngx_http_ac_do_action(ngx_http_request_t *r)
{
    ngx_http_ac_loc_conf_t            *alcf;
    ngx_http_ns_action_t              *action;
#if (NGX_HTTP_SESSION) 
    u_char                            *ac_name = (u_char *)"a/challenge";
#endif

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_active_challenge_module);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
            "active challenge do action: %d", (int)alcf->action);

    action = ngx_pcalloc(r->pool, sizeof(ngx_http_ns_action_t));
    if (action == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    action->action = alcf->action;
#if (NGX_HTTP_SESSION) 
    action->session_name = ac_name;
    action->init = ngx_http_ac_init_ctx_handler;
    action->destroy = ngx_http_ac_destroy_ctx_handler;
    action->get_bl_count = ngx_http_ac_get_bl_count;
    action->bl_max = alcf->failed_count;
#endif
    if (alcf->error_page.data != NULL) {
        action->has_redirect = 1;
        action->redirect_page = &alcf->error_page;
        action->in_body = 0;
    }
    
    return ngx_http_ns_do_action(r, action);
}

static void* ngx_http_ac_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_ac_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ac_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->mode = NGX_HTTP_AC_MODE_JS;
    conf->enabled = 0;
    conf->failed_count = NGX_CONF_UNSET;
    conf->blacktime = 0;
    conf->timeout = NGX_HTTP_AC_DEFAULT_TIMEOUT;
    conf->no_expires = 0;
    conf->whitelist_items = NULL;

    return conf;
}

static char *
ngx_http_ac_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_ac_request_ctx_init(ngx_http_request_t *r)
{
    ngx_http_ac_req_ctx_t    *ctx;

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_ac_req_ctx_t));
    if (ctx == NULL)
        return NGX_ERROR;

    ngx_http_ns_set_ctx(r, ctx, ngx_http_active_challenge_module);

    return NGX_OK;
}

static ngx_http_ac_req_ctx_t *
ngx_http_ac_get_request_ctx(ngx_http_request_t *r)
{
    ngx_http_ac_req_ctx_t       *ctx;

    ctx = ngx_http_ns_get_module_ctx(r, ngx_http_active_challenge_module);

    return ctx;
}


