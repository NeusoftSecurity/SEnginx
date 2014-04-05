/*
 * Copyright (c) 2013 Neusoft Corperation., Ltd.
 */

#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>

const char *tpl = "'X X(){X.X=\\\\'X=X; X-X=X; X=/\\\\';X.X.X()};X X(){X.X=\\\\'X=X; X-X=X; X=/\\\\';X.X.X()}'";
const char *key_tpl = "'%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s'.split('|')";
const char *full_tpl =
    "\"<html><body onload=\\\"challenge();\\\"><script>eval(function(p,a,c,k,e,r){e=function(c){return c.toString(a)};if(!''.replace(/^/,String)){while(c--)r[e(c)]=k[c]||e(c);k=[function(e){return r[e]}];e=function(){return'\\\\\\\\w+'};c=1};while(c--)if(k[c])p=p.replace(new RegExp('\\\\\\\\b'+e(c)+'\\\\\\\\b','g'),k[c]);return p}(%s,26,26,%s,0,{}))</script></body></html>\"";

char maps[] = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b',
    'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
};

char *keys[] = {
    "function",
    "challenge_f",
    "document",
    "cookie",
    "MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM",
    "NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN",
    "max",
    "age",
    "OOOO",
    "path",
    "window",
    "location",
    "reload",
    "function",
    "challenge",
    "document",
    "cookie",
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
    "YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY",
    "max",
    "age",
    "ZZZZ",
    "path",
    "window",
    "location",
    "reload",
};

const char *tpl_p = "'X X(){X=\\\\'X=X\\\\';X.X=\\\\'X=X; X-X=X; X=/\\\\';X.X.X=X.X.X+X.X.X;X.X[0].X()}'";

const char *key_tpl_p = "'|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s'.split('|')";

const char *full_tpl_p =
    "\"<html><body onload=\\\"challenge();\\\"><script>eval(function(p,a,c,k,e,r){e=function(c){return c.toString(a)};if(!''.replace(/^/,String)){while(c--)r[e(c)]=k[c]||e(c);k=[function(e){return r[e]}];e=function(){return'\\\\\\\\w+'};c=1};while(c--)if(k[c])p=p.replace(new RegExp('\\\\\\\\b'+e(c)+'\\\\\\\\b','g'),k[c]);return p}(%s,26,26,%s,0,{}))</script><form name=\\\"response\\\" method=\\\"post\\\">\"";

char maps_p[] = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b',
    'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
};

char *keys_p[] = {
    "function",
    "challenge",
    "t",
    "MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM",
    "NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN",
    "document",
    "cookie",
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
    "YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY",
    "max",
    "age",
    "ZZZZ",
    "path",
    "document",
    "response",
    "action",
    "window",
    "location",
    "pathname",
    "window",
    "location",
    "search",
    "document",
    "forms",
    "submit",
};


void usage(char *prog_name)
{
    printf("usage: %s -n [number] -s [-d]\n", prog_name);
}

int gen_get_js(int range, int debug, int sub, int num)
{
    int i, j, k, *list;
    int tmp;
    char *p, *list_str, **keys_list_str, *key_str;
    char *full_str;
    int pos[6];

    printf("const ngx_http_rm_tpl_t ngx_http_rm_get_js_tpls[] = {\n");

    list = malloc(sizeof(int) * range);
    if (list == NULL) {
        perror("malloc");
        return -1;
    }

    memset(list, 0, sizeof(int) * range);

    j = num;

    srandom(time(NULL));

    for (i = 0; i < num; i++) {
        for (j = 0; j < range; j++) {
gen:
            tmp = random() % range;

            for (k = 0; k < j; k++) {
                if (list[k] == tmp)
                    goto gen;
            }

            /* found a unique random number */
            list[j] = tmp;
        }

        if (sub == 0) {
            /* one list is finished, output */
            printf("list[%d]: ", i);
            for (j = 0; j < range; j++) {
                printf("%c ", maps[list[j]]);
            }
            printf("\n");
        }

        if (sub == 1) {
            list_str = malloc(strlen(tpl) + 1);
            if (list_str == NULL) {
                perror("malloc");
                return -1;
            }

            keys_list_str = malloc(sizeof(char *) * range);
            if (keys_list_str == NULL) {
                perror("malloc");
                return -1;
            }

            key_str = malloc(2048);
            if (key_str == NULL) {
                perror("malloc");
                return -1;
            }

            full_str = malloc(2048);
            if (full_str == NULL) {
                perror("malloc");
                return -1;
            }

            memset(list_str, 0, strlen(tpl) + 1);
            memcpy(list_str, tpl, strlen(tpl));

            for (j = 0; j < range; j++) {
                p = strstr(list_str, "X");
                if (p != NULL) {
                    *p = maps[list[j]];

                    keys_list_str[list[j]] = keys[j];
                }
            }

            snprintf(key_str, 2047, key_tpl,
                    keys_list_str[0],
                    keys_list_str[1],
                    keys_list_str[2],
                    keys_list_str[3],
                    keys_list_str[4],
                    keys_list_str[5],
                    keys_list_str[6],
                    keys_list_str[7],
                    keys_list_str[8],
                    keys_list_str[9],
                    keys_list_str[10],
                    keys_list_str[11],
                    keys_list_str[12],
                    keys_list_str[13],
                    keys_list_str[14],
                    keys_list_str[15],
                    keys_list_str[16],
                    keys_list_str[17],
                    keys_list_str[18],
                    keys_list_str[19],
                    keys_list_str[20],
                    keys_list_str[21],
                    keys_list_str[22],
                    keys_list_str[23],
                    keys_list_str[24],
                    keys_list_str[25]
                    );

            snprintf(full_str, 2047, full_tpl, list_str, key_str);

            pos[0] = strstr(full_str, keys[4]) - full_str + 1 - 14;
            pos[1] = strstr(full_str, keys[5]) - full_str + 1 - 14;
            pos[2] = strstr(full_str, keys[8]) - full_str + 1 - 14;
            pos[3] = strstr(full_str, keys[17]) - full_str + 1 - 14;
            pos[4] = strstr(full_str, keys[18]) - full_str + 1 - 14;
            pos[5] = strstr(full_str, keys[21]) - full_str + 1 - 14;

            if (debug) {
                printf("final map string: %s\n", list_str);
                printf("final keys string: %s\n", key_str);

                for (k = 0; k < 6; k++) {
                    printf("final position: %d\n", pos[k]);
                }
            }

            printf("\n/* #%d */\n{%s, %d, %d, %d, "
                   "%d, %d, %d, %d},\n\n", i, full_str,
                   pos[0], pos[1], pos[2], pos[3], pos[4], pos[5],
                   (int)strlen(full_str) - 14);

            free(list_str);
            free(keys_list_str);
            free(key_str);
            free(full_str);
        }
    }

    printf("};\n");
    printf("\n");
    printf("const ngx_uint_t ngx_http_rm_get_js_tpls_nr = sizeof(ngx_http_rm_get_js_tpls)\n");
    printf("    / sizeof(ngx_http_rm_tpl_t);\n");
    printf("\n");
    printf("\n");

    return 0;
}

int gen_post_js(int range, int debug, int sub, int num)
{
    int i, j, k, *list;
    int tmp;
    char *p, *list_str, **keys_list_str, *key_str;
    char *full_str;
    int pos[5];

    printf("const ngx_http_rm_tpl_t ngx_http_rm_post_js_tpls[] = {\n");

    list = malloc(sizeof(int) * range);
    if (list == NULL) {
        perror("malloc");
        return -1;
    }

    memset(list, 0, sizeof(int) * range);

    srandom(time(NULL));

    for (i = 0; i < num; i++) {
        for (j = 0; j < range; j++) {
gen:
            tmp = random() % (range + 1);

            if (tmp == 0) {
                goto gen;
            }

            for (k = 0; k < j; k++) {
                if (list[k] == tmp)
                    goto gen;
            }

            /* found a unique random number */
            list[j] = tmp;
        }

        if (sub == 0) {
            /* one list is finished, output */
            printf("list[%d]: ", i);
            for (j = 0; j < range; j++) {
                printf("%c ", maps_p[list[j]]);
            }
            printf("\n");
        }

        if (sub == 1) {
            list_str = malloc(strlen(tpl_p) + 1);
            if (list_str == NULL) {
                perror("malloc");
                return -1;
            }

            keys_list_str = malloc(sizeof(char *) * range);
            if (keys_list_str == NULL) {
                perror("malloc");
                return -1;
            }

            key_str = malloc(2048);
            if (key_str == NULL) {
                perror("malloc");
                return -1;
            }

            full_str = malloc(2048);
            if (full_str == NULL) {
                perror("malloc");
                return -1;
            }

            memset(list_str, 0, strlen(tpl_p) + 1);
            memcpy(list_str, tpl_p, strlen(tpl_p));

            for (j = 0; j < range; j++) {
                p = strstr(list_str, "X");
                if (p != NULL) {
                    *p = maps_p[list[j]];

                    keys_list_str[list[j] - 1] = keys_p[j];
                }
            }

            snprintf(key_str, 2047, key_tpl_p,
                    keys_list_str[0],
                    keys_list_str[1],
                    keys_list_str[2],
                    keys_list_str[3],
                    keys_list_str[4],
                    keys_list_str[5],
                    keys_list_str[6],
                    keys_list_str[7],
                    keys_list_str[8],
                    keys_list_str[9],
                    keys_list_str[10],
                    keys_list_str[11],
                    keys_list_str[12],
                    keys_list_str[13],
                    keys_list_str[14],
                    keys_list_str[15],
                    keys_list_str[16],
                    keys_list_str[17],
                    keys_list_str[18],
                    keys_list_str[19],
                    keys_list_str[20],
                    keys_list_str[21],
                    keys_list_str[22],
                    keys_list_str[23],
                    keys_list_str[24]
                    );

            snprintf(full_str, 2047, full_tpl_p, list_str, key_str);

            pos[0] = strstr(full_str, keys_p[3]) - full_str + 1 - 14;
            pos[1] = strstr(full_str, keys_p[4]) - full_str + 1 - 14;
            pos[2] = strstr(full_str, keys_p[7]) - full_str + 1 - 14;
            pos[3] = strstr(full_str, keys_p[8]) - full_str + 1 - 14;
            pos[4] = strstr(full_str, keys_p[11]) - full_str + 1 - 14;

            if (debug) {
                printf("final map string: %s\n", list_str);
                printf("final keys string: %s\n", key_str);
            }

            printf("\n/* #%d */\n{%s, %d, %d, %d, "
                    "%d, %d, %d, %d},\n\n",
                    i, full_str, pos[0], pos[1],
                    0, pos[2], pos[3], pos[4],
                    (int)strlen(full_str) - 14);

            free(list_str);
            free(keys_list_str);
            free(key_str);
            free(full_str);
        }
    }

    printf("};\n");
    printf("\n");
    printf("const ngx_uint_t ngx_http_rm_post_js_tpls_nr = sizeof(ngx_http_rm_post_js_tpls)\n");
    printf("    / sizeof(ngx_http_rm_tpl_t);\n");

    return 0;
}

int main(int argc, char *argv[])
{
    int range_get = 26, range_post = 25;
    int opt, num = 0, sub = 0, debug = 0;

    while ((opt = getopt(argc, argv, "n:sd")) != -1) {
        switch (opt) {
            case 'n':
                num = atoi(optarg);
                break;
            case 's':
                sub = 1;
                break;
            case 'd':
                debug = 1;
                break;
            default: /* '?' */
                usage(argv[0]);
                return -1;
        }
    }

    if (num == 0) {
        usage(argv[0]);
        return -1;
    }

    if (debug)
        printf("args: range_get: %d, range_post: %d, number: %d\n",
                range_get, range_post, num);

    /* head */
    printf("/*\n");
    printf(" * Copyright (c) 2013 Neusoft Corperation., Ltd.\n");
    printf(" */\n");
    printf("\n");
    printf("\n");
    printf("#include <ngx_http_robot_mitigation.h>\n");
    printf("\n");
    printf("\n");
    /* end of head */

    /* get js */
    if (gen_get_js(range_get, debug, sub, num) != 0) {
        return -1;
    }
    /* end of get js */

    /* post js */
    if (gen_post_js(range_post, debug, sub, num) != 0) {
        return -1;
    }
    /* end of post js */

    return 0;
}
