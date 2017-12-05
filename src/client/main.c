/* Copyright StrongLoop, Inc. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "defs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>
#include "util.h"
#include "ssrcipher.h"

#if defined(WIN32)
#define DEFAULT_CONF_PATH "config.json"
#else
#define DEFAULT_CONF_PATH "/etc/ssr-native/config.json"
#endif // defined(WIN32)

#if HAVE_UNISTD_H
#include <unistd.h>  /* getopt */
#endif

static const char * parse_opts(int argc, char **argv);
static bool parse_config_file(const char *file, struct server_config *cf);
static void usage(void);

int main(int argc, char **argv) {
    struct server_config *config = NULL;
    int err = -1;
    const char *config_path = NULL;

    do {
        _setprogname(argv[0]);

        config_path = DEFAULT_CONF_PATH;
        if (argc > 1) {
            config_path = parse_opts(argc, argv);
        }

        if (config_path == NULL) {
            break;
        }

        config = config_create();
        if (parse_config_file(config_path, config) == false) {
            break;
        }

        if (config->method == NULL || config->password==NULL || config->remote_host==NULL) {
            break;
        }

        err = listener_run(config, uv_default_loop());

    } while(0);

    config_release(config);

    if (err != 0) {
        usage();
    }

    return 0;
}

static const char * parse_opts(int argc, char **argv) {
    int opt;

    while (-1 != (opt = getopt(argc, argv, "c:h"))) {
        switch (opt) {
        case 'c':
            return optarg;
            break;
        case 'h':
        default:
            break;
        }
    }
    return NULL;
}

bool json_iter_extract_string(const char *key, const struct json_object_iter *iter, const char **value) {
    bool result = false;
    do {
        if (key == NULL || iter == NULL || value==NULL) {
            break;
        }
        *value = NULL;
        if (strcmp(iter->key, key) != 0) {
            break;
        }
        struct json_object *val = iter->val;
        if (json_type_string != json_object_get_type(val)) {
            break;
        }
        *value = json_object_get_string(val);
        result = true;
    } while (0);
    return result;
}

bool json_iter_extract_int(const char *key, const struct json_object_iter *iter, int *value) {
    bool result = false;
    do {
        if (key == NULL || iter == NULL || value==NULL) {
            break;
        }
        if (strcmp(iter->key, key) != 0) {
            break;
        }
        struct json_object *val = iter->val;
        if (json_type_int != json_object_get_type(val)) {
            break;
        }
        *value = json_object_get_int(val);
        result = true;
    } while (0);
    return result;
}

static bool parse_config_file(const char *file, struct server_config *cf) {
    bool result = false;
    json_object *jso = NULL;
    do {
        jso = json_object_from_file(file);
        if (jso == NULL) {
            break;
        }
        struct json_object_iter iter;
        json_object_object_foreachC(jso, iter) {
            int obj_int = 0;
            const char *obj_str = NULL;
            if (json_iter_extract_string("local_address", &iter, &obj_str)) {
                string_safe_assign(&cf->listen_host, obj_str);
                continue;
            }
            if (json_iter_extract_int("local_port", &iter, &obj_int)) {
                cf->listen_port = obj_int;
                continue;
            }
            if (json_iter_extract_string("server", &iter, &obj_str)) {
                string_safe_assign(&cf->remote_host, obj_str);
                continue;
            }
            if (json_iter_extract_int("server_port", &iter, &obj_int)) {
                cf->remote_port = obj_int;
                continue;
            }
            if (json_iter_extract_string("password", &iter, &obj_str)) {
                string_safe_assign(&cf->password, obj_str);
                continue;
            }
            if (json_iter_extract_string("method", &iter, &obj_str)) {
                string_safe_assign(&cf->method, obj_str);
                continue;
            }
            if (json_iter_extract_string("protocol", &iter, &obj_str)) {
                if (obj_str && strcmp(obj_str, "verify_sha1") == 0) {
                    // LOGI("The verify_sha1 protocol is deprecate! Fallback to origin protocol.");
                    obj_str = NULL;
                }
                string_safe_assign(&cf->protocol, obj_str);
                continue;
            }
            if (json_iter_extract_string("protocol_param", &iter, &obj_str)) {
                string_safe_assign(&cf->protocol_param, obj_str);
                continue;
            }
            if (json_iter_extract_string("obfs", &iter, &obj_str)) {
                string_safe_assign(&cf->obfs, obj_str);
                continue;
            }
            if (json_iter_extract_string("obfs_param", &iter, &obj_str)) {
                string_safe_assign(&cf->obfs_param, obj_str);
                continue;
            }
            if (json_iter_extract_int("timeout", &iter, &obj_int)) {
                cf->idle_timeout = obj_int * SECONDS_PER_MINUTE;
                continue;
            }
        }
        result = true;
    } while (0);
    if (jso) {
        json_object_put(jso);
    }
    return result;
}

static void usage(void) {
    printf("Usage:\n"
        "\n"
        "  %s -c <config file> [-h]\n"
        "\n"
        "Options:\n"
        "\n"
        "  -c <config file>       Configure file path.\n"
        "                         Default: " DEFAULT_CONF_PATH "\n"
        "  -h                     Show this help message.\n"
        "",
        _getprogname());
    exit(1);
}
