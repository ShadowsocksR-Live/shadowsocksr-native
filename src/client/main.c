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

#define DEFAULT_CONF_PATH "/etc/ssr-native/config.json"

#if HAVE_UNISTD_H
#include <unistd.h>  /* getopt */
#endif

#define DEFAULT_BIND_HOST     "127.0.0.1"
#define DEFAULT_BIND_PORT     1080
#define DEFAULT_IDLE_TIMEOUT  (60 * 1000)

static struct server_config * config_create(void);
static void parse_opts(struct server_config *cf, int argc, char **argv);
static bool parse_config_file(const char *file, struct server_config *cf);
static void usage(void);

static const char *progname = __FILE__;  /* Reset in main(). */

int main(int argc, char **argv) {
    struct server_config *config;
    int err;

    progname = argv[0];

    config = config_create();
    parse_opts(config, argc, argv);

    err = listener_run(config, uv_default_loop());
    if (err) {
        exit(1);
    }

    return 0;
}

const char *_getprogname(void) {
#if defined(_MSC_VER)
    return strrchr(progname, '\\') + 1;
#else
    return strrchr(progname, '/') + 1; // return progname;
#endif // defined(_MSC_VER)
}

static struct server_config * config_create(void) {
    struct server_config *config;

    config = (struct server_config *) calloc(1, sizeof(*config));
    config->listen_host = strdup(DEFAULT_BIND_HOST);
    config->listen_port = DEFAULT_BIND_PORT;
    config->idle_timeout = DEFAULT_IDLE_TIMEOUT;

    return config;
}

static void parse_opts(struct server_config *cf, int argc, char **argv) {
    int opt;

    while (-1 != (opt = getopt(argc, argv, "c:h"))) {
        switch (opt) {
        case 'c':
            if (parse_config_file(optarg, cf) == false) {
                usage();
            }
            break;
        case 'h':
        default:
            usage();
        }
    }
}

static bool parse_config_file(const char *file, struct server_config *cf) {
    return false;
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
        progname);
    exit(1);
}
