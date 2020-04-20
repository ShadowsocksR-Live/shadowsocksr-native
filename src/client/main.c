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
#include "config_json.h"
#include "dump_info.h"
#include "common.h"
#include "ssr_executive.h"
#include "ssr_client_api.h"
#include "cmd_line_parser.h"
#include "daemon_wrapper.h"
#include "ssrbuffer.h"

#if HAVE_UNISTD_H
#include <unistd.h>  /* getopt */
#endif

static void usage(void);

struct ssr_client_state *g_state = NULL;
void feedback_state(struct ssr_client_state *state, void *p);
void print_remote_info(const struct server_config *config);

void fn_onexit(void) {
    MEM_CHECK_DUMP_LEAKS();
}

int main(int argc, char **argv) {
    struct server_config *config = NULL;
    int err = -1;
    struct cmd_line_info *cmds = NULL;

    MEM_CHECK_BEGIN();
    MEM_CHECK_BREAK_ALLOC(63);
    MEM_CHECK_BREAK_ALLOC(64);

    atexit(fn_onexit);

    do {
        set_app_name(argv[0]);

        cmds = cmd_line_info_create(argc, argv);

        if (cmds == NULL) {
            break;
        }
        if (cmds->help_flag) {
            break;
        }

        if (cmds->cfg_file == NULL) {
            string_safe_assign(&cmds->cfg_file, DEFAULT_CONF_PATH);
        }

        config = config_create();
        if (parse_config_file(false, cmds->cfg_file, config) == false) {
            break;
        }

        config_ssrot_revision(config);

#ifndef UDP_RELAY_ENABLE
        config->udp = false;
#endif // UDP_RELAY_ENABLE

        if (config->method == NULL || config->password==NULL || config->remote_host==NULL) {
            break;
        }

        if (cmds->daemon_flag) {
            char param[257] = { 0 };
            sprintf(param, "-c \"%s\"", cmds->cfg_file);
            daemon_wrapper(argv[0], param);
        }

        print_remote_info(config);

        // putenv("UV_THREADPOOL_SIZE=64"); // uv_os_setenv("UV_THREADPOOL_SIZE", "64"); // 

        ssr_run_loop_begin(config, &feedback_state, NULL);
        g_state = NULL;

        err = 0;
    } while(0);

    cmd_line_info_destroy(cmds);

    config_release(config);

    if (err != 0) {
        usage();
    }

    return 0;
}

void print_remote_info(const struct server_config *config) {
    char remote_host[256] = { 0 };
    char password[256] = { 0 };

    strcpy(remote_host, config->remote_host);
    if (strlen(remote_host) > 4) {
        size_t i = 0;
        for (i = 4; i < strlen(remote_host); i++) {
            remote_host[i] = '*';
        }
    }

    strcpy(password, config->password);
    if (strlen(password) > 2) {
        size_t i = 0;
        for (i = 2; i < strlen(password); i++) {
            password[i] = '*';
        }
    }

    pr_info("ShadowsocksR native client\n");
    pr_info("remote server    %s:%hu", remote_host, config->remote_port);
    pr_info("method           %s", config->method);
    pr_info("password         %s", password);
    pr_info("protocol         %s", config->protocol);
    if (config->protocol_param && strlen(config->protocol_param)) {
        pr_info("protocol_param   %s", config->protocol_param);
    }
    pr_info("obfs             %s", config->obfs);
    if (config->obfs_param && strlen(config->obfs_param)) {
        pr_info("obfs_param       %s", config->obfs_param);
    }
    if (config->over_tls_enable) {
        pr_info(" ");
        pr_warn("over TLS         %s", config->over_tls_enable ? "yes" : "no");
        pr_info("over TLS domain  %s", config->over_tls_server_domain);
        pr_info("over TLS path    %s", config->over_tls_path);
        pr_info(" ");
    }
    pr_info("udp relay        %s\n", config->udp ? "yes" : "no");
}

void feedback_state(struct ssr_client_state *state, void *p) {
    g_state = state;
    (void)p;
}

static void usage(void) {
    printf(""
        "ShadowsocksR native client\n"
        "\n"
        "Usage:\n"
        "\n"
        "  %s [-d] [-c <config file>] [-h]\n"
        "\n"
        "Options:\n"
        "\n"
        "  -d                     Run in background as a daemon.\n"
        "  -c <config file>       Configure file path.\n"
        "                         Default: " DEFAULT_CONF_PATH "\n"
        "  -h                     Show this help message.\n"
        "",
        get_app_name());
}
