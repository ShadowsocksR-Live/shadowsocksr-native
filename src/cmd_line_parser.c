//
// Created by ssrlive on 18-4-22.
//

#include <stdlib.h>
#include <getopt.h>

#include "cmd_line_parser.h"
#include "ssr_executive.h"

struct cmd_line_info * cmd_line_info_create(int argc, char * const argv[]) {
    int opt;

    struct cmd_line_info *info = (struct cmd_line_info *)calloc(1, sizeof(*info));

    while (-1 != (opt = getopt(argc, argv, "c:P:xdfh"))) {
        switch (opt) {
#ifdef ANDROID
        case 'P':
            string_safe_assign(&info->prefix, optarg);
            break;
        case 'x':
            info->log_tx_rx = 1;
            break;
#endif
        case 'c':
            string_safe_assign(&info->cfg_file, optarg);
            break;
        case 'd':
            info->daemon_flag = true;
            break;
        case 'f':
            info->force_quit = true;
            break;
        case 'h':
        default:
            info->help_flag = true;
            break;
        }
    }
    return info;
}

void cmd_line_info_destroy(struct cmd_line_info *info) {
    if (info) {
#ifdef ANDROID
        object_safe_free((void **)&info->prefix);
#endif
        object_safe_free((void **)&info->cfg_file);
        free(info);
    }
}
