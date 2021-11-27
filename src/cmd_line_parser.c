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

    static struct option long_options[] = {
        { "help", no_argument,       0, 0 },
        { "host", required_argument, 0, 0 },
        { "deadloop", no_argument,   0, 0 },
        { 0,      0, 0, 0 },
    };
    int option_index = 0;

    info->force_quit_delay_ms = 3000; // TODO: add force_quit_delay_ms command argument.

    while (-1 != (opt = getopt_long(argc, argv, "c:S:Vdfh", long_options, &option_index))) {
        switch (opt) {
        case 0:
            if (option_index == 0) {
                info->help_flag = true; // --help option
            }
            break;
#if ANDROID
        case '?':
        case '-':
            // FIXME: ignore all unknow options.
            break;
        case 'S':
            string_safe_assign(&info->stat_path, optarg);
            break;
        case 'V':
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
#if ANDROID
        object_safe_free((void **)&info->stat_path);
#endif
        object_safe_free((void **)&info->cfg_file);
        free(info);
    }
}
