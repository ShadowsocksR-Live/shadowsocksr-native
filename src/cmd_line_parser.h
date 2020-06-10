//
// Created by ssrlive on 18-4-22.
//

#ifndef __SSR_NATIVE_CMD_LINE_H__
#define __SSR_NATIVE_CMD_LINE_H__

#include <stdbool.h>

struct cmd_line_info {
    char * cfg_file;
    bool daemon_flag;
    bool help_flag;
    bool force_quit;
#ifdef ANDROID
    int log_tx_rx;
    char *prefix;
#endif
};

struct cmd_line_info * cmd_line_info_create(int argc, char * const argv[]);
void cmd_line_info_destroy(struct cmd_line_info *info);

#endif // __SSR_NATIVE_CMD_LINE_H__
