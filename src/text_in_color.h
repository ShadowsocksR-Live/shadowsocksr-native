#ifndef __TEXT_IN_COLOR_H__ 
#define __TEXT_IN_COLOR_H__ 1

#include <stdio.h>

#define ANSI_COLOR_RESET   "\x1b[0m"
#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"

#define WIN_CONSOLE_WHITE   15
#define WIN_CONSOLE_RED     12
#define WIN_CONSOLE_GREEN   10
#define WIN_CONSOLE_YELLOW  14
#define WIN_CONSOLE_BLUE    9
#define WIN_CONSOLE_MAGENTA 13
#define WIN_CONSOLE_CYAN    11

#define TEXT_COLOR_MAP(V)                                                       \
    V( text_color_white,        ANSI_COLOR_RESET,       WIN_CONSOLE_WHITE)      \
    V( text_color_red,          ANSI_COLOR_RED,         WIN_CONSOLE_RED)        \
    V( text_color_green,        ANSI_COLOR_GREEN,       WIN_CONSOLE_GREEN)      \
    V( text_color_yellow,       ANSI_COLOR_YELLOW,      WIN_CONSOLE_YELLOW)     \
    V( text_color_blue,         ANSI_COLOR_BLUE,        WIN_CONSOLE_BLUE)       \
    V( text_color_magenta,      ANSI_COLOR_MAGENTA,     WIN_CONSOLE_MAGENTA)    \
    V( text_color_cyan,         ANSI_COLOR_CYAN,        WIN_CONSOLE_CYAN)       \

enum text_color {
#define TEXT_COLOR_GEN(item, ansi_text, win_int) item,
    TEXT_COLOR_MAP(TEXT_COLOR_GEN)
#undef TEXT_COLOR_GEN
    text_color_max,
};

void print_text_in_color(FILE *file, const char *text, enum text_color color);

#endif // __TEXT_IN_COLOR_H__
