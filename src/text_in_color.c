#include <stdio.h>
#if defined(WIN32) || defined(_WIN32)
#include <windows.h>
#endif
#include "text_in_color.h"

void print_text_in_color(FILE *file, const char *text, enum text_color color) {
#if defined(WIN32) || defined(_WIN32)
    WORD wAttributes = 0;
    HANDLE  hConsole;
    CONSOLE_SCREEN_BUFFER_INFO csbiInfo = { 0 };
    struct {
        FILE *filePtr;
        DWORD wHandle;
    } std_handles[] = {
        { stdin, STD_INPUT_HANDLE },
        { stdout, STD_OUTPUT_HANDLE },
        { stderr, STD_OUTPUT_HANDLE },
    };
    int i=0;
    DWORD nStdHandle = 0;

#define TEXT_COLOR_WIN(item, ansi_text, win_int) case (item): wAttributes = (win_int); break;
    switch (color) {
        TEXT_COLOR_MAP(TEXT_COLOR_WIN)
    default:;  // Silence text_color_max -Wswitch warning.
    }
#undef TEXT_COLOR_WIN

    for (i=0; i<(sizeof(std_handles) / sizeof(*(std_handles))); ++i) {
        if (std_handles[i].filePtr == file) {
            nStdHandle = std_handles[i].wHandle;
            break;
        }
    }

    if (nStdHandle) {
        hConsole = GetStdHandle(nStdHandle);
        GetConsoleScreenBufferInfo(hConsole, &csbiInfo);
        SetConsoleTextAttribute(hConsole, wAttributes);
    }
    fprintf(file, "%s", text);
    if (nStdHandle) {
        SetConsoleTextAttribute(hConsole, csbiInfo.wAttributes);
    }

#else
    const char *clr_txt = ANSI_COLOR_RESET;

#define TEXT_COLOR_UNIX(item, ansi_text, win_int) case (item): clr_txt = (ansi_text); break;
    switch (color) {
        TEXT_COLOR_MAP(TEXT_COLOR_UNIX)
    default:;  // Silence text_color_max -Wswitch warning.
    }
#undef TEXT_COLOR_UNIX

    fprintf(file, "%s%s" ANSI_COLOR_RESET, clr_txt, text);

#endif /* WIN32 */
}
