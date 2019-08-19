//
// Created by ssrlive on 18-4-22.
//

#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include "daemon_wrapper.h"
#include "dump_info.h"

#if (defined(_WIN32) || defined(WIN32))
#include <windows.h>
#include <ObjBase.h>
#include <stdio.h>
#include <Shellapi.h>

// #pragma comment(linker, "/subsystem:\"windows\" /entry:\"mainCRTStartup\"") // no console window
#pragma comment(lib, "Shell32.lib")
#endif


void daemon_wrapper(const char *exec, const char *parameters) {
#if (defined(_WIN32) || defined(WIN32))
    SHELLEXECUTEINFOA sei = {0};
    sei.cbSize = sizeof(SHELLEXECUTEINFO);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = "open";
    sei.lpFile = exec;// app name
    sei.lpParameters = parameters;//command line
    sei.nShow = SW_HIDE;

    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    ShellExecuteExA(&sei);

    //ShellExecuteA(0, "open", exec, parameters, NULL, SW_HIDE);

    Sleep(1000); // 1s
    exit(0);
#else

#if defined(__APPLE__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
    (void)exec;
    (void)parameters;

    if(daemon(0, 0) == -1 && errno != 0) {
        pr_err("failed to put the process in background: %s", strerror(errno));
    } else {
        // when in background, write log to a file
        //log_to_file = 1;
    }

#if defined(__APPLE__)
#pragma GCC diagnostic pop
#endif

#endif
}
