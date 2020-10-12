//
// Created by ssrlive on 2020-09-09.
//

#include <stdlib.h>
#include <memory.h>
#include <unistd.h>

#if defined(_WIN32)
#include <Windows.h>
#elif TARGET_OS_IPHONE
#pragma message("exe_file_path will return NULL")
#elif defined(__APPLE__)
#include <stdint.h>
#include <mach-o/dyld.h>
#include <sys/param.h>
#elif defined(__linux__)
#define SELF_EXE "/proc/self/exe"
#elif defined(__FreeBSD__)
#define SELF_EXE "/proc/curproc/file"
#elif defined(sun) || defined(__sun)
#define SELF_EXE "/proc/self/path/a.out"
#else
#error "exe_file_path not implement yet"
#endif

#include "exe_file_path.h"

char* exe_file_path(void* (*allocator)(size_t)) {
    char* buf = NULL;
    size_t bufsize = 0;
    do {
        if (allocator == NULL) {
            break;
        }

#if defined(_WIN32)
        bufsize = MAX_PATH;
        buf = (char*)allocator(bufsize);
        if (buf == NULL) {
            break;
        }
        memset(buf, 0, bufsize);
        if (GetModuleFileNameA(NULL, buf, (DWORD)bufsize) == 0) {
            memset(buf, 0, bufsize);
        }
        break;

#elif TARGET_OS_IPHONE
        break;

#elif defined(__APPLE__)
        bufsize = MAXPATHLEN;
        buf = (char*)allocator(bufsize);
        if (buf == NULL) {
            break;
        }
        memset(buf, 0, bufsize);
        if (_NSGetExecutablePath(buf, (uint32_t*)&bufsize) != 0) {
            memset(buf, 0, bufsize);
        }
        break;

#elif defined(__unix__)
        bufsize = 256*2;
        buf = (char*)allocator(bufsize);
        if (buf == NULL) {
            break;
        }
        memset(buf, 0, bufsize);
        readlink(SELF_EXE, buf, bufsize);
        break;

#else
        break;
#endif
    } while (0);

    return buf;
}
