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

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <uv.h>
#include "util.h"

static const char *progname = __FILE__;  /* Reset in main(). */

void _setprogname(const char *name) {
    progname = name;
}

const char *_getprogname(void) {
    const char *name = NULL;
#if defined(_MSC_VER)
    name = strrchr(progname, '\\');
#else
    name = strrchr(progname, '/');
#endif // defined(_MSC_VER)
    return name ? name + 1 : progname;
}

static void pr_do(FILE *stream, const char *label, const char *fmt, va_list ap);

void pr_info(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    pr_do(stdout, "info", fmt, ap);
    va_end(ap);
}

void pr_warn(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    pr_do(stderr, "warn", fmt, ap);
    va_end(ap);
}

void pr_err(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    pr_do(stderr, "error", fmt, ap);
    va_end(ap);
}

static void pr_do(FILE *stream, const char *label, const char *fmt, va_list ap) {
    static const int size = 1024;
    char *fmtbuf = malloc(size);
    vsnprintf(fmtbuf, size, fmt, ap);
    fprintf(stream, "%s:%s: %s\n", _getprogname(), label, fmtbuf);
    free(fmtbuf);
}

int convert_address(const char *addr_str, unsigned short port, union sockaddr_universal *addr)
{
    struct addrinfo hints = { 0 }, *ai = NULL;
    int status;
    char port_buffer[6] = { 0 };
    int result = -1;

    if (addr_str == NULL || port == 0 || addr == NULL) {
        return result;
    }

    sprintf(port_buffer, "%hu", port);

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV | AI_PASSIVE;

    if ((status = getaddrinfo(addr_str, port_buffer, &hints, &ai)) != 0) {
        return result;
    }

    // Note, we're taking the first valid address, there may be more than one
    switch (ai->ai_family) {
    case AF_INET:
        addr->addr4 = *(const struct sockaddr_in *) ai->ai_addr;
        addr->addr4.sin_port = htons(port);
        result = 0;
        break;
    case AF_INET6:
        addr->addr6 = *(const struct sockaddr_in6 *) ai->ai_addr;
        addr->addr6.sin6_port = htons(port);
        result = 0;
        break;
    default:
        assert(0);
        break;
    }

    freeaddrinfo(ai);
    return result;
}
