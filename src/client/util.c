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
#include <uv.h>
#include "util.h"

static const char *progname = __FILE__;  /* Reset in main(). */

void _setprogname(const char *name) {
    progname = name;
}

const char *_getprogname(void) {
#if defined(_MSC_VER)
    return strrchr(progname, '\\') + 1;
#else
    return strrchr(progname, '/') + 1; // return progname;
#endif // defined(_MSC_VER)
}

void string_safe_assign(char **target, const char *value) {
    object_safe_free(target);
    if (target && value) {
        *target = strdup(value);
    }
}

void object_safe_free(void **obj) {
    if (obj && *obj) {
        free(*obj);
        *obj = NULL;
    }
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

int convert_address(const char *addr_str, unsigned short port, void *ipv4_or_ipv6)
{
    struct addrinfo hints = { 0 }, *ai = NULL;
    int status;
    char port_buffer[6] = { 0 };

    if (addr_str == NULL || port == 0 || ipv4_or_ipv6 == NULL) {
        return -1;
    }

    sprintf(port_buffer, "%hu", port);

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV | AI_PASSIVE;

    if ((status = getaddrinfo(addr_str, port_buffer, &hints, &ai)) != 0) {
        return -1;
    }

    // Note, we're taking the first valid address, there may be more than one
    if (ai->ai_family == AF_INET) {
        *((struct sockaddr_in *)ipv4_or_ipv6) = *(const struct sockaddr_in *) ai->ai_addr;
        ((struct sockaddr_in *)ipv4_or_ipv6)->sin_port = htons(port);
    } else if (ai->ai_family == AF_INET6) {
        *((struct sockaddr_in6 *)ipv4_or_ipv6) = *(const struct sockaddr_in6 *) ai->ai_addr;
        ((struct sockaddr_in6 *)ipv4_or_ipv6)->sin6_port = htons(port);
    }

    freeaddrinfo(ai);
    return 0;
}
