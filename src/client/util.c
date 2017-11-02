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
