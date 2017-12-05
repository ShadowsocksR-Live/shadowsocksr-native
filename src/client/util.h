#if !defined(__UTIL_H__)
#define __UTIL_H__ 1


#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* main.c */
void _setprogname(const char *name);
const char *_getprogname(void);

/* util.c */
#if defined(__GNUC__)
# define ATTRIBUTE_FORMAT_PRINTF(a, b) __attribute__((format(printf, a, b)))
#else
# define ATTRIBUTE_FORMAT_PRINTF(a, b)
#endif
void pr_info(const char *fmt, ...) ATTRIBUTE_FORMAT_PRINTF(1, 2);
void pr_warn(const char *fmt, ...) ATTRIBUTE_FORMAT_PRINTF(1, 2);
void pr_err(const char *fmt, ...) ATTRIBUTE_FORMAT_PRINTF(1, 2);

union sockaddr_universal {
    struct sockaddr_in6 addr6;
    struct sockaddr_in addr4;
    struct sockaddr addr;
};
int convert_address(const char *addr_str, unsigned short port, union sockaddr_universal *addr);

#endif // defined(__UTIL_H__)
