#if !defined(__UTIL_H__)
#define __UTIL_H__ 1


#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* main.c */
void _setprogname(const char *name);
const char *_getprogname(void);

void string_safe_assign(char **target, const char *value);
void object_safe_free(void **obj);

/* util.c */
#if defined(__GNUC__)
# define ATTRIBUTE_FORMAT_PRINTF(a, b) __attribute__((format(printf, a, b)))
#else
# define ATTRIBUTE_FORMAT_PRINTF(a, b)
#endif
void pr_info(const char *fmt, ...) ATTRIBUTE_FORMAT_PRINTF(1, 2);
void pr_warn(const char *fmt, ...) ATTRIBUTE_FORMAT_PRINTF(1, 2);
void pr_err(const char *fmt, ...) ATTRIBUTE_FORMAT_PRINTF(1, 2);

#endif // defined(__UTIL_H__)
