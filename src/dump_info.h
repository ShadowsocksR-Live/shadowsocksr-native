#if !defined(__dump_info_h__)
#define __dump_info_h__ 1

#include <stddef.h>

void set_app_name(const char *name);
const char *get_app_name(void);
void set_dump_info_callback(void(*callback)(int dump_level, const char *info, void *p), void *p);

void gmt_time_now(char *now_str, size_t size);
void localtime_now(char *now_str, size_t size);

#if defined(__GNUC__)
# define ATTRIBUTE_FORMAT_PRINTF(a, b) __attribute__((format(printf, a, b)))
#else
# define ATTRIBUTE_FORMAT_PRINTF(a, b)
#endif
void pr_info(const char *fmt, ...) ATTRIBUTE_FORMAT_PRINTF(1, 2);
void pr_warn(const char *fmt, ...) ATTRIBUTE_FORMAT_PRINTF(1, 2);
void pr_err(const char *fmt, ...) ATTRIBUTE_FORMAT_PRINTF(1, 2);

#if !defined(NDEBUG)
#define PRINT_INFO(format, ...) \
    do { pr_info("%s : %d\t" format, __FILE__, __LINE__, ## __VA_ARGS__); } while (0)

#define PRINT_WARN(format, ...) \
    do { pr_warn("%s : %d\t" format, __FILE__, __LINE__, ## __VA_ARGS__); } while (0)

#define PRINT_ERR(format, ...) \
    do { pr_err("%s : %d\t" format, __FILE__, __LINE__, ## __VA_ARGS__); } while (0)
#else
#define PRINT_INFO(format, ...)
#define PRINT_ERR(format, ...)
#define PRINT_WARN(format, ...)
#endif

#endif // !defined(__dump_info_h__)
