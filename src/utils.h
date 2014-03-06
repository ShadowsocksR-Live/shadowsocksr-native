#ifndef _UTILS_H
#define _UTILS_H

#include <stdio.h>
#include <time.h>

#define PORTSTRLEN 16
#define SS_ADDRSTRLEN (INET6_ADDRSTRLEN + PORTSTRLEN + 1)

#ifdef ANDROID

#include <android/log.h>

#define USE_SYSLOG(ident)
#define LOGD(...) ((void)__android_log_print(ANDROID_LOG_DEBUG, "shadowsocks", __VA_ARGS__))
#define LOGE(...) ((void)__android_log_print(ANDROID_LOG_ERROR, "shadowsocks", __VA_ARGS__))

#else

#define STR(x) #x
#define TOSTR(x) STR(x)

#ifdef _WIN32

#define TIME_FORMAT "%Y-%m-%d %H:%M:%S"

#define USE_SYSLOG(ident)

#define LOGD(format, ...) do {\
    time_t now = time(NULL);\
    char timestr[20];\
    strftime(timestr, 20, TIME_FORMAT, localtime(&now));\
    fprintf(stderr, " %s INFO: " format "\n", timestr, ##__VA_ARGS__);}\
while(0)

#define LOGE(format, ...) do {\
    time_t now = time(NULL);\
    char timestr[20];\
    strftime(timestr, 20, TIME_FORMAT, localtime(&now));\
    fprintf(stderr, " %s ERROR: " format "\n", timestr, ##__VA_ARGS__);}\
while(0)

#else

#include <syslog.h>

#define HAS_SYSLOG
extern int use_syslog;

#define TIME_FORMAT "%F %T"

#define USE_SYSLOG(ident) do {\
    use_syslog = 1;\
    openlog((ident), LOG_CONS | LOG_PID, 0);}\
while(0)

#define LOGD(format, ...) do {\
    if (use_syslog) {\
        syslog(LOG_INFO, format, ##__VA_ARGS__);\
    } else {\
        time_t now = time(NULL);\
        char timestr[20];\
        strftime(timestr, 20, TIME_FORMAT, localtime(&now));\
        fprintf(stderr, "\e[01;32m %s INFO: \e[0m" format "\n", timestr, ##__VA_ARGS__);\
    }}\
while(0)

#define LOGE(format, ...) do {\
    if (use_syslog) {\
        syslog(LOG_ERR, format, ##__VA_ARGS__);\
    } else {\
        time_t now = time(NULL);\
        char timestr[20];\
        strftime(timestr, 20, TIME_FORMAT, localtime(&now));\
        fprintf(stderr, "\e[01;35m %s ERROR: \e[0m" format "\n", timestr, ##__VA_ARGS__);\
    }}\
while(0)

#endif
/* _WIN32 */

#endif

#ifdef __MINGW32__

#ifdef ERROR
#undef ERROR
#endif
#define ERROR(s) ss_error(s)

char *ss_itoa(int i);

#else

void ERROR(const char *s);
char *itoa(int i);

#endif

int run_as(const char *user);
void FATAL(const char *msg);
void usage(void);
void demonize(const char* path);
char *ss_strndup(const char *s, size_t n);

#endif // _UTILS_H
