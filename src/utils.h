#ifndef _UTILS_H
#define _UTILS_H

#define STR(x) #x
#define TOSTR(x) STR(x)
#define TIME_FORMAT "%F %T"

#define LOGD(format, ...) do {\
    time_t now = time(NULL);\
    char timestr[20];\
    strftime(timestr, 20, TIME_FORMAT, localtime(&now));\
    fprintf(stderr, "\e[01;32m %s INFO: \e[0m" format "\n", timestr, ##__VA_ARGS__);}\
while(0)

#define LOGE(format, ...) do {\
    time_t now = time(NULL);\
    char timestr[20];\
    strftime(timestr, 20, TIME_FORMAT, localtime(&now));\
    fprintf(stderr, "\e[01;35m %s ERROR: \e[0m" format " on File: %s Line: %s\n", timestr, ##__VA_ARGS__, __FILE__, TOSTR(__LINE__));}\
while(0)

void FATAL(const char *msg);
void ERROR(const char *s);
void usage(void);
void demonize(const char* path);
char *itoa(int i);

#endif // _UTILS_H
