#ifndef _UTILS_H
#define _UTILS_H

#define LOGD(...) ((void)fprintf(stdout, __VA_ARGS__))
#define LOGE(...) ((void)fprintf(stderr, __VA_ARGS__))

void FATAL(const char *msg);
void usage(void);
void demonize(const char* path);
char *itoa(int i);

#endif // _UTILS_H
