#ifndef _JCONF_H
#define _JCONF_H

#define MAX_REMOTE_NUM 10
#define MAX_CONF_SIZE 16 * 1024
#define DNS_THREAD_NUM 4
#define MAX_UDP_CONN_NUM 4096

typedef struct
{
    char *host;
    char *port;
} ss_addr_t;

typedef struct
{
    int  remote_num;
    ss_addr_t remote_addr[MAX_REMOTE_NUM];
    char *remote_port;
    char *local_addr;
    char *local_port;
    char *password;
    char *method;
    char *timeout;
    int  fast_open;
} jconf_t;

jconf_t *read_jconf(const char* file);
void parse_addr(const char *str, ss_addr_t *addr);
void free_addr(ss_addr_t *addr);

#endif // _JCONF_H
