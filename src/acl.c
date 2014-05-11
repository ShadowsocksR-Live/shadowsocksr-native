#include <ipset/ipset.h>
#include "utils.h"

static struct ip_set set;

static void parse_addr_cidr(const char *str, char **host, int *cidr)
{
    int ret = -1, n = 0;
    char *pch;
    pch = strchr(str, '/');
    while (pch != NULL)
    {
        n++;
        ret = pch - str;
        pch = strchr(pch + 1, '/');
    }
    if (n > 1)
    {
        if (strcmp(str+ret, "]") != 0)
        {
            ret = -1;
        }
    }
    if (ret == -1)
    {
        *host = strdup(str);
        *cidr = -1;
    }
    else
    {
        *host = ss_strndup(str, ret);
        *cidr = atoi(strdup(str + ret + 1));
    }
}

int init_acl(const char *path)
{
    ipset_init_library();
    ipset_init(&set);

    FILE *f = fopen(path, "r");
    if (f == NULL) FATAL("Invalid acl path.");

    char line[256];
    while(!feof(f))
    {
        if (fgets(line, 256, f))
        {
            char *host = NULL;
            int cidr;
            parse_addr_cidr(line, &host, &cidr);
            struct cork_ipv4 addr;
            int err = cork_ipv4_init(&addr, host);
            if (err) continue;
            if (cidr >= 0)
                ipset_ipv4_add_network(&set, &addr, cidr);
            else
                ipset_ipv4_add(&set, &addr);

            if (host != NULL) free(host);
        }
    }

    fclose(f);

    return 0;
}

void free_acl(void)
{
    ipset_done(&set);
}

int acl_is_bypass(const char* host)
{
    struct cork_ipv4 addr;
    int err = cork_ipv4_init(&addr, host);
    if (err) return 0;
    struct cork_ip ip;
    cork_ip_from_ipv4(&ip, &addr);
    return ipset_contains_ip(&set, &ip);
}
