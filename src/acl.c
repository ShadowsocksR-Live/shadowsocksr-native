#include <ipset/ipset.h>
#include <utils.h>

static struct ip_set set;

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
            char host[256];
            int cidr;
            sscanf(line, "%s/%d", host, &cidr);
            struct cork_ipv4 addr;
            int err = cork_ipv4_init(&addr, host);
            if (err) continue;
            ipset_ipv4_add_network(&set, &addr, cidr);
        }
    }

    fclose(f);

    return 0;
}

void free_acl(void)
{
    ipset_done(&set);
}

int is_bypass(const char* host)
{
    struct cork_ipv4 addr;
    int err = cork_ipv4_init(&addr, host);
    if (err) return 0;
    struct cork_ip ip;
    cork_ip_from_ipv4(&ip, &addr);
    return ipset_contains_ip(&set, &ip);
}
