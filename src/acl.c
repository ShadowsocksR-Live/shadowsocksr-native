#include <ipset/ipset.h>

struct ip_set *init_acl(void)
{
    struct ip_set *ipset = ipset_new();
    return ipset;
}
