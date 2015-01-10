/*
 * acl.c - Manage the ACL (Access Control List)
 *
 * Copyright (C) 2013 - 2015, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the shadowsocks-libev.
 *
 * shadowsocks-libev is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * shadowsocks-libev is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with shadowsocks-libev; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <ipset/ipset.h>
#include <libcork/ds.h>

#include "utils.h"

static struct ip_set acl_ip_set;
static struct cork_string_array acl_domain_array;

static void parse_addr_cidr(const char *str, char **host, int *cidr)
{
    int ret = -1, n = 0;
    char *pch;

    pch = strchr(str, '/');
    while (pch != NULL) {
        n++;
        ret = pch - str;
        pch = strchr(pch + 1, '/');
    }
    if (n > 1) {
        if (strcmp(str + ret, "]") != 0) {
            ret = -1;
        }
    }
    if (ret == -1) {
        *host = strdup(str);
        *cidr = -1;
    } else {
        *host = ss_strndup(str, ret);
        *cidr = atoi(strdup(str + ret + 1));
    }
}

int init_acl(const char *path)
{
    // initialize ipset
    ipset_init_library();
    ipset_init(&acl_ip_set);

    // initialize array
    cork_string_array_init(&acl_domain_array);

    FILE *f = fopen(path, "r");
    if (f == NULL) {
        LOGE("Invalid acl path.");
        return -1;
    }

    char line[256];
    while (!feof(f)) {
        if (fgets(line, 256, f)) {
            // Trim the newline
            int len = strlen(line);
            if (len > 0 && line[len - 1] == '\n') {
                line[len - 1] = '\0';
            }

            char *host = NULL;
            int cidr;
            parse_addr_cidr(line, &host, &cidr);

            if (cidr == -1) {
                cork_string_array_append(&acl_domain_array, host);
            } else {
                struct cork_ipv4 addr;
                int err = cork_ipv4_init(&addr, host);
                if (!err) {
                    if (cidr >= 0) {
                        ipset_ipv4_add_network(&acl_ip_set, &addr, cidr);
                    } else {
                        ipset_ipv4_add(&acl_ip_set, &addr);
                    }
                }
            }

            if (host != NULL) {
                free(host);
            }
        }
    }

    fclose(f);

    return 0;
}

void free_acl(void)
{
    ipset_done(&acl_ip_set);
}

int acl_contains_domain(const char * domain)
{
    const char **list = acl_domain_array.items;
    const int size = acl_domain_array.size;
    const int domain_len = strlen(domain);
    int i, offset;

    for (i = 0; i < size; i++) {
        const char *acl_domain = list[i];
        const int acl_domain_len = strlen(acl_domain);
        if (acl_domain_len > domain_len) {
            continue;
        }
        int match = true;
        for (offset = 1; offset <= acl_domain_len; offset++) {
            if (domain[domain_len - offset] !=
                acl_domain[acl_domain_len - offset]) {
                match = false;
                break;
            }
        }
        if (match) {
            return 1;
        }
    }


    return 0;
}

int acl_contains_ip(const char * host)
{
    struct cork_ipv4 addr;
    int err = cork_ipv4_init(&addr, host);
    if (err) {
        return 0;
    }

    struct cork_ip ip;
    cork_ip_from_ipv4(&ip, &addr);
    return ipset_contains_ip(&acl_ip_set, &ip);
}
