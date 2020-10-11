#include <stdio.h>
#include <assert.h>
#include <memory.h>
#include <uv.h>

#if !defined(_WIN32)
#include <netdb.h>
#endif // !defined(_WIN32)

#include "sockaddr_universal.h"

bool socks5_address_parse(const uint8_t *data, size_t len, struct socks5_address *addr) {
    size_t offset     = 0;
    size_t addr_size = 0;
    uint8_t addr_type = 0;

    if (data==NULL || len==0 || addr==NULL) {
        return false;
    }

    addr_type = data[offset++];

    switch ((enum SOCKS5_ADDRTYPE)addr_type) {
        case SOCKS5_ADDRTYPE_IPV4:
            addr_size = sizeof(struct in_addr);
            if (len < sizeof(uint8_t) + addr_size + sizeof(uint16_t)) {
                return false;
            }
            addr->addr_type = SOCKS5_ADDRTYPE_IPV4;
            memcpy(&addr->addr.ipv4, data + offset, addr_size);
            break;
        case SOCKS5_ADDRTYPE_DOMAINNAME:
            addr_size = (size_t)data[offset++];
            if (len < sizeof(uint8_t) + sizeof(uint8_t) + addr_size + sizeof(uint16_t)) {
                return false;
            }
            addr->addr_type = SOCKS5_ADDRTYPE_DOMAINNAME;
            memset(addr->addr.domainname, 0, sizeof(addr->addr.domainname));
            memcpy(addr->addr.domainname, data+offset, addr_size);
            break;
        case SOCKS5_ADDRTYPE_IPV6:
            addr_size = sizeof(struct in6_addr);
            if (len < sizeof(uint8_t) + addr_size + sizeof(uint16_t)) {
                return false;
            }
            addr->addr_type = SOCKS5_ADDRTYPE_IPV6;
            memcpy(&addr->addr.ipv6, data + offset, addr_size);
            break;
        default:
            addr->addr_type = SOCKS5_ADDRTYPE_INVALID;
            return false;
            break;
    }
    offset += addr_size;

    addr->port = ntohs( *((uint16_t *)(data+offset)) );

    offset += sizeof(uint16_t);

    return true;
}

char* socks5_address_to_string(const struct socks5_address* addr, void* (*allocator)(size_t), bool with_port) {
    const char *addr_ptr = NULL;
    char *buffer = NULL;
    static const size_t size = 0x100 + 7;

    if (addr==NULL || allocator==NULL) {
        return NULL;
    }

    if (addr->addr_type == SOCKS5_ADDRTYPE_IPV4 ||
        addr->addr_type == SOCKS5_ADDRTYPE_DOMAINNAME ||
        addr->addr_type == SOCKS5_ADDRTYPE_IPV6 )
    {
        buffer = (char *) allocator(size);
    }
    if (buffer == NULL) {
        return NULL;
    }
    memset(buffer, 0, size);

    switch (addr->addr_type) {
    case SOCKS5_ADDRTYPE_IPV4:
        assert(size >= INET_ADDRSTRLEN);
        uv_inet_ntop(AF_INET, &addr->addr.ipv4, buffer, size);
        break;
    case SOCKS5_ADDRTYPE_IPV6: {
        char tmp[INET6_ADDRSTRLEN + 1] = { 0 };
        uv_inet_ntop(AF_INET6, &addr->addr.ipv6, tmp, sizeof(tmp));
        assert(size >= INET6_ADDRSTRLEN + 3);
        sprintf(buffer, with_port ? "[%s]" : "%s", tmp);
        break;
    }
    case SOCKS5_ADDRTYPE_DOMAINNAME:
        addr_ptr = addr->addr.domainname;
        assert(size >= (strlen(addr_ptr) + 1));
        strcpy(buffer, addr_ptr);
        break;
    default:
        assert(0);
        return NULL;
        break;
    }
    if (with_port) {
        sprintf(buffer + strlen(buffer), ":%d", (int)addr->port);
    }
    return buffer;
}

size_t socks5_address_size(const struct socks5_address *addr) {
    size_t size = 0;
    do {
        if (addr == NULL) {
            break;
        }
        switch (addr->addr_type) {
            case SOCKS5_ADDRTYPE_IPV4:
                size = sizeof(uint8_t) + sizeof(struct in_addr) + sizeof(uint16_t);
                break;
            case SOCKS5_ADDRTYPE_DOMAINNAME:
                size = sizeof(uint8_t) + sizeof(uint8_t) + strlen(addr->addr.domainname) + sizeof(uint16_t);
                break;
            case SOCKS5_ADDRTYPE_IPV6:
                size = sizeof(uint8_t) + sizeof(struct in6_addr) + sizeof(uint16_t);
                break;
            default:
                break;
        }
    } while (0);
    return size;
}

uint8_t* socks5_address_binary(const struct socks5_address* addr, void* (*allocator)(size_t), size_t* size) {
    uint8_t* buffer = NULL;
    size_t offset     = 0;
    size_t addr_size = 0;
    if (addr==NULL || allocator==NULL) {
        return NULL;
    }
    addr_size = socks5_address_size(addr);
    if (size) {
        *size = addr_size;
    }
    buffer = allocator(addr_size + 1);
    if (buffer == NULL) {
        return NULL;
    }
    memset(buffer, 0, addr_size + 1);

    buffer[offset++] = (uint8_t)addr->addr_type;

    switch (addr->addr_type) {
        case SOCKS5_ADDRTYPE_IPV4:
            memcpy(buffer+offset, &addr->addr.ipv4, sizeof(struct in_addr));
            offset += sizeof(struct in_addr);
            break;
        case SOCKS5_ADDRTYPE_DOMAINNAME:
            addr_size = strlen(addr->addr.domainname);
            buffer[offset++] = (uint8_t)addr_size;
            memcpy(buffer+offset, addr->addr.domainname, addr_size);
            offset += addr_size;
            break;
        case SOCKS5_ADDRTYPE_IPV6:
            memcpy(buffer+offset, &addr->addr.ipv6, sizeof(struct in6_addr));
            offset += sizeof(struct in6_addr);
            break;
        default:
            return NULL;
    }
    *((uint16_t *)(buffer + offset)) = htons(addr->port);
    return buffer;
}

bool socks5_address_to_universal(const struct socks5_address *s5addr, bool use_dns, union sockaddr_universal *addr) {
    bool result = false;
    do {
        if (s5addr==NULL || addr==NULL) {
            break;
        }
        switch (s5addr->addr_type) {
        case SOCKS5_ADDRTYPE_IPV4:
            result = true;
            addr->addr4.sin_family = AF_INET;
            addr->addr4.sin_port = htons(s5addr->port);
            addr->addr4.sin_addr = s5addr->addr.ipv4;
            break;
        case SOCKS5_ADDRTYPE_IPV6:
            result = true;
            addr->addr6.sin6_family = AF_INET6;
            addr->addr6.sin6_port = htons(s5addr->port);
            addr->addr6.sin6_addr = s5addr->addr.ipv6;
            break;
        case SOCKS5_ADDRTYPE_DOMAINNAME:
            if (use_dns == false) {
                break;
            }
            if (universal_address_from_string(s5addr->addr.domainname, s5addr->port, true, addr) == 0) {
                result = true;
            }
            break;
        default:
            break;
        }
    } while (0);
    return result;
}

bool universal_address_to_socks5(const union sockaddr_universal *addr, struct socks5_address *s5addr) {
    bool result = false;
    do {
        if (addr==NULL || s5addr==NULL) {
            break;
        }
        switch (addr->addr4.sin_family) {
        case AF_INET:
            result = true;
            s5addr->addr_type = SOCKS5_ADDRTYPE_IPV4;
            s5addr->port = ntohs(addr->addr4.sin_port);
            s5addr->addr.ipv4 = addr->addr4.sin_addr;
            break;
        case AF_INET6:
            result = true;
            s5addr->addr_type = SOCKS5_ADDRTYPE_IPV6;
            s5addr->port = ntohs(addr->addr6.sin6_port);
            s5addr->addr.ipv6 = addr->addr6.sin6_addr;
            break;
        default:
            break;
        }
    } while (0);
    return result;
}

int universal_address_from_string_no_dns(const char* addr_str, uint16_t port, union sockaddr_universal* addr) {
    int result = -1;
    if ((result = uv_inet_pton(AF_INET, addr_str, &addr->addr4.sin_addr)) == 0) {
        addr->addr4.sin_family = AF_INET;
        addr->addr4.sin_port = htons((uint16_t)port);
    } else if ((result = uv_inet_pton(AF_INET6, addr_str, &addr->addr6.sin6_addr)) == 0) {
        addr->addr6.sin6_family = AF_INET6;
        addr->addr6.sin6_port = htons((uint16_t)port);
    }
    return result;
}

int universal_address_from_string(const char *addr_str, uint16_t port, bool tcp, union sockaddr_universal *addr)
{
    struct addrinfo hints = { 0 }, *ai = NULL;
    int status;
    char port_buffer[6] = { 0 };
    int result = -1;

    if (addr_str == NULL || port == 0 || addr == NULL) {
        return result;
    }

    if ((result = universal_address_from_string_no_dns(addr_str, port, addr)) == 0) {
        return result;
    }

    sprintf(port_buffer, "%hu", port);

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = tcp ? SOCK_STREAM : SOCK_DGRAM;
    // hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV | AI_PASSIVE;
    hints.ai_protocol = tcp ? IPPROTO_TCP : IPPROTO_UDP;

    if ((status = getaddrinfo(addr_str, port_buffer, &hints, &ai)) != 0) {
        return result;
    }

    {
        bool found = false;
        struct addrinfo* iter;
        for (iter = ai; iter != NULL; iter = iter->ai_next) {
            if (iter->ai_family == AF_INET) {
                addr->addr4 = *(const struct sockaddr_in*)iter->ai_addr;
                found = true;
                break;
            }
        }
        if (found == false) {
            for (iter = ai; iter != NULL; iter = iter->ai_next) {
                if (iter->ai_family == AF_INET6) {
                    addr->addr6 = *(const struct sockaddr_in6*)iter->ai_addr;
                    found = true;
                    break;
                }
            }
        }
        assert(found);
        addr->addr4.sin_port = htons(port);

        result = found ? 0 : -1;
    }

    freeaddrinfo(ai);
    return result;
}

char* universal_address_to_string(const union sockaddr_universal* addr, void* (*allocator)(size_t), bool with_port)
{
    char *addr_str;
    if (addr==NULL || allocator==NULL) {
        return NULL;
    }
    addr_str = (char *) allocator(INET6_ADDRSTRLEN + 7);
    if (addr_str == NULL) {
        return NULL;
    }
    memset(addr_str, 0, INET6_ADDRSTRLEN + 7);

    switch (addr->addr4.sin_family) {
    case AF_INET:
        uv_inet_ntop(AF_INET, &addr->addr4.sin_addr, addr_str, INET6_ADDRSTRLEN);
        break;
    case AF_INET6: {
        char v6addr[INET6_ADDRSTRLEN + 1] = { 0 };
        uv_inet_ntop(AF_INET6, &addr->addr6.sin6_addr, v6addr, sizeof(v6addr));
        sprintf(addr_str, with_port ? "[%s]" : "%s", v6addr);
        break;
    }
    default:
        break;
    }
    if (with_port && strlen(addr_str)) {
        sprintf(addr_str + strlen(addr_str), ":%d", (int)ntohs(addr->addr4.sin_port));
    }
    return addr_str;
}

uint16_t universal_address_get_port(const union sockaddr_universal *addr) {
    if (addr) {
        return ntohs(addr->addr4.sin_port);
    }
    return 0;
}

bool ip_mapping_v4_to_v6(const struct sockaddr_in* addr4, struct sockaddr_in6* addr6)
{
    volatile struct sockaddr_in addr4_cache;
    if (addr4 == NULL || addr6 == NULL || addr4->sin_family != AF_INET) {
        return false;
    }
    memcpy((void*)&addr4_cache, addr4, sizeof(addr4_cache));

    memset(addr6, 0, sizeof(*addr6));

    addr6->sin6_family = AF_INET6;
    addr6->sin6_port = addr4_cache.sin_port;

    addr6->sin6_addr.s6_addr[10] = 0xff;
    addr6->sin6_addr.s6_addr[11] = 0xff;

    *((uint32_t*)&(addr6->sin6_addr.s6_addr[12])) = addr4_cache.sin_addr.s_addr;

    return true;
}
