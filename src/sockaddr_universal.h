#if !defined(__sockaddr_universal_h__)
#define __sockaddr_universal_h__ 1

#if defined(_WIN32)
//#include <winsock2.h>
#include <WS2tcpip.h>
#else
#include <netinet/in.h>
#endif // defined(_WIN32)

#include <stdint.h>
#include <stdbool.h>

union sockaddr_universal {
    struct sockaddr_storage addr_stor;
    struct sockaddr_in6 addr6;
    struct sockaddr_in addr4;
    struct sockaddr addr;
};

enum SOCKS5_ADDRTYPE {
    SOCKS5_ADDRTYPE_INVALID = 0x00,
    SOCKS5_ADDRTYPE_IPV4 = 0x01,
    SOCKS5_ADDRTYPE_DOMAINNAME = 0x03,
    SOCKS5_ADDRTYPE_IPV6 = 0x04,
};

struct socks5_address {
    union {
        struct in_addr ipv4;
        struct in6_addr ipv6;
        char domainname[0x0100];
    } addr;
    uint16_t port;
    enum SOCKS5_ADDRTYPE addr_type;
};

bool socks5_address_parse(const uint8_t *data, size_t len, struct socks5_address *addr);
char * socks5_address_to_string(const struct socks5_address *addr, char *buffer, size_t size);
size_t socks5_address_size(const struct socks5_address *addr);
uint8_t * socks5_address_binary(const struct socks5_address *addr, uint8_t *buffer, size_t size);
bool socks5_address_to_universal(const struct socks5_address *s5addr, union sockaddr_universal *addr);
bool universal_address_to_socks5(const union sockaddr_universal *addr, struct socks5_address *s5addr);

int universal_address_from_string(const char *addr_str, unsigned short port, union sockaddr_universal *addr);
char * universal_address_to_string(const union sockaddr_universal *addr, char *addr_str, size_t size);
uint16_t universal_address_get_port(const union sockaddr_universal *addr);

#endif // !defined(__sockaddr_universal_h__)
