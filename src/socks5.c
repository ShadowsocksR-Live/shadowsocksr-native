//
// Created by ssrlive on 9/13/17.
//

#include <string.h>
#include <stdlib.h>
#if defined(_WIN32)
#include <winsock2.h> // for htons
#else
#include <netinet/in.h> // for htons
#endif // defined(_WIN32)

#include <assert.h>
#include "socks5.h"

struct socks5_request *
build_socks5_request(const char *host, uint16_t port, uint8_t *buffer, size_t buffer_size, size_t *data_size)
{
    struct socks5_request *request;
    uint8_t *addr_n_port;
    size_t addr_len = strlen(host);
    size_t header_len = addr_len + 3 + (sizeof(struct socks5_request) - 1);

    if(buffer==NULL || buffer_size<header_len) {
        return NULL;
    }

    request = (struct socks5_request *)buffer;
    request->ver = SOCKS5_VERSION;
    request->cmd = SOCKS5_COMMAND_CONNECT;
    request->rsv = 0;
    request->addr_type = SOCKS5_ADDRTYPE__NAME;

    addr_n_port = request->addr_n_port;
    *(addr_n_port + 0) = (uint8_t) addr_len;
    memcpy(addr_n_port + 1, host, (size_t) addr_len);
    *((uint16_t *)(addr_n_port + 1 + addr_len)) = htons((uint16_t)port);

    if (data_size) {
        *data_size = header_len;
    }

    return request;
}

struct method_select_response *
build_socks5_method_select_response(int method, char *buffer, size_t buffer_size)
{
    struct method_select_response *ptr;

    if (buffer == NULL || buffer_size < sizeof(struct method_select_response)) {
        return NULL;
    }

    ptr = (struct method_select_response *)buffer;
    ptr->ver = SOCKS5_VERSION;
    ptr->method = (char) method;

    return ptr;
}

struct socks5_response *
build_socks5_response(int rep, int addr_type, struct sockaddr_in *addr, uint8_t *buffer, size_t buffer_size, size_t *data_size)
{
    size_t min_size;
    struct socks5_response *response;
    uint8_t *iter;

    assert(addr_type == SOCKS5_ADDRTYPE__IPV4); // TODO: other types.

    min_size = (sizeof(struct socks5_response) - 1) + sizeof(addr->sin_addr) + sizeof(addr->sin_port);
    if (buffer==NULL || buffer_size<min_size) {
        return NULL;
    }

    response = (struct socks5_response *)buffer;

    response->ver = SOCKS5_VERSION;
    response->rep = (uint8_t) rep;
    response->rsv = 0;
    response->addr_type = (uint8_t) addr_type;

    iter = response->addr_n_port;
    memcpy(iter, &addr->sin_addr, sizeof(addr->sin_addr));
    iter += sizeof(addr->sin_addr);
    memcpy(iter, &addr->sin_port, sizeof(addr->sin_port));
    iter += sizeof(addr->sin_port);

    if (data_size) {
        *data_size = min_size;
    }

    return response;
}
