//
// Created by ssrlive on 9/13/17.
//

#include <string.h>
#include <stdlib.h>
#include <netinet/in.h> // for htons
#include <assert.h>
#include "socks5.h"

struct socks5_request *
build_socks5_request(const char *host, uint16_t port, char *buffer, size_t buffer_size, size_t *data_size)
{
    size_t addr_len = strlen(host);
    size_t header_len = addr_len + 3 + sizeof(struct socks5_request);

    if(buffer==NULL || buffer_size<header_len) {
        return NULL;
    }

    struct socks5_request *request = (struct socks5_request *)buffer;
    request->ver = SOCKS5_VERSION;
    request->cmd = SOCKS5_COMMAND_CONNECT;
    request->rsv = 0;
    request->addr_type = SOCKS5_ADDRTYPE_NAME;

    char *addr_n_port = request->addr_n_port;
    *(addr_n_port + 0) = (char) addr_len;
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
    if (buffer == NULL || buffer_size < sizeof(struct method_select_response)) {
        return NULL;
    }

    struct method_select_response *ptr = (struct method_select_response *)buffer;
    ptr->ver = SOCKS5_VERSION;
    ptr->method = (char) method;

    return ptr;
}

struct socks5_response *
build_socks5_response(int rep, int addr_type, struct sockaddr_in *addr, char *buffer, size_t buffer_size, size_t *data_size)
{
    assert(addr_type == SOCKS5_ADDRTYPE_IPV4); // TODO: other types.

    size_t min_size = sizeof(struct socks5_response) + sizeof(addr->sin_addr) + sizeof(addr->sin_port);
    if (buffer==NULL || buffer_size<min_size) {
        return NULL;
    }

    struct socks5_response *response = (struct socks5_response *)buffer;

    response->ver = SOCKS5_VERSION;
    response->rep = (char) rep;
    response->rsv = 0;
    response->addr_type = (char) addr_type;

    char *iter = response->addr_n_port;
    memcpy(iter, &addr->sin_addr, sizeof(addr->sin_addr));
    iter += sizeof(addr->sin_addr);
    memcpy(iter, &addr->sin_port, sizeof(addr->sin_port));
    iter += sizeof(addr->sin_port);

    if (data_size) {
        *data_size = min_size;
    }

    return response;
}
