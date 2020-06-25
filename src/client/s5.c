/* Copyright ssrlive, Inc. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "s5.h"
#include <errno.h>
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>  /* abort() */
#include <string.h>  /* memset() */
#if defined(_MSC_VER)
#include <winsock2.h> /* ntohs */
#else
#include <netinet/in.h>  /* ntohs */
#endif // defined(_MSC_VER)

enum s5_stage {
    s5_stage_version,
    s5_stage_nmethods,
    s5_stage_methods,
    s5_stage_auth_pw_version,
    s5_stage_auth_pw_userlen,
    s5_stage_auth_pw_username,
    s5_stage_auth_pw_passlen,
    s5_stage_auth_pw_password,
    s5_stage_req_version,
    s5_stage_req_cmd,
    s5_stage_req_reserved,
    s5_stage_req_atyp,
    s5_stage_req_atyp_host,
    s5_stage_req_daddr,
    s5_stage_req_dport0,
    s5_stage_req_dport1,
    s5_stage_dead,
};

struct s5_ctx {
    uint32_t arg0;  /* Scratch space for the state machine. */
    uint32_t arg1;  /* Scratch space for the state machine. */
    enum s5_stage stage;
    enum s5_auth_method methods;
    enum s5_cmd cmd;
    enum s5_atyp atyp;
    uint8_t userlen;
    uint8_t passlen;
    uint16_t dport;
    uint8_t username[257];
    uint8_t password[257];
    uint8_t daddr[257];
};

//
// https://zh.wikipedia.org/zh-hans/SOCKS#SOCKS5
//

struct s5_ctx * s5_ctx_create(void) {
    struct s5_ctx *cx = (struct s5_ctx *)calloc(1, sizeof(struct s5_ctx));
    cx->stage = s5_stage_version;
    return cx;
}

void s5_ctx_release(struct s5_ctx *cx) {
    free(cx);
}

enum s5_result s5_parse(struct s5_ctx *cx, uint8_t **data, size_t *size) {
    enum s5_result result;
    uint8_t *p;
    uint8_t c;
    size_t i;
    size_t n;
    uint8_t port[2 + 1] = { 0 };

    p = *data;
    n = *size;
    i = 0;

    while (i < n) {
        c = p[i];
        i += 1;
        switch (cx->stage) {
        case s5_stage_version:
            if (c != 5) {
                result = s5_result_bad_version;
                goto out;
            }
            cx->stage = s5_stage_nmethods;
            break;

        case s5_stage_nmethods:
            cx->arg0 = 0;
            cx->arg1 = (uint32_t)c;  /* Number of bytes to read. */
            cx->stage = s5_stage_methods;
            break;

        case s5_stage_methods:
            if (cx->arg0 < cx->arg1) {
                switch (c) {
                case 0:
                    cx->methods |= s5_auth_none;
                    break;
                case 1:
                    cx->methods |= s5_auth_gssapi;
                    break;
                case 2:
                    cx->methods |= s5_auth_passwd;
                    break;
                default:
                    /* Ignore everything we don't understand. */
                    break;
                }
                cx->arg0 += 1;
            }
            if (cx->arg0 == cx->arg1) {
                result = s5_result_auth_select;
                goto out;
            }
            break;

        case s5_stage_auth_pw_version:
            if (c != 1) {
                result = s5_result_bad_version;
                goto out;
            }
            cx->stage = s5_stage_auth_pw_userlen;
            break;

        case s5_stage_auth_pw_userlen:
            cx->arg0 = 0;
            cx->userlen = c;
            cx->stage = s5_stage_auth_pw_username;
            break;

        case s5_stage_auth_pw_username:
            if (cx->arg0 < cx->userlen) {
                cx->username[cx->arg0] = c;
                cx->arg0 += 1;
            }
            if (cx->arg0 == cx->userlen) {
                cx->username[cx->userlen] = '\0';
                cx->stage = s5_stage_auth_pw_passlen;
            }
            break;

        case s5_stage_auth_pw_passlen:
            cx->arg0 = 0;
            cx->passlen = c;
            cx->stage = s5_stage_auth_pw_password;
            break;

        case s5_stage_auth_pw_password:
            if (cx->arg0 < cx->passlen) {
                cx->password[cx->arg0] = c;
                cx->arg0 += 1;
            }
            if (cx->arg0 == cx->passlen) {
                cx->password[cx->passlen] = '\0';
                cx->stage = s5_stage_req_version;
                result = s5_result_auth_verify;
                goto out;
            }
            break;

        case s5_stage_req_version:
            if (c != 5) {
                result = s5_result_bad_version;
                goto out;
            }
            cx->stage = s5_stage_req_cmd;
            break;

        case s5_stage_req_cmd:
            switch (c) {
            case 1:  /* TCP connect */
                cx->cmd = s5_cmd_tcp_connect;
                break;
            case 2: /* TCP bind request*/
                cx->cmd = s5_cmd_tcp_bind;
                break;
            case 3:  /* UDP associate */
                cx->cmd = s5_cmd_udp_assoc;
                break;
            default:
                result = s5_result_bad_cmd;
                goto out;
            }
            cx->stage = s5_stage_req_reserved;
            break;

        case s5_stage_req_reserved:
            cx->stage = s5_stage_req_atyp;
            break;

        case s5_stage_req_atyp:
            cx->arg0 = 0;
            switch (c) {
            case 1:  /* IPv4, four octets. */
                cx->stage = s5_stage_req_daddr;
                cx->atyp = s5_atyp_ipv4;
                cx->arg1 = 4;
                break;
            case 3:  /* Hostname.  First byte is length. */
                cx->stage = s5_stage_req_atyp_host;
                cx->atyp = s5_atyp_host;
                cx->arg1 = 0;
                break;
            case 4:  /* IPv6, sixteen octets. */
                cx->stage = s5_stage_req_daddr;
                cx->atyp = s5_atyp_ipv6;
                cx->arg1 = 16;
                break;
            default:
                result = s5_result_bad_atyp;
                goto out;
            }
            break;

        case s5_stage_req_atyp_host:
            cx->arg1 = (uint32_t)c;
            cx->stage = s5_stage_req_daddr;
            break;

        case s5_stage_req_daddr:
            if (cx->arg0 < cx->arg1) {
                cx->daddr[cx->arg0] = c;
                cx->arg0 += 1;
            }
            if (cx->arg0 == cx->arg1) {
                cx->daddr[cx->arg1] = '\0';
                cx->stage = s5_stage_req_dport0;
            }
            break;

        case s5_stage_req_dport0:
            port[0] = c;
            cx->stage = s5_stage_req_dport1;
            break;

        case s5_stage_req_dport1:
            port[1] = c;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-aliasing"
            cx->dport = (uint16_t) ntohs(*(uint16_t *)port);
#pragma GCC diagnostic pop
            cx->stage = s5_stage_dead;
            result = s5_result_exec_cmd;
            goto out;

        case s5_stage_dead:
            break;

        default:
            abort();
        }
    }
    result = s5_result_need_more;

out:
    *data = p + i;
    *size = n - i;
    return result;
}

enum s5_atyp s5_get_address_type(const struct s5_ctx *cx) {
    return cx->atyp;
}

const char * s5_get_address(const struct s5_ctx *cx) {
    return (const char *) cx->daddr;
}

uint16_t s5_get_dport(const struct s5_ctx *cx) {
    return cx->dport;
}

enum s5_auth_method s5_get_auth_methods(const struct s5_ctx *cx) {
    return cx->methods;
}

enum s5_cmd s5_get_cmd(const struct s5_ctx *cx) {
    return cx->cmd;
}

int s5_select_auth(struct s5_ctx *cx, enum s5_auth_method method) {
    int err;

    err = 0;
    switch (method) {
    case s5_auth_none:
        cx->stage = s5_stage_req_version;
        break;
    case s5_auth_passwd:
        cx->stage = s5_stage_auth_pw_version;
        break;
    default:
        err = -EINVAL;
    }

    return err;
}

const char * str_s5_result(enum s5_result result) {
#define S5_RESULT_GEN(_, name, errmsg) case name: return errmsg;
    switch (result) {
        S5_RESULT_MAP(S5_RESULT_GEN)
    default:;  /* Silence s5_result_max -Wswitch warning. */
    }
#undef S5_RESULT_GEN
    return "Unknown error.";
}

#include "sockaddr_universal.h"
uint8_t * s5_build_udp_assoc_package(bool allow, const char *addr_str, int port, void*(*allocator)(size_t size), size_t *size) {
    uint8_t *buf;
    size_t buf_len = 0;
    union sockaddr_universal addr = { {0} };
    bool ipV6;
    size_t in6_addr_w;
    size_t in4_addr_w;
    size_t port_w;

    if (addr_str == NULL || allocator == NULL) {
        return NULL;
    }

    buf = (uint8_t *) allocator(256);
    memset(buf, 0, 256);

    if (universal_address_from_string(addr_str, port, true, &addr) != 0) {
        return NULL;
    }
    ipV6 = (addr.addr.sa_family == AF_INET6);

    buf[0] = 5;  // Version.
    if (allow) {
        buf[1] = 0;  // Success.
    } else {
        buf[1] = 0x07;  // Command not supported.
    }
    buf[2] = 0;  // Reserved.
    buf[3] = (uint8_t)(ipV6 ? 0x04 : 0x01);  // atyp

    in6_addr_w = sizeof(addr.addr6.sin6_addr);
    in4_addr_w = sizeof(addr.addr4.sin_addr);
    port_w = sizeof(addr.addr4.sin_port);

    if (ipV6) {
        buf_len = 4 + in6_addr_w + port_w;
        memcpy(buf + 4, &addr.addr6.sin6_addr, in6_addr_w);
        memcpy(buf + 4 + in6_addr_w, &addr.addr6.sin6_port, port_w);
    } else {
        buf_len = 4 + in4_addr_w + port_w;
        memcpy(buf + 4, &addr.addr4.sin_addr, in4_addr_w);
        memcpy(buf + 4 + in4_addr_w, &addr.addr4.sin_port, port_w);
    }
    if (size) {
        *size = buf_len;
    }
    return buf;
}

uint8_t * s5_address_package_create(const struct s5_ctx *parser, void*(*allocator)(size_t size), size_t *size) {
    uint8_t *buffer, *iter;
    uint8_t len;

    assert(parser);
    assert(allocator);
    if (parser==NULL || allocator==NULL) {
        return NULL;
    }

    buffer = (uint8_t *) allocator(0x100);
    memset(buffer, 0, 0x100);
    iter = buffer;

    iter[0] = (uint8_t)parser->atyp;
    iter++;

    switch (parser->atyp) {
    case s5_atyp_ipv4:  // IPv4
        memcpy(iter, parser->daddr, sizeof(struct in_addr));
        iter += sizeof(struct in_addr);
        break;
    case s5_atyp_ipv6:  // IPv6
        memcpy(iter, parser->daddr, sizeof(struct in6_addr));
        iter += sizeof(struct in6_addr);
        break;
    case s5_atyp_host:
        len = (uint8_t)strlen((char *)parser->daddr);
        iter[0] = len;
        iter++;
        memcpy(iter, parser->daddr, len);
        iter += len;
        break;
    default:
        assert(0);
        break;
    }
    *((unsigned short *)iter) = htons(parser->dport);
    iter += sizeof(unsigned short);

    if (size) {
        *size = iter - buffer;
    }

    return buffer;
}

uint8_t * s5_connect_response_package(const struct s5_ctx *parser, void*(*allocator)(size_t size), size_t *size) {
    uint8_t *buf, *addr_pkg;
    size_t addr_size = 0;
    assert(parser);
    assert(allocator);
    addr_pkg = s5_address_package_create(parser, &malloc, &addr_size);
    buf = (uint8_t *)allocator(3 + addr_size + 1);
    memset(buf, 0, 3 + addr_size + 1);
    buf[0] = 5;  // Version.
    buf[1] = 0;  // Success.
    buf[2] = 0;  // Reserved.
#if 0
    memcpy(buf + 3, addr_pkg, addr_size);
#else
    assert(addr_size >= 7);
    buf[3] = 1;  addr_size = 7; /* to fit a Privoxy bug. sadly */
#endif
    free(addr_pkg);
    if (size) {
        *size = addr_size + 3;
    }
    return buf;
}

// =============================================================================
// *
// * SOCKS5 UDP Request / Response
// * +----+------+------+----------+----------+----------+
// * |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
// * +----+------+------+----------+----------+----------+
// * | 2  |  1   |  1   | Variable |    2     | Variable |
// * +----+------+------+----------+----------+----------+
// *
const uint8_t * s5_parse_upd_package(const uint8_t *pkg, size_t len, struct socks5_address *dst_addr, size_t *frag_number, size_t *payload_len) {
    const uint8_t *result = NULL;
    do {
        const uint8_t *rsv, *frag, *address;
        struct socks5_address dummy_addr = { {{0}}, 0, SOCKS5_ADDRTYPE_INVALID };
        size_t offset;
        if (pkg==NULL || len<10) {
            break;
        }
        if (dst_addr == NULL) {
            dst_addr = &dummy_addr;
        }
        rsv = pkg;
        if ( *((uint16_t *)rsv) != 0) {
            break;
        }
        frag = pkg + sizeof(uint16_t);
        if (frag_number) {
            *frag_number = (size_t)(*frag);
        }
        offset = sizeof(uint16_t) + sizeof(uint8_t);
        address = pkg + offset;
        if (socks5_address_parse(address, len - offset, dst_addr) == false) {
            break;
        }

        offset += socks5_address_size(dst_addr);

        result = pkg + offset;
        if (payload_len) {
            *payload_len = len - offset;
        }
    } while (false);
    return result;
}

uint8_t * s5_build_udp_datagram(struct socks5_address *dst_addr, const uint8_t *payload, size_t payload_len, void*(*allocator)(size_t size), size_t *size) {
    uint8_t *result = NULL;
    do {
        size_t total, addr_len;
        uint8_t* addr = NULL;
        if (dst_addr==NULL || allocator==NULL) {
            break;
        }

        addr_len = socks5_address_size(dst_addr);

        total = 2 + 1 + addr_len + payload_len;

        result = (uint8_t *) allocator(total + 1);
        if (result == NULL) {
            break;
        }
        memset(result, 0, total + 1);

        addr = socks5_address_binary(dst_addr, &malloc, NULL);
        memmove(result + 2 + 1, addr, addr_len);
        free(addr);

        memcpy(result + 2 + 1 + addr_len, payload, payload_len);

        if (size) {
            *size = total;
        }
    } while (false);
    return result;
}
