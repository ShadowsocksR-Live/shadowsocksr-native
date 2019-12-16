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
#include <stdint.h>
#include <stdlib.h>  /* abort() */
#include <string.h>  /* memset() */
#if defined(_MSC_VER)
#include <winsock2.h> /* ntohs */
#else
#include <netinet/in.h>  /* ntohs */
#endif // defined(_MSC_VER)


//
// https://zh.wikipedia.org/zh-hans/SOCKS#SOCKS5
//

void s5_init(s5_ctx *cx) {
    memset(cx, 0, sizeof(*cx));
    cx->stage = s5_stage_version;
}

enum s5_result s5_parse(s5_ctx *cx, uint8_t **data, size_t *size) {
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
            cx->dport = (uint16_t) ntohs(*(uint16_t *)port);
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

enum s5_auth_method s5_auth_methods(const s5_ctx *cx) {
    return cx->methods;
}

int s5_select_auth(s5_ctx *cx, s5_auth_method method) {
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

#include <sockaddr_universal.h>
uint8_t * build_udp_assoc_package(bool allow, const char *addr_str, int port, uint8_t *buf, size_t *buf_len) {
    union sockaddr_universal addr = { 0 };
    bool ipV6;
    size_t in6_addr_w;
    size_t in4_addr_w;
    size_t port_w;

    if (addr_str == NULL || buf == NULL || buf_len == NULL) {
        return NULL;
    }

    if (convert_universal_address(addr_str, port, &addr) != 0) {
        return NULL;
    }
    ipV6 = (addr.addr.sa_family == AF_INET6);

    if (ipV6) {
        if (*buf_len < 22) {
            return NULL;
        }
    } else {
        if (*buf_len < 10) {
            return NULL;
        }
    }

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
        *buf_len = 4 + in6_addr_w + port_w;
        memcpy(buf + 4, &addr.addr6.sin6_addr, in6_addr_w);
        memcpy(buf + 4 + in6_addr_w, &addr.addr6.sin6_port, port_w);
    } else {
        *buf_len = 4 + in4_addr_w + port_w;
        memcpy(buf + 4, &addr.addr4.sin_addr, in4_addr_w);
        memcpy(buf + 4 + in4_addr_w, &addr.addr4.sin_port, port_w);
    }
    return buf;
}
