/* Copyright StrongLoop, Inc. All rights reserved.
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
// https://zh.wikipedia.org/zh-hans/SOCKS
//

void s5_init(s5_ctx *cx) {
    memset(cx, 0, sizeof(*cx));
    cx->state = s5_state_version;
}

s5_err s5_parse(s5_ctx *cx, uint8_t **data, size_t *size) {
    s5_err err;
    uint8_t *p;
    uint8_t c;
    size_t i;
    size_t n;
    uint8_t port[2] = { 0 };

    p = *data;
    n = *size;
    i = 0;

    while (i < n) {
        c = p[i];
        i += 1;
        switch (cx->state) {
        case s5_state_version:
            if (c != 5) {
                err = s5_bad_version;
                goto out;
            }
            cx->state = s5_state_nmethods;
            break;

        case s5_state_nmethods:
            cx->arg0 = 0;
            cx->arg1 = c;  /* Number of bytes to read. */
            cx->state = s5_state_methods;
            break;

        case s5_state_methods:
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
                err = s5_auth_select;
                goto out;
            }
            break;

        case s5_state_auth_pw_version:
            if (c != 1) {
                err = s5_bad_version;
                goto out;
            }
            cx->state = s5_state_auth_pw_userlen;
            break;

        case s5_state_auth_pw_userlen:
            cx->arg0 = 0;
            cx->userlen = c;
            cx->state = s5_state_auth_pw_username;
            break;

        case s5_state_auth_pw_username:
            if (cx->arg0 < cx->userlen) {
                cx->username[cx->arg0] = c;
                cx->arg0 += 1;
            }
            if (cx->arg0 == cx->userlen) {
                cx->username[cx->userlen] = '\0';
                cx->state = s5_state_auth_pw_passlen;
            }
            break;

        case s5_state_auth_pw_passlen:
            cx->arg0 = 0;
            cx->passlen = c;
            cx->state = s5_state_auth_pw_password;
            break;

        case s5_state_auth_pw_password:
            if (cx->arg0 < cx->passlen) {
                cx->password[cx->arg0] = c;
                cx->arg0 += 1;
            }
            if (cx->arg0 == cx->passlen) {
                cx->password[cx->passlen] = '\0';
                cx->state = s5_state_req_version;
                err = s5_auth_verify;
                goto out;
            }
            break;

        case s5_state_req_version:
            if (c != 5) {
                err = s5_bad_version;
                goto out;
            }
            cx->state = s5_state_req_cmd;
            break;

        case s5_state_req_cmd:
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
                err = s5_bad_cmd;
                goto out;
            }
            cx->state = s5_state_req_reserved;
            break;

        case s5_state_req_reserved:
            cx->state = s5_state_req_atyp;
            break;

        case s5_state_req_atyp:
            cx->arg0 = 0;
            switch (c) {
            case 1:  /* IPv4, four octets. */
                cx->state = s5_state_req_daddr;
                cx->atyp = s5_atyp_ipv4;
                cx->arg1 = 4;
                break;
            case 3:  /* Hostname.  First byte is length. */
                cx->state = s5_state_req_atyp_host;
                cx->atyp = s5_atyp_host;
                cx->arg1 = 0;
                break;
            case 4:  /* IPv6, sixteen octets. */
                cx->state = s5_state_req_daddr;
                cx->atyp = s5_atyp_ipv6;
                cx->arg1 = 16;
                break;
            default:
                err = s5_bad_atyp;
                goto out;
            }
            break;

        case s5_state_req_atyp_host:
            cx->arg1 = c;
            cx->state = s5_state_req_daddr;
            break;

        case s5_state_req_daddr:
            if (cx->arg0 < cx->arg1) {
                cx->daddr[cx->arg0] = c;
                cx->arg0 += 1;
            }
            if (cx->arg0 == cx->arg1) {
                cx->daddr[cx->arg1] = '\0';
                cx->state = s5_state_req_dport0;
            }
            break;

        case s5_state_req_dport0:
            port[0] = c;
            cx->state = s5_state_req_dport1;
            break;

        case s5_state_req_dport1:
            port[1] = c;
            cx->dport = (uint16_t) ntohs(*(uint16_t *)port);
            cx->state = s5_state_dead;
            err = s5_exec_cmd;
            goto out;

        case s5_state_dead:
            break;

        default:
            abort();
        }
    }
    err = s5_ok;

out:
    *data = p + i;
    *size = n - i;
    return err;
}

enum s5_auth_method s5_auth_methods(const s5_ctx *cx) {
    return cx->methods;
}

int s5_select_auth(s5_ctx *cx, s5_auth_method method) {
    int err;

    err = 0;
    switch (method) {
    case s5_auth_none:
        cx->state = s5_state_req_version;
        break;
    case s5_auth_passwd:
        cx->state = s5_state_auth_pw_version;
        break;
    default:
        err = -EINVAL;
    }

    return err;
}

const char *s5_strerror(s5_err err) {
#define S5_ERR_GEN(_, name, errmsg) case s5_ ## name: return errmsg;
    switch (err) {
        S5_ERR_MAP(S5_ERR_GEN)
    default:;  /* Silence s5_max_errors -Wswitch warning. */
    }
#undef S5_ERR_GEN
    return "Unknown error.";
}
