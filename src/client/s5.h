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

#ifndef __S5_H__
#define __S5_H__

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define S5_RESULT_MAP(V)                                                       \
  V(-1, s5_result_bad_version, "Bad protocol version.")                        \
  V(-2, s5_result_bad_cmd,     "Bad protocol command.")                        \
  V(-3, s5_result_bad_atyp,    "Bad address type.")                            \
  V( 0, s5_result_need_more,   "Need more data.")                              \
  V( 1, s5_result_auth_select, "Select authentication method.")                \
  V( 2, s5_result_auth_verify, "Verify authentication.")                       \
  V( 3, s5_result_exec_cmd,    "Execute command.")                             \

enum s5_result {
#define S5_RESULT_GEN(code, name, _) name = code,
    S5_RESULT_MAP(S5_RESULT_GEN)
#undef S5_RESULT_GEN
    s5_result_max,
};

enum s5_atyp {
    s5_atyp_ipv4 = 1,
    s5_atyp_host = 3,
    s5_atyp_ipv6 = 4,
};

enum s5_auth_method {
    s5_auth_none = 1 << 0,
    s5_auth_gssapi = 1 << 1,
    s5_auth_passwd = 1 << 2
};

enum s5_cmd {
    s5_cmd_tcp_connect = 1,
    s5_cmd_tcp_bind = 2,
    s5_cmd_udp_assoc = 3,
};

struct s5_ctx;

struct s5_ctx * s5_ctx_create(void);
void s5_ctx_release(struct s5_ctx *cx);

enum s5_result s5_parse(struct s5_ctx *cx, uint8_t **data, size_t *size);

enum s5_atyp s5_get_address_type(const struct s5_ctx *cx);
const char * s5_get_address(const struct s5_ctx *cx);
uint16_t s5_get_dport(const struct s5_ctx *cx);

/* Only call after s5_parse() has returned s5_want_auth_method. */
enum s5_auth_method s5_get_auth_methods(const struct s5_ctx *cx);

enum s5_cmd s5_get_cmd(const struct s5_ctx *cx);

/* Call after s5_parse() has returned s5_want_auth_method. */
int s5_select_auth(struct s5_ctx *cx, enum s5_auth_method method);

const char * str_s5_result(enum s5_result result);

uint8_t * s5_build_udp_assoc_package(bool allow, const char *addr_str, int port, void*(*allocator)(size_t size), size_t *size);
uint8_t * s5_address_package_create(const struct s5_ctx *parser, void*(*allocator)(size_t size), size_t *size);
uint8_t * s5_connect_response_package(const struct s5_ctx *parser, void*(*allocator)(size_t size), size_t *size);

struct socks5_address;
const uint8_t * s5_parse_upd_package(const uint8_t *pkg, size_t len, struct socks5_address *dst_addr, size_t *frag_number, size_t *payload_len);
uint8_t * s5_build_udp_datagram(struct socks5_address *dst_addr, const uint8_t *payload, size_t payload_len, void*(*allocator)(size_t size), size_t *size);

#endif  /* __S5_H__ */
