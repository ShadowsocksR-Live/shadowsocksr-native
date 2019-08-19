//
//  ssr_cipher_names.h
//  ssrlive
//
//  Created by ssrlive on 12/18/17.
//  Copyright © 2017 ssrlive. All rights reserved.
//

#ifndef ssr_cipher_names_h
#define ssr_cipher_names_h

#include <stdio.h>

//
// enum ss_cipher_type
//
// code, name, text, iv_size, key_size
//
#define SS_CIPHER_MAP(V)                                                       \
    V( 0, ss_cipher_none,              "none",              0, 16)             \
    V( 1, ss_cipher_table,             "table",             0, 16)             \
    V( 2, ss_cipher_rc4,               "rc4",               0, 16)             \
    V( 3, ss_cipher_rc4_md5_6,         "rc4-md5-6",         6, 16)             \
    V( 4, ss_cipher_rc4_md5,           "rc4-md5",          16, 16)             \
    V( 5, ss_cipher_aes_128_cfb,       "aes-128-cfb",      16, 16)             \
    V( 6, ss_cipher_aes_192_cfb,       "aes-192-cfb",      16, 24)             \
    V( 7, ss_cipher_aes_256_cfb,       "aes-256-cfb",      16, 32)             \
    V( 8, ss_cipher_aes_128_ctr,       "aes-128-ctr",      16, 16)             \
    V( 9, ss_cipher_aes_192_ctr,       "aes-192-ctr",      16, 24)             \
    V(10, ss_cipher_aes_256_ctr,       "aes-256-ctr",      16, 32)             \
    V(11, ss_cipher_bf_cfb,            "bf-cfb",            8, 16)             \
    V(12, ss_cipher_camellia_128_cfb,  "camellia-128-cfb", 16, 16)             \
    V(13, ss_cipher_camellia_192_cfb,  "camellia-192-cfb", 16, 24)             \
    V(14, ss_cipher_camellia_256_cfb,  "camellia-256-cfb", 16, 32)             \
    V(15, ss_cipher_cast5_cfb,         "cast5-cfb",         8, 16)             \
    V(16, ss_cipher_des_cfb,           "des-cfb",           8,  8)             \
    V(17, ss_cipher_idea_cfb,          "idea-cfb",          8, 16)             \
    V(18, ss_cipher_rc2_cfb,           "rc2-cfb",           8, 16)             \
    V(19, ss_cipher_seed_cfb,          "seed-cfb",         16, 16)             \
    V(20, ss_cipher_salsa20,           "salsa20",           8, 32)             \
    V(21, ss_cipher_chacha20,          "chacha20",          8, 32)             \
    V(22, ss_cipher_chacha20ietf,      "chacha20-ietf",    12, 32)             \

typedef enum ss_cipher_type {
#define SS_CIPHER_GEN(code, name, text, iv_size, key_size) name = (code),
    SS_CIPHER_MAP(SS_CIPHER_GEN)
#undef SS_CIPHER_GEN
    ss_cipher_max,
} ss_cipher_type;

int ss_cipher_key_size(enum ss_cipher_type index);
int ss_cipher_iv_size(enum ss_cipher_type index);
const char * ss_cipher_name_of_type(enum ss_cipher_type index);
enum ss_cipher_type ss_cipher_type_of_name(const char *name);


#define SSR_PROTOCOL_MAP(V)                                                    \
    V( 0, ssr_protocol_origin,          "origin")                              \
    V( 1, ssr_protocol_verify_simple,   "verify_simple")                       \
    V( 3, ssr_protocol_auth_simple,     "auth_simple")                         \
    V( 4, ssr_protocol_auth_sha1,       "auth_sha1")                           \
    V( 5, ssr_protocol_auth_sha1_v2,    "auth_sha1_v2")                        \
    V( 6, ssr_protocol_auth_sha1_v4,    "auth_sha1_v4")                        \
    V( 7, ssr_protocol_auth_aes128_md5, "auth_aes128_md5")                     \
    V( 8, ssr_protocol_auth_aes128_sha1,"auth_aes128_sha1")                    \
    V( 9, ssr_protocol_auth_chain_a,    "auth_chain_a")                        \
    V(10, ssr_protocol_auth_chain_b,    "auth_chain_b")                        \
    V(11, ssr_protocol_auth_chain_c,    "auth_chain_c")                        \
    V(12, ssr_protocol_auth_chain_d,    "auth_chain_d")                        \
    V(13, ssr_protocol_auth_chain_e,    "auth_chain_e")                        \
    V(14, ssr_protocol_auth_chain_f,    "auth_chain_f")                        \
//    V( 2, ssr_protocol_verify_sha1,     "verify_sha1")                         \

typedef enum ssr_protocol {
#define SSR_PROTOCOL_GEN(code, name, _) name = (code),
    SSR_PROTOCOL_MAP(SSR_PROTOCOL_GEN)
#undef SSR_PROTOCOL_GEN
    ssr_protocol_max,
} ssr_protocol;

const char * ssr_protocol_name_of_type(enum ssr_protocol index);
enum ssr_protocol ssr_protocol_type_of_name(const char *name);


#define SSR_OBFS_MAP(V)                                                        \
    V(0, ssr_obfs_plain,                    "plain")                           \
    V(1, ssr_obfs_http_simple,              "http_simple")                     \
    V(2, ssr_obfs_http_post,                "http_post")                       \
    V(3, ssr_obfs_http_mix,                 "http_mix")                        \
    V(4, ssr_obfs_tls_1_2_ticket_auth,      "tls1.2_ticket_auth")              \
    V(5, ssr_obfs_tls_1_2_ticket_fastauth,  "tls1.2_ticket_fastauth")          \
//    V(3, ssr_obfs_tls_1_0_session_auth,     "tls1.0_session_auth")             \

typedef enum ssr_obfs {
#define SSR_OBFS_GEN(code, name, _) name = (code),
    SSR_OBFS_MAP(SSR_OBFS_GEN)
#undef SSR_OBFS_GEN
    ssr_obfs_max,
} ssr_obfs;

const char * ssr_obfs_name_of_type(enum ssr_obfs index);
enum ssr_obfs ssr_obfs_type_of_name(const char *name);

#endif /* ssr_cipher_names_h */
