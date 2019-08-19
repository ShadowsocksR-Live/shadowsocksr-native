//
//  ssr_cipher_names.c
//  ssrlive
//
//  Created by ssrlive on 12/18/17.
//  Copyright © 2017 ssrlive. All rights reserved.
//

#include <ctype.h>
#include "ssr_cipher_names.h"

#ifndef SIZEOF_ARRAY
#define SIZEOF_ARRAY(a) (sizeof(a)/sizeof((a)[0]))
#endif

int ss_cipher_key_size(enum ss_cipher_type index) {
#define SS_CIPHER_KEY_GEN(_, name, text, iv_size, key_size) case (name): return (key_size);
    switch (index) {
            SS_CIPHER_MAP(SS_CIPHER_KEY_GEN)
        default:;  // Silence ss_cipher_max -Wswitch warning.
    }
#undef SS_CIPHER_KEY_GEN
    return 0; // "Invalid index";
}

int ss_cipher_iv_size(enum ss_cipher_type index) {
#define SS_CIPHER_IV_GEN(_, name, text, iv_size, key_size) case (name): return (iv_size);
    switch (index) {
            SS_CIPHER_MAP(SS_CIPHER_IV_GEN)
        default:;  // Silence ss_cipher_max -Wswitch warning.
    }
#undef SS_CIPHER_IV_GEN
    return 0; // "Invalid index";
}

const char *
ss_cipher_name_of_type(enum ss_cipher_type index)
{
#define SS_CIPHER_GEN(_, name, text, iv_size, key_size) case (name): return (text);
    switch (index) {
            SS_CIPHER_MAP(SS_CIPHER_GEN)
        default:;  // Silence ss_cipher_max -Wswitch warning.
    }
#undef SS_CIPHER_GEN
    return NULL; // "Invalid index";
}

static int strcicmp(char const *a, char const *b) {
    for (;; a++, b++) {
        int d = tolower(*a) - tolower(*b);
        if (d != 0 || !*a) {
            return d;
        }
    }
}

enum ss_cipher_type ss_cipher_type_of_name(const char *name) {
    enum ss_cipher_type m = ss_cipher_none;
    if (name != NULL) {
        for (m = ss_cipher_none; m < ss_cipher_max; ++m) {
            if (strcicmp(name, ss_cipher_name_of_type(m)) == 0) {
                break;
            }
        }
        if (m >= ss_cipher_max) {
            //LOGE("Invalid cipher name: %s, use rc4-md5 instead", name);
            // m = ss_cipher_rc4_md5;
        }
    }
    return m;
}


//=========================== ssr_protocol =====================================

const char * ssr_protocol_name_of_type(enum ssr_protocol index) {
#define SSR_PROTOCOL_GEN(_, name, msg) case (name): return (msg);
    switch (index) {
        SSR_PROTOCOL_MAP(SSR_PROTOCOL_GEN)
        default:;  // Silence ssr_protocol_max -Wswitch warning.
    }
#undef SSR_PROTOCOL_GEN
    return NULL; // "Invalid index";
}

enum ssr_protocol ssr_protocol_type_of_name(const char *name) {
    struct {
        enum ssr_protocol index;
        char *name;
    } protocol_name_arr[] = {
#define SSR_PROTOCOL_GEN_ARR(_, name, msg) { (name), (msg) },
        SSR_PROTOCOL_MAP(SSR_PROTOCOL_GEN_ARR)
#undef SSR_PROTOCOL_GEN_ARR
    };
    
    enum ssr_protocol result = ssr_protocol_max;

     size_t index = 0;    
    for (index=0; index<SIZEOF_ARRAY(protocol_name_arr); ++index) {
        if (strcicmp(name, protocol_name_arr[index].name) == 0) {
            result = protocol_name_arr[index].index;
            break;
        }
    }
    return result;
}


//=========================== ssr_obfs =========================================

const char * ssr_obfs_name_of_type(enum ssr_obfs index) {
#define SSR_OBFS_GEN(_, name, msg) case (name): return (msg);
    switch (index) {
            SSR_OBFS_MAP(SSR_OBFS_GEN)
        default:;  // Silence ssr_obfs_max -Wswitch warning.
    }
#undef SSR_OBFS_GEN
    return NULL; // "Invalid index";
}

enum ssr_obfs ssr_obfs_type_of_name(const char *name) {
    struct {
        enum ssr_obfs index;
        char *name;
    } obfs_name_arr[] = {
#define SSR_OBFS_GEN_ARR(_, name, msg) { (name), (msg) },
        SSR_OBFS_MAP(SSR_OBFS_GEN_ARR)
#undef SSR_OBFS_GEN_ARR
    };
    
    enum ssr_obfs result = ssr_obfs_max;
 
    size_t index = 0;
    for (index=0; index<SIZEOF_ARRAY(obfs_name_arr); ++index) {
        if (strcicmp(name, obfs_name_arr[index].name) == 0) {
            result = obfs_name_arr[index].index;
            break;
        }
    }
    return result;
}
