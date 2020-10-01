/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */
/* ====================================================================
 * Copyright (c) 1995-1999 The Apache Group.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * 4. The names "Apache Server" and "Apache Group" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache"
 *    nor may "Apache" appear in their names without prior written
 *    permission of the Apache Group.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY THE APACHE GROUP ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE APACHE GROUP OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Group and was originally based
 * on public domain software written at the National Center for
 * Supercomputing Applications, University of Illinois, Urbana-Champaign.
 * For more information on the Apache Group and the Apache HTTP server
 * project, please see <http://www.apache.org/>.
 *
 */

/* Base64 encoder/decoder. Originally Apache file ap_base64.c
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "base64.h"

/* aaaack but it's fast and const should make it shared text page. */
static const uint8_t pr2six[256] = {
    /* ASCII table */
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
    64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
    64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
};

size_t std_base64_decode_len(const char* bufcoded)
{
    size_t nbytesdecoded;
    register const uint8_t* bufin;
    register size_t nprbytes;

    bufin = (const uint8_t*)bufcoded;
    while (pr2six[*(bufin++)] <= 63)
        ;

    nprbytes = (size_t)((bufin - (const uint8_t*)bufcoded) - 1);
    nbytesdecoded = ((nprbytes + 3) / 4) * 3;

    return nbytesdecoded + 1;
}

size_t std_base64_decode(const char* bufcoded, uint8_t* bufplain)
{
    int nbytesdecoded;
    register const unsigned char* bufin;
    register unsigned char* bufout;
    register int nprbytes;

    bufin = (const unsigned char*)bufcoded;
    while (pr2six[*(bufin++)] <= 63)
        ;
    nprbytes = (int)((bufin - (const unsigned char*)bufcoded) - 1);
    nbytesdecoded = ((nprbytes + 3) / 4) * 3;

    bufout = (unsigned char*)bufplain;
    bufin = (const unsigned char*)bufcoded;

    while (nprbytes > 4) {
        *(bufout++) = (unsigned char)(pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
        *(bufout++) = (unsigned char)(pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
        *(bufout++) = (unsigned char)(pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
        bufin += 4;
        nprbytes -= 4;
    }

    /* Note: (nprbytes == 1) would be an error, so just ingore that case */
    if (nprbytes > 1) {
        *(bufout++) = (unsigned char)(pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
    }
    if (nprbytes > 2) {
        *(bufout++) = (unsigned char)(pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
    }
    if (nprbytes > 3) {
        *(bufout++) = (unsigned char)(pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
    }

    *(bufout++) = '\0';
    nbytesdecoded -= (4 - nprbytes) & 3;
    return nbytesdecoded;
}

static const uint8_t basis_64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t std_base64_encode_len(volatile size_t len)
{
    return (((len + 2) / 3) * 4) + 1;
}

size_t std_base64_encode(const uint8_t* string, size_t len, char* encoded)
{
    size_t i;
    uint8_t* p;

    p = (uint8_t*)encoded;
    for (i = 0; i < len - 2; i += 3) {
        *p++ = basis_64[(string[i] >> 2) & 0x3F];
        *p++ = basis_64[((string[i] & 0x3) << 4) | ((size_t)(string[i + 1] & 0xF0) >> 4)];
        *p++ = basis_64[((string[i + 1] & 0xF) << 2) | ((size_t)(string[i + 2] & 0xC0) >> 6)];
        *p++ = basis_64[string[i + 2] & 0x3F];
    }
    if (i < len) {
        *p++ = basis_64[(string[i] >> 2) & 0x3F];
        if (i == (len - 1)) {
            *p++ = basis_64[((string[i] & 0x3) << 4)];
            *p++ = '=';
        } else {
            *p++ = basis_64[((string[i] & 0x3) << 4) | ((size_t)(string[i + 1] & 0xF0) >> 4)];
            *p++ = basis_64[((string[i + 1] & 0xF) << 2)];
        }
        *p++ = '=';
    }

    *p = '\0'; // *p++ = '\0';
    return (size_t)(p - (uint8_t*)encoded);
}

char* std_base64_encode_alloc(const uint8_t* plain_src, size_t len_plain_src, void* (*allocator)(size_t))
{
    size_t len = 0;
    char* result = NULL;
    if (plain_src == NULL || len_plain_src == 0 || allocator == NULL) {
        return NULL;
    }
    len = (size_t)std_base64_encode_len((size_t)len_plain_src);
    result = (char*)allocator(len + 1);
    if (result == NULL) {
        return NULL;
    }
    memset(result, 0, len + 1);
    std_base64_encode(plain_src, (size_t)len_plain_src, (char*)result);

    return result;
}

uint8_t* std_base64_decode_alloc(const char* coded_src, void* (*allocator)(size_t), size_t* size)
{
    size_t len = 0;
    uint8_t* result = NULL;
    if (coded_src == NULL || allocator == NULL) {
        return NULL;
    }
    len = (size_t)std_base64_decode_len((const char*)coded_src);
    result = (uint8_t*)allocator(len + 1);
    if (result == NULL) {
        return NULL;
    }
    memset(result, 0, len + 1);
    len = (size_t)std_base64_decode((const char*)coded_src, result);
    if (size) {
        *size = len;
    }
    return result;
}

//
// https://en.wikipedia.org/wiki/Base64#URL_applications
//

static void str_replace_char(char* str, char old_char, char new_char);
static void str_url_safe_base64_to_std_base64(char* coded_src);

size_t url_safe_base64_encode_len(size_t len)
{
    return (size_t)std_base64_encode_len((size_t)len);
}

size_t url_safe_base64_encode(const uint8_t* plain_src, size_t len_plain_src, char* coded_dst)
{
    std_base64_encode(plain_src, (size_t)len_plain_src, (char*)coded_dst);
    str_replace_char(coded_dst, '+', '-');
    str_replace_char(coded_dst, '/', '_');
    str_replace_char(coded_dst, '=', 0);
    return (size_t)strlen((const char*)coded_dst);
}

char* url_safe_base64_encode_alloc(const uint8_t* plain_src, size_t len_plain_src, void* (*allocator)(size_t))
{
    char* result = NULL;
    size_t len = (size_t)url_safe_base64_encode_len(len_plain_src);
    if (plain_src == NULL || len_plain_src == 0 || allocator == NULL) {
        return NULL;
    }
    result = (char*)allocator(len + 1);
    if (result == NULL) {
        return NULL;
    }
    memset(result, 0, len + 1);

    url_safe_base64_encode(plain_src, len_plain_src, (char*)result);

    return result;
}

size_t url_safe_base64_decode_len(const char* coded_src)
{
    size_t result;
    size_t len = strlen((const char*)coded_src);
    char* new_buf = (char*)calloc(len + 4, sizeof(new_buf[0]));
    memcpy(new_buf, coded_src, len);

    str_url_safe_base64_to_std_base64(new_buf);
    result = std_base64_decode_len(new_buf);
    free(new_buf);
    return result;
}

size_t url_safe_base64_decode(const char* coded_src, uint8_t* plain_dst)
{
    size_t result;
    size_t len = strlen((const char*)coded_src);
    char* new_buf = (char*)calloc(len + 4, sizeof(new_buf[0]));
    memcpy(new_buf, coded_src, len);

    str_url_safe_base64_to_std_base64(new_buf);
    result = std_base64_decode(new_buf, plain_dst);
    free(new_buf);
    return result;
}

uint8_t* url_safe_base64_decode_alloc(const char* coded_src, void* (*allocator)(size_t), size_t* size)
{
    size_t len;
    uint8_t* result = NULL;
    if (coded_src == NULL || allocator == NULL || size == NULL) {
        return NULL;
    }
    len = url_safe_base64_decode_len((const char*)coded_src);
    result = (uint8_t*)allocator(len + 1);
    if (result == NULL) {
        return NULL;
    }
    memset(result, 0, len + 1);
    len = url_safe_base64_decode((const char*)coded_src, (uint8_t*)result);
    if (size) {
        *size = len;
    }
    return result;
}

static void str_replace_char(char* str, char old_char, char new_char)
{
    for (;; str++) {
        if (!*str) {
            break;
        }
        if (*str == old_char) {
            *str = new_char;
        }
    }
}

static void str_url_safe_base64_to_std_base64(char* coded_src)
{
    size_t len;

    str_replace_char(coded_src, '-', '+');
    str_replace_char(coded_src, '_', '/');

    len = strlen((const char*)coded_src);

    switch (len % 4) {
    case 1:
        assert(0);
        break;
    case 2:
        coded_src[len] = '=';
        coded_src[len + 1] = '=';
        coded_src[len + 2] = 0;
        break;
    case 3:
        coded_src[len] = '=';
        coded_src[len + 1] = 0;
        break;
    default:
        break;
    }
}
