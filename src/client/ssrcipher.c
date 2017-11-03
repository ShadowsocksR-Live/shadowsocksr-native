/* Copyright SSRLIVE. All rights reserved.
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

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ssrcipher.h"
#include "defs.h"
#include "encrypt.h"

struct server_env_t * create_ssr_cipher_env(struct server_config *config) {
    srand((unsigned int)time(NULL));

    struct server_env_t *env = calloc(1, sizeof(struct server_env_t));
    env->cipher = calloc(1, sizeof(struct cipher_env_t));
    env->config = config;

    enc_init(env->cipher, config->password, config->method);

    // init obfs
    init_obfs(env, config->protocol, config->obfs);

    return env;
}

void init_obfs(struct server_env_t *env, const char *protocol, const char *obfs) {
    env->protocol_plugin = new_obfs_manager(protocol);
    if (env->protocol_plugin) {
        env->protocol_global = env->protocol_plugin->init_data();
    }

    env->obfs_plugin = new_obfs_manager(obfs);
    if (env->obfs_plugin) {
        env->obfs_global = env->obfs_plugin->init_data();
    }
}
