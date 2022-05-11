/*
 * android.c - Setup IPC for shadowsocks-android
 *
 * Copyright (C) 2013 - 2016, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the shadowsocks-libev.
 *
 * shadowsocks-libev is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * shadowsocks-libev is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with shadowsocks-libev; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <locale.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <errno.h>

#if __ANDROID__

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <sys/un.h>
#include <jni.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ssrutils.h"
#include "utils.h"

#if 0

#include <ancillary.h>

int protect_socket(int fd) {
    int sock;
    struct sockaddr_un addr;

    if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        LOGE("[android] socket() failed: %s (socket fd = %d)\n", strerror(errno), sock);
        return -1;
    }

    // Set timeout to 3s
    struct timeval tv;
    tv.tv_sec  = 3;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(struct timeval));

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, "protect_path", sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        LOGE("[android] connect() failed for protect_path: %s (socket fd = %d)\n",
             strerror(errno), sock);
        close(sock);
        return -1;
    }

    if (ancil_send_fd(sock, fd)) {
        LOGE("%s", "[android] ancil_send_fd");
        close(sock);
        return -1;
    }

    char ret = 0;

    if (recv(sock, &ret, 1, 0) == -1) {
        LOGE("%s", "[android] recv");
        close(sock);
        return -1;
    }

    close(sock);
    return ret;
}

#else

#include <assert.h>
#include <ssr_client_api.h>
int main(int argc, char * const argv[]);

JNIEXPORT jint JNICALL
Java_com_github_shadowsocks_bg_SsrClientWrapper_runSsrClient(JNIEnv *env, jclass clazz,
                                                             jobject cmd) {
    int result = -1;
    jclass alCls = NULL;
    do {
        alCls = (*env)->FindClass(env, "java/util/ArrayList");
        if (alCls == NULL) {
            break;
        }
        jmethodID alGetId = (*env)->GetMethodID(env, alCls, "get", "(I)Ljava/lang/Object;");
        jmethodID alSizeId = (*env)->GetMethodID(env, alCls, "size", "()I");
        if (alGetId == NULL || alSizeId == NULL) {
            break;
        }

        int arrayCount = (int) ((*env)->CallIntMethod(env, cmd, alSizeId));
        if (arrayCount <= 0) {
            break;
        }

        char ** argv = NULL;
        argv = (char **) calloc(arrayCount, sizeof(char*));
        if (argv == NULL) {
            break;
        }

        for (int index = 0; index < arrayCount; ++index) {
            jobject obj = (*env)->CallObjectMethod(env, cmd, alGetId, index);
            assert(obj);
            const char *cid = (*env)->GetStringUTFChars(env, obj, NULL);
            assert(cid);

            argv[index] = strdup(cid);
            assert(argv[index]);
            (*env)->DeleteLocalRef(env, obj);
        }

        result = main(arrayCount, argv);

        for (int index = 0; index < arrayCount; ++index) {
            free(argv[index]);
            argv[index] = NULL;
        }
        free(argv);
        argv = NULL;
    } while (false);

    if (alCls) {
        (*env)->DeleteLocalRef(env, alCls);
    }
    (void)clazz;
    return result;
}

JNIEXPORT jint JNICALL
Java_com_github_shadowsocks_bg_SsrClientWrapper_stopSsrClient(JNIEnv *env, jclass clazz) {
    extern struct ssr_client_state *g_state;
    if (g_state) {
        state_set_force_quit(g_state, true, 500);
        ssr_run_loop_shutdown(g_state);
        usleep(800);
    }
    (void)env;
    (void)clazz;
    return 0;
}

#include <dlfcn.h>
#include <fake-dlfcn.h>

int protect_socket(int fd) {
#define LIB_NETD_CLIENT_SO "libnetd_client.so"
    typedef int (*PFN_protectFromVpn)(int socketFd) ;
    static PFN_protectFromVpn protectFromVpn = NULL;
    if (protectFromVpn == NULL) {
        struct fake_dl_ctx *handle = fake_dlopen(SYSTEM_LIB_PATH LIB_NETD_CLIENT_SO, RTLD_NOW);
        if (!handle) {
            assert(!"cannot load " LIB_NETD_CLIENT_SO);
            return -1;
        }
        protectFromVpn = (PFN_protectFromVpn) fake_dlsym(handle, "protectFromVpn");
        fake_dlclose(handle);
        if (!protectFromVpn) {
            assert(!"required function protectFromVpn missing in " LIB_NETD_CLIENT_SO);
            return -1;
        }
        LOGI("%s", "==== protectFromVpn catched from " LIB_NETD_CLIENT_SO "! ====\n");
    }
    return protectFromVpn(fd);
}

#endif

static char status_file_path[512] = { 0 };

void set_traffic_status_file_path(const char *path) {
    if (path) {
        strncpy(status_file_path, path, sizeof(status_file_path));
    }
}

const char * get_traffic_status_file_path(void) {
    return status_file_path;
}

int
send_traffic_stat(uint64_t tx, uint64_t rx)
{
    if (strlen(get_traffic_status_file_path()) == 0) return 0;
    int sock;
    struct sockaddr_un addr;

    if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        LOGE("[android] socket() failed: %s (socket fd = %d)\n", strerror(errno), sock);
        return -1;
    }

    // Set timeout to 1s
    struct timeval tv;
    tv.tv_sec  = 1;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(struct timeval));

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, get_traffic_status_file_path(), sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        LOGE("[android] connect() failed for stat_path: %s (socket fd = %d)\n",
             strerror(errno), sock);
        close(sock);
        return -1;
    }

    uint64_t stat[2] = { tx, rx };

    if (send(sock, stat, sizeof(stat), 0) == -1) {
        LOGE("%s", "[android] send");
        close(sock);
        return -1;
    }

    char ret = 0;

    if (recv(sock, &ret, 1, 0) == -1) {
        LOGE("%s", "[android] recv");
        close(sock);
        return -1;
    }

    close(sock);
    return ret;
}

int log_tx_rx  = 0;

void set_flag_of_log_tx_rx(int log) {
    log_tx_rx = log;
}

#include <uv.h>

void traffic_status_update(uint64_t delta_tx, uint64_t delta_rx) {
    static uint64_t last  = 0;
    static uint64_t tx    = 0;
    static uint64_t rx    = 0;

    tx += delta_tx;
    rx += delta_rx;
    if (log_tx_rx) {
        uint64_t _now = uv_hrtime();
        if (_now - last > 1000) {
            send_traffic_stat(tx, rx);
            last = _now;
        }
    }
}

#endif // __ANDROID__
