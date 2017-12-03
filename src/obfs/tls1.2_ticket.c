#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include "obfs.h"
#include "tls1.2_ticket.h"
#include "obfsutil.h"
#include "../encrypt.h"

typedef struct tls12_ticket_auth_global_data {
    uint8_t local_client_id[32];
}tls12_ticket_auth_global_data;

typedef struct tls12_ticket_auth_local_data {
    int handshake_status;
    uint8_t *send_buffer;
    int send_buffer_size;
    uint8_t *recv_buffer;
    int recv_buffer_size;
}tls12_ticket_auth_local_data;

void tls12_ticket_auth_local_data_init(tls12_ticket_auth_local_data* local) {
    local->handshake_status = 0;
    local->send_buffer = malloc(0);
    local->send_buffer_size = 0;
    local->recv_buffer = malloc(0);
    local->recv_buffer_size = 0;
}

void * tls12_ticket_auth_init_data(void) {
    tls12_ticket_auth_global_data *global = (tls12_ticket_auth_global_data*)malloc(sizeof(tls12_ticket_auth_global_data));
    rand_bytes(global->local_client_id, 32);
    return global;
}

struct obfs_t * tls12_ticket_auth_new_obfs(void) {
    struct obfs_t * obfs = new_obfs();
    obfs->l_data = malloc(sizeof(tls12_ticket_auth_local_data));
    tls12_ticket_auth_local_data_init((tls12_ticket_auth_local_data*)obfs->l_data);
    return obfs;
}

int tls12_ticket_auth_get_overhead(struct obfs_t *obfs) {
    return 5;
}

void tls12_ticket_auth_dispose(struct obfs_t *obfs) {
    tls12_ticket_auth_local_data *local = (tls12_ticket_auth_local_data*)obfs->l_data;
    if (local->send_buffer != NULL) {
        free(local->send_buffer);
        local->send_buffer = NULL;
    }
    if (local->recv_buffer != NULL) {
        free(local->recv_buffer);
        local->recv_buffer = NULL;
    }
    free(local);
    dispose_obfs(obfs);
}

int tls12_ticket_pack_auth_data(tls12_ticket_auth_global_data *global, struct server_info_t *server, uint8_t *outdata) {
    int out_size = 32;
    time_t t = time(NULL);
    outdata[0] = (uint8_t)(t >> 24);
    outdata[1] = (uint8_t)(t >> 16);
    outdata[2] = (uint8_t)(t >> 8);
    outdata[3] = (uint8_t)t;
    rand_bytes((uint8_t*)outdata + 4, 18);

    uint8_t *key = (uint8_t*)malloc(server->key_len + 32);
    char hash[SHA1_BYTES];
    memcpy(key, server->key, server->key_len);
    memcpy(key + server->key_len, global->local_client_id, 32);
    ss_sha1_hmac_with_key(hash, (char *)outdata, out_size - OBFS_HMAC_SHA1_LEN, key, (server->key_len + 32));
    free(key);
    memcpy(outdata + out_size - OBFS_HMAC_SHA1_LEN, hash, OBFS_HMAC_SHA1_LEN);
    return out_size;
}

void tls12_ticket_auth_pack_data(const uint8_t *encryptdata, uint16_t start, uint16_t len, uint8_t *out_buffer, uint16_t outlength) {
    out_buffer[outlength] = 0x17;
    out_buffer[outlength + 1] = 0x3;
    out_buffer[outlength + 2] = 0x3;
    out_buffer[outlength + 3] = (uint8_t)(len >> 8);
    out_buffer[outlength + 4] = (uint8_t)len;
    memcpy(out_buffer + outlength + 5, encryptdata + start, len);
}

size_t tls12_ticket_auth_client_encode(struct obfs_t *obfs, char **pencryptdata, size_t datalength, size_t* capacity) {
    uint8_t *encryptdata = (uint8_t *)*pencryptdata;
    tls12_ticket_auth_local_data *local = (tls12_ticket_auth_local_data*)obfs->l_data;
    tls12_ticket_auth_global_data *global = (tls12_ticket_auth_global_data*)obfs->server.g_data;
    uint8_t * out_buffer = NULL;

    if (local->handshake_status == 8) {
        if (datalength < (SSR_BUFF_SIZE / 2)) {
            if (*capacity < datalength + 5) {
                *pencryptdata = (char*)realloc(*pencryptdata, *capacity = (size_t)((datalength + 5) * 2));
                encryptdata = (uint8_t *)*pencryptdata;
            }
            memmove(encryptdata + 5, encryptdata, datalength);
            encryptdata[0] = 0x17;
            encryptdata[1] = 0x3;
            encryptdata[2] = 0x3;
            encryptdata[3] = (uint8_t)(datalength >> 8);
            encryptdata[4] = (uint8_t)datalength;
            return datalength + 5;
        } else {
            out_buffer = (uint8_t*)malloc((size_t)(datalength + (SSR_BUFF_SIZE * 2)));
            size_t start = 0;
            size_t outlength = 0;
            size_t len;
            while (datalength - start > SSR_BUFF_SIZE) {
                len = xorshift128plus() % (SSR_BUFF_SIZE * 2) + 100;
                if (len > datalength - start) {
                    len = datalength - start;
                }
                tls12_ticket_auth_pack_data(encryptdata, (uint16_t)start, (uint16_t)len, out_buffer, (uint16_t)outlength);
                outlength += len + 5;
                start += len;
            }
            if (datalength - start > 0) {
                len = datalength - start;
                tls12_ticket_auth_pack_data(encryptdata, (uint16_t)start, (uint16_t)len, out_buffer, (uint16_t)outlength);
                outlength += len + 5;
            }
            if (*capacity < outlength) {
                *pencryptdata = (char*)realloc(*pencryptdata, *capacity = (size_t)(outlength * 2));
                encryptdata = (uint8_t *)*pencryptdata;
            }
            memcpy(encryptdata, out_buffer, outlength);
            free(out_buffer);
            return outlength;
        }
    }

    if (datalength > 0) {
        if (datalength < (SSR_BUFF_SIZE / 2)) {
            local->send_buffer = (uint8_t *)realloc(local->send_buffer, ((size_t)local->send_buffer_size + datalength + 5));
            tls12_ticket_auth_pack_data(encryptdata, 0, (uint16_t)datalength, local->send_buffer, (uint16_t)local->send_buffer_size);
            local->send_buffer_size += (int)datalength + 5;
        } else {
            out_buffer = (uint8_t *)malloc(datalength + (SSR_BUFF_SIZE * 2));
            size_t start = 0;
            size_t outlength = 0;
            size_t len;
            while (datalength - start > SSR_BUFF_SIZE) {
                len = xorshift128plus() % (SSR_BUFF_SIZE * 2) + 100;
                if (len > datalength - start) {
                    len = datalength - start;
                }
                tls12_ticket_auth_pack_data(encryptdata, (uint16_t)start, (uint16_t)len, out_buffer, (uint16_t)outlength);
                outlength += len + 5;
                start += len;
            }
            if (datalength - start > 0) {
                len = datalength - start;
                tls12_ticket_auth_pack_data(encryptdata, (uint16_t)start, (uint16_t)len, out_buffer, (uint16_t)outlength);
                outlength += len + 5;
            }
            if (*capacity < outlength) {
                *pencryptdata = (char*)realloc(*pencryptdata, *capacity = (size_t)(outlength * 2));
                encryptdata = (uint8_t *)*pencryptdata;
            }
            local->send_buffer = (uint8_t *)realloc(local->send_buffer, ((size_t)local->send_buffer_size + outlength));
            memcpy(local->send_buffer + local->send_buffer_size, out_buffer, outlength);
            local->send_buffer_size += outlength;
            free(out_buffer);
        }
    }

    if (local->handshake_status == 0) {
#define CSTR_DECL(name, len, str) const char* (name) = (str); const size_t (len) = sizeof(str) - 1;
        CSTR_DECL(tls_data0, tls_data0_len, "\x00\x1c\xc0\x2b\xc0\x2f\xcc\xa9\xcc\xa8\xcc\x14\xcc\x13\xc0\x0a\xc0\x14\xc0\x09\xc0\x13\x00\x9c\x00\x35\x00\x2f\x00\x0a\x01\x00"
                );
        CSTR_DECL(tls_data1, tls_data1_len, "\xff\x01\x00\x01\x00"
                );
        CSTR_DECL(tls_data2, tls_data2_len, "\x00\x17\x00\x00\x00\x23\x00\xd0");
        CSTR_DECL(tls_data3, tls_data3_len, "\x00\x0d\x00\x16\x00\x14\x06\x01\x06\x03\x05\x01\x05\x03\x04\x01\x04\x03\x03\x01\x03\x03\x02\x01\x02\x03\x00\x05\x00\x05\x01\x00\x00\x00\x00\x00\x12\x00\x00\x75\x50\x00\x00\x00\x0b\x00\x02\x01\x00\x00\x0a\x00\x06\x00\x04\x00\x17\x00\x18"
                //"00150066000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" // padding
                );
        uint8_t * tls_data = (uint8_t *)calloc(SSR_BUFF_SIZE, sizeof(uint8_t));
        size_t tls_data_len = 0;
        memcpy(tls_data, tls_data1, tls_data1_len);
        tls_data_len += tls_data1_len;

        char hosts[(SSR_BUFF_SIZE / 2)];
        char * phost[128];
        int host_num = 0;
        int pos;

        char sni[256] = {0};
        char* param = NULL;
        if (obfs->server.param && strlen(obfs->server.param) > 0) {
            param = obfs->server.param;
        } else {
            param = obfs->server.host;
        }
        strncpy(hosts, param, sizeof hosts);
        phost[host_num++] = hosts;
        for (pos = 0; hosts[pos]; ++pos) {
            if (hosts[pos] == ',') {
                phost[host_num++] = &hosts[pos + 1];
                hosts[pos] = 0;
            }
        }
        host_num = (int)(xorshift128plus() % (uint64_t)host_num);

        snprintf(sni, sizeof sni, "%s", phost[host_num]);
        size_t sni_len = strlen(sni);
        if (sni_len > 0 && sni[sni_len - 1] >= '0' && sni[sni_len - 1] <= '9') {
            sni_len = 0;
        }
        tls_data[tls_data_len] = '\0';
        tls_data[tls_data_len + 1] = '\0';
        tls_data[tls_data_len + 2] = (uint8_t)((sni_len + 5) >> 8);
        tls_data[tls_data_len + 3] = (uint8_t)(sni_len + 5);
        tls_data[tls_data_len + 4] = (uint8_t)((sni_len + 3) >> 8);
        tls_data[tls_data_len + 5] = (uint8_t)(sni_len + 3);
        tls_data[tls_data_len + 6] = '\0';
        tls_data[tls_data_len + 7] = (uint8_t)(sni_len >> 8);
        tls_data[tls_data_len + 8] = (uint8_t)sni_len;
        memcpy(tls_data + tls_data_len + 9, sni, (size_t) sni_len);
        tls_data_len += 9 + sni_len;
        memcpy(tls_data + tls_data_len, tls_data2, tls_data2_len);
        tls_data_len += tls_data2_len;
        size_t ticket_len = (xorshift128plus() % (uint64_t)164) * 2 + 64;
        tls_data[tls_data_len - 1] = (uint8_t)(ticket_len & 0xff);
        tls_data[tls_data_len - 2] = (uint8_t)(ticket_len >> 8);
        rand_bytes(tls_data + tls_data_len, (int)ticket_len);
        tls_data_len += ticket_len;
        memcpy(tls_data + tls_data_len, tls_data3, tls_data3_len);
        tls_data_len += tls_data3_len;

        datalength = 11 + 32 + 1 + 32 + tls_data0_len + 2 + tls_data_len;
        out_buffer = (uint8_t *)malloc((size_t)datalength);
        uint8_t *pdata = out_buffer + datalength - tls_data_len;
        int len = (int)tls_data_len;
        memcpy(pdata, tls_data, tls_data_len);
        pdata[-1] = (uint8_t)tls_data_len;
        pdata[-2] = (uint8_t)(tls_data_len >> 8);
        pdata -= 2; len += 2;
        memcpy(pdata - tls_data0_len, tls_data0, tls_data0_len);
        pdata -= tls_data0_len; len += (int)tls_data0_len;
        memcpy(pdata - 32, global->local_client_id, 32);
        pdata -= 32; len += 32;
        pdata[-1] = 0x20;
        pdata -= 1; len += 1;
        tls12_ticket_pack_auth_data(global, &obfs->server, pdata - 32);
        pdata -= 32; len += 32;
        pdata[-1] = 0x3;
        pdata[-2] = 0x3; // tls version
        pdata -= 2; len += 2;
        pdata[-1] = (uint8_t)len;
        pdata[-2] = (uint8_t)(len >> 8);
        pdata[-3] = 0;
        pdata[-4] = 1;
        pdata -= 4; len += 4;

        pdata[-1] = (uint8_t)len;
        pdata[-2] = (uint8_t)(len >> 8);
        pdata -= 2; len += 2;
        pdata[-1] = 0x1;
        pdata[-2] = 0x3; // tls version
        pdata -= 2; len += 2;
        pdata[-1] = 0x16; // tls handshake
        pdata -= 1; len += 1;

        local->handshake_status = 1;

        free(tls_data);
    } else if (datalength == 0) {
        datalength = (size_t)local->send_buffer_size + 43;
        out_buffer = (uint8_t *)malloc(datalength);
        uint8_t *pdata = out_buffer;
        memcpy(pdata, "\x14\x03\x03\x00\x01\x01", 6);
        pdata += 6;
        memcpy(pdata, "\x16\x03\x03\x00\x20", 5);
        pdata += 5;
        rand_bytes((uint8_t*)pdata, 22);
        pdata += 22;

        uint8_t *key = (uint8_t*)malloc(obfs->server.key_len + 32);
        char hash[SHA1_BYTES];
        memcpy(key, obfs->server.key, obfs->server.key_len);
        memcpy(key + obfs->server.key_len, global->local_client_id, 32);
        ss_sha1_hmac_with_key(hash, (char *)out_buffer, (int)(pdata - out_buffer), key, (int)(obfs->server.key_len + 32));
        free(key);
        memcpy(pdata, hash, OBFS_HMAC_SHA1_LEN);

        pdata += OBFS_HMAC_SHA1_LEN;
        memcpy(pdata, local->send_buffer, (size_t) local->send_buffer_size);
        free(local->send_buffer);
        local->send_buffer = NULL;

        local->handshake_status = 8;
    } else {
        return 0;
    }
    if (*capacity < datalength) {
        *pencryptdata = (char*)realloc(*pencryptdata, *capacity = (datalength * 2));
        encryptdata = (uint8_t *)*pencryptdata;
    }
    memmove(encryptdata, out_buffer, datalength);
    free(out_buffer);
    return datalength;
}

ssize_t tls12_ticket_auth_client_decode(struct obfs_t *obfs, char **pencryptdata, size_t datalength, size_t* capacity, int *needsendback) {
    char *encryptdata = *pencryptdata;
    tls12_ticket_auth_local_data *local = (tls12_ticket_auth_local_data*)obfs->l_data;
    tls12_ticket_auth_global_data *global = (tls12_ticket_auth_global_data*)obfs->server.g_data;

    *needsendback = 0;
    if (local->handshake_status == 8) {
        local->recv_buffer_size += (int) datalength;
        local->recv_buffer = (uint8_t *)realloc(local->recv_buffer, (size_t)local->recv_buffer_size);
        memcpy(local->recv_buffer + local->recv_buffer_size - datalength, encryptdata, datalength);
        datalength = 0;
        while (local->recv_buffer_size > 5) {
            if (local->recv_buffer[0] != 0x17) {
                return -1;
            }
            size_t size = (((size_t)local->recv_buffer[3]) << 8) + (size_t)local->recv_buffer[4];
            if (size + 5 > (size_t)local->recv_buffer_size) {
                break;
            }
            if (*capacity < datalength + size) {
                *pencryptdata = (char*)realloc(*pencryptdata, *capacity = (size_t)((datalength + size) * 2));
                encryptdata = *pencryptdata;
            }
            memcpy(encryptdata + datalength, local->recv_buffer + 5, size);
            datalength += size;
            local->recv_buffer_size -= 5 + size;
            memmove(local->recv_buffer, local->recv_buffer + 5 + size, local->recv_buffer_size);
        }
        return (ssize_t)datalength;
    }
    if (datalength < 11 + 32 + 1 + 32) {
        return -1;
    }

    uint8_t *key = (uint8_t*)malloc(obfs->server.key_len + 32);
    char hash[SHA1_BYTES];
    memcpy(key, obfs->server.key, obfs->server.key_len);
    memcpy(key + obfs->server.key_len, global->local_client_id, 32);
    ss_sha1_hmac_with_key(hash, encryptdata + 11, 22, key, (int)obfs->server.key_len + 32);
    free(key);

    if (memcmp(encryptdata + 33, hash, OBFS_HMAC_SHA1_LEN)) {
        return -1;
    }

    *needsendback = 1;
    return 0;
}
