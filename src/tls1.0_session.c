
#include "tls1.0_session.h"

typedef struct tls10_session_auth_global_data {
    uint8_t local_client_id[32];
}tls10_session_auth_global_data;

typedef struct tls10_session_auth_local_data {
    int has_sent_header;
    int has_recv_header;
    char *send_buffer;
    int send_buffer_size;
}tls10_session_auth_local_data;

void tls10_session_auth_local_data_init(tls10_session_auth_local_data* local) {
    local->has_sent_header = 0;
    local->has_recv_header = 0;
    local->send_buffer = malloc(0);
    local->send_buffer_size = 0;
}

void * tls10_session_auth_init_data() {
    tls10_session_auth_global_data *global = (tls10_session_auth_global_data*)malloc(sizeof(tls10_session_auth_global_data));
    rand_bytes(global->local_client_id, 32);
    return global;
}

obfs * tls10_session_auth_new_obfs() {
    obfs * self = new_obfs();
    self->l_data = malloc(sizeof(tls10_session_auth_local_data));
    tls10_session_auth_local_data_init((tls10_session_auth_local_data*)self->l_data);
    return self;
}

void tls10_session_auth_dispose(obfs *self) {
    tls10_session_auth_local_data *local = (tls10_session_auth_local_data*)self->l_data;
    if (local->send_buffer != NULL) {
        free(local->send_buffer);
        local->send_buffer = NULL;
    }
    free(local);
    dispose_obfs(self);
}

int tls10_session_pack_auth_data(tls10_session_auth_global_data *global, server_info *server, char *outdata) {
    int out_size = 32;
    time_t t = time(NULL);
    outdata[0] = t >> 24;
    outdata[1] = t >> 16;
    outdata[2] = t >> 8;
    outdata[3] = t;
    rand_bytes((uint8_t*)outdata + 4, 18);

    uint8_t *key = (uint8_t*)malloc(server->key_len + 32);
    char hash[ONETIMEAUTH_BYTES * 2];
    memcpy(key, server->key, server->key_len);
    memcpy(key + server->key_len, global->local_client_id, 32);
    ss_sha1_hmac_with_key(hash, outdata, out_size - OBFS_HMAC_SHA1_LEN, key, server->key_len + 32);
    free(key);
    memcpy(outdata + out_size - OBFS_HMAC_SHA1_LEN, hash, OBFS_HMAC_SHA1_LEN);
    return out_size;
}

int tls10_session_auth_client_encode(obfs *self, char **pencryptdata, int datalength, size_t* capacity) {
    char *encryptdata = *pencryptdata;
    tls10_session_auth_local_data *local = (tls10_session_auth_local_data*)self->l_data;
    tls10_session_auth_global_data *global = (tls10_session_auth_global_data*)self->server.g_data;
    if (local->has_sent_header == 2) {
        return datalength;
    }
    local->send_buffer = (char*)realloc(local->send_buffer, local->send_buffer_size + datalength);
    memcpy(local->send_buffer + local->send_buffer_size, encryptdata, datalength);
    local->send_buffer_size += datalength;
    char * out_buffer = NULL;

    if (local->has_sent_header == 0) {
        const char * tls_data = "\x00\x16\xc0\x2b\xc0\x2f\xc0\x0a\xc0\x09\xc0\x13\xc0\x14\x00\x33\x00\x39\x00\x2f\x00\x35\x00\x0a\x01\x00\x00\x6f\xff\x01\x00\x01\x00\x00\x0a\x00\x08\x00\x06\x00\x17\x00\x18\x00\x19\x00\x0b\x00\x02\x01\x00\x00\x23\x00\x00\x33\x74\x00\x00\x00\x10\x00\x29\x00\x27\x05\x68\x32\x2d\x31\x36\x05\x68\x32\x2d\x31\x35\x05\x68\x32\x2d\x31\x34\x02\x68\x32\x08\x73\x70\x64\x79\x2f\x33\x2e\x31\x08\x68\x74\x74\x70\x2f\x31\x2e\x31\x00\x05\x00\x05\x01\x00\x00\x00\x00\x00\x0d\x00\x16\x00\x14\x04\x01\x05\x01\x06\x01\x02\x01\x04\x03\x05\x03\x06\x03\x02\x03\x04\x02\x02\x02";
        datalength = 11 + 32 + 1 + 32 + 139;
        out_buffer = (char*)malloc(datalength);
        char *pdata = out_buffer + datalength - 139;
        int len = 139;
        memcpy(pdata, tls_data, 139);
        memcpy(pdata - 32, global->local_client_id, 32);
        pdata -= 32; len += 32;
        pdata[-1] = 0x20;
        pdata -= 1; len += 1;
        tls10_session_pack_auth_data(global, &self->server, pdata - 32);
        pdata -= 32; len += 32;
        pdata[-1] = 0x1;
        pdata[-2] = 0x3; // tls version
        pdata -= 2; len += 2;
        pdata[-1] = len;
        pdata[-2] = len >> 8;
        pdata[-3] = 0;
        pdata[-4] = 1;
        pdata -= 4; len += 4;

        pdata[-1] = len;
        pdata[-2] = len >> 8;
        pdata -= 2; len += 2;
        pdata[-1] = 0x1;
        pdata[-2] = 0x3; // tls version
        pdata -= 2; len += 2;
        pdata[-1] = 0x16; // tls handshake
        pdata -= 1; len += 1;

        local->has_sent_header = 1;
    } else if (datalength == 0) {
        datalength = local->send_buffer_size + 43;
        out_buffer = (char*)malloc(datalength);
        char *pdata = out_buffer;
        memcpy(pdata, "\x14\x03\x01\x00\x01\x01", 6);
        pdata += 6;
        memcpy(pdata, "\x16\x03\x01\x00\x20", 5);
        pdata += 5;
        rand_bytes((uint8_t*)pdata, 22);
        pdata += 22;

        uint8_t *key = (uint8_t*)malloc(self->server.key_len + 32);
        char hash[ONETIMEAUTH_BYTES * 2];
        memcpy(key, self->server.key, self->server.key_len);
        memcpy(key + self->server.key_len, global->local_client_id, 32);
        ss_sha1_hmac_with_key(hash, out_buffer, pdata - out_buffer, key, self->server.key_len + 32);
        free(key);
        memcpy(pdata, hash, OBFS_HMAC_SHA1_LEN);

        pdata += OBFS_HMAC_SHA1_LEN;
        memcpy(pdata, local->send_buffer, local->send_buffer_size);
        free(local->send_buffer);
        local->send_buffer = NULL;

        local->has_sent_header = 2;
    } else {
        return 0;
    }
    if (*capacity < datalength) {
        *pencryptdata = (char*)realloc(*pencryptdata, *capacity = datalength * 2);
        encryptdata = *pencryptdata;
    }
    memmove(encryptdata, out_buffer, datalength);
    free(out_buffer);
    return datalength;
}

int tls10_session_auth_client_decode(obfs *self, char **pencryptdata, int datalength, size_t* capacity, int *needsendback) {
    char *encryptdata = *pencryptdata;
    tls10_session_auth_local_data *local = (tls10_session_auth_local_data*)self->l_data;
    tls10_session_auth_global_data *global = (tls10_session_auth_global_data*)self->server.g_data;

    *needsendback = 0;
    if (local->has_recv_header) {
        return datalength;
    }
    if (datalength < 11 + 32 + 1 + 32) {
        return -1;
    }

    uint8_t *key = (uint8_t*)malloc(self->server.key_len + 32);
    char hash[ONETIMEAUTH_BYTES * 2];
    memcpy(key, self->server.key, self->server.key_len);
    memcpy(key + self->server.key_len, global->local_client_id, 32);
    ss_sha1_hmac_with_key(hash, encryptdata + 11, 22, key, self->server.key_len + 32);
    free(key);

    if (memcmp(encryptdata + 33, hash, OBFS_HMAC_SHA1_LEN)) {
        return -1;
    }

    local->has_recv_header = 1;
    *needsendback = 1;
    return 0;
}

