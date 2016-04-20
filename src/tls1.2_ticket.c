
#include "tls1.2_ticket.h"

typedef struct tls12_ticket_auth_global_data {
    uint8_t local_client_id[32];
}tls12_ticket_auth_global_data;

typedef struct tls12_ticket_auth_local_data {
    int handshake_status;
    char *send_buffer;
    int send_buffer_size;
    char *recv_buffer;
    int recv_buffer_size;
}tls12_ticket_auth_local_data;

void tls12_ticket_auth_local_data_init(tls12_ticket_auth_local_data* local) {
    local->handshake_status = 0;
    local->send_buffer = malloc(0);
    local->send_buffer_size = 0;
    local->recv_buffer = malloc(0);
    local->recv_buffer_size = 0;
}

void * tls12_ticket_auth_init_data() {
    tls12_ticket_auth_global_data *global = (tls12_ticket_auth_global_data*)malloc(sizeof(tls12_ticket_auth_global_data));
    rand_bytes(global->local_client_id, 32);
    return global;
}

obfs * tls12_ticket_auth_new_obfs() {
    obfs * self = new_obfs();
    self->l_data = malloc(sizeof(tls12_ticket_auth_local_data));
    tls12_ticket_auth_local_data_init((tls12_ticket_auth_local_data*)self->l_data);
    return self;
}

void tls12_ticket_auth_dispose(obfs *self) {
    tls12_ticket_auth_local_data *local = (tls12_ticket_auth_local_data*)self->l_data;
    if (local->send_buffer != NULL) {
        free(local->send_buffer);
        local->send_buffer = NULL;
    }
    if (local->recv_buffer != NULL) {
        free(local->recv_buffer);
        local->recv_buffer = NULL;
    }
    free(local);
    dispose_obfs(self);
}

int tls12_ticket_pack_auth_data(tls12_ticket_auth_global_data *global, server_info *server, char *outdata) {
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

int tls12_ticket_auth_client_encode(obfs *self, char **pencryptdata, int datalength, size_t* capacity) {
    char *encryptdata = *pencryptdata;
    tls12_ticket_auth_local_data *local = (tls12_ticket_auth_local_data*)self->l_data;
    tls12_ticket_auth_global_data *global = (tls12_ticket_auth_global_data*)self->server.g_data;
    char * out_buffer = NULL;

    if (local->handshake_status == 8) {
        if (*capacity < datalength + 5) {
            *pencryptdata = (char*)realloc(*pencryptdata, *capacity = (datalength + 5) * 2);
            encryptdata = *pencryptdata;
        }
        memmove(encryptdata + 5, encryptdata, datalength);
        encryptdata[0] = 0x17;
        encryptdata[1] = 0x3;
        encryptdata[2] = 0x3;
        encryptdata[3] = datalength >> 8;
        encryptdata[4] = datalength;
        return datalength + 5;
    }
    local->send_buffer = (char*)realloc(local->send_buffer, local->send_buffer_size + datalength + 5);
    memcpy(local->send_buffer + local->send_buffer_size + 5, encryptdata, datalength);
    local->send_buffer[local->send_buffer_size] = 0x17;
    local->send_buffer[local->send_buffer_size + 1] = 0x3;
    local->send_buffer[local->send_buffer_size + 2] = 0x3;
    local->send_buffer[local->send_buffer_size + 3] = datalength >> 8;
    local->send_buffer[local->send_buffer_size + 4] = datalength;
    local->send_buffer_size += datalength + 5;

    if (local->handshake_status == 0) {
#define CSTR_DECL(name, len, str) const char* name = str; const int len = sizeof str;
        CSTR_DECL(tls_data, tls_data_len, "\x00\x1c\xc0\x2b\xc0\x2f\xcc\xa9\xcc\xa8\xcc\x14\xcc\x13\xc0\x0a\xc0\x14\xc0\x09\xc0\x13\x00\x9c\x00\x35\x00\x2f\x00\x0a\x01\x00"
                "\xff\x01\x00\x01\x00"
                "\x00\x00\x00\x05\x00\x03\x00\x00\x00" // empty sni
                "\x00\x17\x00\x00\x00\x23\x00\xd0"
                "\x00\x0d\x00\x16\x00\x14\x06\x01\x06\x03\x05\x01\x05\x03\x04\x01\x04\x03\x03\x01\x03\x03\x02\x01\x02\x03\x00\x05\x00\x05\x01\x00\x00\x00\x00\x00\x12\x00\x00\x75\x50\x00\x00\x00\x0b\x00\x02\x01\x00\x00\x0a\x00\x06\x00\x04\x00\x17\x00\x18"
                //"00150066000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" // padding
                );
        datalength = 11 + 32 + 1 + 32 + tls_data_len;
        out_buffer = (char*)malloc(datalength);
        char *pdata = out_buffer + datalength - tls_data_len;
        int len = tls_data_len;
        memcpy(pdata, tls_data, tls_data_len);
        memcpy(pdata - 32, global->local_client_id, 32);
        pdata -= 32; len += 32;
        pdata[-1] = 0x20;
        pdata -= 1; len += 1;
        tls12_ticket_pack_auth_data(global, &self->server, pdata - 32);
        pdata -= 32; len += 32;
        pdata[-1] = 0x3;
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

        local->handshake_status = 1;
    } else if (datalength == 0) {
        datalength = local->send_buffer_size + 43;
        out_buffer = (char*)malloc(datalength);
        char *pdata = out_buffer;
        memcpy(pdata, "\x14\x03\x03\x00\x01\x01", 6);
        pdata += 6;
        memcpy(pdata, "\x16\x03\x03\x00\x20", 5);
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

        local->handshake_status = 8;
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

int tls12_ticket_auth_client_decode(obfs *self, char **pencryptdata, int datalength, size_t* capacity, int *needsendback) {
    char *encryptdata = *pencryptdata;
    tls12_ticket_auth_local_data *local = (tls12_ticket_auth_local_data*)self->l_data;
    tls12_ticket_auth_global_data *global = (tls12_ticket_auth_global_data*)self->server.g_data;

    *needsendback = 0;
    if (local->handshake_status == 8) {
        local->recv_buffer_size += datalength;
        local->recv_buffer = (char*)realloc(local->recv_buffer, local->recv_buffer_size);
        memcpy(local->recv_buffer + local->recv_buffer_size - datalength, encryptdata, datalength);
        datalength = 0;
        while (local->recv_buffer_size > 5) {
            if (local->recv_buffer[0] != 0x17)
                return -1;
            int size = ((int)(unsigned char)local->recv_buffer[3] << 8) + (unsigned char)local->recv_buffer[4];
            if (size + 5 > local->recv_buffer_size)
                break;
            if (*capacity < datalength + size) {
                *pencryptdata = (char*)realloc(*pencryptdata, *capacity = (datalength + size) * 2);
                encryptdata = *pencryptdata;
            }
            memcpy(encryptdata + datalength, local->recv_buffer + 5, size);
            datalength += size;
            local->recv_buffer_size -= 5 + size;
            memmove(local->recv_buffer, local->recv_buffer + 5 + size, local->recv_buffer_size);
        }
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

    *needsendback = 1;
    return 0;
}

