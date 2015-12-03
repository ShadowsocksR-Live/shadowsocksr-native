
#include "auth.h"

static int auth_simple_pack_unit_size = 2000;

int rand_bytes(uint8_t *output, int len);

typedef struct auth_simple_global_data {
    uint8_t local_client_id[4];
    uint32_t connection_id;
}auth_simple_global_data;

typedef struct auth_simple_local_data {
    int has_sent_header;
    char * recv_buffer;
    int recv_buffer_size;
}auth_simple_local_data;

void auth_simple_local_data_init(auth_simple_local_data* local) {
    local->has_sent_header = 0;
    local->recv_buffer = (char*)malloc(16384);
    local->recv_buffer_size = 0;
}

void * auth_simple_init_data() {
    auth_simple_global_data *global = (auth_simple_global_data*)malloc(sizeof(auth_simple_global_data));
    rand_bytes(global->local_client_id, 4);
    rand_bytes((uint8_t*)&global->connection_id, 4);
    global->connection_id &= 0xFFFFFF;
    return global;
}

obfs * auth_simple_new_obfs() {
    obfs * self = new_obfs();
    self->l_data = malloc(sizeof(auth_simple_local_data));
    auth_simple_local_data_init((auth_simple_local_data*)self->l_data);
    return self;
}

void auth_simple_dispose(obfs *self) {
    auth_simple_local_data *local = (auth_simple_local_data*)self->l_data;
    if (local->recv_buffer != NULL) {
        free(local->recv_buffer);
        local->recv_buffer = NULL;
    }
    free(local);
    self->l_data = NULL;
    dispose_obfs(self);
}

int auth_simple_pack_data(char *data, int datalength, char *outdata) {
    unsigned char rand_len = (xorshift128plus() & 0xF) + 1;
    int out_size = rand_len + datalength + 6;
    outdata[0] = out_size >> 8;
    outdata[1] = out_size;
    outdata[2] = rand_len;
    memmove(outdata + rand_len + 2, data, datalength);
    fillcrc32((unsigned char *)outdata, out_size);
    return out_size;
}

int auth_simple_pack_auth_data(auth_simple_global_data *global, char *data, int datalength, char *outdata) {
    unsigned char rand_len = (xorshift128plus() & 0xF) + 1;
    int out_size = rand_len + datalength + 6 + 12;
    outdata[0] = out_size >> 8;
    outdata[1] = out_size;
    outdata[2] = rand_len;
    ++global->connection_id;
    if (global->connection_id > 0xFF000000) {
        rand_bytes(global->local_client_id, 4);
        rand_bytes((uint8_t*)&global->connection_id, 4);
        global->connection_id &= 0xFFFFFF;
    }
    time_t t = time(NULL);
    memmove(outdata + rand_len + 2, &t, 4);
    memmove(outdata + rand_len + 2 + 4, global->local_client_id, 4);
    memmove(outdata + rand_len + 2 + 8, &global->connection_id, 4);
    memmove(outdata + rand_len + 2 + 12, data, datalength);
    fillcrc32((unsigned char *)outdata, out_size);
    return out_size;
}

int auth_simple_client_pre_encrypt(obfs *self, char **pplaindata, int datalength, ssize_t* capacity) {
    char *plaindata = *pplaindata;
    auth_simple_local_data *local = (auth_simple_local_data*)self->l_data;
    char * out_buffer = (char*)malloc(datalength * 2 + 64);
    char * buffer = out_buffer;
    char * data = plaindata;
    int len = datalength;
    int pack_len;
    if (len > 0 && local->has_sent_header == 0) {
        int head_size = get_head_size(plaindata, datalength, 30);
        if (head_size > datalength)
            head_size = datalength;
        pack_len = auth_simple_pack_auth_data((auth_simple_global_data *)self->server.g_data, data, head_size, buffer);
        buffer += pack_len;
        data += head_size;
        len -= head_size;
        local->has_sent_header = 1;
    }
    while ( len > auth_simple_pack_unit_size ) {
        pack_len = auth_simple_pack_data(data, auth_simple_pack_unit_size, buffer);
        buffer += pack_len;
        data += auth_simple_pack_unit_size;
        len -= auth_simple_pack_unit_size;
    }
    if (len > 0) {
        pack_len = auth_simple_pack_data(data, len, buffer);
        buffer += pack_len;
    }
    len = buffer - out_buffer;
    if (*capacity < len) {
        *pplaindata = (char*)realloc(*pplaindata, *capacity = len * 2);
        plaindata = *pplaindata;
    }
    memmove(plaindata, out_buffer, len);
    free(out_buffer);
    return len;
}

int auth_simple_client_post_decrypt(obfs *self, char **pplaindata, int datalength, ssize_t* capacity) {
    char *plaindata = *pplaindata;
    auth_simple_local_data *local = (auth_simple_local_data*)self->l_data;
    uint8_t * recv_buffer = (uint8_t *)local->recv_buffer;
    if (local->recv_buffer_size + datalength > 16384)
        return -1;
    memmove(recv_buffer + local->recv_buffer_size, plaindata, datalength);
    local->recv_buffer_size += datalength;

    char * out_buffer = (char*)malloc(local->recv_buffer_size);
    char * buffer = out_buffer;
    while (local->recv_buffer_size > 2) {
        int length = ((int)recv_buffer[0] << 8) | recv_buffer[1];
        if (length >= 8192 || length < 7) {
            free(out_buffer);
            local->recv_buffer_size = 0;
            return -1;
        }
        if (length > local->recv_buffer_size)
            break;

        int crc = crc32((unsigned char*)recv_buffer, length);
        if (crc != -1) {
            free(out_buffer);
            local->recv_buffer_size = 0;
            return -1;
        }
        int data_size = length - recv_buffer[2] - 6;
        memmove(buffer, recv_buffer + 2 + recv_buffer[2], data_size);
        buffer += data_size;
        memmove(recv_buffer, recv_buffer + length, local->recv_buffer_size -= length);
    }
    int len = buffer - out_buffer;
    if (*capacity < len) {
        *pplaindata = (char*)realloc(*pplaindata, *capacity = len * 2);
        plaindata = *pplaindata;
    }
    memmove(plaindata, out_buffer, len);
    free(out_buffer);
    return len;
}


int auth_sha1_pack_data(char *data, int datalength, char *outdata) {
    unsigned char rand_len = (xorshift128plus() & 0xF) + 1;
    int out_size = rand_len + datalength + 6;
    outdata[0] = out_size >> 8;
    outdata[1] = out_size;
    outdata[2] = rand_len;
    memmove(outdata + rand_len + 2, data, datalength);
    filladler32((unsigned char *)outdata, out_size);
    return out_size;
}

int auth_sha1_pack_auth_data(auth_simple_global_data *global, server_info *server, char *data, int datalength, char *outdata) {
    unsigned char rand_len = (xorshift128plus() & 0x7F) + 1;
    int data_offset = rand_len + 4 + 2;
    int out_size = data_offset + datalength + 12 + 10;
    fillcrc32to((unsigned char *)server->key, server->key_len, (unsigned char *)outdata);
    outdata[4] = out_size >> 8;
    outdata[5] = out_size;
    outdata[6] = rand_len;
    ++global->connection_id;
    if (global->connection_id > 0xFF000000) {
        rand_bytes(global->local_client_id, 4);
        rand_bytes((uint8_t*)&global->connection_id, 4);
        global->connection_id &= 0xFFFFFF;
    }
    time_t t = time(NULL);
    memmove(outdata + data_offset, &t, 4);
    memmove(outdata + data_offset + 4, global->local_client_id, 4);
    memmove(outdata + data_offset + 8, &global->connection_id, 4);
    memmove(outdata + data_offset + 12, data, datalength);
    char hash[ONETIMEAUTH_BYTES * 2];
    ss_onetimeauth(hash, outdata, out_size - 10, server->iv);
    memcpy(outdata + out_size - 10, hash, ONETIMEAUTH_BYTES);
    return out_size;
}

int auth_sha1_client_pre_encrypt(obfs *self, char **pplaindata, int datalength, ssize_t* capacity) {
    char *plaindata = *pplaindata;
    auth_simple_local_data *local = (auth_simple_local_data*)self->l_data;
    char * out_buffer = (char*)malloc(datalength * 2 + 256);
    char * buffer = out_buffer;
    char * data = plaindata;
    int len = datalength;
    int pack_len;
    if (len > 0 && local->has_sent_header == 0) {
        int head_size = get_head_size(plaindata, datalength, 30);
        if (head_size > datalength)
            head_size = datalength;
        pack_len = auth_sha1_pack_auth_data((auth_simple_global_data *)self->server.g_data, &self->server, data, head_size, buffer);
        buffer += pack_len;
        data += head_size;
        len -= head_size;
        local->has_sent_header = 1;
    }
    while ( len > auth_simple_pack_unit_size ) {
        pack_len = auth_sha1_pack_data(data, auth_simple_pack_unit_size, buffer);
        buffer += pack_len;
        data += auth_simple_pack_unit_size;
        len -= auth_simple_pack_unit_size;
    }
    if (len > 0) {
        pack_len = auth_sha1_pack_data(data, len, buffer);
        buffer += pack_len;
    }
    len = buffer - out_buffer;
    if (*capacity < len) {
        *pplaindata = (char*)realloc(*pplaindata, *capacity = len * 2);
        plaindata = *pplaindata;
    }
    memmove(plaindata, out_buffer, len);
    free(out_buffer);
    return len;
}

int auth_sha1_client_post_decrypt(obfs *self, char **pplaindata, int datalength, ssize_t* capacity) {
    char *plaindata = *pplaindata;
    auth_simple_local_data *local = (auth_simple_local_data*)self->l_data;
    uint8_t * recv_buffer = (uint8_t *)local->recv_buffer;
    if (local->recv_buffer_size + datalength > 16384)
        return -1;
    memmove(recv_buffer + local->recv_buffer_size, plaindata, datalength);
    local->recv_buffer_size += datalength;

    char * out_buffer = (char*)malloc(local->recv_buffer_size);
    char * buffer = out_buffer;
    while (local->recv_buffer_size > 2) {
        int length = ((int)recv_buffer[0] << 8) | recv_buffer[1];
        if (length >= 8192 || length < 7) {
            free(out_buffer);
            local->recv_buffer_size = 0;
            return -1;
        }
        if (length > local->recv_buffer_size)
            break;

        if (checkadler32((unsigned char*)recv_buffer, length) == 0) {
            free(out_buffer);
            local->recv_buffer_size = 0;
            return -1;
        }
        int data_size = length - recv_buffer[2] - 6;
        memmove(buffer, recv_buffer + 2 + recv_buffer[2], data_size);
        buffer += data_size;
        memmove(recv_buffer, recv_buffer + length, local->recv_buffer_size -= length);
    }
    int len = buffer - out_buffer;
    if (*capacity < len) {
        *pplaindata = (char*)realloc(*pplaindata, *capacity = len * 2);
        plaindata = *pplaindata;
    }
    memmove(plaindata, out_buffer, len);
    free(out_buffer);
    return len;
}

