#include <stdlib.h>
#include <string.h>
#include "verify.h"
#include "obfsutil.h"
#include "crc32.h"
#include "obfs.h"
#include "encrypt.h"

static int verify_simple_pack_unit_size = 2000;

typedef struct verify_simple_local_data {
    char * recv_buffer;
    int recv_buffer_size;
}verify_simple_local_data;

void verify_simple_local_data_init(verify_simple_local_data* local) {
    local->recv_buffer = (char*) calloc(16384, sizeof(char));
    local->recv_buffer_size = 0;
}

struct obfs_t * verify_simple_new_obfs(void) {
    struct obfs_t * obfs = (struct obfs_t*)calloc(1, sizeof(struct obfs_t));
    obfs->generate_global_init_data = generate_global_init_data;
    obfs->need_feedback = need_feedback_false;
    obfs->get_server_info = get_server_info;
    obfs->set_server_info = set_server_info;
    obfs->dispose = verify_simple_dispose;

    obfs->client_pre_encrypt = verify_simple_client_pre_encrypt;
    obfs->client_post_decrypt = verify_simple_client_post_decrypt;

    obfs->l_data = calloc(1, sizeof(verify_simple_local_data));
    verify_simple_local_data_init((verify_simple_local_data*)obfs->l_data);

    return obfs;
}

void verify_simple_dispose(struct obfs_t *obfs) {
    verify_simple_local_data *local = (verify_simple_local_data*)obfs->l_data;
    if (local->recv_buffer != NULL) {
        free(local->recv_buffer);
        local->recv_buffer = NULL;
    }
    free(local);
    obfs->l_data = NULL;
    dispose_obfs(obfs);
}

int verify_simple_pack_data(char *data, int datalength, char *outdata) {
    unsigned char rand_len = (xorshift128plus() & 0xF) + 1;
    int out_size = rand_len + datalength + 6;
    outdata[0] = (char)(out_size >> 8);
    outdata[1] = (char)out_size;
    rand_bytes((uint8_t *)outdata + 2, rand_len); // note: first byte is the length.
    outdata[2] = (char)rand_len;
    memmove(outdata + 2 + rand_len, data, datalength);
    fillcrc32((unsigned char *)outdata, (unsigned int)out_size);
    return out_size;
}

size_t verify_simple_client_pre_encrypt(struct obfs_t *obfs, char **pplaindata, size_t datalength, size_t *capacity) {
    char *plaindata = *pplaindata;
    //verify_simple_local_data *local = (verify_simple_local_data*)obfs->l_data;
    char * out_buffer = (char*) calloc((size_t)(datalength * 2 + 32), sizeof(char));
    char * buffer = out_buffer;
    char * data = plaindata;
    int len = (int) datalength;
    int pack_len;
    (void)obfs;
    while ( len > verify_simple_pack_unit_size ) {
        pack_len = verify_simple_pack_data(data, verify_simple_pack_unit_size, buffer);
        buffer += pack_len;
        data += verify_simple_pack_unit_size;
        len -= verify_simple_pack_unit_size;
    }
    if (len > 0) {
        pack_len = verify_simple_pack_data(data, len, buffer);
        buffer += pack_len;
    }
    len = (int)(buffer - out_buffer);
    if ((int)*capacity < len) {
        *pplaindata = (char*)realloc(*pplaindata, *capacity = (size_t)(len * 2));
        plaindata = *pplaindata;
    }
    memmove(plaindata, out_buffer, len);
    free(out_buffer);
    return len;
}

ssize_t verify_simple_client_post_decrypt(struct obfs_t *obfs, char **pplaindata, int datalength, size_t *capacity) {
    char *plaindata = *pplaindata;
    verify_simple_local_data *local = (verify_simple_local_data*)obfs->l_data;
    uint8_t * recv_buffer = (uint8_t *)local->recv_buffer;
    char * out_buffer;
    char * buffer;
    int len;

    if (local->recv_buffer_size + datalength > 16384)
        return -1;
    memmove(recv_buffer + local->recv_buffer_size, plaindata, datalength);
    local->recv_buffer_size += datalength;

    out_buffer = (char*) calloc((size_t)local->recv_buffer_size, sizeof(char));
    buffer = out_buffer;
    while (local->recv_buffer_size > 2) {
        int length = ((int)recv_buffer[0] << 8) | recv_buffer[1];
        int crc;
        int data_size;

        if (length >= 8192 || length < 7) {
            free(out_buffer);
            local->recv_buffer_size = 0;
            return -1;
        }
        if (length > local->recv_buffer_size)
            break;

        crc = (int)crc32_imp((unsigned char*)recv_buffer, (unsigned int)length);
        if (crc != -1) {
            free(out_buffer);
            local->recv_buffer_size = 0;
            return -1;
        }
        data_size = length - recv_buffer[2] - 6;
        memmove(buffer, recv_buffer + 2 + recv_buffer[2], data_size);
        buffer += data_size;
        memmove(recv_buffer, recv_buffer + length, local->recv_buffer_size -= length);
    }
    len = (int)(buffer - out_buffer);
    if ((int)*capacity < len) {
        *pplaindata = (char*)realloc(*pplaindata, *capacity = (size_t)(len * 2));
        plaindata = *pplaindata;
    }
    memmove(plaindata, out_buffer, len);
    free(out_buffer);
    return len;
}

