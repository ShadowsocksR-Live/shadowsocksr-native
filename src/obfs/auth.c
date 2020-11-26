#include <string.h>
#include <time.h>
#include <unistd.h>
#include <assert.h>
#include "auth.h"
#include "obfsutil.h"
#include "crc32.h"
#include "base64.h"
#include "encrypt.h"
#include "obfs.h"
#include "ssrbuffer.h"
#include "strtrim.h"
#if defined(WIN32) || defined(_WIN32)
#include <winsock2.h>
#else
#include <netinet/in.h>
#endif

struct buffer_t * auth_sha1_v4_server_pre_encrypt(struct obfs_t *obfs, const struct buffer_t *buf);
struct buffer_t * auth_sha1_v4_server_post_decrypt(struct obfs_t *obfs, struct buffer_t *buf, bool *need_feedback);

static size_t auth_simple_pack_unit_size = 2000;
typedef size_t (*hmac_with_key_func)(uint8_t auth[SHA1_BYTES], const struct buffer_t *msg, const struct buffer_t *key);
typedef size_t (*hash_func)(uint8_t *auth, const uint8_t *msg, size_t msg_len);

typedef struct _auth_simple_global_data {
    uint8_t local_client_id[8];
    uint32_t connection_id;
} auth_simple_global_data;

typedef struct _auth_simple_local_data {
    int has_sent_header;
    struct buffer_t * recv_buffer;
    uint32_t recv_id;
    uint32_t pack_id;
    const char * salt;
    struct buffer_t *user_key;
    char uid[4];
    hmac_with_key_func hmac;
    hash_func hash;
    int hash_len;
    size_t last_data_len;
    size_t unit_len;
    bool has_recv_header;
    size_t extra_wait_size;
    int max_time_dif;
    uint32_t client_id;
    uint32_t connection_id;
} auth_simple_local_data;

auth_simple_local_data * auth_simple_local_data_init(void) {
    auth_simple_local_data *local = (auth_simple_local_data *)calloc(1, sizeof(*local));
    if (local == NULL) { return NULL; }

    local->has_sent_header = 0;
    local->recv_buffer = buffer_create(16384);
    local->recv_id = 1;
    local->pack_id = 1;
    local->salt = "";
    local->user_key = buffer_create(SSR_BUFF_SIZE);
    local->hmac = 0;
    local->hash = 0;
    local->hash_len = 0;
    local->unit_len = 2000; // 8100
    local->has_recv_header = false;
    {
        uint16_t extra_wait_size;
        rand_bytes((uint8_t *)&extra_wait_size, sizeof(extra_wait_size));
        local->extra_wait_size = (size_t) (extra_wait_size % 1024);
    }
    local->max_time_dif = 60 * 60 * 24;

    return local;
}

static void * auth_simple_generate_global_init_data(void) {
    auth_simple_global_data *global = (auth_simple_global_data*)calloc(1, sizeof(auth_simple_global_data));
    if (global == NULL) { return NULL; }
    rand_bytes(global->local_client_id, 8);
    rand_bytes((uint8_t*)&global->connection_id, 4);
    global->connection_id &= 0xFFFFFF;
    return global;
}

struct obfs_t * auth_simple_new_obfs(void) {
    struct obfs_t * obfs = (struct obfs_t*)calloc(1, sizeof(struct obfs_t));
    if (obfs == NULL) { return NULL; }
    obfs->generate_global_init_data = auth_simple_generate_global_init_data;
    obfs->need_feedback = need_feedback_false;
    obfs->get_server_info = get_server_info;
    obfs->set_server_info = set_server_info;
    obfs->dispose = auth_simple_dispose;

    obfs->client_pre_encrypt = auth_simple_client_pre_encrypt;
    obfs->client_post_decrypt = auth_simple_client_post_decrypt;

    obfs->l_data = auth_simple_local_data_init();

    return obfs;
}

struct obfs_t * auth_sha1_new_obfs(void) {
    struct obfs_t *obfs = auth_simple_new_obfs();
    if (obfs == NULL) { return NULL; }

    obfs->generate_global_init_data = auth_simple_generate_global_init_data;
    obfs->get_overhead = get_overhead;
    obfs->need_feedback = need_feedback_false;
    obfs->get_server_info = get_server_info;
    obfs->set_server_info = set_server_info;
    obfs->dispose = auth_simple_dispose;

    obfs->client_pre_encrypt = auth_sha1_client_pre_encrypt;
    obfs->client_post_decrypt = auth_sha1_client_post_decrypt;

    return obfs;
}

struct obfs_t * auth_sha1_v2_new_obfs(void) {
    struct obfs_t *obfs = auth_simple_new_obfs();

    obfs->generate_global_init_data = auth_simple_generate_global_init_data;
    obfs->get_overhead = get_overhead;
    obfs->need_feedback = need_feedback_true;
    obfs->get_server_info = get_server_info;
    obfs->set_server_info = set_server_info;
    obfs->dispose = auth_simple_dispose;

    obfs->client_pre_encrypt = auth_sha1_v2_client_pre_encrypt;
    obfs->client_post_decrypt = auth_sha1_v2_client_post_decrypt;

    return obfs;
}

struct obfs_t * auth_sha1_v4_new_obfs(void) {
    struct obfs_t *obfs = auth_simple_new_obfs();
    auth_simple_local_data *local = (auth_simple_local_data *) obfs->l_data;

    local->salt = "auth_sha1_v4";

    obfs->generate_global_init_data = auth_simple_generate_global_init_data;
    obfs->get_overhead = get_overhead;
    obfs->need_feedback = need_feedback_true;
    obfs->get_server_info = get_server_info;
    obfs->set_server_info = set_server_info;
    obfs->dispose = auth_simple_dispose;

    obfs->client_pre_encrypt = auth_sha1_v4_client_pre_encrypt;
    obfs->client_post_decrypt = auth_sha1_v4_client_post_decrypt;

    obfs->server_pre_encrypt = auth_sha1_v4_server_pre_encrypt;
    obfs->server_post_decrypt = auth_sha1_v4_server_post_decrypt;

    return obfs;
}

struct obfs_t * auth_aes128_md5_new_obfs(void) {
    struct obfs_t *obfs = (struct obfs_t *)calloc(1, sizeof(struct obfs_t));
    auth_simple_local_data *l_data;

    if (obfs == NULL) { return NULL; }

    obfs->generate_global_init_data = auth_simple_generate_global_init_data;
    obfs->get_overhead = auth_aes128_sha1_get_overhead;
    obfs->need_feedback = need_feedback_true;
    obfs->get_server_info = get_server_info;
    obfs->set_server_info = set_server_info;
    obfs->dispose = auth_simple_dispose;

    obfs->client_pre_encrypt = auth_aes128_sha1_client_pre_encrypt;
    obfs->client_post_decrypt = auth_aes128_sha1_client_post_decrypt;

    obfs->server_pre_encrypt = auth_aes128_sha1_server_pre_encrypt;
    obfs->server_encode = generic_server_encode;
    obfs->server_decode = generic_server_decode;
    obfs->server_post_decrypt = auth_aes128_sha1_server_post_decrypt;

    l_data = auth_simple_local_data_init();
    l_data->hmac = ss_md5_hmac_with_key;
    l_data->hash = ss_md5_hash_func;
    l_data->hash_len = 16;
    l_data->salt = "auth_aes128_md5";

    obfs->l_data = l_data;

    return obfs;
}

struct obfs_t * auth_aes128_sha1_new_obfs(void) {
    struct obfs_t *obfs = auth_aes128_md5_new_obfs();
    auth_simple_local_data *l_data;

    l_data = (auth_simple_local_data*)obfs->l_data;

    l_data->hmac = ss_sha1_hmac_with_key;
    l_data->hash = ss_sha1_hash_func;
    l_data->hash_len = 20;
    l_data->salt = "auth_aes128_sha1";
    return obfs;
}

size_t
auth_aes128_sha1_get_overhead(struct obfs_t *obfs)
{
    (void)obfs;
    return 9;
}

static struct buffer_t * auth_aes128_not_match_return(struct obfs_t *obfs, struct buffer_t *buf, bool *feedback) {
    auth_simple_local_data *local = (auth_simple_local_data*)obfs->l_data;
    obfs->server_info.overhead = 0;
    if (feedback) { *feedback = false; }
    if (local->salt && strlen(local->salt)) {
        struct buffer_t *ret;
        uint8_t *tmp = (uint8_t *) calloc(SSR_BUFF_SIZE+1, sizeof(uint8_t));
        assert(tmp);
        memset(tmp, 'E', SSR_BUFF_SIZE);
        ret = buffer_create_from(tmp, SSR_BUFF_SIZE+1);
        free(tmp);
        return ret;
    }
    return buffer_clone(buf);
}

void
auth_simple_dispose(struct obfs_t *obfs)
{
    auth_simple_local_data *local = (auth_simple_local_data*)obfs->l_data;
    buffer_release(local->recv_buffer);
    buffer_release(local->user_key);
    free(local);
    obfs->l_data = NULL;
    dispose_obfs(obfs);
}

static size_t
auth_simple_pack_data(const uint8_t *data, size_t datalength, uint8_t *outdata)
{
    unsigned char rand_len = (xorshift128plus() & 0xF) + 1;
    size_t out_size = (size_t)rand_len + datalength + 6;
    outdata[0] = (uint8_t)(out_size >> 8);
    outdata[1] = (uint8_t)(out_size);
    outdata[2] = (uint8_t)(rand_len);
    memmove(outdata + rand_len + 2, data, datalength);
    fillcrc32((unsigned char *)outdata, out_size);
    return out_size;
}

size_t
auth_simple_pack_auth_data(auth_simple_global_data *global, char *data, size_t datalength, char *outdata)
{
    time_t t;
    unsigned char rand_len = (xorshift128plus() & 0xF) + 1;
    size_t out_size = rand_len + datalength + 6 + 12;
    outdata[0] = (char)(out_size >> 8);
    outdata[1] = (char)(out_size);
    outdata[2] = (char)(rand_len);
    ++global->connection_id;
    if (global->connection_id > 0xFF000000) {
        rand_bytes(global->local_client_id, 8);
        rand_bytes((uint8_t*)&global->connection_id, 4);
        global->connection_id &= 0xFFFFFF;
    }
    t = time(NULL);
    memintcopy_lt(outdata + rand_len + 2, (uint32_t)t);
    memmove(outdata + rand_len + 2 + 4, global->local_client_id, 4);
    memintcopy_lt(outdata + rand_len + 2 + 8, global->connection_id);
    memmove(outdata + rand_len + 2 + 12, data, datalength);
    fillcrc32((unsigned char *)outdata, (unsigned int)out_size);
    return out_size;
}

size_t
auth_simple_client_pre_encrypt(struct obfs_t *obfs, char **pplaindata, size_t datalength, size_t* capacity)
{
    char *plaindata = *pplaindata;
    auth_simple_local_data *local = (auth_simple_local_data*)obfs->l_data;
    char * out_buffer = (char*)calloc((size_t)(datalength * 2 + 64), sizeof(char));
    char * buffer = out_buffer;
    char * data = plaindata;
    size_t len = datalength;
    size_t pack_len;
    if (len > 0 && local->has_sent_header == 0) {
        size_t head_size = get_s5_head_size((const uint8_t *)plaindata, datalength, 30);
        if (head_size > datalength) {
            head_size = datalength;
        }
        pack_len = auth_simple_pack_auth_data((auth_simple_global_data *)obfs->server_info.g_data, data, head_size, buffer);
        buffer += pack_len;
        data += head_size;
        len -= head_size;
        local->has_sent_header = 1;
    }
    while ( len > auth_simple_pack_unit_size ) {
        pack_len = auth_simple_pack_data((uint8_t *)data, auth_simple_pack_unit_size, (uint8_t *)buffer);
        buffer += pack_len;
        data += auth_simple_pack_unit_size;
        len -= auth_simple_pack_unit_size;
    }
    if (len > 0) {
        pack_len = auth_simple_pack_data((uint8_t *)data, len, (uint8_t *)buffer);
        buffer += pack_len;
    }
    len = (int)(buffer - out_buffer);
    if ((int)(*capacity) < (int)len) {
        *pplaindata = (char*)realloc(*pplaindata, *capacity = (size_t)(len * 2));
        plaindata = *pplaindata;
    }
    memmove(plaindata, out_buffer, len);
    free(out_buffer);
    return len;
}

ssize_t
auth_simple_client_post_decrypt(struct obfs_t *obfs, char **pplaindata, int datalength, size_t* capacity)
{
    int len;
    char * out_buffer;
    char * buffer;
    char *plaindata = *pplaindata;
    auth_simple_local_data *local = (auth_simple_local_data*)obfs->l_data;
    const uint8_t * recv_buffer = buffer_get_data(local->recv_buffer, NULL);
    if (buffer_get_length(local->recv_buffer) + datalength > 16384) {
        return -1;
    }
    buffer_concatenate(local->recv_buffer, (uint8_t *)plaindata, datalength);

    out_buffer = (char*)calloc(buffer_get_length(local->recv_buffer), sizeof(char));
    buffer = out_buffer;
    while (buffer_get_length(local->recv_buffer) > 2) {
        int crc;
        size_t data_size;
        size_t length = (size_t)ntohs(*(uint16_t *)(recv_buffer + 0)); // ((int)recv_buffer[0] << 8) | recv_buffer[1];
        if (length >= 8192 || length < 7) {
            free(out_buffer);
            buffer_reset(local->recv_buffer);
            return -1;
        }
        if (length > buffer_get_length(local->recv_buffer)) {
            break;
        }
        crc = (int) crc32_imp((unsigned char*)recv_buffer, length);
        if (crc != -1) {
            free(out_buffer);
            buffer_reset(local->recv_buffer);
            return -1;
        }
        data_size = length - recv_buffer[2] - 6;
        memmove(buffer, recv_buffer + 2 + recv_buffer[2], data_size);
        buffer += data_size;
        buffer_shortened_to(local->recv_buffer, length,  buffer_get_length(local->recv_buffer) - length);
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


size_t
auth_sha1_pack_data(char *data, size_t datalength, char *outdata)
{
    unsigned char rand_len = (xorshift128plus() & 0xF) + 1;
    size_t out_size = rand_len + datalength + 6;
    outdata[0] = (char)(out_size >> 8);
    outdata[1] = (char)out_size;
    outdata[2] = (char)rand_len;
    memmove(outdata + rand_len + 2, data, datalength);
    filladler32((unsigned char *)outdata, (unsigned int)out_size);
    return out_size;
}

size_t
auth_sha1_pack_auth_data(auth_simple_global_data *global, struct server_info_t *server, char *data, size_t datalength, char *outdata)
{
    time_t t;
    uint8_t hash[SHA1_BYTES + 1] = { 0 };
    unsigned char rand_len = (xorshift128plus() & 0x7F) + 1;
    size_t data_offset = rand_len + 4 + 2;
    size_t out_size = data_offset + datalength + 12 + OBFS_HMAC_SHA1_LEN;
    fillcrc32to((unsigned char *)server->key, (unsigned int)server->key_len, (unsigned char *)outdata);
    outdata[4] = (char)(out_size >> 8);
    outdata[5] = (char)out_size;
    outdata[6] = (char)rand_len;
    ++global->connection_id;
    if (global->connection_id > 0xFF000000) {
        rand_bytes(global->local_client_id, 8);
        rand_bytes((uint8_t*)&global->connection_id, 4);
        global->connection_id &= 0xFFFFFF;
    }
    t = time(NULL);
    memintcopy_lt(outdata + data_offset, (uint32_t)t);
    memmove(outdata + data_offset + 4, global->local_client_id, 4);
    memintcopy_lt(outdata + data_offset + 8, global->connection_id);
    memmove(outdata + data_offset + 12, data, datalength);
    ss_sha1_hmac(hash, (uint8_t *)outdata, out_size - OBFS_HMAC_SHA1_LEN, server->iv, server->iv_len, server->key, server->key_len);
    memcpy(outdata + out_size - OBFS_HMAC_SHA1_LEN, hash, OBFS_HMAC_SHA1_LEN);
    return out_size;
}

size_t
auth_sha1_client_pre_encrypt(struct obfs_t *obfs, char **pplaindata, size_t datalength, size_t* capacity)
{
    char *plaindata = *pplaindata;
    auth_simple_local_data *local = (auth_simple_local_data*)obfs->l_data;
    char * out_buffer = (char*)calloc((size_t)(datalength * 2 + 256), sizeof(char));
    char * buffer = out_buffer;
    char * data = plaindata;
    size_t len = datalength;
    size_t pack_len;
    if (len > 0 && local->has_sent_header == 0) {
        size_t head_size = get_s5_head_size((const uint8_t *)plaindata, datalength, 30);
        if (head_size > datalength) {
            head_size = datalength;
        }
        pack_len = auth_sha1_pack_auth_data((auth_simple_global_data *)obfs->server_info.g_data, &obfs->server_info, data, head_size, buffer);
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
    len = (int)(buffer - out_buffer);
    if ((int)*capacity < (int)len) {
        *pplaindata = (char*)realloc(*pplaindata, *capacity = (size_t)(len * 2));
        plaindata = *pplaindata;
    }
    memmove(plaindata, out_buffer, len);
    free(out_buffer);
    return len;
}

ssize_t
auth_sha1_client_post_decrypt(struct obfs_t *obfs, char **pplaindata, int datalength, size_t* capacity)
{
    int len;
    char * buffer;
    char * out_buffer;
    char *plaindata = *pplaindata;
    auth_simple_local_data *local = (auth_simple_local_data*)obfs->l_data;
    if (buffer_get_length(local->recv_buffer) + datalength > 16384) {
        return -1;
    }
    buffer_concatenate(local->recv_buffer, (const uint8_t*)plaindata, datalength);

    out_buffer = (char*)calloc((size_t)buffer_get_length(local->recv_buffer), sizeof(char));
    buffer = out_buffer;
    while (buffer_get_length(local->recv_buffer) > 2) {
        size_t pos;
        size_t data_size;
        const uint8_t * recv_buffer = buffer_get_data(local->recv_buffer, NULL);
        size_t length = (size_t)ntohs(*(uint16_t *)(recv_buffer + 0)); // ((int)recv_buffer[0] << 8) | recv_buffer[1];
        if (length >= 8192 || length < 7) {
            free(out_buffer);
            buffer_reset(local->recv_buffer);
            return -1;
        }
        if (length > buffer_get_length(local->recv_buffer)) {
            break;
        }
        if (checkadler32((unsigned char*)recv_buffer, (unsigned int)length) == false) {
            free(out_buffer);
            buffer_reset(local->recv_buffer);
            return -1;
        }
        pos = recv_buffer[2] + 2;
        data_size = length - pos - 4;
        memmove(buffer, recv_buffer + pos, data_size);
        buffer += data_size;
        buffer_shortened_to(local->recv_buffer, length, buffer_get_length(local->recv_buffer)-length);
    }
    len = (int)(buffer - out_buffer);
    if ((int)*capacity < len) {
        *pplaindata = (char*)realloc(*pplaindata, *capacity = (size_t)(len * 2));
        plaindata = *pplaindata;
    }
    memmove(plaindata, out_buffer, len);
    free(out_buffer);
    return (ssize_t)len;
}

size_t
auth_sha1_v2_pack_data(char *data, size_t datalength, char *outdata)
{
    unsigned int rand_len = (datalength > 1300 ? 0 : datalength > 400 ? (xorshift128plus() & 0x7F) : (xorshift128plus() & 0x3FF)) + 1;
    size_t out_size = (size_t)rand_len + datalength + 6;
    outdata[0] = (char)(out_size >> 8);
    outdata[1] = (char)out_size;
    if (rand_len < 128) {
        outdata[2] = (char)rand_len;
    } else {
        outdata[2] = (char)0xFF;
        outdata[3] = (char)(rand_len >> 8);
        outdata[4] = (char)rand_len;
    }
    memmove(outdata + rand_len + 2, data, datalength);
    filladler32((unsigned char *)outdata, (unsigned int)out_size);
    return out_size;
}

size_t
auth_sha1_v2_pack_auth_data(auth_simple_global_data *global, struct server_info_t *server, char *data, size_t datalength, char *outdata)
{
    uint8_t hash[SHA1_BYTES + 1] = { 0 };
    unsigned int rand_len = (datalength > 1300 ? 0 : datalength > 400 ? (xorshift128plus() & 0x7F) : (xorshift128plus() & 0x3FF)) + 1;
    size_t data_offset = (size_t)rand_len + 4 + 2;
    size_t out_size = data_offset + datalength + 12 + OBFS_HMAC_SHA1_LEN;
    const char* salt = "auth_sha1_v2";
    int salt_len = (int) strlen(salt);
    unsigned char *crc_salt = (unsigned char*)calloc((size_t)salt_len + server->key_len, sizeof(char));
    memcpy(crc_salt, salt, salt_len);
    memcpy(crc_salt + salt_len, server->key, server->key_len);
    fillcrc32to(crc_salt, (unsigned int)((size_t)salt_len + server->key_len), (unsigned char *)outdata);
    free(crc_salt);
    outdata[4] = (char)(out_size >> 8);
    outdata[5] = (char)out_size;
    if (rand_len < 128) {
        outdata[6] = (char)rand_len;
    } else {
        outdata[6] = (char)0xFF;
        outdata[7] = (char)(rand_len >> 8);
        outdata[8] = (char)rand_len;
    }
    ++global->connection_id;
    if (global->connection_id > 0xFF000000) {
        rand_bytes(global->local_client_id, 8);
        rand_bytes((uint8_t*)&global->connection_id, 4);
        global->connection_id &= 0xFFFFFF;
    }
    memmove(outdata + data_offset, global->local_client_id, 8);
    memintcopy_lt(outdata + data_offset + 8, global->connection_id);
    memmove(outdata + data_offset + 12, data, datalength);
    ss_sha1_hmac(hash, (uint8_t *)outdata, out_size - OBFS_HMAC_SHA1_LEN, server->iv, server->iv_len, server->key, server->key_len);
    memcpy(outdata + out_size - OBFS_HMAC_SHA1_LEN, hash, OBFS_HMAC_SHA1_LEN);
    return out_size;
}

size_t
auth_sha1_v2_client_pre_encrypt(struct obfs_t *obfs, char **pplaindata, size_t datalength, size_t* capacity)
{
    char *plaindata = *pplaindata;
    auth_simple_local_data *local = (auth_simple_local_data*)obfs->l_data;
    auth_simple_global_data *g_data = (auth_simple_global_data *)obfs->server_info.g_data;
    char * out_buffer = (char*)calloc((size_t)(datalength * 2 + (SSR_BUFF_SIZE * 2)), sizeof(char));
    char * buffer = out_buffer;
    char * data = plaindata;
    size_t len = datalength;
    size_t pack_len;
    if (len > 0 && local->has_sent_header == 0) {
        size_t head_size = get_s5_head_size((const uint8_t *)plaindata, datalength, 30);
        if (head_size > datalength) {
            head_size = datalength;
        }
        pack_len = auth_sha1_v2_pack_auth_data(g_data, &obfs->server_info, data, head_size, buffer);
        buffer += pack_len;
        data += head_size;
        len -= head_size;
        local->has_sent_header = 1;
    }
    while ( len > auth_simple_pack_unit_size ) {
        pack_len = auth_sha1_v2_pack_data(data, auth_simple_pack_unit_size, buffer);
        buffer += pack_len;
        data += auth_simple_pack_unit_size;
        len -= auth_simple_pack_unit_size;
    }
    if (len > 0) {
        pack_len = auth_sha1_v2_pack_data(data, len, buffer);
        buffer += pack_len;
    }
    len = (int)(buffer - out_buffer);
    if ((int)*capacity < (int)len) {
        *pplaindata = (char*)realloc(*pplaindata, *capacity = (size_t)(len * 2));
        plaindata = *pplaindata;
    }
    memmove(plaindata, out_buffer, len);
    free(out_buffer);
    return len;
}

ssize_t
auth_sha1_v2_client_post_decrypt(struct obfs_t *obfs, char **pplaindata, int datalength, size_t* capacity)
{
    int len;
    char error;
    char * buffer;
    char * out_buffer;
    char *plaindata = *pplaindata;
    auth_simple_local_data *local = (auth_simple_local_data*)obfs->l_data;
    if (buffer_get_length(local->recv_buffer) + datalength > 16384) {
        return -1;
    }
    buffer_concatenate(local->recv_buffer, (const uint8_t*)plaindata, datalength);

    out_buffer = (char*)calloc((size_t)buffer_get_length(local->recv_buffer), sizeof(char));
    buffer = out_buffer;
    error = 0;
    while (buffer_get_length(local->recv_buffer) > 2) {
        size_t data_size;
        size_t pos;
        const uint8_t * recv_buffer = buffer_get_data(local->recv_buffer, NULL);
        size_t length = (size_t)ntohs(*(uint16_t *)(recv_buffer + 0)); //((int)recv_buffer[0] << 8) | recv_buffer[1];
        if (length >= 8192 || length < 7) {
            buffer_reset(local->recv_buffer);
            error = 1;
            break;
        }
        if (length > buffer_get_length(local->recv_buffer)) {
            break;
        }
        if (checkadler32((unsigned char*)recv_buffer, length) == false) {
            buffer_reset(local->recv_buffer);
            error = 1;
            break;
        }
        pos = recv_buffer[2];
        if (pos < 255) {
            pos += 2;
        } else {
            pos = ((recv_buffer[3] << 8) | recv_buffer[4]) + 2;
        }
        data_size = length - pos - 4;
        memmove(buffer, recv_buffer + pos, data_size);
        buffer += data_size;
        buffer_shortened_to(local->recv_buffer, length, buffer_get_length(local->recv_buffer) - length);
    }
    if (error == 0) {
        len = (int)(buffer - out_buffer);
        if ((int)*capacity < len) {
            *pplaindata = (char*)realloc(*pplaindata, *capacity = (size_t)(len * 2));
            plaindata = *pplaindata;
        }
        memmove(plaindata, out_buffer, len);
    } else {
        len = -1;
    }
    free(out_buffer);
    return (ssize_t) len;
}

size_t
auth_sha1_v4_pack_data(const char *data, size_t datalength, char *outdata)
{
    uint32_t crc_val;
    unsigned int rand_len = (datalength > 1300 ? 0 : datalength > 400 ? (xorshift128plus() & 0x7F) : (xorshift128plus() & 0x3FF)) + 1;
    size_t out_size = (size_t)rand_len + datalength + 8;
    outdata[0] = (char)(out_size >> 8);
    outdata[1] = (char)out_size;
    crc_val = crc32_imp((unsigned char*)outdata, 2);
    outdata[2] = (char)crc_val;
    outdata[3] = (char)(crc_val >> 8);
    if (rand_len < 128) {
        outdata[4] = (char)rand_len;
    } else {
        outdata[4] = (char)0xFF;
        outdata[5] = (char)(rand_len >> 8);
        outdata[6] = (char)rand_len;
    }
    memmove(outdata + rand_len + 4, data, datalength);
    filladler32((unsigned char *)outdata, (unsigned int)out_size);
    return out_size;
}

size_t
auth_sha1_v4_pack_auth_data(auth_simple_global_data *global, struct server_info_t *server, char *data, size_t datalength, char *outdata)
{
    uint8_t hash[SHA1_BYTES + 1] = { 0 };
    time_t t;
    unsigned int rand_len = (datalength > 1300 ? 0 : datalength > 400 ? (xorshift128plus() & 0x7F) : (xorshift128plus() & 0x3FF)) + 1;
    size_t data_offset = (size_t)rand_len + 4 + 2;
    size_t out_size = data_offset + datalength + 12 + OBFS_HMAC_SHA1_LEN;
    const char* salt = "auth_sha1_v4";
    size_t salt_len = (size_t)strlen(salt);
    unsigned char *crc_salt = (unsigned char*)calloc((size_t)salt_len + server->key_len + 2, sizeof(unsigned char));
    crc_salt[0] = (unsigned char)(outdata[0] = (char)(out_size >> 8));
    crc_salt[1] = (unsigned char)(outdata[1] = (char)out_size);

    memcpy(crc_salt + 2, salt, salt_len);
    memcpy(crc_salt + salt_len + 2, server->key, server->key_len);
    fillcrc32to(crc_salt, (unsigned int)((size_t)salt_len + server->key_len + 2), (unsigned char *)outdata + 2);
    free(crc_salt);
    if (rand_len < 128) {
        outdata[6] = (char)rand_len;
    } else {
        outdata[6] = (char)0xFF;
        outdata[7] = (char)(rand_len >> 8);
        outdata[8] = (char)rand_len;
    }
    ++global->connection_id;
    if (global->connection_id > 0xFF000000) {
        rand_bytes(global->local_client_id, 8);
        rand_bytes((uint8_t*)&global->connection_id, 4);
        global->connection_id &= 0xFFFFFF;
    }
    t = time(NULL);
    memintcopy_lt(outdata + data_offset, (uint32_t)t);
    memmove(outdata + data_offset + 4, global->local_client_id, 4);
    memintcopy_lt(outdata + data_offset + 8, global->connection_id);
    memmove(outdata + data_offset + 12, data, datalength);
    ss_sha1_hmac(hash, (uint8_t *)outdata, out_size - OBFS_HMAC_SHA1_LEN, server->iv, server->iv_len, server->key, server->key_len);
    memcpy(outdata + out_size - OBFS_HMAC_SHA1_LEN, hash, OBFS_HMAC_SHA1_LEN);
    return out_size;
}

size_t
auth_sha1_v4_client_pre_encrypt(struct obfs_t *obfs, char **pplaindata, size_t datalength, size_t* capacity)
{
    char *plaindata = *pplaindata;
    auth_simple_local_data *local = (auth_simple_local_data*)obfs->l_data;
    auth_simple_global_data *g_data = (auth_simple_global_data *)obfs->server_info.g_data;
    char * out_buffer = (char*)calloc((size_t)(datalength * 2 + (SSR_BUFF_SIZE * 2)), sizeof(char));
    char * buffer = out_buffer;
    char * data = plaindata;
    size_t len = datalength;
    size_t pack_len;
    if (len > 0 && local->has_sent_header == 0) {
        size_t head_size = get_s5_head_size((const uint8_t *)plaindata, datalength, 30);
        if (head_size > datalength) {
            head_size = datalength;
        }
        pack_len = auth_sha1_v4_pack_auth_data(g_data, &obfs->server_info, data, head_size, buffer);
        buffer += pack_len;
        data += head_size;
        len -= head_size;
        local->has_sent_header = 1;
    }
    while ( len > auth_simple_pack_unit_size ) {
        pack_len = auth_sha1_v4_pack_data(data, auth_simple_pack_unit_size, buffer);
        buffer += pack_len;
        data += auth_simple_pack_unit_size;
        len -= auth_simple_pack_unit_size;
    }
    if (len > 0) {
        pack_len = auth_sha1_v4_pack_data(data, len, buffer);
        buffer += pack_len;
    }
    len = (int)(buffer - out_buffer);
    if ((int)*capacity < (int)len) {
        *pplaindata = (char*)realloc(*pplaindata, *capacity = (size_t)(len * 2));
        plaindata = *pplaindata;
    }
    memmove(plaindata, out_buffer, len);
    free(out_buffer);
    return len;
}

ssize_t
auth_sha1_v4_client_post_decrypt(struct obfs_t *obfs, char **pplaindata, int datalength, size_t* capacity)
{
    int len;
    char error;
    char * buffer;
    char * out_buffer;
    char *plaindata = *pplaindata;
    auth_simple_local_data *local = (auth_simple_local_data*)obfs->l_data;
    if (buffer_get_length(local->recv_buffer) + datalength > 16384) {
        return -1;
    }
    buffer_concatenate(local->recv_buffer, (const uint8_t*)plaindata, datalength);

    out_buffer = (char*)calloc((size_t)buffer_get_length(local->recv_buffer), sizeof(char));
    buffer = out_buffer;
    error = 0;
    while (buffer_get_length(local->recv_buffer) > 4) {
        size_t length;
        const uint8_t * recv_buffer = buffer_get_data(local->recv_buffer, NULL);
        size_t pos;
        size_t data_size;
        uint32_t crc_val = crc32_imp((unsigned char*)recv_buffer, 2);
        if ((((uint32_t)recv_buffer[3] << 8) | recv_buffer[2]) != (crc_val & 0xffff)) {
            buffer_reset(local->recv_buffer);
            error = 1;
            break;
        }
        length = (size_t)ntohs(*(uint16_t *)(recv_buffer + 0)); // ((int)recv_buffer[0] << 8) | recv_buffer[1];
        if (length >= 8192 || length < 7) {
            buffer_reset(local->recv_buffer);
            error = 1;
            break;
        }
        if (length > buffer_get_length(local->recv_buffer)) {
            break;
        }
        if (checkadler32((unsigned char*)recv_buffer, length) == false) {
            buffer_reset(local->recv_buffer);
            error = 1;
            break;
        }
        pos = recv_buffer[4];
        if (pos < 255) {
            pos += 4;
        } else {
            pos = (((int)recv_buffer[5] << 8) | recv_buffer[6]) + 4;
        }
        data_size = length - pos - 4;
        memmove(buffer, recv_buffer + pos, data_size);
        buffer += data_size;
        buffer_shortened_to(local->recv_buffer, length, buffer_get_length(local->recv_buffer) - length);
    }
    if (error == 0) {
        len = (int)(buffer - out_buffer);
        if ((int)*capacity < len) {
            *pplaindata = (char*)realloc(*pplaindata, *capacity = (size_t)(len * 2));
            plaindata = *pplaindata;
        }
        memmove(plaindata, out_buffer, len);
    } else {
        len = -1;
    }
    free(out_buffer);
    return (ssize_t)len;
}

struct buffer_t * auth_sha1_v4_server_pre_encrypt(struct obfs_t *obfs, const struct buffer_t *buf) {
    struct buffer_t *ret;
    struct buffer_t *in_buf = buffer_clone(buf);
    auth_simple_local_data *local = (auth_simple_local_data*)obfs->l_data;
    char * buffer0 = (char *) calloc(buffer_get_length(buf) * 2 + SSR_BUFF_SIZE * 2, sizeof(*buffer0));
    char * buffer = buffer0;
    size_t pack_len, ret_len = 0;

    while(buffer_get_length(in_buf) > local->unit_len) {
        pack_len = auth_sha1_v4_pack_data((const char *) buffer_get_data(in_buf, NULL), local->unit_len, buffer);
        buffer += pack_len;
        ret_len += pack_len;
        buffer_shortened_to(in_buf, local->unit_len, buffer_get_length(in_buf) - local->unit_len);
    }
    pack_len = auth_sha1_v4_pack_data((const char *)buffer_get_data(in_buf, NULL), buffer_get_length(in_buf), buffer);
    ret_len += pack_len;

    ret = buffer_create_from((const uint8_t*)buffer0, ret_len);
    buffer_release(in_buf);
    free(buffer0);
    return ret;
}

struct buffer_t * auth_sha1_v4_server_post_decrypt(struct obfs_t *obfs, struct buffer_t *buf, bool *need_feedback) {
    auth_simple_local_data *local = (auth_simple_local_data*)obfs->l_data;
    struct server_info_t *server_info = &obfs->server_info;
    bool sendback = false;
    struct buffer_t *out_buf = buffer_create(SSR_BUFF_SIZE);
    do {
        buffer_concatenate2(local->recv_buffer, buf);
        if (local->has_recv_header == false) {
            const uint8_t *buffer = buffer_get_data(local->recv_buffer, NULL);
            struct buffer_t *crc_src;
            uint32_t crc_val;
            uint32_t crc_stock;
            uint16_t length = 0;
            uint8_t sha1data[SHA1_BYTES];
            size_t pos;
            uint32_t utc_time;
            uint32_t client_id;
            uint32_t connection_id;
            int time_diff;

            if (buffer_get_length(local->recv_buffer) <= 6) {
                break;
            }

            crc_src = buffer_create_from(buffer, 2);
            buffer_concatenate(crc_src, (uint8_t *)local->salt, strlen(local->salt));
            buffer_concatenate(crc_src, server_info->key, server_info->key_len);
            crc_val = crc32_imp((unsigned char*) buffer_get_data(crc_src, NULL), buffer_get_length(crc_src));
            buffer_release(crc_src);

            crc_stock = *((uint32_t *)(buffer + 2)); // TODO: ntohl
            if (crc_val != crc_stock) {
                buffer_release(out_buf); out_buf = NULL;
                break;
            }

            length = ntohs(*((uint16_t *)(buffer + 0)));
            if (length > buffer_get_length(local->recv_buffer)) {
                break;
            }

            ss_sha1_hmac(sha1data,
                buffer, length - 10,
                server_info->recv_iv, server_info->recv_iv_len,
                server_info->key, server_info->key_len);
            if (memcmp(sha1data, buffer + length - 10, 10) != 0) {
                // logging.error('auth_sha1_v4 data incorrect auth HMAC-SHA1')
                buffer_release(out_buf); out_buf = NULL;
                break;
            }

            pos = (size_t) (*((uint8_t *)(buffer + 6)));
            if (pos < 255) {
                pos += 6;
            } else {
                pos = (size_t) ntohs(*((uint16_t *)(buffer + 7))) + 6;
            }
            buffer_store(out_buf, buffer + pos, length - 10 - pos);
            if (buffer_get_length(out_buf) < 12) {
                // logging.info('auth_sha1_v4: too short, data %s' % (binascii.hexlify(self.recv_buf),))
                buffer_release(out_buf); out_buf = NULL;
                break;
            }

            utc_time = (*((uint32_t *)(buffer_get_data(out_buf, NULL) + 0))); // TODO: ntohl
            client_id = (*((uint32_t *)(buffer_get_data(out_buf, NULL) + 4))); // TODO: ntohl
            connection_id = (*((uint32_t *)(buffer_get_data(out_buf, NULL) + 8))); // TODO: ntohl
            time_diff = abs((int)time(NULL) - (int)utc_time);
            if (time_diff > local->max_time_dif) {
                // logging.info('auth_sha1_v4: wrong timestamp, time_dif %d, data %s' % (time_dif, binascii.hexlify(out_buf),))
                buffer_release(out_buf); out_buf = NULL;
                break;
            }

            //TODO: check client_id / connection_id to avoid `Replay Attacks`

            buffer_shortened_to(out_buf, 12, buffer_get_length(out_buf) - 12);
            local->client_id = client_id;
            local->connection_id = connection_id;

            buffer_shortened_to(local->recv_buffer, length, buffer_get_length(local->recv_buffer) - length);

            local->has_recv_header = true;
            sendback = true;
        }

        while (buffer_get_length(local->recv_buffer) > 4) {
            const uint8_t *buffer = buffer_get_data(local->recv_buffer, NULL);
            uint16_t crc_val;
            uint16_t crc_stock;
            size_t length;
            size_t pos;
            crc_val = (uint16_t) crc32_imp((unsigned char*)buffer, 2);
            crc_stock = *((uint16_t *)(buffer + 2)); // TODO: ntohs
            if (crc_stock != crc_val) {
                // logging.info('auth_sha1_v4: wrong crc')
                buffer_release(out_buf); out_buf = NULL;
                break;
            }
            length = (size_t) ntohs(*((uint16_t *)(buffer + 0)));
            if (length >= 8192 || length < 7) {
                // logging.info('auth_sha1_v4: over size')
                buffer_reset(local->recv_buffer);
                buffer_release(out_buf); out_buf = NULL;
                break;
            }
            if (length > buffer_get_length(local->recv_buffer)) {
                break;
            }
            if (checkadler32(buffer, length) == false) {
                // logging.info('auth_sha1_v4: checksum error, data %s' % (binascii.hexlify(self.recv_buf[:length]),))
                buffer_reset(local->recv_buffer);
                buffer_release(out_buf); out_buf = NULL;
                break;
            }
            pos = (size_t) (*((uint8_t *)(buffer + 4)));
            if (pos < 255) {
                pos += 4;
            } else {
                pos = (size_t) ntohs(*((uint16_t *)(buffer + 5))) + 4;
            }
            buffer_concatenate(out_buf, buffer + pos, length - 4 - pos);

            if (pos == (length - 4)) {
                sendback = true;
            }

            buffer_shortened_to(local->recv_buffer, length, buffer_get_length(local->recv_buffer) - length);
        }
    } while(0);
    if (need_feedback) { *need_feedback = sendback; }
    //if (out_buf && out_buf->len) {
    //    self.server_info.data.update(self.client_id, self.connection_id)
    //    self.decrypt_packet_num += 1
    //}
    return out_buf;
}

size_t
get_rand_len(size_t datalength, size_t fulldatalength, auth_simple_local_data *local, struct server_info_t *server)
{
    if (datalength > 1300 || (size_t) local->last_data_len > 1300 || fulldatalength >= (size_t)server->buffer_size) {
        return 0;
    }
    if (datalength > 1100) {
        return (size_t) (xorshift128plus() & 0x7F);
    }
    if (datalength > 900) {
        return (size_t) (xorshift128plus() & 0xFF);
    }
    if (datalength > 400) {
        return (size_t) (xorshift128plus() & 0x1FF);
    }
    return (size_t) (xorshift128plus() & 0x3FF);
}

size_t
auth_aes128_sha1_pack_data(const uint8_t *data, size_t datalength, size_t fulldatalength, uint8_t *outdata, struct obfs_t *obfs)
{
    auth_simple_local_data *local = (auth_simple_local_data*)obfs->l_data;
    struct server_info_t *server_info = &obfs->server_info;
    uint8_t key_len;
    uint8_t *key;
    size_t rand_len = get_rand_len(datalength, fulldatalength, local, server_info) + 1;
    size_t out_size = (size_t)rand_len + datalength + 8;

    size_t local_key_len = 0;
    const uint8_t *local_key = buffer_get_data(local->user_key, &local_key_len);

    memcpy(outdata + rand_len + 4, data, datalength);
    outdata[0] = (uint8_t)out_size;
    outdata[1] = (uint8_t)(out_size >> 8);
    key_len = (uint8_t)(local_key_len + 4);
    key = (uint8_t*)calloc(key_len, sizeof(uint8_t));
    assert(key);
    memcpy(key, local_key, local_key_len);
    memintcopy_lt(key + key_len - 4, local->pack_id);

    {
        uint8_t * rnd_data = (uint8_t *) calloc(rand_len * sizeof(uint8_t), sizeof(uint8_t));
        assert(rnd_data);
        rand_bytes(rnd_data, (int)rand_len);
        memcpy(outdata + 4, rnd_data, rand_len);
        free(rnd_data);
    }

    {
        uint8_t hash[SHA1_BYTES + 1] = { 0 };
        struct buffer_t *_msg = buffer_create_from(outdata, 2);
        struct buffer_t *_key = buffer_create_from(key, key_len);
        local->hmac(hash, _msg, _key);
        memcpy(outdata + 2, hash, 2);
        buffer_release(_msg);
        buffer_release(_key);
    }

    if (rand_len < 128) {
        outdata[4] = (char)rand_len;
    } else {
        outdata[4] = (char)0xFF;
        outdata[5] = (char)rand_len;
        outdata[6] = (char)(rand_len >> 8);
    }
    ++local->pack_id;

    {
        uint8_t hash[SHA1_BYTES + 1] = { 0 };
        struct buffer_t *_msg = buffer_create_from(outdata, out_size - 4);
        struct buffer_t *_key = buffer_create_from(key, key_len);
        local->hmac(hash, _msg, _key);
        buffer_release(_msg);
        buffer_release(_key);
        memcpy(outdata + out_size - 4, hash, 4);
    }
    free(key);

    return out_size;
}

static size_t
auth_aes128_sha1_pack_auth_data(auth_simple_global_data *global, struct server_info_t *server, auth_simple_local_data *local, const uint8_t *data, size_t datalength, uint8_t *outdata)
{
    time_t t;
    unsigned int rand_len = (datalength > 400 ? (xorshift128plus() & 0x1FF) : (xorshift128plus() & 0x3FF));
    size_t data_offset = (size_t)rand_len + 16 + 4 + 4 + 7;
    size_t out_size = data_offset + datalength + 4;
    const char* salt = local->salt;

    uint8_t encrypt[24 + 1] = { 0 };
    uint8_t encrypt_data[16] = { 0 };

    uint8_t *key = (uint8_t*)calloc(server->iv_len + server->key_len, sizeof(uint8_t));
    uint8_t key_len = (uint8_t)(server->iv_len + server->key_len);
    memcpy(key, server->iv, server->iv_len);
    memcpy(key + server->iv_len, server->key, server->key_len);

    {
        uint8_t *rnd_data = (uint8_t *) calloc(rand_len, sizeof(uint8_t));
        rand_bytes(rnd_data, (int)rand_len);
        memcpy(outdata + data_offset - rand_len, rnd_data, rand_len);
        free(rnd_data);
    }

    ++global->connection_id;
    if (global->connection_id > 0xFF000000) {
        rand_bytes(global->local_client_id, 8);
        rand_bytes((uint8_t*)&global->connection_id, 4);
        global->connection_id &= 0xFFFFFF;
    }
    t = time(NULL);
    memintcopy_lt(encrypt, (uint32_t)t);
    memcpy(encrypt + 4, global->local_client_id, 4);
    memintcopy_lt(encrypt + 8, global->connection_id);
#if 1
    encrypt[12] = (char)out_size;
    encrypt[13] = (char)(out_size >> 8);
    encrypt[14] = (char)rand_len;
    encrypt[15] = (char)(rand_len >> 8);
#else
    *((uint16_t *)(encrypt + 12)) = htons((uint16_t)out_size); // TODO 
    *((uint16_t *)(encrypt + 14)) = htons((uint16_t)rand_len); // TODO 
#endif

    {
        size_t enc_key_len;
        uint8_t enc_key[16 + 1] = { 0 };
        char encrypt_key_base64[256] = {0};
        if (buffer_get_length(local->user_key) == 0) {
            if(server->param != NULL && server->param[0] != 0) {
                char* param = strdup(server->param);
                char* delim = NULL;
                if (param && ((delim = strchr(param, ':')) != NULL)) {
                    uint8_t hash[SHA1_BYTES + 1] = { 0 };
                    long uid_long;
                    char* key_str = NULL;
                    char* uid_str = param;
                    delim[0] = 0;
                    key_str = delim + 1;
                    uid_str = strtrim(uid_str, trim_type_both, NULL);
                    uid_long = strtol(uid_str, NULL, 10);
                    memintcopy_lt(local->uid, (uint32_t)uid_long);

                    key_str = strtrim(key_str, trim_type_both, NULL);
                    local->hash(hash, (uint8_t*)key_str, (int)strlen(key_str));

                    buffer_store(local->user_key, hash, local->hash_len);
                }
                free(param);
            }
            if (buffer_get_length(local->user_key) == 0) {
                rand_bytes((uint8_t *)local->uid, 4);
                buffer_store(local->user_key, server->key, server->key_len);
            }
        }

        {
            size_t local_key_len = 0;
            const uint8_t *local_key = buffer_get_data(local->user_key, &local_key_len);
            std_base64_encode(local_key, (size_t)local_key_len, (char*)encrypt_key_base64);
        }
        strcat(encrypt_key_base64, salt);

        enc_key_len = strlen(encrypt_key_base64);
        bytes_to_key_with_size((uint8_t *)encrypt_key_base64, enc_key_len, enc_key, 16);

        ss_aes_128_cbc_encrypt(16, encrypt, encrypt_data, enc_key);
        memcpy(encrypt + 4, encrypt_data, 16);
        memcpy(encrypt, local->uid, 4);
    }

    {
        uint8_t hash[SHA1_BYTES + 1] = { 0 };
        struct buffer_t *_msg = buffer_create_from(encrypt, 20);
        struct buffer_t *_key = buffer_create_from(key, key_len);
        local->hmac(hash, _msg, _key);
        buffer_release(_msg);
        buffer_release(_key);
        memcpy(encrypt + 20, hash, 4);
    }

    rand_bytes((uint8_t*)outdata, 1);
    {
        uint8_t hash[SHA1_BYTES + 1] = { 0 };
        struct buffer_t *_msg = buffer_create_from(outdata, 1);
        struct buffer_t *_key = buffer_create_from(key, key_len);
        local->hmac(hash, _msg, _key);
        buffer_release(_msg);
        buffer_release(_key);
        memcpy(outdata + 1, hash, 6);
    }

    memcpy(outdata + 7, encrypt, 24);
    memcpy(outdata + data_offset, data, datalength);

    {
        uint8_t hash[SHA1_BYTES + 1] = { 0 };
        struct buffer_t *_msg = buffer_create_from(outdata, out_size - 4);
        local->hmac(hash, _msg, local->user_key);
        buffer_release(_msg);
        memmove(outdata + out_size - 4, hash, 4);
    }
    free(key);

    return out_size;
}

size_t
auth_aes128_sha1_client_pre_encrypt(struct obfs_t *obfs, char **pplaindata, size_t datalength, size_t* capacity)
{
    uint8_t *plaindata = (uint8_t *)(*pplaindata);
    auth_simple_local_data *local = (auth_simple_local_data*)obfs->l_data;
    auth_simple_global_data *g_data = (auth_simple_global_data *)obfs->server_info.g_data;
    uint8_t * out_buffer = (uint8_t *)calloc((size_t)(datalength * 2 + (SSR_BUFF_SIZE * 2)), sizeof(uint8_t));
    uint8_t * buffer = out_buffer;
    uint8_t * data = plaindata;
    size_t len = datalength;
    size_t pack_len;
    if (len > 0 && local->has_sent_header == 0) {
        size_t head_size = 1200;
        if (head_size > datalength) {
            head_size = datalength;
        }
        pack_len = auth_aes128_sha1_pack_auth_data(g_data, &obfs->server_info, local, data, head_size, buffer);
        buffer += pack_len;
        data += head_size;
        len -= head_size;
        local->has_sent_header = 1;
    }
    while ( len > auth_simple_pack_unit_size ) {
        pack_len = auth_aes128_sha1_pack_data(data, auth_simple_pack_unit_size, datalength, buffer, obfs);
        buffer += pack_len;
        data += auth_simple_pack_unit_size;
        len -= auth_simple_pack_unit_size;
    }
    if (len > 0) {
        pack_len = auth_aes128_sha1_pack_data(data, len, datalength, buffer, obfs);
        buffer += pack_len;
    }
    len = (size_t)(buffer - out_buffer);
    if ((size_t)*capacity < len) {
        *pplaindata = (char*)realloc(*pplaindata, *capacity = (size_t)(len * 2));
        plaindata = (uint8_t *)*pplaindata;
    }
    local->last_data_len = datalength;
    memmove(plaindata, out_buffer, len);
    free(out_buffer);
    return len;
}

ssize_t
auth_aes128_sha1_client_post_decrypt(struct obfs_t *obfs, char **pplaindata, int datalength, size_t* capacity)
{
    int len;
    size_t key_len;
    uint8_t *key;
    char * out_buffer;
    char * buffer;
    char error = 0;
    char *plaindata = *pplaindata;
    auth_simple_local_data *local = (auth_simple_local_data*)obfs->l_data;
    //struct server_info_t *server = (struct server_info_t *)&obfs->server;
    if (buffer_get_length(local->recv_buffer) + datalength > 16384) {
        return -1;
    }
    buffer_concatenate(local->recv_buffer, (const uint8_t*)plaindata, datalength);

    {
        size_t local_key_len = 0;
        const uint8_t *local_key = buffer_get_data(local->user_key, &local_key_len);
        key_len = local_key_len + 4;
        key = (uint8_t*)calloc((size_t)key_len, sizeof(uint8_t));
        memcpy(key, local_key, local_key_len);
    }

    out_buffer = (char*)calloc(buffer_get_length(local->recv_buffer), sizeof(char));
    buffer = out_buffer;
    while (buffer_get_length(local->recv_buffer) > 4) {
        const uint8_t * recv_buffer = buffer_get_data(local->recv_buffer, NULL);
        size_t length;
        size_t pos;
        size_t data_size;
        memintcopy_lt(key + key_len - 4, local->recv_id);

        {
            uint8_t hash[SHA1_BYTES + 1] = { 0 };
            struct buffer_t *_msg = buffer_create_from(recv_buffer, 2);
            struct buffer_t *_key = buffer_create_from(key, key_len);
            local->hmac(hash, _msg, _key);
            buffer_release(_msg);
            buffer_release(_key);

            if (memcmp(hash, recv_buffer + 2, 2)) {
                buffer_reset(local->recv_buffer);
                error = 1;
                break;
            }
        }

        length = ((size_t)recv_buffer[1] << 8) + recv_buffer[0];
        if (length >= 8192 || length < 8) {
            buffer_reset(local->recv_buffer);
            error = 1;
            break;
        }
        if (length > buffer_get_length(local->recv_buffer)) {
            break;
        }

        {
            uint8_t hash[SHA1_BYTES + 1] = { 0 };
            struct buffer_t *_msg = buffer_create_from(recv_buffer, length - 4);
            struct buffer_t *_key = buffer_create_from(key, key_len);
            local->hmac(hash, _msg, _key);
            buffer_release(_msg);
            buffer_release(_key);
            if (memcmp(hash, recv_buffer + length - 4, 4)) {
                buffer_reset(local->recv_buffer);
                error = 1;
                break;
            }
        }

        ++local->recv_id;
        pos = recv_buffer[4];
        if (pos < 255) {
            pos += 4;
        } else {
            pos = (((size_t)recv_buffer[6] << 8) | recv_buffer[5]) + 4;
        }
        data_size = length - pos - 4;
        memmove(buffer, recv_buffer + pos, data_size);
        buffer += data_size;
        buffer_shortened_to(local->recv_buffer, length, buffer_get_length(local->recv_buffer) - length);
    }
    if (error == 0) {
        len = (int)(buffer - out_buffer);
        if ((int)*capacity < len) {
            *pplaindata = (char*)realloc(*pplaindata, *capacity = (size_t)(len * 2));
            plaindata = *pplaindata;
        }
        memmove(plaindata, out_buffer, len);
    } else {
        len = -1;
    }
    free(out_buffer);
    free(key);
    return (ssize_t)len;
}

struct buffer_t * auth_aes128_sha1_server_pre_encrypt(struct obfs_t *obfs, const struct buffer_t *buf) {
    struct buffer_t *ret = NULL;
    auth_simple_local_data *local = (auth_simple_local_data*)obfs->l_data;
    struct buffer_t *buf2 = buffer_clone(buf);
    size_t ogn_data_len = buffer_get_length(buf2);

    uint8_t * out_buffer = (uint8_t *)calloc((size_t)(ogn_data_len * 2 + (SSR_BUFF_SIZE * 2)), sizeof(uint8_t));
    uint8_t * buffer = out_buffer;

    size_t pack_len;
    size_t unit_len = local->unit_len;

    while (buffer_get_length(buf2) > unit_len) {
        pack_len = auth_aes128_sha1_pack_data(buffer_get_data(buf2, NULL), unit_len, ogn_data_len, buffer, obfs);
        buffer += pack_len;
        buffer_shortened_to(buf2, unit_len, buffer_get_length(buf2) - unit_len);
    }
    if (buffer_get_length(buf2) > 0) {
        pack_len = auth_aes128_sha1_pack_data(buffer_get_data(buf2, NULL), buffer_get_length(buf2), ogn_data_len, buffer, obfs);
        buffer += pack_len;
    }
    ret = buffer_create_from(out_buffer, buffer-out_buffer);
    free(out_buffer);
    buffer_release(buf2);
    return ret;
}

struct buffer_t * auth_aes128_sha1_server_encode(struct obfs_t *obfs, const struct buffer_t *buf) {
    // TODO : need implementation future.
    return generic_server_encode(obfs, buf);
}

struct buffer_t * auth_aes128_sha1_server_decode(struct obfs_t *obfs, const struct buffer_t *buf, bool *need_decrypt, bool *need_feedback) {
    // TODO : need implementation future.
    return generic_server_decode(obfs, buf, need_decrypt, need_feedback);
}

struct buffer_t * auth_aes128_sha1_server_post_decrypt(struct obfs_t *obfs, struct buffer_t *buf, bool *need_feedback) {
    struct server_info_t *server_info = &obfs->server_info;
    struct buffer_t *out_buf = NULL;
    struct buffer_t *mac_key = NULL;
    uint8_t sha1data[SHA1_BYTES + 1] = { 0 };
    size_t length;
    bool sendback = false;
    auth_simple_local_data *local = (auth_simple_local_data*)obfs->l_data;
    buffer_concatenate2(local->recv_buffer, buf);
    out_buf = buffer_create(SSR_BUFF_SIZE);

    mac_key = buffer_create_from(server_info->recv_iv, server_info->recv_iv_len);
    buffer_concatenate(mac_key, server_info->key, server_info->key_len);

    if (local->has_recv_header == false) {
        uint32_t utc_time;
        uint32_t client_id;
        uint32_t connection_id;
        uint16_t rnd_len;
        int time_diff;
        uint32_t uid;
        char uid_str[32] = { 0 };
        const char *auth_key = NULL;
        bool is_multi_user = false;
        bool user_exist = false;

        uint8_t head[16] = { 0 };
        size_t len = buffer_get_length(local->recv_buffer);
        if ((len >= 7) || (len==2 || len==3)) {
            size_t recv_len = min(len, 7);
            struct buffer_t *_msg = buffer_create_from(buffer_get_data(local->recv_buffer, NULL), 1);
            local->hmac(sha1data, _msg, mac_key);
            buffer_release(_msg);
            if (memcmp(sha1data, buffer_get_data(local->recv_buffer, NULL)+1, recv_len - 1) != 0) {
                return auth_aes128_not_match_return(obfs, local->recv_buffer, need_feedback);
            }
        }
        if (buffer_get_length(local->recv_buffer) < 31) {
            if (need_feedback) { *need_feedback = false; }
            return buffer_create(1);
        }
        {
            struct buffer_t *_msg = buffer_create_from(buffer_get_data(local->recv_buffer, NULL)+7, 20);
            local->hmac(sha1data, _msg, mac_key);
            buffer_release(_msg);
        }
        if (memcmp(sha1data, buffer_get_data(local->recv_buffer, NULL)+27, 4) != 0) {
            // '%s data incorrect auth HMAC-SHA1 from %s:%d, data %s'
            if (buffer_get_length(local->recv_buffer) < (31 + local->extra_wait_size)) {
                if (need_feedback) { *need_feedback = false; }
                return buffer_create(1);
            }
            return auth_aes128_not_match_return(obfs, local->recv_buffer, need_feedback);
        }

        memcpy(local->uid, buffer_get_data(local->recv_buffer, NULL) + 7, 4);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-aliasing"
        uid = (uint32_t) (*((uint32_t *)(local->uid))); // TODO: ntohl
#pragma GCC diagnostic pop
        sprintf(uid_str, "%d", (int)uid);

        if (obfs->audit_incoming_user) {
            user_exist = obfs->audit_incoming_user(obfs, uid_str, &auth_key, &is_multi_user);
        }
        if (user_exist) {
            uint8_t hash[SHA1_BYTES + 1] = { 0 };
            assert(is_multi_user);
            assert(auth_key);
            local->hash(hash, (const uint8_t*)auth_key, strlen(auth_key));
            buffer_store(local->user_key, hash, local->hash_len);
        } else {
            if (is_multi_user == false) {
                buffer_store(local->user_key, server_info->key, server_info->key_len);
            } else {
                buffer_store(local->user_key, server_info->recv_iv, server_info->recv_iv_len);
            }
        }
        {
            uint8_t enc_key[16] = { 0 };
            uint8_t in_data[32 + 1] = { 0 };
            size_t local_key_len = 0;
            const uint8_t *local_key = buffer_get_data(local->user_key, &local_key_len);

            size_t b64len = (size_t)std_base64_encode_len((size_t)local_key_len);
            uint8_t *key = (uint8_t*) calloc(b64len + strlen(local->salt) + 1, sizeof(*key));
            size_t key_len;

            (void)in_data;
            key_len = (size_t) std_base64_encode(local_key, (size_t)local_key_len, (char*)key);
            memmove(key+key_len, (uint8_t *)local->salt, strlen(local->salt));
            key_len += strlen(local->salt);

            bytes_to_key_with_size(key, key_len, enc_key, sizeof(enc_key));

            ss_aes_128_cbc_decrypt(16, buffer_get_data(local->recv_buffer, NULL)+11, head, enc_key);

            free(key);
        }

        length = (size_t) ( *((uint16_t *)(head + 12)) ); // TODO: ntohs
        if (buffer_get_length(local->recv_buffer) < length) {
            if (need_feedback) { *need_feedback = false; }
            // TODO: Waiting for the next packet
            return buffer_create(1);
        }

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-aliasing"
        utc_time = (uint32_t) (*((uint32_t *)(head + 0))); // TODO: ntohl
        client_id = (uint32_t) (*((uint32_t *)(head + 4))); // TODO: ntohl
        connection_id = (uint32_t) (*((uint32_t *)(head + 8))); // TODO: ntohl
        rnd_len = (uint16_t) (*((uint16_t *)(head + 14))); // TODO: ntohs
#pragma GCC diagnostic pop
        {
            struct buffer_t *_msg = buffer_create_from(buffer_get_data(local->recv_buffer, NULL), length-4);
            local->hmac(sha1data, _msg, local->user_key);
            buffer_release(_msg);
        }
        if (memcmp(sha1data, buffer_get_data(local->recv_buffer, NULL)+length-4, 4) != 0) {
            // '%s: checksum error, data %s'
            return auth_aes128_not_match_return(obfs, local->recv_buffer, need_feedback);
        }
        time_diff = abs((int)time(NULL) - (int)utc_time);
        if (time_diff > local->max_time_dif) {
            // '%s: wrong timestamp, time_dif %d, data %s'
            return auth_aes128_not_match_return(obfs, local->recv_buffer, need_feedback);
        }
        // if self.server_info.data.insert(self.user_id, client_id, connection_id):
        {
            size_t len;
            local->has_recv_header = true;
            len = (length - 4) - (31 + rnd_len);
            buffer_store(out_buf, buffer_get_data(local->recv_buffer, NULL) + (31 + rnd_len), len);
            local->client_id = client_id;
            local->connection_id = connection_id;
        }
        buffer_shortened_to(local->recv_buffer, length, buffer_get_length(local->recv_buffer) - length);
        local->has_recv_header = true;
        sendback = true;
    }

    while (buffer_get_length(local->recv_buffer) > 4) {
        size_t pos;
        uint32_t recv_id = (local->recv_id); // TODO: htonl
        buffer_replace(mac_key, local->user_key);
        buffer_concatenate(mac_key, (uint8_t *)&recv_id, sizeof(recv_id));
        {
            struct buffer_t *_msg = buffer_create_from(buffer_get_data(local->recv_buffer, NULL), 2);
            local->hmac(sha1data, _msg, mac_key);
            buffer_release(_msg);
        }
        if (memcmp(sha1data, buffer_get_data(local->recv_buffer, NULL)+2, 2) != 0) {
            // '%s: wrong crc'
            return auth_aes128_not_match_return(obfs, local->recv_buffer, need_feedback);
        }
        length = (size_t) (*((uint16_t *)buffer_get_data(local->recv_buffer, NULL))); // TODO: ntohs
        if (length >= 8192 || length < 7) {
            // '%s: over size'
            buffer_reset(local->recv_buffer);
            return auth_aes128_not_match_return(obfs, local->recv_buffer, need_feedback);
        }
        if (length > buffer_get_length(local->recv_buffer)) {
            break;
        }
        {
            struct buffer_t *_msg = buffer_create_from(buffer_get_data(local->recv_buffer, NULL), length-4);
            local->hmac(sha1data, _msg, mac_key);
            buffer_release(_msg);
        }
        if (memcmp(sha1data, buffer_get_data(local->recv_buffer, NULL) + length-4, 4) != 0) {
            // '%s: checksum error, data %s'
            buffer_reset(local->recv_buffer);
            return auth_aes128_not_match_return(obfs, local->recv_buffer, need_feedback);
        }
        local->recv_id += 1;
        pos = (size_t) buffer_get_data(local->recv_buffer, NULL)[4];
        if (pos < 255) {
            pos += 4;
        } else {
            pos = (*(uint16_t *)(buffer_get_data(local->recv_buffer, NULL) + 5)) + 4; // TODO: ntohs
        }
        buffer_concatenate(out_buf, buffer_get_data(local->recv_buffer, NULL) + pos, (length - 4) - pos);
        buffer_shortened_to(local->recv_buffer, length, buffer_get_length(local->recv_buffer) - length);
        if (pos == (length - 4)) {
            sendback = true;
        }
    }
    if (buffer_get_length(out_buf)) {
        // TODO : self.server_info.data.update(self.user_id, self.client_id, self.connection_id)
    }

    buffer_release(mac_key);

    if (need_feedback) { *need_feedback = sendback; }
    return out_buf;
}
