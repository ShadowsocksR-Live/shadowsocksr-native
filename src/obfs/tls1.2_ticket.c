#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdbool.h>
#include <assert.h>
#if defined(WIN32) || defined(_WIN32)
#include <winsock2.h>
#else
#include <netinet/in.h>
#endif

#include "obfs.h"
#include "tls1.2_ticket.h"
#include "obfsutil.h"
#include "encrypt.h"
#include "ssrbuffer.h"
#include "ssr_executive.h"

struct tls12_ticket_auth_global_data {
    uint8_t local_client_id[32];
};

struct tls12_ticket_auth_local_data {
    int handshake_status;
    struct buffer_t *send_buffer;
    struct buffer_t *recv_buffer;
    struct buffer_t *client_id;
    struct cstl_list *data_sent_buffer;
    uint32_t max_time_dif;
    int send_id;
    bool fastauth;
    struct buffer_t *empty_buf;
    struct buffer_t *tls_version;
};

void tls12_ticket_auth_dispose(struct obfs_t *obfs);

struct buffer_t * tls12_ticket_auth_client_encode(struct obfs_t *obfs, const struct buffer_t *buf);
struct buffer_t * tls12_ticket_auth_client_decode(struct obfs_t *obfs, const struct buffer_t *buf, bool *needsendback);

size_t tls12_ticket_auth_get_overhead(struct obfs_t *obfs);

struct buffer_t * tls12_ticket_auth_server_pre_encrypt(struct obfs_t *obfs, const struct buffer_t *buf);
struct buffer_t * tls12_ticket_auth_server_encode(struct obfs_t *obfs, const struct buffer_t *buf);
struct buffer_t * tls12_ticket_auth_server_decode(struct obfs_t *obfs, const struct buffer_t *buf, bool *need_decrypt, bool *need_feedback);
struct buffer_t * tls12_ticket_auth_server_post_decrypt(struct obfs_t *obfs, struct buffer_t *buf, bool *need_feedback);

static void free_element(void* ptr) {
    struct buffer_t *p = *((struct buffer_t**)ptr);
    buffer_release(p);
}

static int compare_element(const void *left, const void *right) {
    struct buffer_t *l = *((struct buffer_t**)left);
    struct buffer_t *r = *((struct buffer_t**)right);
    return buffer_compare(l, r, SIZE_MAX);
}

static void tls12_ticket_auth_local_data_init(struct tls12_ticket_auth_local_data* local) {
    local->handshake_status = 0;
    local->send_buffer = buffer_create(SSR_BUFF_SIZE);
    local->recv_buffer = buffer_create(SSR_BUFF_SIZE);
    local->client_id = buffer_create(SSR_BUFF_SIZE);
    local->max_time_dif = 60 * 60 *24; // time dif (second) setting
    local->send_id = 0;
    local->fastauth = false;
    local->data_sent_buffer = obj_list_create(compare_element, free_element);
    local->empty_buf = buffer_create_from((const uint8_t *)"", 0);
    local->tls_version = buffer_create_from((const uint8_t *)"\x03\x03", 2);
}

void * tls12_ticket_auth_generate_global_init_data(void) {
    struct tls12_ticket_auth_global_data *global = (struct tls12_ticket_auth_global_data*) calloc(1, sizeof(struct tls12_ticket_auth_global_data));
    rand_bytes(global->local_client_id, sizeof(global->local_client_id));
    return global;
}

struct obfs_t * tls12_ticket_auth_new_obfs(void) {
    struct obfs_t * obfs = (struct obfs_t*)calloc(1, sizeof(struct obfs_t));

    obfs->generate_global_init_data = tls12_ticket_auth_generate_global_init_data;
    obfs->get_overhead = tls12_ticket_auth_get_overhead;
    obfs->need_feedback = need_feedback_true;
    obfs->get_server_info = get_server_info;
    obfs->set_server_info = set_server_info;
    obfs->dispose = tls12_ticket_auth_dispose;

    obfs->client_encode = tls12_ticket_auth_client_encode;
    obfs->client_decode = tls12_ticket_auth_client_decode;

    obfs->server_pre_encrypt = tls12_ticket_auth_server_pre_encrypt;
    obfs->server_encode = tls12_ticket_auth_server_encode;
    obfs->server_decode = tls12_ticket_auth_server_decode;
    obfs->server_post_decrypt = tls12_ticket_auth_server_post_decrypt;

    obfs->l_data = calloc(1, sizeof(struct tls12_ticket_auth_local_data));
    tls12_ticket_auth_local_data_init((struct tls12_ticket_auth_local_data *)obfs->l_data);

    return obfs;
}

size_t tls12_ticket_auth_get_overhead(struct obfs_t *obfs) {
    (void)obfs;
    return 5;
}

void tls12_ticket_auth_dispose(struct obfs_t *obfs) {
    struct tls12_ticket_auth_local_data *local = (struct tls12_ticket_auth_local_data*)obfs->l_data;
    buffer_release(local->empty_buf);
    buffer_release(local->tls_version);
    buffer_release(local->send_buffer);
    buffer_release(local->recv_buffer);
    buffer_release(local->client_id);
    obj_list_destroy(local->data_sent_buffer);
    free(local);
    dispose_obfs(obfs);
}

static void tls12_sha1_hmac(struct obfs_t *obfs,
                            const struct buffer_t *client_id,
                            const struct buffer_t *msg,
                            uint8_t digest[SHA1_BYTES])
{
    size_t id_size = buffer_get_length(client_id);
    size_t key_size = obfs->server_info.key_len;
    uint8_t *key = (uint8_t*) calloc(key_size + id_size, sizeof(*key));
    memcpy(key, obfs->server_info.key, key_size);
    memcpy(key + key_size, buffer_get_data(client_id, NULL), id_size);
    {
        struct buffer_t *_key = buffer_create_from(key, (key_size + id_size));
        ss_sha1_hmac_with_key(digest, msg, _key);
        buffer_release(_key);
    }
    free(key);
}

struct buffer_t * tls12_ticket_auth_sni(const char *url0) {
    const char *url = url0 ? url0 : "";
    size_t url_len = strlen(url);
    size_t len0 = 1 + sizeof(uint16_t) + url_len;
    size_t len = 2 + sizeof(uint16_t) + sizeof(uint16_t) + len0;
    struct buffer_t *result = NULL;
    uint8_t *result_buffer = (uint8_t *) calloc(len, sizeof(*result_buffer));
    uint8_t *iter = result_buffer;

    memmove(iter, "\x00\x00", 2); iter += 2;
    *((uint16_t *)iter) = htons((uint16_t)len0 + 2); iter += sizeof(uint16_t);
    *((uint16_t *)iter) = htons((uint16_t)len0); iter += sizeof(uint16_t);

    memmove(iter, "\x00", 1); iter += 1;
    *((uint16_t *)iter) = htons((uint16_t)url_len); iter += sizeof(uint16_t);
    memmove(iter, url, url_len); iter += url_len;

    assert((size_t)(iter - result_buffer) == len);

    result = buffer_create_from(result_buffer, len);
    free(result_buffer);

    return result;
}

static int tls12_ticket_pack_auth_data(struct obfs_t *obfs, const struct buffer_t *client_id, uint8_t outdata[32]) {
    uint8_t hash[SHA1_BYTES] = { 0 };
    int out_size = 32;
    *((uint32_t *)(outdata + 0)) = htonl((uint32_t)time(NULL));
    rand_bytes((uint8_t*)outdata + sizeof(uint32_t), 18);

    {
        struct buffer_t *pMsg = buffer_create_from(outdata, 22);
        assert(buffer_get_length(client_id) == 32);
        tls12_sha1_hmac(obfs, client_id, pMsg, hash);
        buffer_release(pMsg);
    }
    memcpy(outdata + out_size - OBFS_HMAC_SHA1_LEN, hash, OBFS_HMAC_SHA1_LEN);
    return out_size;
}

static struct buffer_t * _pack_data(const uint8_t *encryptdata, size_t len) {
    struct buffer_t *result = NULL;
    uint8_t *result_buffer = (uint8_t *) calloc(5 + len, sizeof(*result_buffer));
    size_t result_len = 0;
    uint8_t *iter = result_buffer;

    memmove(iter, "\x17\x03\x03", 3);  iter += 3;
    *((uint16_t *)(iter)) = htons((uint16_t)len);  iter += sizeof(uint16_t);
    memcpy(iter, encryptdata, len);  iter += len;

    result_len = iter - result_buffer;
    result = buffer_create_from(result_buffer, result_len);
    free(result_buffer);
    return result;
}

struct buffer_t * tls12_ticket_auth_client_encode(struct obfs_t *obfs, const struct buffer_t *buf) {
    size_t datalength = 0;
    const uint8_t *encryptdata = buffer_get_data(buf, &datalength);
    struct tls12_ticket_auth_local_data *local = (struct tls12_ticket_auth_local_data*)obfs->l_data;
    struct tls12_ticket_auth_global_data *global = (struct tls12_ticket_auth_global_data*)obfs->server_info.g_data;
    struct buffer_t *result = NULL;
    if (local->handshake_status == -1) {
        return buffer_clone(buf);
    }
    result = buffer_create(SSR_BUFF_SIZE);
    if ((local->handshake_status & 4) == 4) {
        size_t start = 0;
        while (local->send_id <=4 && datalength - start > 256) {
            struct buffer_t *tmp = NULL;
            size_t len = (size_t)rand_integer() % 512 + 64;
            if (len > datalength - start) { len = datalength - start; }
            tmp = _pack_data(encryptdata + start, len);
            buffer_concatenate2(result, tmp); buffer_release(tmp);
            start += len;
        }
        while (datalength - start > SSR_BUFF_SIZE) {
            struct buffer_t *tmp = NULL;
            size_t len = (size_t)rand_integer() % 4096 + 100;
            if (len > datalength - start) { len = datalength - start; }
            tmp = _pack_data(encryptdata + start, len);
            buffer_concatenate2(result, tmp); buffer_release(tmp);
            start += len;
        }
        if (datalength - start > 0) {
            struct buffer_t *tmp = NULL;
            tmp = _pack_data(encryptdata + start, datalength - start);
            buffer_concatenate2(result, tmp); buffer_release(tmp);
        }
        return result;
    }
    if (datalength > 0) {
        struct buffer_t *tmp = _pack_data(encryptdata, datalength);
        size_t pos = obj_list_size(local->data_sent_buffer);
        obj_list_insert(local->data_sent_buffer, pos, &tmp, sizeof(tmp));
    }
    if ((local->handshake_status & 3) != 0) {
        if ((local->handshake_status & 2) == 0) {
            size_t finish_len_set[] = { 32, /* 40, 64, */ };
            int index = rand_integer() % (ARRAY_SIZE(finish_len_set));
            size_t finish_len = finish_len_set[index];
            uint8_t *rnd = (uint8_t *)calloc(finish_len - 10, sizeof(*rnd));
#define CSTR_DECL(name, len, str) const char* (name) = (str); const size_t (len) = (sizeof(str) - 1)
            CSTR_DECL(handshake_finish, handshake_finish_len, "\x14\x03\x03\x00\x01\x01\x16\x03\x03");
#undef CSTR_DECL
            uint16_t len = 0;
            struct buffer_t *hmac_data = buffer_create(SSR_BUFF_SIZE);
            uint8_t hash[SHA1_BYTES + 1] = { 0 };
            struct buffer_t *client_id = buffer_create_from(global->local_client_id, 32);
            
            buffer_concatenate(hmac_data, (uint8_t *)handshake_finish, handshake_finish_len);

            len = htons((uint16_t)finish_len);
            buffer_concatenate(hmac_data, (uint8_t *)&len, sizeof(len));

            rand_bytes(rnd, finish_len - 10);
            buffer_concatenate(hmac_data, rnd, finish_len - 10);
            free(rnd);

            tls12_sha1_hmac(obfs, client_id, hmac_data, hash);
            buffer_release(client_id);
            buffer_concatenate(hmac_data, hash, 10);

            obj_list_insert(local->data_sent_buffer, 0, &hmac_data, sizeof(hmac_data));

            local->handshake_status |= 2;
        }
        if (datalength==0 || local->fastauth) {
            size_t count = obj_list_size(local->data_sent_buffer);
            size_t index = 0;
            for (index=0; index<count; ++index) {
                struct buffer_t *data = *(struct buffer_t **)obj_list_element_at(local->data_sent_buffer, index);
                buffer_concatenate2(result, data);
            }
            obj_list_clear(local->data_sent_buffer);
        }
        if (datalength == 0) {
            local->handshake_status |= 4;
        }
        return result;
    }
    {
#define CSTR_DECL(name, len, str) const char* (name) = (str); const size_t (len) = (sizeof(str) - 1)
        CSTR_DECL(tls_data0, tls_data0_len, "\x00\x1c\xc0\x2b\xc0\x2f\xcc\xa9\xcc\xa8\xcc\x14\xcc\x13\xc0\x0a\xc0\x14\xc0\x09\xc0\x13\x00\x9c\x00\x35\x00\x2f\x00\x0a\x01\x00");
        CSTR_DECL(tls_data1, tls_data1_len, "\xff\x01\x00\x01\x00");
        CSTR_DECL(tls_data2, tls_data2_len, "\x00\x17\x00\x00\x00\x23");
        CSTR_DECL(tls_data3, tls_data3_len, "\x00\x0d\x00\x16\x00\x14\x06\x01\x06\x03\x05\x01\x05\x03\x04\x01\x04\x03\x03\x01\x03\x03\x02\x01\x02\x03\x00\x05\x00\x05\x01\x00\x00\x00\x00\x00\x12\x00\x00\x75\x50\x00\x00\x00\x0b\x00\x02\x01\x00\x00\x0a\x00\x06\x00\x04\x00\x17\x00\x18");
#undef CSTR_DECL

        char *hosts = NULL;
        char *param = NULL;
        char *phost[128] = { NULL };
        size_t host_num = 0;
        size_t pos;
        struct buffer_t *sni;
        struct buffer_t *ext_buf = buffer_create(SSR_BUFF_SIZE);
        uint16_t temp = 0;

        uint8_t rnd[32 + 1] = { 0 };
        struct buffer_t *client_id = buffer_create_from(global->local_client_id, sizeof(global->local_client_id));

        tls12_ticket_pack_auth_data(obfs, client_id, rnd);
        rnd[32] = 32;

        buffer_concatenate(result, rnd, 32 + 1);
        buffer_concatenate2(result, client_id);
        buffer_release(client_id);
        buffer_concatenate(result, (uint8_t *)tls_data0, tls_data0_len);

        buffer_concatenate(ext_buf, (uint8_t *)tls_data1, tls_data1_len);

        if (obfs->server_info.param && strlen(obfs->server_info.param) > 0) {
            param = obfs->server_info.param;
        } else {
            param = obfs->server_info.host;
        }
        hosts = (char *) calloc(strlen(param)+1, sizeof(*hosts));
        strcpy(hosts, param);
        phost[host_num++] = hosts;
        for (pos = 0; hosts[pos]; ++pos) {
            if (hosts[pos] == ',') {
                hosts[pos] = 0;
                phost[host_num++] = hosts + pos + 1;
            }
        }
        host_num = (size_t)rand_integer() % host_num;
        sni = tls12_ticket_auth_sni(phost[host_num]);
        buffer_concatenate2(ext_buf, sni); // <====
        free(hosts);
        buffer_release(sni);

        buffer_concatenate(ext_buf, (uint8_t *)tls_data2, tls_data2_len);
        {
            size_t ticket_size = (32 + rand_integer() % (196 - 32)) * 2;
            uint16_t size = htons((uint16_t)ticket_size);
            uint8_t *ticket = (uint8_t *)calloc(ticket_size + 1, sizeof(*ticket));

            rand_bytes(ticket, ticket_size);
            buffer_concatenate(ext_buf, (uint8_t *)&size, sizeof(size));
            buffer_concatenate(ext_buf, ticket, ticket_size);

            free(ticket);
        }
        buffer_concatenate(ext_buf, (uint8_t *)tls_data3, tls_data3_len);
        temp = htons((uint16_t) buffer_get_length(ext_buf));
        buffer_insert(ext_buf, 0, (uint8_t *)&temp, sizeof(temp));

        buffer_concatenate2(result, ext_buf);

        buffer_release(ext_buf);

        // client version
        buffer_insert2(result, 0, local->tls_version);

        // length
        temp = htons((uint16_t) buffer_get_length(result));
        buffer_insert(result, 0, (uint8_t *)&temp, sizeof(temp));

        // client hello
        buffer_insert(result, 0, (uint8_t *)"\x01\x00", 2);

        // length
        temp = htons((uint16_t) buffer_get_length(result));
        buffer_insert(result, 0, (uint8_t *)&temp, sizeof(temp));

        // TLS handshake and version
        buffer_insert(result, 0, (uint8_t *)"\x16\x03\x01", 3);

        local->handshake_status |= 1;

        return result;
    }
}

struct buffer_t * tls12_ticket_auth_client_decode(struct obfs_t *obfs, const struct buffer_t *buf, bool *needsendback) {
    struct buffer_t *result = buffer_create(SSR_BUFF_SIZE);
    struct tls12_ticket_auth_local_data *local = (struct tls12_ticket_auth_local_data*)obfs->l_data;
    struct tls12_ticket_auth_global_data *global = (struct tls12_ticket_auth_global_data*)obfs->server_info.g_data;

    *needsendback = false;
    buffer_concatenate2(local->recv_buffer, buf);

    if ((local->handshake_status & 8) == 8) {
        while (buffer_get_length(local->recv_buffer) > 5) {
            size_t size;
            if (buffer_get_data(local->recv_buffer, NULL)[0] != 0x17) {
                buffer_release(result); result = NULL;
                return result;
            }
            size = (size_t)ntohs(*((uint16_t *)(buffer_get_data(local->recv_buffer, NULL) + 3)));
            if (size + 5 > buffer_get_length(local->recv_buffer)) {
                break;
            }
            buffer_concatenate(result, buffer_get_data(local->recv_buffer, NULL) + 5, size);
            buffer_shortened_to(local->recv_buffer, 5 + size, buffer_get_length(local->recv_buffer) - (5 + size));
        }
        return result;
    }
    if (buffer_get_length(local->recv_buffer) < 11 + 32 + 1 + 32) {
        buffer_reset(result);
        return result;
    } else {
        const uint8_t *encryptdata = buffer_get_data(local->recv_buffer, NULL);
        uint8_t hash[SHA1_BYTES] = { 0 };
        size_t headerlength = 0;
        {
        struct buffer_t *client_id = buffer_create_from(global->local_client_id, 32);
        struct buffer_t *msg = buffer_create_from(encryptdata + 11, 22);
        tls12_sha1_hmac(obfs, client_id, msg, hash);
        buffer_release(client_id);
        buffer_release(msg);
        }
        if (memcmp(encryptdata + 33, hash, OBFS_HMAC_SHA1_LEN) != 0) {
            buffer_release(result); result = NULL;
            return result;
        }

        {
        struct buffer_t *client_id = buffer_create_from(global->local_client_id, 32);
        struct buffer_t *total = buffer_create_from(encryptdata, buffer_get_length(local->recv_buffer) - 10);
        tls12_sha1_hmac(obfs, client_id, total, hash);
        buffer_release(client_id);
        buffer_release(total);
        }
        headerlength = buffer_get_length(local->recv_buffer);
        if (memcmp(encryptdata + buffer_get_length(local->recv_buffer) - 10, hash, OBFS_HMAC_SHA1_LEN) != 0) {
            const uint8_t *iter = buffer_get_data(local->recv_buffer, NULL);
            headerlength = 0;
            while(headerlength < buffer_get_length(local->recv_buffer) && 
                (iter[headerlength]==0x14 || iter[headerlength]==0x16))
            {
                headerlength += 5;
                if (headerlength >= buffer_get_length(local->recv_buffer)) {
                    buffer_replace(result, buf);
                    return result;
                }
                headerlength += (size_t) ntohs(*((uint16_t *)(iter + headerlength - 2)));
                if (headerlength > buffer_get_length(local->recv_buffer)) {
                    buffer_replace(result, buf);
                    return result;
                }
            }
            {
                struct buffer_t *client_id = buffer_create_from(global->local_client_id, 32);
                struct buffer_t *total2 = buffer_create_from(iter, headerlength - 10);
                tls12_sha1_hmac(obfs, client_id, total2, hash);
                buffer_release(client_id);
                buffer_release(total2);
                if (memcmp(iter + headerlength - 10, hash, OBFS_HMAC_SHA1_LEN) != 0) {
                    buffer_release(result); result = NULL;
                    return result;
                }
            }
        }
        buffer_shortened_to(local->recv_buffer, headerlength, buffer_get_length(local->recv_buffer) - headerlength);

        local->handshake_status |= 8;

        buffer_release(result);
        result = tls12_ticket_auth_client_decode(obfs, local->empty_buf, needsendback);

        *needsendback = true;
        return result;
    }
}

struct buffer_t * tls12_ticket_auth_server_pre_encrypt(struct obfs_t *obfs, const struct buffer_t *buf) {
    return generic_server_pre_encrypt(obfs, buf);
}

struct buffer_t * tls12_ticket_auth_server_encode(struct obfs_t *obfs, const struct buffer_t *buf) {
    struct tls12_ticket_auth_local_data *local = (struct tls12_ticket_auth_local_data*)obfs->l_data;
    struct tls12_ticket_auth_global_data *global = (struct tls12_ticket_auth_global_data*)obfs->server_info.g_data;
    uint8_t rand_buf[SSR_BUFF_SIZE] = { 0 };
    uint8_t auth_data[32] = { 0 };
    size_t size = 0;
    uint16_t size2 = 0;

    (void)global;
    if (local->handshake_status == -1) {
        return buffer_clone(buf);
    }
    if ((local->handshake_status & 8) == 8 ) {
        struct buffer_t *ret = buffer_create(SSR_BUFF_SIZE);
        struct buffer_t *input = buffer_clone(buf);
        while (buffer_get_length(input) > SSR_BUFF_SIZE) {
            rand_bytes(rand_buf, 2);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-aliasing"
            size = min((size_t)ntohs(*((uint16_t *)rand_buf)) % 4096 + 100, buffer_get_length(input));
#pragma GCC diagnostic pop
            size2 = htons((uint16_t)size);

            buffer_concatenate(ret, (uint8_t *)"\x17", 1);
            buffer_concatenate2(ret, local->tls_version);
            buffer_concatenate(ret, (uint8_t *)&size2, sizeof(size2));
            buffer_concatenate(ret, buffer_get_data(input, NULL), size);

            buffer_shortened_to(input, size, buffer_get_length(input) - size);
        }
        if (buffer_get_length(input) > 0) {
            size2 = htons((uint16_t)buffer_get_length(input));

            buffer_concatenate(ret, (uint8_t *)"\x17", 1);
            buffer_concatenate2(ret, local->tls_version);
            buffer_concatenate(ret, (uint8_t *)&size2, sizeof(size2));
            buffer_concatenate(ret, buffer_get_data(input, NULL), buffer_get_length(input));
        }
        buffer_release(input);

        return ret;
    }

    {
        struct buffer_t *chunk1 = NULL;
        struct buffer_t *chunk2 = NULL;
        struct buffer_t *data = NULL;
        uint16_t size3 = 0;

        local->handshake_status |= 8;
        tls12_ticket_pack_auth_data(obfs, local->client_id, auth_data);

        // data = self.tls_version + self.pack_auth_data(self.client_id) + b"\x20" + self.client_id + binascii.unhexlify(b"c02f000005ff01000100")
        chunk1 = buffer_create(SSR_BUFF_SIZE);
        buffer_concatenate2(chunk1, local->tls_version);
        buffer_concatenate(chunk1, auth_data, sizeof(auth_data));
        buffer_concatenate(chunk1, (uint8_t *) "\x20", 1);
        buffer_concatenate2(chunk1, local->client_id);
        buffer_concatenate(chunk1, (uint8_t *) "\xc0\x2f\x00\x00\x05\xff\x01\x00\x01\x00", 10);

        // data = b"\x02\x00" + struct.pack('>H', len(data)) + data #server hello
        chunk2 = buffer_create(SSR_BUFF_SIZE);
        buffer_concatenate(chunk2, (uint8_t *)"\x02\x00", 2);
        size2 = htons((uint16_t)buffer_get_length(chunk1));
        buffer_concatenate(chunk2, (uint8_t *)&size2, sizeof(size2));
        buffer_concatenate2(chunk2, chunk1);

        // data = b"\x16" + self.tls_version + struct.pack('>H', len(data)) + data
        data = buffer_create(SSR_BUFF_SIZE);
        buffer_concatenate(data, (uint8_t *)"\x16", 1);
        buffer_concatenate2(data, local->tls_version);
        size2 = htons((uint16_t)buffer_get_length(chunk2));
        buffer_concatenate(data, (uint8_t *)&size2, sizeof(size2));
        buffer_concatenate2(data, chunk2);

        srand((unsigned int)time((time_t *)NULL));

        if ((rand_integer() % 8) < 1) {
            rand_bytes(rand_buf, 2);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-aliasing"
            size = (size_t)((ntohs(*((uint16_t *)rand_buf)) % 164) * 2 + 64);
#pragma GCC diagnostic pop
            rand_bytes(rand_buf, (int)size);
            size2 = htons((uint16_t)(size + 4));
            size3 = htons((uint16_t)size);

            // data += b"\x16" + self.tls_version + ticket #New session ticket
            buffer_concatenate(data, (uint8_t *)"\x16", 1);
            buffer_concatenate2(data, local->tls_version);

            // ticket = struct.pack('>H', len(ticket) + 4) + b"\x04\x00" + struct.pack('>H', len(ticket)) + ticket
            buffer_concatenate(data, (uint8_t *)&size2, sizeof(size2));
            buffer_concatenate(data, (uint8_t *)"\x04\x00", 2);
            buffer_concatenate(data, (uint8_t *)&size3, sizeof(size3));
            buffer_concatenate(data, (uint8_t *)rand_buf, size);
        }

        // data += b"\x14" + self.tls_version + b"\x00\x01\x01" #ChangeCipherSpec
        buffer_concatenate(data, (uint8_t *)"\x14", 1);
        buffer_concatenate2(data, local->tls_version);
        buffer_concatenate(data, (uint8_t *)"\x00\x01\x01", 3);

        // data += b"\x16" + self.tls_version + struct.pack('>H', finish_len) + os.urandom(finish_len - 10) #Finished
        size2 = (uint16_t)((rand_integer() % 8) + 32);
        rand_bytes(rand_buf, (int)(size2 - 10));
        size3 = htons(size2);
        buffer_concatenate(data, (uint8_t *)"\x16", 1);
        buffer_concatenate2(data, local->tls_version);
        buffer_concatenate(data, (uint8_t *)&size3, sizeof(size3));
        buffer_concatenate(data, (uint8_t *)rand_buf, (size_t)(size2 - 10));

        // data += hmac.new(self.server_info.key + self.client_id, data, hashlib.sha1).digest()[:10]
        {
            uint8_t sha1[SHA1_BYTES + 1] = { 0 };
            tls12_sha1_hmac(obfs, local->client_id, data, sha1);
            buffer_concatenate(data, sha1, OBFS_HMAC_SHA1_LEN);
        }

        if (buf && buffer_get_length(buf)) {
            struct buffer_t *tmp = tls12_ticket_auth_server_encode(obfs, buf);
            buffer_concatenate2(data, tmp);
            buffer_release(tmp);
        }

        buffer_release(chunk1);
        buffer_release(chunk2);

        return data;
    }
}

struct buffer_t * decode_error_return(struct obfs_t *obfs, const struct buffer_t *buf, bool *need_decrypt, bool *need_feedback) {
    struct tls12_ticket_auth_local_data *local = (struct tls12_ticket_auth_local_data*)obfs->l_data;
    struct tls12_ticket_auth_global_data *global = (struct tls12_ticket_auth_global_data*)obfs->server_info.g_data;

    (void)global;
    local->handshake_status = -1;
    if (obfs->server_info.overhead > 0) {
        // self.server_info.overhead -= self.overhead
    }
    obfs->server_info.overhead = 0; // self.overhead = 0
    // if (self.method in ['tls1.2_ticket_auth', 'tls1.2_ticket_fastauth'])
    {
        uint8_t temp[SSR_BUFF_SIZE] = { 0 };
        if (need_decrypt) { *need_decrypt = false; }
        if (need_feedback) { *need_feedback = false; }
        memset(temp, 'E', SSR_BUFF_SIZE);
        return buffer_create_from(temp, SSR_BUFF_SIZE);
    }
    if (need_decrypt) { *need_decrypt = true; }
    if (need_feedback) { *need_feedback = false; }
    return buffer_clone(buf);
}

struct buffer_t * tls12_ticket_auth_server_decode(struct obfs_t *obfs, const struct buffer_t *buf, bool *need_decrypt, bool *need_feedback) {
    struct tls12_ticket_auth_local_data *local = (struct tls12_ticket_auth_local_data*)obfs->l_data;
    struct tls12_ticket_auth_global_data *global = (struct tls12_ticket_auth_global_data*)obfs->server_info.g_data;
    struct buffer_t *result = NULL;
    struct buffer_t *buf_copy = NULL;
    struct buffer_t *ogn_buf = NULL;
    struct buffer_t *verifyid = NULL;
    struct buffer_t *sessionid = NULL;

    (void)global;
    if (need_decrypt) { *need_decrypt = true; }
    if (need_feedback) { *need_feedback = false; }
    if (local->handshake_status == -1) {
        result = buffer_clone(buf);
        return result;
    }
    if ((local->handshake_status & 4) == 4) {
        result = buffer_create(SSR_BUFF_SIZE);
        buffer_concatenate2(local->recv_buffer, buf);
        while (buffer_get_length(local->recv_buffer) > 5) {
            const uint8_t *beginning = buffer_get_data(local->recv_buffer, NULL);
            size_t size = 0;
            size_t thunk_size = 0;
            if (memcmp(beginning, "\x17\x03\x03", 3) != 0) {
                buffer_release(result); result = NULL;
                return result;
            }
            size = (size_t) ntohs( *((uint16_t *)(beginning+3)) ); // uint16_t
            thunk_size = size + 5;
            if (buffer_get_length(local->recv_buffer) < thunk_size) {
                break;
            }
            buffer_concatenate(result, beginning + 5, size);

            buffer_shortened_to(local->recv_buffer, thunk_size, buffer_get_length(local->recv_buffer) - thunk_size);
         }
        return result;
    }
    if ((local->handshake_status & 1) == 1) {
        const uint8_t *buf_ptr2 = NULL;
        uint8_t hash[SHA1_BYTES + 1] = { 0 };
        struct buffer_t *verify = NULL;
        size_t verify_len = 0;
        struct buffer_t *swap = buffer_create(SSR_BUFF_SIZE);

        buffer_concatenate2(local->recv_buffer, buf);
        verify = buffer_clone(local->recv_buffer);

        if (buffer_get_length(local->recv_buffer) < 11) {
            buffer_release(verify);
            buffer_release(swap);
            return NULL;
        }

        // ChangeCipherSpec: b"\x14" + tls_version + b"\x00\x01\x01"
        buffer_reset(swap);
        {
            struct buffer_t *const_buff1 = buffer_create_from((const uint8_t *)"\x14", 1);
            struct buffer_t *const_buff2 = buffer_create_from((const uint8_t *)"\x00\x01\x01", 3);
            buffer_concatenate2(swap, const_buff1);
            buffer_concatenate2(swap, local->tls_version);
            buffer_concatenate2(swap, const_buff2);
            buffer_release(const_buff1);
            buffer_release(const_buff2);
        }
        if (buffer_compare(local->recv_buffer, swap, buffer_get_length(swap)) != 0) {
            buffer_release(verify);
            buffer_release(swap);
            return NULL;
        }

        buf_ptr2 = buffer_get_data(local->recv_buffer, NULL) + buffer_get_length(swap); // buf = buf[6:]

        // Finished: b"\x16" + tls_version + b"\x00"
        buffer_reset(swap);
        {
            struct buffer_t *const_buff1 = buffer_create_from((const uint8_t *)"\x16", 1);
            struct buffer_t *const_buff2 = buffer_create_from((const uint8_t *)"\x00", 1);
            buffer_concatenate2(swap, const_buff1);
            buffer_concatenate2(swap, local->tls_version);
            buffer_concatenate2(swap, const_buff2);
            buffer_release(const_buff1);
            buffer_release(const_buff2);
        }
        if (memcmp(buf_ptr2, buffer_get_data(swap, NULL), buffer_get_length(swap)) != 0) {
            buffer_release(verify);
            buffer_release(swap);
            return NULL;
        }

        verify_len = (size_t) ntohs(*((uint16_t *)(buf_ptr2+3))) + 1; // 11-10
        if (buffer_get_length(verify) < (verify_len + 10)) {
            if (need_decrypt) { *need_decrypt = false; }
            if (need_feedback) { *need_feedback = false; }
            buffer_release(verify);
            buffer_release(swap);
            return buffer_create(1);
        }
        {
            struct buffer_t *pMsg = buffer_create_from(buffer_get_data(verify, NULL), verify_len);
            tls12_sha1_hmac(obfs, local->client_id, pMsg, hash);
            buffer_release(pMsg);
        }
        if (memcmp(hash, buffer_get_data(verify, NULL)+verify_len, OBFS_HMAC_SHA1_LEN) != 0) {
            buffer_release(verify);
            buffer_release(swap);
            return NULL;
        }

        verify_len = verify_len + OBFS_HMAC_SHA1_LEN;
        buffer_store(local->recv_buffer, buffer_get_data(verify, NULL) + verify_len, buffer_get_length(verify) - verify_len);

        buffer_release(verify);
        buffer_release(swap);

        local->handshake_status |= 4;

        return tls12_ticket_auth_server_decode(obfs, local->empty_buf, need_decrypt, need_feedback);
    }
    do {
        uint8_t sha1[SHA1_BYTES + 1] = { 0 };
        size_t header_len = 0;
        size_t msg_size = 0;
        size_t sessionid_len = 0;
        uint32_t utc_time = 0;
        uint32_t time_dif = 0;

        (void)time_dif;
        buffer_concatenate2(local->recv_buffer, buf);
        buf_copy = buffer_clone(local->recv_buffer);
        ogn_buf = buffer_clone(local->recv_buffer);
        if (buffer_get_length(buf_copy) < 3) {
            if (need_decrypt) { *need_decrypt = false; }
            if (need_feedback) { *need_feedback = false; }
            result = buffer_clone(local->empty_buf);
            break;
        }
        if (memcmp(buffer_get_data(buf_copy, NULL), "\x16\x03\x01", 3) != 0) {
            result = decode_error_return(obfs, ogn_buf, need_decrypt, need_feedback);
            break;
        }
        buffer_shortened_to(buf_copy, 3, buffer_get_length(buf_copy) - 3);
        header_len = (size_t) ntohs(*((uint16_t *)buffer_get_data(buf_copy, NULL)));
        if (header_len > (buffer_get_length(buf_copy) - sizeof(uint16_t))) {
            if (need_decrypt) { *need_decrypt = false; }
            if (need_feedback) { *need_feedback = false; }
            result = buffer_clone(local->empty_buf);
            break;
        }
        buffer_shortened_to(local->recv_buffer, header_len+5, buffer_get_length(local->recv_buffer) - (header_len + 5));
        local->handshake_status = 1;
        buffer_shortened_to(buf_copy, 2, header_len);
        if (memcmp(buffer_get_data(buf_copy, NULL), "\x01\x00", 2) != 0) {
            // logging.info("tls_auth not client hello message")
            result = decode_error_return(obfs, ogn_buf, need_decrypt, need_feedback);
            break;
        }
        buffer_shortened_to(buf_copy, 2, buffer_get_length(buf_copy) - 2);
        msg_size = (size_t) ntohs(*((uint16_t *)buffer_get_data(buf_copy, NULL)));
        if (msg_size != buffer_get_length(buf_copy) - 2) {
            // logging.info("tls_auth wrong message size")
            result = decode_error_return(obfs, ogn_buf, need_decrypt, need_feedback);
            break;
        }
        buffer_shortened_to(buf_copy, 2, buffer_get_length(buf_copy) - 2);
        if (memcmp(buffer_get_data(buf_copy, NULL), buffer_get_data(local->tls_version, NULL), 2) != 0) {
            // logging.info("tls_auth wrong tls version")
            result = decode_error_return(obfs, ogn_buf, need_decrypt, need_feedback);
            break;
        }
        buffer_shortened_to(buf_copy, 2, buffer_get_length(buf_copy) - 2);
        verifyid = buffer_create_from(buffer_get_data(buf_copy, NULL), 32);
        buffer_shortened_to(buf_copy, 32, buffer_get_length(buf_copy) - 32);
        sessionid_len = (size_t) buffer_get_data(buf_copy, NULL)[0];
        if (sessionid_len < 32) {
            // logging.info("tls_auth wrong sessionid_len")
            result = decode_error_return(obfs, ogn_buf, need_decrypt, need_feedback);
            break;
        }
        sessionid = buffer_create_from(buffer_get_data(buf_copy, NULL) + 1, sessionid_len);
        buffer_shortened_to(buf_copy, sessionid_len + 1, buffer_get_length(buf_copy) - (sessionid_len + 1));
        buffer_replace(local->client_id, sessionid);
        {
            struct buffer_t *pMsg = buffer_create_from(buffer_get_data(verifyid, NULL), 22);
            tls12_sha1_hmac(obfs, local->client_id, pMsg, sha1);
            buffer_release(pMsg);
        }
        utc_time = (uint32_t) ntohl(*(uint32_t *)buffer_get_data(verifyid, NULL));
        time_dif = (uint32_t)(time(NULL) & 0xffffffff) - utc_time;
        //if (obfs->server.param) {
        //    // self.max_time_dif = int(self.server_info.obfs_param)
        //    local->max_time_dif = obfs->server.param;
        //}
        //if self.max_time_dif > 0 and (time_dif < -self.max_time_dif or time_dif > self.max_time_dif
        //        or common.int32(utc_time - self.server_info.data.startup_time) < -self.max_time_dif / 2):
        //    logging.info("tls_auth wrong time")
        //    return self.decode_error_return(ogn_buf)
        if (memcmp(sha1, buffer_get_data(verifyid, NULL)+22, 10) != 0) {
            // logging.info("tls_auth wrong sha1")
            result = decode_error_return(obfs, ogn_buf, need_decrypt, need_feedback);
            break;
        }
        //if self.server_info.data.client_data.get(verifyid[:22]):
        //    logging.info("replay attack detect, id = %s" % (binascii.hexlify(verifyid)))
        //    return self.decode_error_return(ogn_buf)
        //self.server_info.data.client_data.sweep()
        //self.server_info.data.client_data[verifyid[:22]] = sessionid
        if (buffer_get_length(local->recv_buffer) >= 11) {
            result = tls12_ticket_auth_server_decode(obfs, local->empty_buf, need_decrypt, need_feedback);
            if (need_decrypt) { *need_decrypt = true; }
            if (need_feedback) { *need_feedback = true; }
            break;
        } else {
            if (need_decrypt) { *need_decrypt = false; }
            if (need_feedback) { *need_feedback = true; }
            result = buffer_clone(local->empty_buf);
            break;
        }
    } while(0);
    buffer_release(buf_copy);
    buffer_release(ogn_buf);
    buffer_release(verifyid);
    buffer_release(sessionid);
    return result;
}

struct buffer_t * tls12_ticket_auth_server_post_decrypt(struct obfs_t *obfs, struct buffer_t *buf, bool *need_feedback) {
    // TODO : need implementation future.
    return generic_server_post_decrypt(obfs, buf, need_feedback);
}

//============================= tls1.2_ticket_fastauth ==================================

struct obfs_t * tls12_ticket_fastauth_new_obfs(void) {
    struct obfs_t *obfs = tls12_ticket_auth_new_obfs();
    ((struct tls12_ticket_auth_local_data*)obfs->l_data)->fastauth = true;
    return obfs;
}
