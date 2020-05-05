#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>

#include "http_simple.h"
#include "obfsutil.h"
#include "obfs.h"
#include "ssrbuffer.h"
#include "encrypt.h"

struct buffer_t * http_simple_client_encode(struct obfs_t *obfs, const struct buffer_t *buf);
struct buffer_t * http_simple_client_decode(struct obfs_t *obfs, const struct buffer_t *buf, bool *needsendback);

struct buffer_t * http_simple_server_encode(struct obfs_t *obfs, const struct buffer_t *buf);
struct buffer_t * http_simple_server_decode(struct obfs_t *obfs, const struct buffer_t *buf, bool *need_decrypt, bool *need_feedback);

struct buffer_t * http_post_client_encode(struct obfs_t *obfs, const struct buffer_t *buf);
struct buffer_t * http_mix_client_encode(struct obfs_t *obfs, const struct buffer_t *buf);

static char* g_useragent[] = {
    "Mozilla/5.0 (Windows NT 6.3; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
    "Mozilla/5.0 (Windows NT 6.3; WOW64; rv:40.0) Gecko/20100101 Firefox/44.0",
    "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.11 (KHTML, like Gecko) Ubuntu/11.10 Chromium/27.0.1453.93 Chrome/27.0.1453.93 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:35.0) Gecko/20100101 Firefox/35.0",
    "Mozilla/5.0 (compatible; WOW64; MSIE 10.0; Windows NT 6.2)",
    "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27",
    "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.3; Trident/7.0; .NET4.0E; .NET4.0C)",
    "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Linux; Android 4.4; Nexus 5 Build/BuildID) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/30.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 5_0 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9A334 Safari/7534.48.3",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 5_0 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9A334 Safari/7534.48.3",
};

static const char *request_path[] = {
    "", "",
    "login.php?redir=", "",
    "register.php?code=", "",
    "?keyword=", "",
    "search?src=typd&q=", "&lang=en",
    "s?ie=utf-8&f=8&rsv_bp=1&rsv_idx=1&ch=&bar=&wd=", "&rn=",
    "post.php?id=", "&goto=view.php",
};

static int g_useragent_index = -1;

struct http_simple_local_data {
    int has_sent_header;
    int has_recv_header;
    struct buffer_t *encode_buffer;
    struct buffer_t *recv_buffer;
};

void http_simple_local_data_init(struct http_simple_local_data *local) {
    local->has_sent_header = 0;
    local->has_recv_header = 0;
    local->encode_buffer = buffer_create(SSR_BUFF_SIZE);
    local->recv_buffer = buffer_create(SSR_BUFF_SIZE);

    if (g_useragent_index == -1) {
        g_useragent_index = xorshift128plus() % (sizeof(g_useragent) / sizeof(*g_useragent));
    }
}

struct obfs_t * http_simple_new_obfs(void) {
    struct obfs_t * obfs = (struct obfs_t *)calloc(1, sizeof(struct obfs_t));
    obfs->generate_global_init_data = generate_global_init_data;
    obfs->get_overhead = get_overhead;
    obfs->need_feedback = need_feedback_false;
    obfs->get_server_info = get_server_info;
    obfs->set_server_info = set_server_info;
    obfs->dispose = http_simple_dispose;
    obfs->client_encode = http_simple_client_encode;
    obfs->client_decode = http_simple_client_decode;

    obfs->server_encode = http_simple_server_encode;
    obfs->server_decode = http_simple_server_decode;

    obfs->l_data = calloc(1, sizeof(struct http_simple_local_data));
    http_simple_local_data_init((struct http_simple_local_data*)obfs->l_data);

    return obfs;
}

struct obfs_t * http_post_new_obfs(void) {
    struct obfs_t * obfs = http_simple_new_obfs();
    obfs->client_encode = http_post_client_encode;
    return obfs;
}

struct obfs_t * http_mix_new_obfs(void) {
    struct obfs_t * obfs = http_simple_new_obfs();
    obfs->client_encode = http_mix_client_encode;
    return obfs;
}

void http_simple_dispose(struct obfs_t *obfs) {
    struct http_simple_local_data *local = (struct http_simple_local_data*)obfs->l_data;
    buffer_release(local->encode_buffer);
    buffer_release(local->recv_buffer);
    free(local);
    dispose_obfs(obfs);
}

char http_simple_hex(char c) {
    if (c < 10) return c + '0';
    return c - 10 + 'a';
}

// Converts a hex character to its integer value
uint8_t from_hex(uint8_t ch) {
    return isdigit((int)ch) ? ch - '0' : (uint8_t)tolower((int)ch) - 'a' + 10;
}

struct buffer_t * get_data_from_http_header(const uint8_t *buf) {
    uint8_t tmp[SSR_BUFF_SIZE] = { 0 };
    const uint8_t *iter = (uint8_t *) strchr((char *)buf, '%');
    uint8_t *target = tmp;
    while(iter) {
        *target++ = from_hex(iter[1]) << 4 | from_hex(iter[2]);
        iter += 3;
        if (*iter != '%') {
            break;
        }
    }
    return buffer_create_from(tmp, target - tmp);
}

void get_host_from_http_header(const uint8_t *buf, char host_port[128]) {
    static const char *hoststr = "Host: ";
    static const char *crlf = "\r\n";
    const uint8_t *iter = (uint8_t *) strstr((char *)buf, hoststr);
    if(iter) {
        const uint8_t *end = NULL;
        iter += strlen(hoststr);
        end = (const uint8_t *) strstr((const char *)iter, crlf);
        if (end) {
            size_t len = end - iter;
            memmove(host_port, iter, len);
            host_port[len] = 0;
        }
    }
}

void http_simple_encode_head(struct http_simple_local_data *local, const uint8_t *data, size_t datalength) {
    size_t pos = 0, len, capacity;
    uint8_t *buffer;
    buffer_realloc(local->encode_buffer, (size_t)(datalength * 3 + 1));
    buffer = (uint8_t *) buffer_raw_clone(local->encode_buffer, &malloc, &len, &capacity);
    for (; pos < datalength; ++pos) {
        buffer[pos * 3] = '%';
        buffer[pos * 3 + 1] = http_simple_hex(((unsigned char)data[pos] >> 4));
        buffer[pos * 3 + 2] = http_simple_hex(data[pos] & 0xF);
    }
    buffer[pos * 3] = 0;
    buffer_store(local->encode_buffer, buffer, pos * 3);
    free(buffer);
}

struct buffer_t * fake_request_data(const uint8_t *url_encoded_data) {
    struct buffer_t *ret = buffer_create(SSR_BUFF_SIZE);
    size_t arr_size = sizeof(request_path)/sizeof(request_path[0]);
    size_t index = 0;
    const char *ptr;
    index = (rand_integer() % (arr_size / 2)) * 2;

    ptr = request_path[index];
    buffer_concatenate(ret, (const uint8_t *)ptr, strlen(ptr));

    ptr = (const char *)url_encoded_data;
    buffer_concatenate(ret, (const uint8_t *)ptr, strlen(ptr));

    ptr = request_path[index + 1];
    buffer_concatenate(ret, (const uint8_t *)ptr, strlen(ptr));

    return ret;
}

struct buffer_t * http_simple_client_encode(struct obfs_t *obfs, const struct buffer_t *buf) {
    size_t datalength = 0;
    const uint8_t *encryptdata = buffer_get_data(buf, &datalength);
    struct http_simple_local_data *local = (struct http_simple_local_data*)obfs->l_data;
    char hosts[(SSR_BUFF_SIZE / 2)];
    char * phost[128];
    int host_num = 0;
    int pos;
    char hostport[128];
    size_t head_size;
    size_t outlength;
    char * out_buffer;
    char * body_buffer = NULL;
    struct buffer_t *fake_path = NULL;
    struct buffer_t *result = NULL;

    if (local->has_sent_header) {
        return buffer_clone(buf);
    }
    head_size = (size_t)obfs->server_info.head_len + (xorshift128plus() & 0x3F);
    out_buffer = (char*) calloc((size_t)(datalength + SSR_BUFF_SIZE), sizeof(*out_buffer));
    if ((size_t)head_size > datalength) {
        head_size = datalength;
    }
    http_simple_encode_head(local, encryptdata, head_size);
    if (obfs->server_info.param && strlen(obfs->server_info.param) == 0) {
        obfs->server_info.param = NULL;
    }
    strncpy(hosts, obfs->server_info.param ? obfs->server_info.param : obfs->server_info.host, sizeof(hosts)-1);
    phost[host_num++] = hosts;
    for (pos = 0; hosts[pos]; ++pos) {
        if (hosts[pos] == ',') {
            phost[host_num++] = &hosts[pos + 1];
            hosts[pos] = 0;
        } else if (hosts[pos] == '#') {
            char * body_pointer = &hosts[pos + 1];
            char * p;
            int trans_char = 0;
            p = body_buffer = (char*) calloc(SSR_BUFF_SIZE, sizeof(char));
            for ( ; *body_pointer; ++body_pointer) {
                if (trans_char) {
                    if (*body_pointer == '\\' ) {
                        *p = '\\';
                    } else if (*body_pointer == 'n' ) {
                        *p = '\r';
                        *++p = '\n';
                    } else {
                        *p = '\\';
                        *++p = *body_pointer;
                    }
                    trans_char = 0;
                } else {
                    if (*body_pointer == '\\') {
                        trans_char = 1;
                        continue;
                    } else if (*body_pointer == '\n') {
                        *p++ = '\r';
                    }
                    *p = *body_pointer;
                }
                ++p;
            }
            *p = 0;
            hosts[pos] = 0;
            break;
        }
    }
    host_num = (int)(xorshift128plus() % (uint64_t)host_num);
    if (obfs->server_info.port == 80) {
        sprintf(hostport, "%s", phost[host_num]);
    } else {
        sprintf(hostport, "%s:%d", phost[host_num], obfs->server_info.port);
    }
    fake_path = fake_request_data(buffer_get_data(local->encode_buffer, NULL));

    if (body_buffer) {
        sprintf(out_buffer,
            "GET /%s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "%s\r\n\r\n",
            (char *)buffer_get_data(fake_path, NULL),
            hostport,
            body_buffer);
    } else {
        sprintf(out_buffer,
            "GET /%s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "User-Agent: %s\r\n"
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
            "Accept-Language: en-US,en;q=0.8\r\n"
            "Accept-Encoding: gzip, deflate\r\n"
            "DNT: 1\r\n"
            "Connection: keep-alive\r\n"
            "\r\n",
            (char *)buffer_get_data(fake_path, NULL),
            hostport,
            g_useragent[g_useragent_index]
            );
    }
    //LOGI("http header: %s", out_buffer);
    outlength = strlen(out_buffer);
    memmove(out_buffer + outlength, encryptdata + head_size, datalength - (size_t)head_size);
    outlength += datalength - head_size;
    local->has_sent_header = 1;
    result = buffer_create_from((uint8_t *)out_buffer, outlength);
    free(out_buffer);
    if (body_buffer != NULL)
        free(body_buffer);
    buffer_release(fake_path);
    return result;
}

struct buffer_t * http_simple_client_decode(struct obfs_t *obfs, const struct buffer_t *buf, bool *needsendback) {
    struct buffer_t *result = buffer_clone(buf);
    const char *encryptdata = (const char *) buffer_get_data(result, NULL);
    struct http_simple_local_data *local = (struct http_simple_local_data*)obfs->l_data;
    const char* data_begin;

    *needsendback = false;
    if (local->has_recv_header) {
        return result;
    }
    data_begin = strstr(encryptdata, "\r\n\r\n");
    if (data_begin) {
        size_t outlength;
        data_begin += 4;
        local->has_recv_header = 1;
        outlength = buffer_get_length(result) - (data_begin - encryptdata);
        buffer_shortened_to(result, (data_begin - encryptdata), outlength);
    } else {
        buffer_reset(result);
    }
    return result;
}

struct buffer_t * http_simple_server_encode(struct obfs_t *obfs, const struct buffer_t *buf) {
    struct http_simple_local_data *local = (struct http_simple_local_data*)obfs->l_data;
    struct buffer_t *header = buffer_create(SSR_BUFF_SIZE);
    static const char *header1 = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Encoding: gzip\r\nContent-Type: text/html\r\nDate: ";
    static const char *header2 = "\r\nServer: nginx\r\nVary: Accept-Encoding\r\n\r\n";
    do {
        if (local->has_sent_header) {
            buffer_concatenate2(header, buf);
            break;
        }

        buffer_store(header, (const uint8_t *)header1, strlen(header1));
        {
            time_t t = time(NULL);
            struct tm *tmp = gmtime(&t);
            char current[128] = { 0 };
            strftime(current, sizeof(current), "%a, %d %b %Y %H:%M:%S GMT", tmp);

            buffer_concatenate(header, (uint8_t *)current, strlen(current));
        }
        buffer_concatenate(header, (const uint8_t *)header2, strlen(header2));
        buffer_concatenate2(header, buf);

        local->has_sent_header = true;
    } while (0);
    return header;
}

bool match_http_header(struct buffer_t *buf) {
    bool result = false;
    static char * header[] = {
        "GET ",
        "POST ",
    };
    int i = 0;
    if (buf==NULL || buffer_get_length(buf) ==0) {
        return result;
    }
    for (i=0; i< (int)(sizeof(header)/sizeof(header[0])); ++i) {
        if (memcmp(header[i], buffer_get_data(buf, NULL), strlen(header[i])) == 0) {
            result = true;
            break;
        }
    }
    return result;
}

struct buffer_t * http_simple_server_decode(struct obfs_t *obfs, const struct buffer_t *buf, bool *need_decrypt, bool *need_feedback) {
    struct http_simple_local_data *local = (struct http_simple_local_data*)obfs->l_data;
    static const char *crlfcrlf = "\r\n\r\n";
    struct buffer_t *ret = buffer_create(SSR_BUFF_SIZE);
    struct buffer_t *in_buf = NULL;
    uint8_t *real_data = NULL;
    size_t len = 0;
    char host_port[128] = { 0 };
    do {
        if (need_decrypt) { *need_decrypt = true; }
        if (need_feedback) { *need_feedback = false; }
        if (local->has_recv_header) {
            buffer_concatenate2(ret, buf);
            break;
        }

        local->has_recv_header = true;

        buffer_concatenate2(local->recv_buffer, buf);
        in_buf = buffer_clone(local->recv_buffer);
        if (buffer_get_length(in_buf) <= 10) {
            break;
        }
        if (match_http_header(in_buf) == false) {
            // logging.debug('http_simple: not match begin')
            buffer_reset(local->recv_buffer);
            break;
        }
        if (buffer_get_length(in_buf) > 65536) {
            // logging.warn('http_simple: over size')
            buffer_reset(local->recv_buffer);
            if (need_decrypt) { *need_decrypt = false; }
            break;
        }
        real_data = (uint8_t *) strstr((char *)buffer_get_data(in_buf, NULL), crlfcrlf);
        if (real_data == NULL) {
            break;
        }
        *real_data = 0;
        real_data += strlen(crlfcrlf);

        buffer_release(ret);
        ret = get_data_from_http_header(buffer_get_data(in_buf, NULL));
        get_host_from_http_header(buffer_get_data(in_buf, NULL), host_port);

        // TODO: check obfs_param
        // if host_port and self.server_info.obfs_param: 
        //     ....

        len = (buffer_get_data(in_buf, NULL) + buffer_get_length(in_buf) - real_data);
        if (len > 0) {
            buffer_concatenate(ret, real_data, len);
        }

        if (buffer_get_length(ret) < 13) {
            // not_match_return
            buffer_replace(ret, buf);
            break;
        }

    } while(0);
    buffer_release(in_buf);
    return ret;
}

void boundary(char result[])
{
    char *str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    int i,lstr;
    char ss[3] = {0};
    lstr = (int)strlen(str);
    srand((unsigned int)time((time_t *)NULL));
    for(i = 0; i < 32; ++i)
    {
        sprintf(ss, "%c", str[(rand_integer()%lstr)]);
        strcat(result, ss);
    }
}

struct buffer_t * http_post_client_encode(struct obfs_t *obfs, const struct buffer_t *buf) {
    size_t datalength = 0;
    const uint8_t *encryptdata = buffer_get_data(buf, &datalength);
    struct http_simple_local_data *local = (struct http_simple_local_data*)obfs->l_data;
    char hosts[(SSR_BUFF_SIZE / 2)];
    char * phost[128];
    int host_num = 0;
    int pos;
    char hostport[128];
    size_t head_size;
    size_t outlength;
    char * out_buffer;
    char * body_buffer = NULL;
    struct buffer_t *fake_path = NULL;
    struct buffer_t *result = NULL;

    if (local->has_sent_header) {
        return buffer_clone(buf);
    }
    head_size = (size_t)obfs->server_info.head_len + (xorshift128plus() & 0x3F);
    out_buffer = (char*) calloc((size_t)(datalength + (SSR_BUFF_SIZE * 2)), sizeof(char));
    if ((size_t)head_size > datalength)
        head_size = datalength;
    http_simple_encode_head(local, encryptdata, head_size);
    if (obfs->server_info.param && strlen(obfs->server_info.param) == 0) {
        obfs->server_info.param = NULL;
    }
    strncpy(hosts, obfs->server_info.param ? obfs->server_info.param : obfs->server_info.host, sizeof(hosts)-1);
    phost[host_num++] = hosts;
    for (pos = 0; hosts[pos]; ++pos) {
        if (hosts[pos] == ',') {
            phost[host_num++] = &hosts[pos + 1];
            hosts[pos] = 0;
        } else if (hosts[pos] == '#') {
            char * body_pointer = &hosts[pos + 1];
            char * p;
            int trans_char = 0;
            p = body_buffer = (char*) calloc(SSR_BUFF_SIZE, sizeof(char));
            for ( ; *body_pointer; ++body_pointer) {
                if (trans_char) {
                    if (*body_pointer == '\\' ) {
                        *p = '\\';
                    } else if (*body_pointer == 'n' ) {
                        *p = '\r';
                        *++p = '\n';
                    } else {
                        *p = '\\';
                        *++p = *body_pointer;
                    }
                    trans_char = 0;
                } else {
                    if (*body_pointer == '\\') {
                        trans_char = 1;
                        continue;
                    } else if (*body_pointer == '\n') {
                        *p++ = '\r';
                    }
                    *p = *body_pointer;
                }
                ++p;
            }
            *p = 0;
            hosts[pos] = 0;
            break;
        }
    }
    host_num = (int)(xorshift128plus() % (uint64_t)host_num);
    if (obfs->server_info.port == 80) {
        snprintf(hostport, sizeof(hostport), "%s", phost[host_num]);
    } else {
        snprintf(hostport, sizeof(hostport), "%s:%d", phost[host_num], obfs->server_info.port);
    }

    fake_path = fake_request_data(buffer_get_data(local->encode_buffer, NULL));

    if (body_buffer) {
        snprintf(out_buffer, SSR_BUFF_SIZE,
            "POST /%s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "%s\r\n\r\n",
            (char *)buffer_get_data(fake_path, NULL),
            hostport,
            body_buffer);
    } else {
        char result[33] = {0};
        boundary(result);
        snprintf(out_buffer, SSR_BUFF_SIZE,
            "POST /%s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "User-Agent: %s\r\n"
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
            "Accept-Language: en-US,en;q=0.8\r\n"
            "Accept-Encoding: gzip, deflate\r\n"
            "Content-Type: multipart/form-data; boundary=%s\r\n"
            "DNT: 1\r\n"
            "Connection: keep-alive\r\n"
            "\r\n",
            (char *)buffer_get_data(fake_path, NULL),
            hostport,
            g_useragent[g_useragent_index],
            result
            );
    }
    //LOGI("http header: %s", out_buffer);
    outlength = strlen(out_buffer);
    memmove(out_buffer + outlength, encryptdata + head_size, datalength - head_size);
    outlength += datalength - head_size;
    local->has_sent_header = 1;
    result = buffer_create_from((uint8_t *)out_buffer, outlength);
    free(out_buffer);
    if (body_buffer != NULL)
        free(body_buffer);
    buffer_release(fake_path);
    return result;
}

struct buffer_t * http_mix_client_encode(struct obfs_t *obfs, const struct buffer_t *buf) {
    int rate = 0;

    // The probability of occurrence of `post` is 1/3 to 1/7.
    rate = (rand_integer() % 4) + 3;

    if ((rand_integer() % rate) == 0) {
        return http_post_client_encode(obfs, buf);
    } else {
        return http_simple_client_encode(obfs, buf);
    }
}
