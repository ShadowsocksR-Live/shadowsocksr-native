#ifndef __WEBSOCKET_BASIC_H__
#define __WEBSOCKET_BASIC_H__

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(__cplusplus)
#ifdef _MSC_VER
#undef inline
#define inline __inline
#endif /* _MSC_VER */
#endif /* __cplusplus */

#define MAX_REQUEST_SIZE      0x8000

#define WEBSOCKET_STATUS    "Switching Protocols"
#define SEC_WEBSOKET_KEY    "Sec-WebSocket-Key"
#define SEC_WEBSOKET_ACCEPT "Sec-WebSocket-Accept"

#if !defined(CRLF)
#define CRLF            "\r\n"
#define CRLF_LEN        2
#endif
#if !defined(CRLFCRLF)
#define CRLFCRLF        "\r\n\r\n"
#define CRLFCRLF_LEN    4
#endif

#ifndef SHA_DIGEST_LENGTH
#define SHA_DIGEST_LENGTH 20
#endif

/* see https://tools.ietf.org/html/rfc6455#section-7.4.1 */
#define WS_CLOSE_REASON_MAP(V)                                                  \
    V(0000, WS_CLOSE_REASON_UNKNOWN, "WS_CLOSE_REASON_UNKNOWN")                 \
    V(1000, WS_CLOSE_REASON_NORMAL, "WS_CLOSE_REASON_NORMAL")                   \
    V(1001, WS_CLOSE_REASON_GOING_AWAY, "WS_CLOSE_REASON_GOING_AWAY")           \
    V(1002, WS_CLOSE_REASON_PROTOCOL_ERROR, "WS_CLOSE_REASON_PROTOCOL_ERROR")   \
    V(1003, WS_CLOSE_REASON_UNEXPECTED_DATA, "WS_CLOSE_REASON_UNEXPECTED_DATA") \
    V(1005, WS_CLOSE_REASON_NO_REASON, "WS_CLOSE_REASON_NO_REASON")             \
    V(1006, WS_CLOSE_REASON_ABRUPTLY, "WS_CLOSE_REASON_ABRUPTLY")               \
    V(1007, WS_CLOSE_REASON_INCONSISTENT_DATA, "WS_CLOSE_REASON_INCONSISTENT_DATA") \
    V(1008, WS_CLOSE_REASON_POLICY_VIOLATION, "WS_CLOSE_REASON_POLICY_VIOLATION") \
    V(1009, WS_CLOSE_REASON_TOO_BIG, "WS_CLOSE_REASON_TOO_BIG")                 \
    V(1010, WS_CLOSE_REASON_MISSING_EXTENSION, "WS_CLOSE_REASON_MISSING_EXTENSION") \
    V(1011, WS_CLOSE_REASON_SERVER_ERROR, "WS_CLOSE_REASON_SERVER_ERROR")       \
    V(3000, WS_CLOSE_REASON_IANA_REGISTRY_START, "WS_CLOSE_REASON_IANA_REGISTRY_START") \
    V(3999, WS_CLOSE_REASON_IANA_REGISTRY_END, "WS_CLOSE_REASON_IANA_REGISTRY_END") \
    V(4000, WS_CLOSE_REASON_PRIVATE_START, "WS_CLOSE_REASON_PRIVATE_START") \
    V(4999, WS_CLOSE_REASON_PRIVATE_END, "WS_CLOSE_REASON_PRIVATE_END") \

typedef enum ws_close_reason {
#define WS_CLOSE_REASON_GEN(code, name, _) name = code,
    WS_CLOSE_REASON_MAP(WS_CLOSE_REASON_GEN)
#undef WS_CLOSE_REASON_GEN
    WS_CLOSE_REASON_MAX,
} ws_close_reason;

const char* ws_close_reason_string(enum ws_close_reason reason);


typedef enum ws_opcode {
    WS_OPCODE_CONTINUATION  = 0x0,
    WS_OPCODE_TEXT          = 0x1,
    WS_OPCODE_BINARY        = 0x2,
    WS_OPCODE_CLOSE         = 0x8,
    WS_OPCODE_PING          = 0x9,
    WS_OPCODE_PONG          = 0xa,
} ws_opcode;

typedef struct ws_frame_info {
    ws_opcode opcode;
    bool fin;
    bool masking;
    ws_close_reason reason;
    size_t frame_size;
    size_t payload_size;
} ws_frame_info;

static inline void ws_frame_binary_first(bool masking, ws_frame_info *info) {
    info->opcode = WS_OPCODE_BINARY;
    info->fin = false;
    info->masking = masking;
}

static inline void ws_frame_binary_continuous(bool masking, ws_frame_info *info) {
    info->opcode = WS_OPCODE_CONTINUATION;
    info->fin = false;
    info->masking = masking;
}

static inline void ws_frame_binary_final(bool masking, ws_frame_info *info) {
    info->opcode = WS_OPCODE_CONTINUATION;
    info->fin = true;
    info->masking = masking;
}

static inline void ws_frame_binary_alone(bool masking, ws_frame_info *info) {
    info->opcode = WS_OPCODE_BINARY;
    info->fin = true;
    info->masking = masking;
}

uint8_t* http_header_append_new_field(uint8_t*orig, size_t *len, void*(*re_alloc)(void*, size_t), const char*field);
uint8_t* http_header_set_payload_data(uint8_t*orig, size_t *len, void*(*re_alloc)(void*, size_t), const uint8_t*data, size_t data_len);

void random_bytes_generator(const char *seed, uint8_t *buffer, size_t len);

char * websocket_generate_sec_websocket_key(void*(*allocator)(size_t));
char * websocket_generate_sec_websocket_accept(const char *sec_websocket_key, void*(*allocator)(size_t));
uint8_t * websocket_connect_request(const char *domain, uint16_t port, const char *url,
    const char *key, void*(*allocator)(size_t), size_t *result_len);
char * websocket_connect_response(const char *sec_websocket_key, void*(*allocator)(size_t));
uint8_t * websocket_build_frame(ws_frame_info *info, const uint8_t *payload, size_t payload_len, void*(*allocator)(size_t));
uint8_t * websocket_build_close_frame(bool masking, ws_close_reason reason, const char *text_info, void*(*allocator)(size_t), size_t *frame_size);
uint8_t * websocket_retrieve_payload(const uint8_t *data, size_t dataLen, void*(*allocator)(size_t), ws_frame_info *info);

size_t websocket_frame_size(bool masking, size_t payload_len);

uint16_t ws_ntoh16(uint16_t n);
uint16_t ws_hton16(uint16_t n);

uint32_t ws_ntoh32(uint32_t n);
uint32_t ws_hton32(uint32_t n);

uint64_t ws_ntoh64(uint64_t n);
uint64_t ws_hton64(uint64_t n);

char* ws_normal_response(void* (*allocator)(size_t), const char* domain);

#ifdef __cplusplus
}
#endif

#endif /* __WEBSOCKET_BASIC_H__ */
