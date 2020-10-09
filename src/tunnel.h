#if !defined(__tunnel_h__)
#define __tunnel_h__ 1

#include "ref_count_def.h"
#include "sockaddr_universal.h"
#include <stdbool.h>
#include <uv.h>

enum socket_state {
    socket_state_stop, /* Stopped. */
    socket_state_busy, /* Busy; waiting for incoming data or for a write to complete. */
    socket_state_done, /* Done; read incoming data or write finished. */
    socket_state_dead,
};

struct socket_ctx;

typedef void (*socket_ctx_on_getaddrinfo_cb)(struct socket_ctx* socket, int status, const struct addrinfo* ai, void* p);
typedef void (*socket_ctx_on_connect_cb)(struct socket_ctx* socket, int status, void* p);
typedef size_t (*socket_ctx_on_alloc_cb)(struct socket_ctx* socket, size_t size, void* p);
typedef void (*socket_ctx_on_read_cb)(struct socket_ctx* socket, int status, const uv_buf_t* buf, void* p);
typedef void (*socket_ctx_on_written_cb)(struct socket_ctx* socket, int status, void* p);
typedef void (*socket_ctx_on_closed_cb)(struct socket_ctx* socket, void* p);
typedef void (*socket_ctx_on_timeout_cb)(struct socket_ctx* socket, void* p);

struct socket_ctx {
    enum socket_state rdstate;
    enum socket_state wrstate;
    unsigned int idle_timeout;
    bool is_terminated;

    REF_COUNT_MEMBER;

    int result;
    union uv_any_handle handle;
    bool check_timeout;
    uv_timer_t timer_handle; /* For detecting timeouts. */
    /* We only need one of these at a time so make them share memory. */
    union uv_any_req req;
    union sockaddr_universal addr;
    const uv_buf_t* buf; /* Scratch space. Used to read data into. */

    bool on_getaddrinfo_pending;
    socket_ctx_on_getaddrinfo_cb on_getaddrinfo;
    void* on_getaddrinfo_p;

    socket_ctx_on_connect_cb on_connect;
    void* on_connect_p;

    socket_ctx_on_alloc_cb on_alloc;
    void* on_alloc_p;

    socket_ctx_on_read_cb on_read;
    void* on_read_p;

    socket_ctx_on_written_cb on_written;
    void* on_written_p;

    socket_ctx_on_closed_cb on_closed;
    void* on_closed_p;
    int closing_count;

    socket_ctx_on_timeout_cb on_timeout;
    void* on_timeout_p;
};

struct socket_ctx* socket_context_create(uv_loop_t* loop, unsigned int idle_timeout);

REF_COUNT_ADD_REF_DECL(socket_ctx); // socket_ctx_add_ref
REF_COUNT_RELEASE_DECL(socket_ctx); // socket_ctx_release

void socket_ctx_set_on_getaddrinfo_cb(struct socket_ctx* socket, socket_ctx_on_getaddrinfo_cb on_getaddrinfo, void* p);
void socket_ctx_set_on_connect_cb(struct socket_ctx* socket, socket_ctx_on_connect_cb on_connect, void* p);
void socket_ctx_set_on_alloc_cb(struct socket_ctx* socket, socket_ctx_on_alloc_cb on_alloc, void* p);
void socket_ctx_set_on_read_cb(struct socket_ctx* socket, socket_ctx_on_read_cb on_read, void* p);
void socket_ctx_set_on_written_cb(struct socket_ctx* socket, socket_ctx_on_written_cb on_written, void* p);
void socket_ctx_set_on_timeout_cb(struct socket_ctx* socket, socket_ctx_on_timeout_cb on_timeout, void* p);

uv_os_sock_t uv_stream_fd(const uv_tcp_t* handle);
uint16_t get_socket_port(const uv_tcp_t* tcp);
size_t update_tcp_mss(struct socket_ctx* socket);
size_t get_fd_tcp_mss(uv_os_sock_t fd);
size_t socket_arrived_data_size(struct socket_ctx* socket, size_t suggested_size);

int socket_ctx_connect(struct socket_ctx* socket);
void socket_ctx_close(struct socket_ctx* socket, socket_ctx_on_closed_cb on_closed, void* p);
bool socket_ctx_is_terminated(struct socket_ctx* socket);
bool socket_ctx_is_readable(struct socket_ctx* socket);
bool socket_ctx_is_writeable(struct socket_ctx* socket);
void socket_ctx_read(struct socket_ctx* socket, bool check_timeout);
void socket_ctx_getaddrinfo(struct socket_ctx* socket, const char* hostname, uint16_t port);
void socket_ctx_write(struct socket_ctx* socket, const void* data, size_t len);

struct tunnel_ctx {
    void* data;
    bool is_terminated;
    uv_loop_t* loop; /* Backlink to owning loop object. */
    struct socket_ctx* incoming; /* Connection with the SOCKS client. */
    struct socket_ctx* outgoing; /* Connection with upstream. */
    struct socks5_address* desired_addr;
    char extra_info[0x100];

    REF_COUNT_MEMBER;

#if defined(__PRINT_INFO__)
    bool in_streaming;
#endif

    void (*tunnel_destroying)(struct tunnel_ctx* tunnel);

    void (*tunnel_dispatcher)(struct tunnel_ctx* tunnel, struct socket_ctx* socket);
    void (*tunnel_timeout_expire_done)(struct tunnel_ctx* tunnel, struct socket_ctx* socket);
    void (*tunnel_outgoing_connected_done)(struct tunnel_ctx* tunnel, struct socket_ctx* socket);
    void (*tunnel_read_done)(struct tunnel_ctx* tunnel, struct socket_ctx* socket);
    void (*tunnel_arrive_end_of_file)(struct tunnel_ctx* tunnel, struct socket_ctx* socket);
    void (*tunnel_on_getaddrinfo_done)(struct tunnel_ctx* tunnel, struct socket_ctx* socket, const struct addrinfo* ai);
    void (*tunnel_write_done)(struct tunnel_ctx* tunnel, struct socket_ctx* socket);
    size_t (*tunnel_get_alloc_size)(struct tunnel_ctx* tunnel, struct socket_ctx* socket, size_t suggested_size);
    uint8_t* (*tunnel_extract_data)(struct tunnel_ctx* tunnel, struct socket_ctx* socket, void* (*allocator)(size_t size), size_t* size);
    bool (*tunnel_is_in_streaming)(struct tunnel_ctx* tunnel);
    void (*tunnel_shutdown)(struct tunnel_ctx* tunnel);
    bool (*tunnel_is_terminated)(struct tunnel_ctx* tunnel);
};

typedef bool (*tunnel_init_done_cb)(struct tunnel_ctx* tunnel, void* p);
struct tunnel_ctx* tunnel_initialize(uv_loop_t* loop, uv_tcp_t* listener, unsigned int idle_timeout, tunnel_init_done_cb init_done_cb, void* p);

REF_COUNT_ADD_REF_DECL(tunnel_ctx); // tunnel_ctx_add_ref
REF_COUNT_RELEASE_DECL(tunnel_ctx); // tunnel_ctx_release

void tunnel_socket_ctx_write(struct tunnel_ctx* tunnel, struct socket_ctx* socket, const void* data, size_t len);
void tunnel_dump_error_info(struct tunnel_ctx* tunnel, struct socket_ctx* socket, const char* title);

#endif // !defined(__tunnel_h__)
