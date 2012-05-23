#pragma once

#include <ev.h>

#define BUF_SIZE 4096

struct server {
	int server_fd;
	char server_buf[BUF_SIZE];
	int server_buf_len;
	struct server_read_ctx *server_read_ctx;
	struct server_write_ctx *server_write_ctx;
	struct remote *remote;
};
struct server_read_ctx {
	ev_io server_read_io;
	struct server *server;
};
struct server_write_ctx {
	ev_io server_write_io;
	struct server *server;
};
struct remote {
	int remote_fd;
	char remote_buf[BUF_SIZE];
	int remote_buf_len;
	struct remote_read_ctx *remote_read_ctx;
	struct remote_write_ctx *remote_write_ctx;
	struct server *server;
};
struct remote_read_ctx {
	ev_io remote_read_io;
	struct remote *remote;
};
struct remote_write_ctx {
	ev_io remote_write_io;
	struct remote *remote;
};


static void
accept_cb (EV_P_ ev_io *w, int revents);
static void
server_read_cb (EV_P_ ev_io *w, int revents);
static void
server_write_cb (EV_P_ ev_io *w, int revents);
static void
remote_read_cb (EV_P_ ev_io *w, int revents);
static void
remote_write_cb (EV_P_ ev_io *w, int revents);

