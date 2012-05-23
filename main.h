#pragma once

#include <ev.h>

#define BUF_SIZE 4096

struct listen_ctx {
	ev_io io;
	int fd;
	struct sockaddr sock;
};

struct server {
	int fd;
	char buf[BUF_SIZE]; // server recv into, remote send from
	int buf_len;
	struct server_ctx *recv_ctx;
	struct server_ctx *send_ctx;
	struct remote *remote;
};
struct server_ctx {
	ev_io io;
	int connected;
	struct server *server;
};
struct remote {
	int fd;
	char buf[BUF_SIZE]; // remote recv into, server send from
	int buf_len;
	struct remote_ctx *recv_ctx;
	struct remote_ctx *send_ctx;
	struct server *server;
};
struct remote_ctx {
	ev_io io;
	int connected;
	struct remote *remote;
};


static void accept_cb (EV_P_ ev_io *w, int revents);
static void server_recv_cb (EV_P_ ev_io *w, int revents);
static void server_send_cb (EV_P_ ev_io *w, int revents);
static void remote_recv_cb (EV_P_ ev_io *w, int revents);
static void remote_send_cb (EV_P_ ev_io *w, int revents);

