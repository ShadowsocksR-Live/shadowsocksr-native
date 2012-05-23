#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <langinfo.h>
#include <locale.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include "main.h"

#define PORT 1090
#define REPLY "HTTP/1.1 200 OK\n\nhello"


// every watcher type has its own typedef'd struct
// with the name ev_TYPE
ev_io stdin_watcher;


struct client_ctx {
	ev_io io;
	int fd;
};

int setnonblocking(int fd) {
	int flags;
	if (-1 ==(flags = fcntl(fd, F_GETFL, 0)))
		flags = 0;
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int create_and_bind(char *port) {
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int s, listen_sock;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC; /* Return IPv4 and IPv6 choices */
	hints.ai_socktype = SOCK_STREAM; /* We want a TCP socket */
	hints.ai_flags = AI_PASSIVE; /* All interfaces */

	s = getaddrinfo("0.0.0.0", port, &hints, &result);
	if (s != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
		return -1;
	}

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		listen_sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		int opt = 1;
		setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
		if (listen_sock == -1)
			continue;

		s = bind(listen_sock, rp->ai_addr, rp->ai_addrlen);
		if (s == 0) {
			/* We managed to bind successfully! */
			break;
		}

		close(listen_sock);
	}

	if (rp == NULL) {
		fprintf(stderr, "Could not bind\n");
		return -1;
	}

	freeaddrinfo(result);

	return listen_sock;
}
void send_cb (EV_P_ ev_io *w, int revents)
{
	struct client_ctx *client = (struct client_ctx *)w;
	ev_io_stop(EV_A_ &client->io);
	close(client->fd);
	free(client);
}
void recv_cb (EV_P_ ev_io *w, int revents)
{
	struct client_ctx *client = (struct client_ctx *)w;
	char buf[4096];
	int n = recv(client->fd, buf, 4096, 0);
	if (n == 0) {
		ev_io_stop(EV_A_ &client->io);
		close(client->fd);
		free(client);
		return;
	} else if (n < 0) {
		perror("recv");
		return;
	}
	send(client->fd, REPLY, sizeof(REPLY), MSG_NOSIGNAL);
	ev_io_stop(EV_A_ &client->io);
	ev_io_init(&client->io, send_cb, client->fd, EV_WRITE);
	ev_io_start(EV_A_ &client->io);
}


struct client_ctx* client_new(int fd) {
	struct client_ctx* client;

	client = malloc(sizeof(struct client_ctx));
	client->fd = fd;
	//client->server = server;
	setnonblocking(client->fd);
	ev_io_init(&client->io, recv_cb, client->fd, EV_READ);
	return client;
}

static void server_recv_cb (EV_P_ ev_io *w, int revents) {
	struct server_ctx *server_recv_ctx = (struct server_ctx *)w;
	struct server *server = server_recv_ctx->server;
	struct remote *remote = server->remote;
	while (1) {
		ssize_t r = recv(server->fd, server->buf, BUF_SIZE, 0);
		if (r == 0) {
			// TODO connection closed
			return;
		} else if(r == -1) {
			perror("recv");
			if (errno == EAGAIN) {
				// no data
				// continue to wait for recv
				break;
			}
		}
		int w = send(remote->fd, server->buf, r, MSG_NOSIGNAL);
		if (w == 0) {
			// TODO connection closed
			return;
		} else if(w == -1) {
			perror("send");
			if (errno == EAGAIN) {
				// no data, wait for send
				ev_io_stop(EV_A_ &server_recv_ctx->io);
				ev_io_start(EV_A_ &remote->send_ctx->io);
				break;
			}
		} else if(w < r) {
			char *pt;
			for (pt = server->buf; pt < pt + w; pt++) {
				*pt = *(pt + w);
			}
			server->buf_len = w;
			ev_io_stop(EV_A_ &server_recv_ctx->io);
			ev_io_start(EV_A_ &remote->send_ctx->io);
			break;
		}
	}
}
static void server_send_cb (EV_P_ ev_io *w, int revents) {
	struct server_ctx *server_send_ctx = (struct server_ctx *)w;
	struct server *server = server_send_ctx->server;
	struct remote *remote = server->remote;
	if (remote->buf_len == 0) {
		// TODO close and free
	} else {
		// has data to send
		ssize_t r = send(server->fd, remote->buf,
				remote->buf_len, 0);
		if (r < 0) {
			perror("send");
			// TODO close and free
			return;
		}
		if (r < remote->buf_len) {
			// partly sent, move memory, wait for the next time to send
			char *pt;
			for (pt = remote->buf; pt < pt + r; pt++) {
				*pt = *(pt + r);
			}
			remote->buf_len = r;
			return;
		} else {
			// all sent out, wait for reading
			ev_io_stop(EV_A_ &server_send_ctx->io);
			ev_io_start(EV_A_ &remote->recv_ctx->io);
		}
	}

}
static void remote_recv_cb (EV_P_ ev_io *w, int revents) {
	struct remote_ctx *remote_recv_ctx = (struct remote_ctx *)w;
	struct remote *remote = remote_recv_ctx->remote;
	struct server *server = remote->server;
	while (1) {
		ssize_t r = recv(remote->fd, remote->buf, BUF_SIZE, 0);
		if (r == 0) {
			// TODO connection closed
			return;
		} else if(r == -1) {
			perror("recv");
			if (errno == EAGAIN) {
				// no data
				// continue to wait for recv
				break;
			}
		}
		int w = send(server->fd, remote->buf, r, MSG_NOSIGNAL);
		if (w == 0) {
			// TODO connection closed
			return;
		} else if(w == -1) {
			perror("send");
			if (errno == EAGAIN) {
				// no data, wait for send
				ev_io_stop(EV_A_ &remote_recv_ctx->io);
				ev_io_start(EV_A_ &server->send_ctx->io);
				break;
			}
		} else if(w < r) {
			char *pt;
			for (pt = remote->buf; pt < pt + w; pt++) {
				*pt = *(pt + w);
			}
			remote->buf_len = w;
			ev_io_stop(EV_A_ &remote_recv_ctx->io);
			ev_io_start(EV_A_ &server->send_ctx->io);
			break;
		}
	}
}
static void remote_send_cb (EV_P_ ev_io *w, int revents) {
	struct remote_ctx *remote_send_ctx = (struct remote_ctx *)w;
	struct remote *remote = remote_send_ctx->remote;
	struct server *server = remote->server;
	if (!remote_send_ctx->connected) {
		socklen_t len;
		struct sockaddr_storage addr;
		char ipstr[INET6_ADDRSTRLEN];
		int port;
		len = sizeof addr;
		int r = getpeername(remote->fd, (struct sockaddr*)&addr, &len);
		if (r == 0) {
			remote_send_ctx->connected = 1;
			ev_io_stop(EV_A_ &remote_send_ctx->io);
			ev_io_start(EV_A_ &server->recv_ctx->io);
			ev_io_start(EV_A_ &remote->recv_ctx->io);
		} else {
			perror("getpeername");
			// not connected
			// TODO
			return;
		}
	} else {
		if (server->buf_len == 0) {
			// TODO close and free
		} else {
			// has data to send
			ssize_t r = send(remote->fd, server->buf,
				server->buf_len, 0);
			if (r < 0) {
				perror("send");
				// TODO close and free
				return;
			}
			if (r < server->buf_len) {
				// partly sent, move memory, wait for the next time to send
				char *pt;
				for (pt = server->buf; pt < pt + r; pt++) {
					*pt = *(pt + r);
				}
				server->buf_len = r;
				return;
			} else {
				// all sent out, wait for reading
				ev_io_stop(EV_A_ &remote_send_ctx->io);
				ev_io_start(EV_A_ &server->recv_ctx->io);
			}
		}
	}
}

struct remote* new_remote(int fd) {
	struct remote *remote;
	remote = malloc(sizeof(struct remote));
	remote->fd = fd;
	remote->recv_ctx = malloc(sizeof(struct remote_ctx));
	remote->send_ctx = malloc(sizeof(struct remote_ctx));
	ev_io_init(&remote->recv_ctx->io, remote_recv_cb, fd, EV_READ);
	ev_io_init(&remote->send_ctx->io, remote_send_cb, fd, EV_WRITE);
	remote->recv_ctx->remote = remote;
	remote->recv_ctx->connected = 0;
	remote->send_ctx->remote = remote;
	remote->send_ctx->connected = 0;
	return remote;
}
struct server* new_server(int fd) {
	struct server *server;
	server = malloc(sizeof(struct server));
	server->fd = fd;
	server->recv_ctx = malloc(sizeof(struct server_ctx));
	server->send_ctx = malloc(sizeof(struct server_ctx));
	ev_io_init(&server->recv_ctx->io, server_recv_cb, fd, EV_READ);
	ev_io_init(&server->send_ctx->io, server_send_cb, fd, EV_WRITE);
	server->recv_ctx->server = server;
	server->recv_ctx->connected = 0;
	server->send_ctx->server = server;
	server->send_ctx->connected = 0;
	return server;
}

static void accept_cb (EV_P_ ev_io *w, int revents)
{
	struct listen_ctx *listener = (struct listen_ctx *)w;
	int serverfd;
	while (1) {
		serverfd = accept(listener->fd, NULL, NULL);
		if (serverfd == -1) {
			perror("accept");
			break;
		}
		struct server *server = new_server(serverfd);
		struct addrinfo hints, *res;
		int sockfd;
		memset(&hints, 0, sizeof hints);
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		getaddrinfo("www.sina.com.cn", "80", &hints, &res);
		sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (sockfd < 0) {
			perror("socket");
			exit(1); // TODO close, free and return
		}
		setnonblocking(sockfd);
		struct remote *remote = new_remote(sockfd);
		server->remote = remote;
		remote->server = server;
		connect(sockfd, res->ai_addr, res->ai_addrlen);
		// listen to remote connected event
		ev_io_start(EV_A_ &remote->send_ctx->io);
		break;
	}
}

int main (void)
{
	int listenfd;
	listenfd = create_and_bind("1090");
	if (listen(listenfd, SOMAXCONN) == -1) {
		perror("listen() error.");
		return 1;
	}
	setnonblocking(listenfd);
	struct listen_ctx listen_ctx;
	listen_ctx.fd = listenfd;
	struct ev_loop *loop = EV_DEFAULT;
	ev_io_init (&listen_ctx.io, accept_cb, listenfd, EV_READ);
	ev_io_start (loop, &listen_ctx.io);
	ev_run (loop, 0);
	return 0;
}

