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

#include "encrypt.h"
#include "socks5.h"
#include "server.h"

#define SERVER "127.0.0.1"
#define REMOTE_PORT "8499"
#define PORT "1080"
#define KEY "foobar!"

#define REPLY "HTTP/1.1 200 OK\n\nhello"

#define min(a,b) \
	({ typeof (a) _a = (a); \
	 typeof (b) _b = (b); \
	 _a < _b ? _a : _b; })

#define FD_NULL 0

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
		} else {
			perror("bind");
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

static void server_recv_cb (EV_P_ ev_io *w, int revents) {
	struct server_ctx *server_recv_ctx = (struct server_ctx *)w;
	struct server *server = server_recv_ctx->server;
	struct remote *remote = server->remote;
	if (server->stage == 5 && remote == NULL) {
		close_and_free_server(EV_A_ server);
		return;
	}
	// if remote is not created, use server->buf for both read & write
	char *buf = server->buf;
	int *buf_len = &server->buf_len;
	if (remote != NULL) {
		buf = remote->buf;
		buf_len = &remote->buf_len;
	}
	while (1) {
		ssize_t r = recv(server->fd, buf, BUF_SIZE, 0);
		if (r == 0) {
			// connection closed
			*buf_len = 0;
			close_and_free_server(EV_A_ server);
			if (remote != NULL) {
				ev_io_start(EV_A_ &remote->send_ctx->io);
			}
			return;
		} else if(r < 0) {
			perror("recv");
			if (errno == EAGAIN) {
				// no data
				// continue to wait for recv
				break;
			} else {
				close_and_free_server(EV_A_ server);
				close_and_free_remote(EV_A_ remote);
				return;
			}
		}
		decrypt(buf, r);
		if (server->stage == 5) {
			int w = send(remote->fd, remote->buf, r, MSG_NOSIGNAL);
			if(w == -1) {
				perror("send");
				if (errno == EAGAIN) {
					// no data, wait for send
					ev_io_stop(EV_A_ &server_recv_ctx->io);
					ev_io_start(EV_A_ &remote->send_ctx->io);
					break;
				} else {
					close_and_free_server(EV_A_ server);
					close_and_free_remote(EV_A_ remote);
					return;
				}
			} else if(w < r) {
				char *pt;
				for (pt = remote->buf; pt < pt + min(w, BUF_SIZE); pt++) {
					*pt = *(pt + w);
				}
				remote->buf_len = r - w;
				ev_io_stop(EV_A_ &server_recv_ctx->io);
				ev_io_start(EV_A_ &remote->send_ctx->io);
				break;
			}
		} else if (server->stage == 0) {
			struct method_select_response response;
			response.ver = VERSION;
			response.method = 0;
			char *send_buf = (char *)&response;
			send_encrypt(server->fd, send_buf, sizeof(response), MSG_NOSIGNAL);
			server->stage = 1;
			return;
		} else if (server->stage == 1) {
			struct socks5_request *request = (struct socks5_request *)server->buf;
			if (request->cmd != 1) {
				fprintf(stderr, "unsupported cmd: %d\n", request->cmd);
				struct socks5_response response;
				response.ver = VERSION;
				response.rep = CMD_NOT_SUPPORTED;
				response.rsv = 0;
				response.atyp = 1;
				char *send_buf = (char *)&response;
				send_encrypt(server->fd, send_buf, 4, MSG_NOSIGNAL);
				close_and_free_server(EV_A_ server);
				return;
			}

			struct addrinfo remote_addrinfo;
			struct sockaddr remote_sockaddr;
			int rv;

			// get remote addr and port
			if (request->atyp == 1) {
				// IP V4
				struct sockaddr_in *addrp = (struct sockaddr_in *)&remote_sockaddr;
				struct in_addr *in_addr;
				in_addr = (struct in_addr *)(server->buf + 4);
				addrp->sin_addr = *in_addr;
				// get port
				addrp->sin_port = *(unsigned short *)(server->buf + 4 + 4);
			} else if (request->atyp == 3) {
				struct addrinfo hints, *res;
				memset(&hints, 0, sizeof hints);
				hints.ai_family = AF_UNSPEC;
				hints.ai_socktype = SOCK_STREAM;
				char name_buf[256];
				unsigned char name_len = *(unsigned char *)(server->buf + 4);
				memcpy(name_buf, server->buf + 4 + 1, name_len);
				name_buf[name_len] = 0; // append NUL
				fprintf(stderr, "connecting: %s\n", name_buf);
				if ((rv = getaddrinfo(name_buf, "80", &hints, &res)) != 0) {
					perror("getaddrinfo");
					// TODO send reply
					close_and_free_server(EV_A_ server);
					return;
				}
				remote_addrinfo = *res;
				remote_sockaddr = *(res->ai_addr);
				remote_addrinfo.ai_addr = &remote_sockaddr;

				// get port
				struct sockaddr_in *addrp = (struct sockaddr_in *)&remote_sockaddr;
				addrp->sin_port = *(unsigned short *)(server->buf + 4 + 1 + name_len);
				freeaddrinfo(res);
			} else {
				fprintf(stderr, "unsupported addrtype: %d\n", request->atyp);
				// TODO send reply
				close_and_free_server(EV_A_ server);
				return;
			}
			

			int sockfd;
			sockfd = socket(remote_addrinfo.ai_family, remote_addrinfo.ai_socktype,
				remote_addrinfo.ai_protocol);
			if (sockfd < 0) {
				perror("socket");
				close(sockfd);
				// TODO send reply
				close_and_free_server(EV_A_ server);
				close_and_free_remote(EV_A_ remote);
				return;
			}
			setnonblocking(sockfd);
			remote = new_remote(sockfd);
			server->remote = remote;
			remote->server = server;
			connect(sockfd, remote_addrinfo.ai_addr, remote_addrinfo.ai_addrlen);
			ev_io_stop(EV_A_ &server->recv_ctx->io);
			ev_io_start(EV_A_ &remote->send_ctx->io);
			server->stage = 4;
			return;
		}
	}
}
static void server_send_cb (EV_P_ ev_io *w, int revents) {
	struct server_ctx *server_send_ctx = (struct server_ctx *)w;
	struct server *server = server_send_ctx->server;
	struct remote *remote = server->remote;
	if (server->buf_len == 0) {
		// close and free
		close_and_free_server(EV_A_ server);
		close_and_free_remote(EV_A_ remote);
		return;
	} else {
		// has data to send
		ssize_t r = send(server->fd, server->buf,
				server->buf_len, 0);
		if (r < 0) {
			perror("send");
			if (errno != EAGAIN) {
				close_and_free_server(EV_A_ server);
				close_and_free_remote(EV_A_ remote);
				return;
			}
			return;
		}
		if (r < server->buf_len) {
			// printf("r=%d\n", r);
			// printf("server->buf_len=%d\n", server->buf_len);
			// partly sent, move memory, wait for the next time to send
			char *pt;
			for (pt = server->buf; pt < pt + min(r, BUF_SIZE); pt++) {
				*pt = *(pt + r);
			}
			server->buf_len -= r;
			return;
		} else {
			// all sent out, wait for reading
			ev_io_stop(EV_A_ &server_send_ctx->io);
			if (remote != NULL) {
				ev_io_start(EV_A_ &remote->recv_ctx->io);
			} else {
				close_and_free_server(EV_A_ server);
				close_and_free_remote(EV_A_ remote);
				return;
			}
		}
	}

}
static void remote_recv_cb (EV_P_ ev_io *w, int revents) {
	struct remote_ctx *remote_recv_ctx = (struct remote_ctx *)w;
	struct remote *remote = remote_recv_ctx->remote;
	struct server *server = remote->server;
	if (server == NULL) {
		close_and_free_remote(EV_A_ remote);
		return;
	}
	while (1) {
		ssize_t r = recv(remote->fd, server->buf, BUF_SIZE, 0);
		// printf("after recv: r=%d\n", r);
		if (r == 0) {
			// connection closed
			server->buf_len = 0;
			close_and_free_remote(EV_A_ remote);
			if (server != NULL) {
				ev_io_start(EV_A_ &server->send_ctx->io);
			}
			return;
		} else if(r < 0) {
			perror("recv");
			if (errno == EAGAIN) {
				// no data
				// continue to wait for recv
				break;
			} else {
				close_and_free_server(EV_A_ server);
				close_and_free_remote(EV_A_ remote);
				return;
			}
		}
		encrypt(server->buf, r);
		int w = send(server->fd, server->buf, r, MSG_NOSIGNAL);
		// printf("after send: w=%d\n", w);
		if(w == -1) {
			perror("send");
			if (errno == EAGAIN) {
				// no data, wait for send
				ev_io_stop(EV_A_ &remote_recv_ctx->io);
				ev_io_start(EV_A_ &server->send_ctx->io);
				break;
			} else {
				close_and_free_server(EV_A_ server);
				close_and_free_remote(EV_A_ remote);
				return;
			}
		} else if(w < r) {
			char *pt;
			for (pt = server->buf; pt < pt + min(w, BUF_SIZE); pt++) {
				*pt = *(pt + w);
			}
			server->buf_len = r - w;
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
	printf("remote_send_cb\n");
	if (!remote_send_ctx->connected) {

		printf("not connected\n");
		socklen_t len;
		struct sockaddr_storage addr;
		char ipstr[INET6_ADDRSTRLEN];
		int port;
		len = sizeof addr;
		int r = getpeername(remote->fd, (struct sockaddr*)&addr, &len);
		if (r == 0) {
			remote_send_ctx->connected = 1;

			printf("send reply\n");
			// send reply
			struct sockaddr_in sockaddr;
			socklen_t sockaddrlen = sizeof(sockaddr);
			int rv = getsockname(remote->fd, (struct sockaddr *)&sockaddr, &sockaddrlen);
			if (rv == -1) {
				perror("getsockname");
				close_and_free_remote(EV_A_ remote);
				close_and_free_server(EV_A_ server);
				return;
			}
			struct socks5_response response;
			response.ver = VERSION;
			response.rep = 0;
			response.rsv = 0;
			response.atyp = 1;

			memcpy(server->buf, &response, 4);
			memcpy(server->buf + 4, &sockaddr.sin_addr, sizeof(struct in_addr));
			memcpy(server->buf + 4 + sizeof(struct in_addr), &sockaddr.sin_port, 
					sizeof(struct in_addr));

			fprintf(stderr, "send reply\n");
			int r = send_encrypt(server->fd, server->buf, 4 + sizeof(struct in_addr) + 
					sizeof(unsigned short), 0);
			if (r < 4 + sizeof(struct in_addr) + sizeof(unsigned short)) {
				fprintf(stderr, "header not complete sent\n");
				close_and_free_remote(EV_A_ remote);
				close_and_free_server(EV_A_ server);
			}
			server->stage = 5;

			ev_io_stop(EV_A_ &remote_send_ctx->io);
			ev_io_start(EV_A_ &server->recv_ctx->io);
			ev_io_start(EV_A_ &remote->recv_ctx->io);
		} else {
			perror("getpeername");
			// not connected
			close_and_free_remote(EV_A_ remote);
			close_and_free_server(EV_A_ server);
			return;
		}
	} else {
		printf("is connected\n");
		if (remote->buf_len == 0) {
			// close and free
			close_and_free_remote(EV_A_ remote);
			close_and_free_server(EV_A_ server);
			return;
		} else {
			// has data to send
			ssize_t r = send(remote->fd, remote->buf,
					remote->buf_len, 0);
			if (r < 0) {
				perror("send");
				if (errno != EAGAIN) {
					// close and free
					close_and_free_remote(EV_A_ remote);
					close_and_free_server(EV_A_ server);
					return;
				}
				return;
			}
			if (r < remote->buf_len) {
				// partly sent, move memory, wait for the next time to send
				char *pt;
				for (pt = remote->buf; pt < pt + min(r, BUF_SIZE); pt++) {
					*pt = *(pt + r);
				}
				remote->buf_len -= r;
				return;
			} else {
				// all sent out, wait for reading
				ev_io_stop(EV_A_ &remote_send_ctx->io);
				if (server != NULL) {
					ev_io_start(EV_A_ &server->recv_ctx->io);
				} else {
					close_and_free_remote(EV_A_ remote);
					close_and_free_server(EV_A_ server);
					return;
				}
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
	fprintf(stderr, "new remote\n");
	return remote;
}
void free_remote(struct remote *remote) {
	if (remote != NULL) {
		if (remote->server != NULL) {
			remote->server->remote = NULL;
		}
		free(remote->recv_ctx);
		free(remote->send_ctx);
		free(remote);
		fprintf(stderr, "free remote\n");
	}
}
void close_and_free_remote(EV_P_ struct remote *remote) {
	if (remote != NULL) {
		ev_io_stop(EV_A_ &remote->send_ctx->io);
		ev_io_stop(EV_A_ &remote->recv_ctx->io);
		if (remote->fd != FD_NULL) {
			close(remote->fd);
		}
		free_remote(remote);
	}
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
	server->stage = 0;
	fprintf(stderr, "new server\n");
	return server;
}
void free_server(struct server *server) {
	if (server != NULL) {
		if (server->remote != NULL) {
			server->remote->server = NULL;
		}
		free(server->recv_ctx);
		free(server->send_ctx);
		free(server);
		fprintf(stderr, "free server\n");
	}
}
void close_and_free_server(EV_P_ struct server *server) {
	if (server != NULL) {
		ev_io_stop(EV_A_ &server->send_ctx->io);
		ev_io_stop(EV_A_ &server->recv_ctx->io);
		if (server->fd != FD_NULL) {
			close(server->fd);
		}
		free_server(server);
	}
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
 		setnonblocking(serverfd);
		struct server *server = new_server(serverfd);
// 		struct addrinfo hints, *res;
// 		int sockfd;
// 		memset(&hints, 0, sizeof hints);
// 		hints.ai_family = AF_UNSPEC;
// 		hints.ai_socktype = SOCK_STREAM;
// 		getaddrinfo(SERVER, REMOTE_PORT, &hints, &res);
// 		sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
// 		if (sockfd < 0) {
// 			perror("socket");
// 			close(sockfd);
// 			free_server(server);
// 			continue;
// 		}
// 		setnonblocking(sockfd);
 		server->remote = NULL;
// 		connect(sockfd, res->ai_addr, res->ai_addrlen);
// 		// listen to remote connected event
// 		ev_io_start(EV_A_ &remote->send_ctx->io);
		ev_io_start(EV_A_ &server->recv_ctx->io);
		break;
	}
}

int main (void)
{
	fprintf(stderr, "calculating ciphers\n");
	get_table(KEY);

	int listenfd;
	listenfd = create_and_bind(REMOTE_PORT);
	if (listenfd < 0) {
		return 1;
	}
	if (listen(listenfd, SOMAXCONN) == -1) {
		perror("listen() error.");
		return 1;
	}
	fprintf(stderr, "server listening at port %s\n", REMOTE_PORT);
	setnonblocking(listenfd);
	struct listen_ctx listen_ctx;
	listen_ctx.fd = listenfd;
	struct ev_loop *loop = EV_DEFAULT;
	ev_io_init (&listen_ctx.io, accept_cb, listenfd, EV_READ);
	ev_io_start (loop, &listen_ctx.io);
	ev_run (loop, 0);
	return 0;
}

