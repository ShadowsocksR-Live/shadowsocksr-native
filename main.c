#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <errno.h>
#include <ev.h>
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

#define PORT 1090

// every watcher type has its own typedef'd struct
// with the name ev_TYPE
ev_io stdin_watcher;
ev_timer timeout_watcher;

struct server_ctx {
	ev_io io;
	int fd;
	struct sockaddr sock;
};

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

	s = getaddrinfo(NULL, port, &hints, &result);
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

static void
read_cb (EV_P_ ev_io *w, int revents)
{
	struct client_ctx *client = (struct client_ctx *)w;
	char buf[4096];
	int n = recv(client->fd, buf, 4096, 0);
	if (n == 0) {
		ev_io_stop(EV_A_ &client->io);
	  	close(client->fd);
		return;
	} else if (n < 0) {
		perror("recv");
		return;
	}
	write(1, buf, n);
}


static struct client_ctx* client_new(int fd) {
  struct client_ctx* client;

  client = malloc(sizeof(struct client_ctx));
  client->fd = fd;
  //client->server = server;
  setnonblocking(client->fd);
  ev_io_init(&client->io, read_cb, client->fd, EV_READ);

  return client;
}
// all watcher callbacks have a similar signature
// this callback is called when data is readable on stdin
	static void
server_cb (EV_P_ ev_io *w, int revents)
{
	puts ("clients connected");
	struct server_ctx *server = (struct server_ctx *)w;
	int connectfd;
	while (1) {
		connectfd = accept(server->fd, NULL, NULL);
		if (connectfd == -1) {
			perror("accept");
			break;
		}
		struct client_ctx *client = client_new(connectfd);
		ev_io_start(EV_A_ &client->io);
		break;
	}

}
	int
main (void)
{
	int listenfd, connectfd;
	listenfd = create_and_bind("1090");
	if (listen(listenfd, SOMAXCONN) == -1) {
		perror("listen() error.");
		return 1;
	}
	setnonblocking(listenfd);

	struct server_ctx listen_ctx;
	listen_ctx.fd = listenfd;

	// use the default event loop unless you have special needs
	struct ev_loop *loop = EV_DEFAULT;

	// initialise an io watcher, then start it
	// this one will watch for stdin to become readable
	ev_io_init (&listen_ctx.io, server_cb, listenfd, EV_READ);
	ev_io_start (loop, &listen_ctx.io);

	// now wait for events to arrive
	ev_run (loop, 0);

	// break was called, so exit
	return 0;
}

