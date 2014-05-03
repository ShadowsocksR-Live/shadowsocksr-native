#ifndef _INCLUDE_H
#define _INCLUDE_H

// only enable TCP_FASTOPEN on linux
#if __linux

/*  conditional define for TCP_FASTOPEN */
#ifndef TCP_FASTOPEN
#define TCP_FASTOPEN   23
#endif
 
/*  conditional define for MSG_FASTOPEN */
#ifndef MSG_FASTOPEN
#define MSG_FASTOPEN   0x20000000
#endif

#endif

int udprelay_init(const char *server_host, const char *server_port,
#ifdef UDPRELAY_LOCAL
                  const char *remote_host, const char *remote_port,
#ifdef UDPRELAY_TUNNEL
                  const ss_addr_t tunnel_addr,
#endif
#endif
#ifdef UDPRELAY_REMOTE
                  int dns_thread_num,
#endif
                  int method, int timeout, const char *iface);

#endif // _INCLUDE_H
