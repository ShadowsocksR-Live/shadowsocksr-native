#ifndef _INCLUDE_H
#define _INCLUDE_H

int udprelay_init(const char *server_host, const char *server_port,
#ifdef UDPRELAY_LOCAL
             const char *remote_host, const char *remote_port,
#endif
#ifdef UDPRELAY_REMOTE
             asyncns_t *asyncns,
#endif
             int method, int timeout, const char *iface);

#endif // _INCLUDE_H
