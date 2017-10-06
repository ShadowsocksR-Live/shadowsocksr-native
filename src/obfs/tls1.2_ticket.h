/*
 * tls1.2_ticket.h - Define shadowsocksR server's buffers and callbacks
 *
 * Copyright (C) 2015 - 2017, Break Wa11 <mmgac001@gmail.com>
 */

#ifndef _OBFS_TLS1_2_TICKET_H
#define _OBFS_TLS1_2_TICKET_H

void * tls12_ticket_auth_init_data(void);
struct obfs_t * tls12_ticket_auth_new_obfs(void);
void tls12_ticket_auth_dispose(struct obfs_t *obfs);

size_t tls12_ticket_auth_client_encode(struct obfs_t *obfs, char **pencryptdata, size_t datalength, size_t* capacity);
size_t tls12_ticket_auth_client_decode(struct obfs_t *obfs, char **pencryptdata, size_t datalength, size_t* capacity, int *needsendback);

int tls12_ticket_auth_get_overhead(struct obfs_t *obfs);

#endif // _OBFS_TLS1_2_TICKET_H
