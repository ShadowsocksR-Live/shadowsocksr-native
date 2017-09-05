/*
 * tls1.2_ticket.h - Define shadowsocksR server's buffers and callbacks
 *
 * Copyright (C) 2015 - 2017, Break Wa11 <mmgac001@gmail.com>
 */

#ifndef _OBFS_TLS1_2_TICKET_H
#define _OBFS_TLS1_2_TICKET_H

void * tls12_ticket_auth_init_data();
struct obfs_t * tls12_ticket_auth_new_obfs();
void tls12_ticket_auth_dispose(struct obfs_t *self);

int tls12_ticket_auth_client_encode(struct obfs_t *self, char **pencryptdata, int datalength, size_t* capacity);
int tls12_ticket_auth_client_decode(struct obfs_t *self, char **pencryptdata, int datalength, size_t* capacity, int *needsendback);

int tls12_ticket_auth_get_overhead(struct obfs_t *self);

#endif // _OBFS_TLS1_2_TICKET_H
