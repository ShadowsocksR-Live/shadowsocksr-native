/*
 * tls1.2_ticket.h - Define shadowsocksR server's buffers and callbacks
 *
 * Copyright (C) 2015 - 2017, Break Wa11 <mmgac001@gmail.com>
 */

#ifndef _OBFS_TLS1_2_TICKET_H
#define _OBFS_TLS1_2_TICKET_H

struct obfs_t * tls12_ticket_auth_new_obfs(void);

//============================= tls1.2_ticket_fastauth ==================================

void * tls12_ticket_fastauth_init_data(void);
struct obfs_t * tls12_ticket_fastauth_new_obfs(void);

#endif // _OBFS_TLS1_2_TICKET_H
