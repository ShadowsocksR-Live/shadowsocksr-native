/*
 * auth.h - Define shadowsocksR server's buffers and callbacks
 *
 * Copyright (C) 2015 - 2016, Break Wa11 <mmgac001@gmail.com>
 */

#ifndef _OBFS_AUTH_CHAIN_H
#define _OBFS_AUTH_CHAIN_H

struct obfs_t;

//============================= auth_chain_a ==================================
struct obfs_t * auth_chain_a_new_obfs(void);

//============================= auth_chain_b ==================================
struct obfs_t * auth_chain_b_new_obfs(void);

//============================= auth_chain_c ==================================
struct obfs_t * auth_chain_c_new_obfs(void);

//============================= auth_chain_d ==================================
struct obfs_t * auth_chain_d_new_obfs(void);

//============================= auth_chain_e ==================================
struct obfs_t * auth_chain_e_new_obfs(void);

//============================= auth_chain_f ==================================
struct obfs_t * auth_chain_f_new_obfs(void);


#endif // _OBFS_AUTH_CHAIN_H
