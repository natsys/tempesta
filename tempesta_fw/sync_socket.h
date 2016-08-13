/**
 *		Synchronous Socket API.
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2016 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#ifndef __SS_SOCK_H__
#define __SS_SOCK_H__

#include <net/sock.h>
#include <net/tcp.h>
#include <linux/skbuff.h>

#include "addr.h"
#include "ss_skb.h"

/* Protocol descriptor. */
typedef struct ss_proto_t {
	const struct ss_hooks	*hooks;
	struct sock		*listener;
	int			type;
} SsProto;

/* Table of Synchronous Sockets connection callbacks. */
typedef struct ss_hooks {
	/* New connection accepted. */
	int (*connection_new)(struct sock *sk);

	/* Drop TCP connection associated with the socket. */
	int (*connection_drop)(struct sock *sk);

	/* Error on TCP connection associated with the socket. */
	int (*connection_error)(struct sock *sk);

	/* Process data received on the socket. */
	int (*connection_recv)(void *conn, struct sk_buff *skb,
			       unsigned int off);
} SsHooks;

static inline void
ss_sock_hold(struct sock *sk)
{
	sock_hold(sk);
}

static inline void
ss_sock_put(struct sock *sk)
{
	sock_put(sk);
}

static inline bool
ss_sock_live(struct sock *sk)
{
	return sk->sk_state == TCP_ESTABLISHED;
}

enum {
	__SS_F_SYNC = 0,		/* Synchronous operation required. */
	__SS_F_KEEP_SKB,		/* Keep SKBs (use clones) on sending. */
	__SS_F_CONN_CLOSE,		/* Close (drop) the connection. */
};

#define SS_F_SYNC			(1 << __SS_F_SYNC)
#define SS_F_KEEP_SKB			(1 << __SS_F_KEEP_SKB)
#define SS_F_CONN_CLOSE			(1 << __SS_F_CONN_CLOSE)

#define ss_close(sk)			\
	__ss_close(sk, 0)
#define ss_close_sync(sk, drop)		\
	__ss_close(sk, SS_F_SYNC | (drop ? SS_F_CONN_CLOSE : 0))

int ss_hooks_register(SsHooks* hooks);
void ss_hooks_unregister(SsHooks* hooks);

void ss_proto_init(SsProto *proto, const SsHooks *hooks, int type);
void ss_proto_inherit(const SsProto *parent, SsProto *child, int child_type);
void ss_set_callbacks(struct sock *sk);
void ss_set_listen(struct sock *sk);
int ss_send(struct sock *sk, SsSkbList *skb_list, int flags);
int __ss_close(struct sock *sk, int flags);
int ss_sock_create(int family, int type, int protocol, struct sock **res);
void ss_release(struct sock *sk);
int ss_connect(struct sock *sk, struct sockaddr *addr, int addrlen, int flags);
int ss_bind(struct sock *sk, struct sockaddr *addr, int addrlen);
int ss_listen(struct sock *sk, int backlog);
void ss_getpeername(struct sock *sk, TfwAddr *addr);

#endif /* __SS_SOCK_H__ */
