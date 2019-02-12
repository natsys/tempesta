/**
 *		Tempesta FW
 *
 * Definitions for generic connection management at OSI level 6 (presentation).
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2018 Tempesta Technologies, Inc.
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
#ifndef __TFW_CONNECTION_H__
#define __TFW_CONNECTION_H__

#include <net/sock.h>

#include "gfsm.h"
#include "msg.h"
#include "peer.h"

#include "http_parser.h"

#include "sync_socket.h"
#include "tls.h"

/*
 * Flag bits definition for SsProto.type field.
 * NOTE: There are also flags definition for this
 * field in SS layer (in sync_socket.h)
 */
enum {
	/* Protocol bits. */
	__Conn_Bits	= 0x8,

	/* Each connection has Client or Server bit. */
	Conn_Clnt	= 0x1 << __Conn_Bits,
	Conn_Srv	= 0x2 << __Conn_Bits,

	/* HTTP */
	Conn_HttpClnt	= Conn_Clnt | TFW_FSM_HTTP,
	Conn_HttpSrv	= Conn_Srv | TFW_FSM_HTTP,

	/* HTTPS */
	Conn_HttpsClnt	= Conn_Clnt | TFW_FSM_HTTPS,
	Conn_HttpsSrv	= Conn_Srv | TFW_FSM_HTTPS,
};

#define TFW_CONN_TYPE2IDX(t)	TFW_FSM_TYPE(t)

/**
 * Session/Presentation layer (in OSI terms) handling.
 *
 * An instance of TfwConn{} structure links each HTTP message to properties
 * of a connection the message has come on. Some messages may stay longer
 * in Tempesta after they're sent out to their destinations. Requests are
 * kept until a paired response comes. By the time the request's connection
 * is needed for sending the response, it may be destroyed already. Thus,
 * TfwConn{} instance is not destroyed along with the connection so that
 * it can be safely dereferenced. It's kept around until refcnt's value
 * permits freeing of the instance, so it may have longer lifetime than
 * the connection itself.
 *
 * @sk is an intrinsic property of TfwConn{}.
 * It has exactly the same lifetime as an instance of TfwConn{}.
 *
 * @peer is major property of TfwConn{}. An instance of @peer has longer
 * lifetime expectation than a connection. @peer is always valid while
 * it's referenced from an instance of TfwConn{}. That is supported by
 * a separate reference counter in @peer.
 *
 * These are the properties of a connection that are common to client
 * and server connections.
 *
 * @proto	- protocol handler. Base class, must be first;
 * @state	- connection processing state;
 * @list	- member in the list of connections with @peer;
 * @refcnt	- number of users of the connection structure instance;
 * @timer	- The keep-alive/retry timer for the connection;
 * @msg		- message that is currently being processed;
 * @peer	- TfwClient or TfwServer handler;
 * @sk		- an appropriate sock handler;
 * @destructor	- called when a connection is destroyed;
 */
#define TFW_CONN_COMMON					\
	SsProto			proto;			\
	TfwGState		state;			\
	TfwHttpParser		parser;			\
	struct list_head	list;			\
	atomic_t		refcnt;			\
	struct timer_list	timer;			\
	TfwMsg			*msg;			\
	TfwPeer 		*peer;			\
	struct sock		*sk;			\
	void			(*destructor)(void *);

typedef struct {
	TFW_CONN_COMMON;
} TfwConn;

#define TFW_CONN_TYPE(c)	((c)->proto.type)
#define TFW_CONN_PROTO(c)	TFW_CONN_TYPE2IDX(TFW_CONN_TYPE(c))

/*
 * Queues in client and server connections provide support for correct
 * handling of requests and responses.
 *
 * Incoming requests are put on client connection's @seq_queue in the
 * order they come in. When responses to these requests come, they're
 * sent back to client in exactly the same order the requests came in.
 * @seq_queue is contended by threads that process requests, as well
 * as by threads that process responses. In the latter case that may
 * not lead to sending a response. Thus a separate @ret_qlock is used
 * for sending responses to decrease the time @seq_qlock is taken for.
 *
 * Unless serviced from cache, each request is forwarded to a server
 * over specific server connection. It's put on server connection's
 * @fwd_queue, and also on @nip_queue if it's non-idempotent. Requests
 * must be forwarded in the same order they're put on @fwd_queue, so
 * it must be done under the queue lock. Otherwise pairing of requests
 * to responses may get broken. When a response comes then the first
 * request is taken out of @fwd_queue, and that's the paired request.
 * There're two types of requests in @fwd_queue: those that were sent
 * out, and those that were not sent out yet. @msg_sent points at the
 * latest request that was sent out. That is helpful when repairing
 * a server connection that had gone bad.
 *
 * A request is in @seq_queue until it's deleted, and may also be in
 * @fwd_queue if it's forwarded to a server. @nip_queue supplements
 * @fwd_queue and may be considered as part of @fwd_queue for this
 * description. A response is never put on any queue. Instead, it's
 * attached to a paired request as @req->resp. A request is always
 * processed in the context of just one queue at any given moment.
 * That way NO locking hierarchy is involved. Please see the code.
 */

/*
 * These are specific properties that are relevant to client connections.
 *
 * @seq_queue	- queue of client's messages in the order they came;
 * @seq_qlock	- lock for accessing @seq_queue;
 * @ret_qlock	- lock for serializing sets of responses;
 * @rmem_used	- total memory used by all pending requests;
 */
typedef struct {
	TFW_CONN_COMMON;
	struct list_head	seq_queue;
	spinlock_t		seq_qlock;
	spinlock_t		ret_qlock;
	atomic_t		rmem_used;
} TfwCliConn;

/*
 * These are specific properties that are relevant to server connections.
 * See the description of special features of this structure in sock_srv.c.
 *
 * @fwd_queue	- queue of messages to be sent to a back-end server;
 * @nip_queue	- queue of non-idempotent messages in server's @fwd_queue;
 * @fwd_qlock	- lock for accessing @fwd_queue and @nip_queue;
 * @flags	- atomic flags related to server connection's state;
 * @qsize	- current number of requests in server's @fwd_queue;
 * @recns	- the number of reconnect attempts;
 * @msg_sent	- request that was sent last in a server connection;
 */
typedef struct {
	TFW_CONN_COMMON;
	struct list_head	fwd_queue;
	struct list_head	nip_queue;
	spinlock_t		fwd_qlock;
	unsigned long		flags;
	unsigned int		qsize;
	unsigned int		recns;
	TfwMsg			*msg_sent;
} TfwSrvConn;

#define TFW_CONN_DEATHCNT	(INT_MIN / 2)

/* Connection flags are defined by the bit number. */
enum {
	/* Need to re-send requests. */
	TFW_CONN_B_RESEND = 0,
	/* Need to forward requests in the queue. */
	TFW_CONN_B_QFORWD,
	/* Has non-idempotent requests. */
	TFW_CONN_B_HASNIP,

	/* Remove connection */
	TFW_CONN_B_DEL,
	/* Connection is in use or at least scheduled to be established. */
	TFW_CONN_B_ACTIVE
};

/**
 * TLS hardened connection.
 */
typedef struct {
	TfwCliConn	cli_conn;
	TlsCtx		tls;
} TfwTlsConn;

#define tfw_tls_context(conn)	(TlsCtx *)(&((TfwTlsConn *)conn)->tls)

/* Callbacks used by l5-l7 protocols to operate on connection level. */
typedef struct {
	/*
	 * Called before servicing a new connection (connection
	 * type, client or server, is checked in the callback).
	 * This is a good place to handle Access or GEO modules
	 * (block a client or bind its descriptor with GEO data).
	 */
	int (*conn_init)(TfwConn *conn);

	/*
	 * Called when a new connection is initialized and before
	 * the initialization is complete. Makes sense only for
	 * server connections. Used to re-send requests that were
	 * left in the connection queue.
	 */
	void (*conn_repair)(TfwConn *conn);

	/*
	 * Called to close a connection intentionally on Tempesta side.
	 */
	int (*conn_close)(TfwConn *conn, bool sync);

	/*
	 * Called when closing a connection (client or server,
	 * as in conn_init()). This is required for modules that
	 * maintain the number of established client connections.
	 */
	void (*conn_drop)(TfwConn *conn);

	/*
	 * Called when there are no more users of a connection
	 * and the connection's resources are finally released.
	 */
	void (*conn_release)(TfwConn *conn);

	/*
	 * Called by the connection layer when there is a message
	 * that needs to be send.
	 */
	int (*conn_send)(TfwConn *conn, TfwMsg *msg);
} TfwConnHooks;

#define TFW_CONN_MAX_PROTOS	TFW_GFSM_FSM_N

extern TfwConnHooks *conn_hooks[TFW_CONN_MAX_PROTOS];

/* These macros are for calling the defined proto hooks. */
#define tfw_conn_hook_call(proto, c, f, ...)	\
	conn_hooks[proto]->f ? conn_hooks[proto]->f(c, ## __VA_ARGS__) : 0
#define TFW_CONN_HOOK_CALL(c, f...)		\
	tfw_conn_hook_call(TFW_CONN_TYPE2IDX(TFW_CONN_TYPE(c)), c, f)

/*
 * Tell if a server connection is restricted. A restricted connection
 * is not available to schedulers.
 *
 * The flag RESEND is set when a newly established server connection
 * has messages in the forwarding queue. That means that the connection
 * had been closed prematurely, and the messages in the queue need to
 * be re-sent to a back-end server. The new connection is not available
 * to schedulers (restricted) until all messages in the forwarding queue
 * are re-sent.
 */
static inline bool
tfw_srv_conn_restricted(TfwSrvConn *srv_conn)
{
	return test_bit(TFW_CONN_B_RESEND, &srv_conn->flags);
}

/*
 * Tell if a connection has non-idempotent requests.
 */
static inline bool
tfw_srv_conn_hasnip(TfwSrvConn *srv_conn)
{
	return test_bit(TFW_CONN_B_HASNIP, &srv_conn->flags);
}

static inline bool
tfw_connection_live(TfwConn *conn)
{
	return atomic_read(&conn->refcnt) > 0;
}

#define tfw_srv_conn_live(c)	tfw_connection_live((TfwConn *)(c))

static inline void
tfw_connection_get(TfwConn *conn)
{
	atomic_inc(&conn->refcnt);
}

#define tfw_cli_conn_get(c)	tfw_connection_get((TfwConn *)(c))
#define tfw_srv_conn_get(c)	tfw_connection_get((TfwConn *)(c))

/**
 * Increment reference counter and return true if @conn is not in
 * failovering process, i.e. @refcnt wasn't less or equal to zero.
 */
static inline bool
__tfw_connection_get_if_live(TfwConn *conn)
{
	int old, rc = atomic_read(&conn->refcnt);

	while (likely(rc > 0)) {
		old = atomic_cmpxchg(&conn->refcnt, rc, rc + 1);
		if (likely(old == rc))
			return true;
		rc = old;
	}

	return false;
}

#define tfw_srv_conn_get_if_live(c)	\
	__tfw_connection_get_if_live((TfwConn *)(c))

static inline void
tfw_connection_put(TfwConn *conn)
{
	int rc;

	if (unlikely(!conn))
		return;

	rc = atomic_dec_return(&conn->refcnt);
	if (likely(rc && rc != TFW_CONN_DEATHCNT))
		return;
	if (conn->destructor)
		conn->destructor(conn);
}

#define tfw_cli_conn_put(c)	tfw_connection_put((TfwConn *)(c))
#define tfw_srv_conn_put(c)	tfw_connection_put((TfwConn *)(c))

static inline void
tfw_connection_put_to_death(TfwConn *conn)
{
	atomic_add(TFW_CONN_DEATHCNT, &conn->refcnt);
}

static inline void
tfw_connection_revive(TfwConn *conn)
{
	atomic_set(&conn->refcnt, 1);
}

/*
 * Initialize a server connection to a special value. The value
 * indicates that the connection is dead and can't take requests
 * from schedulers. Also, it indicates that a TfwConn{} instance
 * is busy and can't be released yet.
 */
static inline void
tfw_srv_conn_init_as_dead(TfwSrvConn *srv_conn)
{
	atomic_set(&srv_conn->refcnt, TFW_CONN_DEATHCNT + 1);
}

/*
 * Link Sync Sockets layer with Tempesta. The socket @sk now carries
 * a reference to Tempesta's @conn instance. When a Tempesta's socket
 * callback is called by Sync Sockets on an event in the socket, then
 * the reference to @conn instance for the socket can be found quickly.
 */
static inline void
tfw_connection_link_from_sk(TfwConn *conn, struct sock *sk)
{
	BUG_ON(sk->sk_user_data);
	sk->sk_user_data = conn;
}

/*
 * Link Tempesta with Sync Sockets layer. @conn instance now carries
 * a reference to @sk. When there's need to send data on a connection,
 * then the socket for that connection can be found quickly. Also,
 * get a hold of the socket to avoid premature socket release.
 */
static inline void
tfw_connection_link_to_sk(TfwConn *conn, struct sock *sk)
{
	ss_sock_hold(sk);
	conn->sk = sk;
}

/*
 * Do an opposite to what tfw_connection_link_from_sk() does.
 * Sync Sockets layer is unlinked from Tempesta, so that Tempesta
 * callbacks are not called anymore on events in the socket.
 */
static inline void
tfw_connection_unlink_from_sk(struct sock *sk)
{
	BUG_ON(!sk->sk_user_data);
	sk->sk_user_data = NULL;
}

/*
 * Do an opposite to what tfw_connection_link_to_sk() does. Tempesta
 * is unlinked from Sync Sockets layer, so that no data can be sent
 * anymore on a connection. The previously held socket is released.
 * Note that clearing of conn->sk is necessary. In case of failover
 * on a server connection an indicator is needed to remove a hold
 * on the socket. A zeroed conn->sk is that indicator.
 */
static inline void
tfw_connection_unlink_to_sk(TfwConn *conn)
{
	struct sock *sk = conn->sk;

	conn->sk = NULL;
	ss_sock_put(sk);
}

static inline void
tfw_connection_unlink_from_peer(TfwConn *conn)
{
	BUG_ON(!conn->peer || list_empty(&conn->list));
	tfw_peer_del_conn(conn->peer, &conn->list);
}

static inline void
tfw_connection_unlink_msg(TfwConn *conn)
{
	conn->msg = NULL;
}

/**
 * Check that TfwConn{} resources are cleaned up properly.
 */
static inline void
tfw_connection_validate_cleanup(TfwConn *conn)
{
	int rc;

	BUG_ON(!conn);
	BUG_ON(!list_empty(&conn->list));
	BUG_ON(conn->msg);

	rc = atomic_read(&conn->refcnt);
	BUG_ON(rc && rc != TFW_CONN_DEATHCNT);
}

void tfw_connection_hooks_register(TfwConnHooks *hooks, int type);
void tfw_connection_hooks_unregister(int type);
int tfw_connection_send(TfwConn *conn, TfwMsg *msg);

/* Generic helpers, used for both client and server connections. */
void tfw_connection_init(TfwConn *conn);
void tfw_connection_link_peer(TfwConn *conn, TfwPeer *peer);

int tfw_connection_new(TfwConn *conn);
void tfw_connection_repair(TfwConn *conn);
int tfw_connection_close(TfwConn *conn, bool sync);
void tfw_connection_drop(TfwConn *conn);
void tfw_connection_release(TfwConn *conn);

int tfw_connection_recv(void *cdata, struct sk_buff *skb, unsigned int off);

#endif /* __TFW_CONNECTION_H__ */
