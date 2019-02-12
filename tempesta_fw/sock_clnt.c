/**
 *		Tempesta FW
 *
 * TCP/IP stack hooks and socket routines to handle client traffic.
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
#include "tempesta_fw.h"
#include "cfg.h"
#include "client.h"
#include "connection.h"
#include "http_limits.h"
#include "log.h"
#include "procfs.h"
#include "server.h"
#include "sync_socket.h"
#include "tls.h"

/*
 * ------------------------------------------------------------------------
 *	Client socket handling.
 * ------------------------------------------------------------------------
 */

static struct kmem_cache *tfw_cli_conn_cache;
static struct kmem_cache *tfw_tls_conn_cache;
static int tfw_cli_cfg_ka_timeout = -1;
/*
 * Maximum size of memory used to store requests. Used for receive window size
 * steering
 */
int tfw_cfg_cli_rmem __read_mostly = 0;

static inline struct kmem_cache *
tfw_cli_cache(int type)
{
	return type & TFW_FSM_HTTPS ?
		tfw_tls_conn_cache : tfw_cli_conn_cache;
}

static void
tfw_sock_cli_keepalive_timer_cb(unsigned long data)
{
	TfwCliConn *cli_conn = (TfwCliConn *)data;

	TFW_DBG("Client timeout end\n");

	/*
	 * Close the socket (and the connection) asynchronously to avoid
	 * a deadlock on del_timer_sync(). In case of error try to close
	 * it one second later.
	 */
	if (tfw_connection_close((TfwConn *)cli_conn, false))
		mod_timer(&cli_conn->timer, jiffies + msecs_to_jiffies(1000));
}

static TfwCliConn *
tfw_cli_conn_alloc(int type)
{
	TfwCliConn *cli_conn;

	if (!(cli_conn = kmem_cache_alloc(tfw_cli_cache(type), GFP_ATOMIC)))
		return NULL;

	tfw_connection_init((TfwConn *)cli_conn);
	INIT_LIST_HEAD(&cli_conn->seq_queue);
	spin_lock_init(&cli_conn->seq_qlock);
	spin_lock_init(&cli_conn->ret_qlock);
#ifdef CONFIG_LOCKDEP
	/*
	 * The lock is acquired at only one place where there is no conflict
	 * with the socket lock, so prevent LOCKDEP complaining the dependency.
	 * Use subclass > SINGLE_DEPTH_NESTING to avoid collisions with kernel
	 * and TempestaDB locking subclasses.
	 */
	lockdep_init_map(&cli_conn->ret_qlock.dep_map, "cli_conn->ret_qlock",
			 &__lockdep_no_validate__, 2);
#endif

	setup_timer(&cli_conn->timer, tfw_sock_cli_keepalive_timer_cb,
		    (unsigned long)cli_conn);

	return cli_conn;
}

static void
tfw_cli_conn_free(TfwCliConn *cli_conn)
{
	BUG_ON(timer_pending(&cli_conn->timer));

	/* Check that all nested resources are freed. */
	tfw_connection_validate_cleanup((TfwConn *)cli_conn);
	BUG_ON(!list_empty(&cli_conn->seq_queue));

	kmem_cache_free(tfw_cli_cache(TFW_CONN_TYPE(cli_conn)), cli_conn);
}

void
tfw_cli_conn_release(TfwCliConn *cli_conn)
{
	del_timer_sync(&cli_conn->timer);

	if (likely(cli_conn->sk))
		tfw_connection_unlink_to_sk((TfwConn *)cli_conn);
	if (likely(cli_conn->peer))
		tfw_client_put((TfwClient *)cli_conn->peer);
	tfw_cli_conn_free(cli_conn);
	TFW_INC_STAT_BH(clnt.conn_disconnects);
}

int
tfw_cli_conn_send(TfwCliConn *cli_conn, TfwMsg *msg)
{
	int r;

	r = tfw_connection_send((TfwConn *)cli_conn, msg);
	mod_timer(&cli_conn->timer,
		  jiffies +
		  msecs_to_jiffies((long)tfw_cli_cfg_ka_timeout * 1000));

	if (r)
		/* Quite usual on system shutdown. */
		TFW_DBG("Cannot send data to client (%d)\n", r);

	return r;
}

/**
 * This hook is called when a new client connection is established.
 */
static int
tfw_sock_clnt_new(struct sock *sk)
{
	int r = -ENOMEM;
	TfwClient *cli;
	TfwConn *conn;
	SsProto *listen_sock_proto;

	TFW_DBG3("new client socket: sk=%p, state=%u\n", sk, sk->sk_state);
	TFW_INC_STAT_BH(clnt.conn_attempts);

	/*
	 * New sk->sk_user_data points to TfwListenSock{} of the parent
	 * listening socket. We set it to NULL to stop other functions
	 * from referencing TfwListenSock{} while a new TfwConn{} object
	 * is not yet allocated/initialized.
	 */
	listen_sock_proto = sk->sk_user_data;
	tfw_connection_unlink_from_sk(sk);

	cli = tfw_client_obtain(sk, NULL);
	if (!cli) {
		TFW_ERR("can't obtain a client for the new socket\n");
		return -ENOENT;
	}

	conn = (TfwConn *)tfw_cli_conn_alloc(listen_sock_proto->type);
	if (!conn) {
		TFW_ERR("can't allocate a new client connection\n");
		goto err_client;
	}

	ss_proto_inherit(listen_sock_proto, &conn->proto, Conn_Clnt);

	conn->destructor = (void *)tfw_cli_conn_release;

	r = tfw_connection_new(conn);
	if (r) {
		TFW_ERR("cannot establish a new client connection\n");
		goto err_conn;
	}

#if defined(DEBUG) && (DEBUG == 3)
	sock_set_flag(sk, SOCK_DBG);
#endif

	/* Link Tempesta with the socket and the peer. */
	tfw_connection_revive(conn);
	tfw_connection_link_to_sk(conn, sk);
	tfw_connection_link_from_sk(conn, sk);
	tfw_connection_link_peer(conn, (TfwPeer *)cli);

	ss_set_callbacks(sk);
	if (TFW_CONN_TYPE(conn) & TFW_FSM_HTTPS)
		/*
		 * Probably, that's not beautiful to introduce an alternate
		 * upcall beside GFSM and SS, but that's efficient and I didn't
		 * find a simple and better solution.
		 */
		sk->sk_write_xmit = tfw_tls_encrypt;

	/* Activate keepalive timer. */
	mod_timer(&conn->timer,
		  jiffies +
		  msecs_to_jiffies((long)tfw_cli_cfg_ka_timeout * 1000));

	TFW_DBG3("new client socket is accepted: sk=%p, conn=%p, cli=%p\n",
		 sk, conn, cli);
	TFW_INC_STAT_BH(clnt.conn_established);
	return 0;

err_conn:
	tfw_cli_conn_free((TfwCliConn *)conn);
err_client:
	tfw_client_put(cli);
	return r;
}

/**
 * Do the same stuff for intentional client connection closing and due to some
 * error on TCP socket or application layers.
 */
static void
tfw_sock_clnt_do_drop(struct sock *sk, const char *msg)
{
	TfwConn *conn = sk->sk_user_data;

	TFW_DBG3("%s: close client socket: sk=%p, conn=%p, client=%p\n",
		 msg, sk, conn, conn->peer);
	/*
	 * Withdraw from socket activity. Connection is now closed,
	 * and Tempesta is not called anymore on events in the socket.
	 * Remove the connection from the list that is kept in @peer.
	 * Release resources allocated in Tempesta for the connection.
	 */
	tfw_connection_unlink_from_sk(sk);
	tfw_connection_unlink_from_peer(conn);
	tfw_connection_drop(conn);

	/*
	 * Connection @conn, as well as @sk and @peer that make
	 * the essence of it, remain accessible as long as there
	 * are references to @conn.
	 */
	tfw_connection_put(conn);
}

/*
 * The hook is executed when a client connection is closed by either
 * side of the connection.
 */
static void
tfw_sock_clnt_drop(struct sock *sk)
{
	tfw_sock_clnt_do_drop(sk, "connection lost");
}

/*
 * The hook is executed when a client connection is terminated due to
 * an error of any kind.
 */
static void
tfw_sock_clnt_error(struct sock *sk)
{
	tfw_sock_clnt_do_drop(sk, "connection error");
}

static const SsHooks tfw_sock_clnt_ss_hooks = {
	.connection_new		= tfw_sock_clnt_new,
	.connection_drop	= tfw_sock_clnt_drop,
	.connection_error	= tfw_sock_clnt_error,
	.connection_recv	= tfw_connection_recv,
};

static int
__cli_conn_close_cb(TfwConn *conn)
{
	/*
	 * Use asynchronous closing to release peer connection list and
	 * client hash bucket locks as soon as possible and let softirq
	 * do all the jobs.
	 */
	return tfw_connection_close(conn, false);
}

static int
tfw_cli_conn_close_all(TfwClient *cli)
{
	TfwConn *conn;

	return tfw_peer_for_each_conn(cli, conn, list, __cli_conn_close_cb);
}

/*
 * ------------------------------------------------------------------------
 *	Receive buffer management.
 * ------------------------------------------------------------------------
 */

/**
 * A new part of the http message was parsed. Account its size in rmem to
 * manage the receive window. See `tfw_cfgop_cli_rmem` description.
 *
 * @sz is always less than INT_MAX, save to use it as 32-bit integer.
 * Total memory used for all requests can't be bigger than 'client_rmem' value,
 * which is 32-bit integer.
 */
void
tfw_cli_rmem_reserve(TfwCliConn *cli_conn, unsigned int sz)
{
	struct sock *sk = cli_conn->sk;

	BUG_ON(!sk);
	if (!(sk->sk_userlocks & SOCK_RCVBUF_LOCK))
		return;

	atomic_add(sz, &cli_conn->rmem_used);
	atomic_add(sz, &sk->sk_rmem_alloc);
	smp_mb__after_atomic();
}

void
tfw_cli_rmem_release(TfwCliConn *cli_conn, unsigned int sz)
{
	struct sock *sk = cli_conn->sk;

	BUG_ON(!sk);
	if (!(sk->sk_userlocks & SOCK_RCVBUF_LOCK))
		return;

	atomic_sub(sz, &cli_conn->rmem_used);
	atomic_sub(sz, &sk->sk_rmem_alloc);
	smp_mb__after_atomic();
}

void
tfw_cli_rmem_drop(TfwCliConn *cli_conn)
{
	struct sock *sk = cli_conn->sk;

	BUG_ON(!sk);
	if (!(sk->sk_userlocks & SOCK_RCVBUF_LOCK))
		return;

	smp_mb__before_atomic();
	atomic_sub(atomic_read(&cli_conn->rmem_used), &sk->sk_rmem_alloc);
	atomic_set(&cli_conn->rmem_used, 0);
}

/*
 * ------------------------------------------------------------------------
 *	Listening socket handling.
 * ------------------------------------------------------------------------
 */

#define TFW_LISTEN_SOCK_BACKLOG_LEN 	1024

/**
 * The listening socket representation.
 * One such structure corresponds to one "listen" configuration entry.
 *
 * @proto	- protocol descriptor for the listening socket;
 * @sk		- The underlying networking representation.
 * @list	- An entry in the tfw_listen_socks list.
 * @addr	- The IP address specified in the configuration.
 */
typedef struct {
	SsProto			proto;
	struct sock		*sk;
	struct list_head	list;
	TfwAddr			addr;
} TfwListenSock;

/**
 * The list of all existing TfwListenSock structures.
 *
 * The list is filled when Tempesta FW is started and emptied when it is
 * stopped, and not changed in between. Therefore, no locking is required.
 */
static LIST_HEAD(tfw_listen_socks);

/**
 * Allocate a new TfwListenSock and add it to the global list of sockets.
 * Don't open a socket now, just save the configuration data.
 * The socket is opened later in tfw_listen_sock_start().
 *
 * @type is the SsProto->type.
 */
static int
tfw_listen_sock_add(const TfwAddr *addr, int type)
{
	TfwListenSock *ls;

	/* Check for supported types */
	if (!(type == TFW_FSM_HTTP || type == TFW_FSM_HTTPS))
		return -EINVAL;

	/* Is there such an address on the list already? */
	list_for_each_entry(ls, &tfw_listen_socks, list) {
		if (tfw_addr_eq(addr, &ls->addr)) {
			TFW_LOG_ADDR("Duplicate listener with", addr,
			             TFW_WITH_PORT);
			return -EINVAL;
		}
	}

	ls = kzalloc(sizeof(*ls), GFP_KERNEL);
	if (!ls)
		return -ENOMEM;

	if (type == TFW_FSM_HTTP)
		ss_proto_init(&ls->proto, &tfw_sock_clnt_ss_hooks, Conn_HttpClnt);
	else if (type == TFW_FSM_HTTPS)
		ss_proto_init(&ls->proto, &tfw_sock_clnt_ss_hooks, Conn_HttpsClnt);

	list_add(&ls->list, &tfw_listen_socks);
	ls->addr = *addr;

	tfw_classifier_add_inport(tfw_addr_port(addr));

	return 0;
}

static void
tfw_listen_sock_del_all(void)
{
	TfwListenSock *ls, *tmp;

	list_for_each_entry_safe(ls, tmp, &tfw_listen_socks, list) {
		BUG_ON(ls->sk);
		kfree(ls);
	}

	INIT_LIST_HEAD(&tfw_listen_socks);
	tfw_classifier_cleanup_inport();
}

/**
 * Start listening on a socket.
 * Create a new socket in @ls->sk that listens the @ls->addr.
 * This is similar to a classic socket()/bind()/listen() sequence.
 */
static int
tfw_listen_sock_start(TfwListenSock *ls)
{
	int r;
	struct sock *sk;
	TfwAddr *addr = &ls->addr;

	TFW_LOG_ADDR("Open listen socket on", addr, TFW_WITH_PORT);

	r = ss_sock_create(tfw_addr_sa_family(addr), SOCK_STREAM, IPPROTO_TCP,
	                   &sk);
	if (r) {
		TFW_ERR_NL("can't create listening socket (err: %d)\n", r);
		return r;
	}

	/*
	 * Link the new socket and TfwListenSock.
	 * That must be done before calling ss_set_listen() that uses SsProto.
	 */
	ls->sk = sk;
	sk->sk_user_data = ls;

	/*
	 * Limit receive window size for accepted connections.
	 * Similarly to setsockopt() behaviour, double the limit
	 * on the way in to account for "struct sk_buff" etc. overhead.
	 * Set a smaller limit for beginning, if a client performs fast the
	 * limit will be updated in ss_rcv_space_adjust().
	 */
	if (tfw_cfg_cli_rmem) {
		int bsz = tfw_cfg_cli_rmem * 2;

		if (/* sysctl_tcp_moderate_rcvbuf && */ (bsz > sysctl_tcp_rmem[1]))
			bsz = sysctl_tcp_rmem[1];
		sk->sk_userlocks |= SOCK_RCVBUF_LOCK;
		sk->sk_rcvbuf = bsz;
	}

	/*
	 * For listening sockets we use
	 * ss_set_listen() instead of ss_set_callbacks().
	 */
	ss_set_listen(sk);

	inet_sk(sk)->freebind = 1;
	sk->sk_reuse = 1;
	r = ss_bind(sk, addr);
	if (r) {
		TFW_ERR_ADDR("can't bind to", addr, TFW_WITH_PORT);
		return r;
	}

	TFW_DBG("start listening on socket: sk=%p\n", sk);
	r = ss_listen(sk, TFW_LISTEN_SOCK_BACKLOG_LEN);
	if (r) {
		TFW_ERR_NL("can't listen on front-end socket sk=%p (%d)\n",
			   sk, r);
		return r;
	}

	return 0;
}

static int
tfw_sock_check_lst(TfwServer *srv)
{
	TfwListenSock *ls;

	TFW_DBG3("Checking server....\n");
	list_for_each_entry(ls, &tfw_listen_socks, list) {
		TFW_DBG3("Iterating listener\n");
		if (tfw_addr_ifmatch(&srv->addr, &ls->addr))
			return -EINVAL;
	}
	return 0;
}

/*
 * ------------------------------------------------------------------------
 *	configuration handling
 * ------------------------------------------------------------------------
 */

static int
tfw_cfgop_listen(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;
	int port;
	TfwAddr addr;
	const char *in_str = NULL;

	r = tfw_cfg_check_val_n(ce, 1);
	if (r)
		goto parse_err;

	/*
	 * Try both:
	 * - a single port without IP address (e.g. "listen 8081");
	 * - a full IP address (e.g. "listen 127.0.0.1:8081").
	 */
	in_str = ce->vals[0];
	r = __tfw_cfg_parse_int(in_str, &port);
	if (!r) {
		r = tfw_cfg_check_range(port, 0, 65535);
		if (r)
			goto parse_err;

		/* For single port, use 0.0.0.0:port (IPv4, but not IPv6). */
		addr = tfw_addr_new_v4(INADDR_ANY, htons(port));

	} else {
		r = tfw_addr_pton(&TFW_STR_FROM_CSTR(in_str), &addr);
		if (r)
			goto parse_err;
	}

	r = tfw_cfg_check_range(ce->attr_n, 0, 1);
	if (r)
		goto parse_err;

	if (!ce->attr_n)
		return tfw_listen_sock_add(&addr, TFW_FSM_HTTP);

	in_str = tfw_cfg_get_attr(ce, "proto", NULL);
	if (!in_str)
		goto parse_err;

	if (!strcasecmp(in_str, "http")) {
		return tfw_listen_sock_add(&addr, TFW_FSM_HTTP);
	}
	else if (!strcasecmp(in_str, "https")) {
		tfw_tls_cfg_require();
		return tfw_listen_sock_add(&addr, TFW_FSM_HTTPS);
	}
	else {
		goto parse_err;
	}

parse_err:
	TFW_ERR_NL("Unable to parse 'listen' value: '%s'\n",
		   in_str ? in_str : "No value specified");
	return -EINVAL;
}

static int
tfw_cfgop_keepalive_timeout(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;

	if ((r = tfw_cfg_check_val_n(ce, 1)))
		return r;

	if ((r = tfw_cfg_parse_int(ce->vals[0], &tfw_cli_cfg_ka_timeout)))
		return r;
	if ((r = tfw_cfg_check_range(tfw_cli_cfg_ka_timeout, 0, INT_MAX)))
		return r;

	return 0;
}

/**
 * Limit total memory used to serve single TCP connection.
 *
 * Received skb may be stored in one of two buffers: socket receive buffer
 * (sk->sk_receive_queue) or Tempesta connection buffer (TfwCliConn->seq_queue).
 * Receive buffer size is limited by 'net.core.rmem_max' and
 * 'net.ipv4.tcp_rmem'. The kernel manages tcp receive window size to slow
 * dawn clients when the socket receive buffer is about to be full.
 *
 * When skb is stored in receive queue, it's tracked in sk->sk_rmem_alloc.
 * The kernel uses the parameter to calculate available receive window size.
 * When the option is enabled, HTTP messages stored in Tempesta connection
 * buffer are also tracked by sk->sk_rmem_alloc. Thus the kernel is aware of
 * free space in both buffers when a new TCP window is calculated.
 *
 * Note, the http message size and underlying skb size can change during
 * message processing inside the Tempesta due to message modifications.
 * Two variants are possible: mirror all modifications to sk->sk_rmem_alloc
 * or operate only by original message size. The second case was chosen
 * because its simplicity and error-free possibilities.
 *
 * Generally we don't want the same rmem limits for clients and servers.
 * Server connections are fast and require relatively big buffers.
 * Client connections doesn't require high speeds, but a big number of
 * client connections can cause memory starvation. Limit client connection
 * socket buffer size with SO_RCVBUF to deny automatic buffer size moderation
 * inside the kernel functions.
 *
 * Restricting buffer size for a server connection in the same way is a bad
 * idea. Responses stored as pairs for requests in client seq_queue may belong
 * to different servers. There can be tricky situations leading to server
 * receive and forwarding deadlocks if clients are slow or advertise zero
 * windows.
 *
 * If zero receive window was advertised to client, the client connection will
 * be closed after 'keepalive_timeout'. Responses forwarded rearm the timer,
 * while window probe requests are not.
 */
static int
tfw_cfgop_cli_rmem(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;

	/*
	 * The value for specific socket can overflow system limits tcp_rmem[2]
	 * and rmem_max. See SO_RCVBUFFORCE socket option.
	 *
	 * '0' means the option is disabled (defaults), but positive values
	 * below 'SOCK_MIN_RCVBUF / 2' are not allowed. Enforce correct value.
	 */
	if ((r = tfw_cfg_set_int(cs, ce)))
		return r;
	if (tfw_cfg_cli_rmem && (tfw_cfg_cli_rmem < SOCK_MIN_RCVBUF / 2)) {
		tfw_cfg_cli_rmem = SOCK_MIN_RCVBUF / 2;
		TFW_WARN_NL("%s: value is too small, set to %i\n",
			    cs->name, tfw_cfg_cli_rmem);
	}

	return 0;
}

static void
tfw_cfgop_cleanup_sock_clnt(TfwCfgSpec *cs)
{
	tfw_listen_sock_del_all();
}

static int
tfw_sock_clnt_cfgend(void)
{
	int r;

	TFW_DBG("Checking backends and listeners\n");
	if ((r = tfw_sg_for_each_srv_reconfig(tfw_sock_check_lst))) {
		TFW_ERR_NL("One of the backends is Tempesta itself!"
			   " Please, fix the configuration.\n");
		return r;
	}

	return 0;
}

/**
 * Start listening on all existing sockets (added via "listen" configuration
 * entries).
 */
static int
tfw_sock_clnt_start(void)
{
	int r;
	TfwListenSock *ls;

	if (tfw_runstate_is_reconfig())
		return 0;

	list_for_each_entry(ls, &tfw_listen_socks, list) {
		if ((r = tfw_listen_sock_start(ls))) {
			TFW_ERR_ADDR("can't start listening on", &ls->addr,
			             TFW_WITH_PORT);
			return r;
		}
	}

	return 0;
}

static void
tfw_sock_clnt_stop(void)
{
	TfwListenSock *ls;

	if (tfw_runstate_is_reconfig())
		return;

	might_sleep();

	/* Stop listening sockets. */
	list_for_each_entry(ls, &tfw_listen_socks, list) {
		if (!ls->sk)
			continue;
		ss_release(ls->sk);
		ls->sk = NULL;
	}
	ss_wait_newconn();

	/*
	 * Now all listening sockets are closed, so no new connections
	 * can appear. Close all established client connections.
	 * We're going to acquire client hash bucket and peer connection list
	 * locks, so disable softirq to avoid deadlock with the sockets closing
	 * in softirq context.
	 */
	local_bh_disable();
	while (tfw_client_for_each(tfw_cli_conn_close_all)) {
		/*
		 * SS transport is overloaded: let softirqs make progress and
		 * repeat again. Not a big deal that we'll probably close the
		 * same connections - SS can handle it and it's expected that
		 * softirqs close some of them while we wait.
		 */
		local_bh_enable();
		schedule();
		local_bh_disable();
	}
	local_bh_enable();
}

static TfwCfgSpec tfw_sock_clnt_specs[] = {
	{
		.name = "listen",
		.deflt = "80",
		.handler = tfw_cfgop_listen,
		.cleanup = tfw_cfgop_cleanup_sock_clnt,
		.allow_repeat = true,
	},
	{
		.name = "keepalive_timeout",
		.deflt = "75",
		.handler = tfw_cfgop_keepalive_timeout,
		.cleanup = tfw_cfgop_cleanup_sock_clnt,
		.allow_repeat = false,
	},
	{
		.name = "client_rmem",
		.deflt = "0", /* No limit. */
		.handler = tfw_cfgop_cli_rmem,
		.dest = &tfw_cfg_cli_rmem,
		.spec_ext = &(TfwCfgSpecInt) {
			/*
			 * The value is used for (int)sock->sk_rcvbuf and
			 * multiplicated by 2, limit maximum possible value
			 * to prevent overflows.
			*/
			.range = { 0, INT_MAX / 2 },
		},
	},
	{ 0 }
};

TfwMod tfw_sock_clnt_mod  = {
	.name	= "sock_clnt",
	.cfgend = tfw_sock_clnt_cfgend,
	.start	= tfw_sock_clnt_start,
	.stop	= tfw_sock_clnt_stop,
	.specs	= tfw_sock_clnt_specs,
};

/*
 * ------------------------------------------------------------------------
 *	init/exit
 * ------------------------------------------------------------------------
 */

int
tfw_sock_clnt_init(void)
{
	/*
	 * Check that flags for SS layer and Connection
	 * layer are not overlapping.
	 */
	BUILD_BUG_ON(Conn_Stop & (Conn_Clnt |
				  Conn_Srv |
				  TFW_FSM_HTTP |
				  TFW_FSM_HTTPS));
	BUG_ON(tfw_cli_conn_cache);
	BUG_ON(tfw_tls_conn_cache);

	tfw_cli_conn_cache = kmem_cache_create("tfw_cli_conn_cache",
					       sizeof(TfwCliConn), 0, 0, NULL);
	tfw_tls_conn_cache = kmem_cache_create("tfw_tls_conn_cache",
					       sizeof(TfwTlsConn), 0, 0, NULL);

	if (tfw_cli_conn_cache && tfw_tls_conn_cache) {
		tfw_mod_register(&tfw_sock_clnt_mod);
		return 0;
	}

	if (tfw_cli_conn_cache)
		kmem_cache_destroy(tfw_cli_conn_cache);
	if (tfw_tls_conn_cache)
		kmem_cache_destroy(tfw_tls_conn_cache);

	return -ENOMEM;
}

void
tfw_sock_clnt_exit(void)
{
	tfw_mod_unregister(&tfw_sock_clnt_mod);
	kmem_cache_destroy(tfw_tls_conn_cache);
	kmem_cache_destroy(tfw_cli_conn_cache);
}
