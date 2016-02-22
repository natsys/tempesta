/**
 *		Tempesta FW
 *
 * TCP/IP stack hooks and socket routines to handle client traffic.
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
#include "cfg.h"
#include "classifier.h"
#include "client.h"
#include "connection.h"
#include "http_msg.h"
#include "log.h"
#include "sync_socket.h"
#include "tempesta_fw.h"
#include "server.h"
#include "procfs.h"

/*
 * ------------------------------------------------------------------------
 *	Client socket handling.
 * ------------------------------------------------------------------------
 */

/**
 * TfwConnection extension for client sockets.
 *
 * @conn	- The base structure. Must be the first member.
 * @ka_timer	- The keep-alive timer for the connection.
 */
typedef struct {
	TfwConnection		conn;
	struct timer_list	ka_timer;
} TfwCliConnection;

static struct kmem_cache *tfw_cli_conn_cache;
static int tfw_cli_cfg_ka_timeout = -1;

static void
tfw_sock_cli_keepalive_timer_cb(unsigned long data)
{
	TfwConnection *conn = (TfwConnection *)data;

	TFW_DBG("Client timeout end\n");
	ss_close(conn->sk);
}

static TfwCliConnection *
tfw_cli_conn_alloc(void)
{
	TfwCliConnection *cli_conn;

	cli_conn = kmem_cache_alloc(tfw_cli_conn_cache, GFP_ATOMIC);
	if (!cli_conn)
		return NULL;

	tfw_connection_init(&cli_conn->conn);
	setup_timer(&cli_conn->ka_timer,
		    tfw_sock_cli_keepalive_timer_cb,
		    (unsigned long)&cli_conn->conn);

	return cli_conn;
}

static void
tfw_cli_conn_free(TfwCliConnection *cli_conn)
{
	BUG_ON(timer_pending(&cli_conn->ka_timer));

	/* Check that all nested resources are freed. */
	tfw_connection_validate_cleanup(&cli_conn->conn);
	kmem_cache_free(tfw_cli_conn_cache, cli_conn);
}

void
tfw_cli_conn_release(TfwConnection *conn)
{
	TfwCliConnection *cli_conn = (TfwCliConnection *)conn;

	del_timer_sync(&cli_conn->ka_timer);

	if (likely(conn->sk))
		tfw_connection_unlink_to_sk(conn);
	if (likely(conn->peer))
		tfw_client_put((TfwClient *)conn->peer);
	tfw_cli_conn_free((TfwCliConnection *)conn);
	TFW_INC_STAT_BH(clnt.conn_disconnects);
}

int
tfw_cli_conn_send(TfwConnection *conn, TfwMsg *msg, bool unref_data)
{
	int r;
	TfwCliConnection *cli_conn = (TfwCliConnection *)conn;

	r = tfw_connection_send(conn, msg, unref_data);
	mod_timer(&cli_conn->ka_timer,
		  jiffies + msecs_to_jiffies(tfw_cli_cfg_ka_timeout * 1000));

	if (r)
		TFW_WARN("Cannot send data to client\n");
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
	TfwCliConnection *cli_conn;
	TfwConnection *conn;
	SsProto *listen_sock_proto;

	TFW_DBG3("new client socket: sk=%p, state=%u\n", sk, sk->sk_state);
	TFW_INC_STAT_BH(clnt.conn_attempts);

	/*
	 * New sk->sk_user_data points to TfwListenSock{} of the parent
	 * listening socket. We set it to NULL to stop other functions
	 * from referencing TfwListenSock{} while a new TfwConnection{}
	 * object is not yet allocated/initialized.
	 */
	listen_sock_proto = rcu_dereference_sk_user_data(sk);
	tfw_connection_unlink_from_sk(sk);

	cli = tfw_client_obtain(sk);
	if (!cli) {
		TFW_ERR("can't obtain a client for the new socket\n");
		return -ENOENT;
	}

	cli_conn = tfw_cli_conn_alloc();
	if (!cli_conn) {
		TFW_ERR("can't allocate a new client connection\n");
		goto err_client;
	}

	conn = &cli_conn->conn;

	ss_proto_inherit(listen_sock_proto, &conn->proto, Conn_Clnt);

	r = tfw_connection_new(conn);
	if (r) {
		TFW_ERR("conn_init() hook returned error\n");
		goto err_conn;
	}

	/* Link Tempesta with the socket and the peer. */
	tfw_connection_link_to_sk(conn, sk);
	tfw_connection_link_from_sk(conn, sk);
	tfw_connection_link_peer(conn, (TfwPeer *)cli);
	ss_set_callbacks(sk);

	TFW_DBG3("new client socket is accepted: sk=%p, conn=%p, cli=%p\n",
		sk, conn, cli);
	TFW_INC_STAT_BH(clnt.conn_established);
	return 0;

err_conn:
	tfw_connection_drop(conn);
	/*
	 * We have just created the connection and did not link anything
	 * to it yet. There's no need to play with conn->refcnt. We can
	 * just free @conn unconditionally.
	 */
	tfw_cli_conn_free(cli_conn);
err_client:
	tfw_client_put(cli);
	return r;
}

static int
tfw_sock_clnt_drop(struct sock *sk)
{
	TfwCliConnection *cli_conn = rcu_dereference_sk_user_data(sk);
	TfwConnection *conn = &cli_conn->conn;

	TFW_DBG3("close client socket: sk=%p, conn=%p, client=%p\n",
		 sk, conn, conn->peer);
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
	if (tfw_connection_put(conn))
		tfw_cli_conn_release(conn);

	return 0;
}

static const SsHooks tfw_sock_clnt_ss_hooks = {
	.connection_new		= tfw_sock_clnt_new,
	.connection_drop	= tfw_sock_clnt_drop,
	.connection_recv	= tfw_connection_recv,
};

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

	ls = kzalloc(sizeof(*ls), GFP_KERNEL);
	if (!ls)
		return -ENOMEM;

	if (type == TFW_FSM_HTTP)
		ss_proto_init(&ls->proto, &tfw_sock_clnt_ss_hooks, Conn_HttpClnt);
	else if (type == TFW_FSM_HTTPS)
		ss_proto_init(&ls->proto, &tfw_sock_clnt_ss_hooks, Conn_HttpsClnt);
	else
		return -EINVAL;
	list_add(&ls->list, &tfw_listen_socks);
	ls->addr = *addr;

	/* Port is placed at the same offset in sockaddr_in and sockaddr_in6. */
	tfw_classifier_add_inport(addr->v4.sin_port);

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

	TFW_LOG_ADDR("Open listen socket on", addr);

	r = ss_sock_create(addr->family, SOCK_STREAM, IPPROTO_TCP, &sk);
	if (r) {
		TFW_ERR("can't create listening socket (err: %d)\n", r);
		return r;
	}

	/*
	 * Link the new socket and TfwListenSock.
	 * That must be done before calling ss_set_listen() that uses SsProto.
	 */
	ls->sk = sk;
	rcu_assign_sk_user_data(sk, ls);

	/*
	 * For listening sockets we use
	 * ss_set_listen() instead of ss_set_callbacks().
	 */
	ss_set_listen(sk);

	inet_sk(sk)->freebind = 1;
	sk->sk_reuse = 1;
	r = ss_bind(sk, &addr->sa, tfw_addr_sa_len(addr));
	if (r) {
		TFW_ERR_ADDR("can't bind to", addr);
		return r;
	}

	/* TODO adjust /proc/sys/net/core/somaxconn */
	TFW_DBG("start listening on socket: sk=%p\n", sk);
	r = ss_listen(sk, TFW_LISTEN_SOCK_BACKLOG_LEN);
	if (r) {
		TFW_ERR("can't listen on front-end socket sk=%p (%d)\n", sk, r);
		return r;
	}

	return 0;
}

/**
 * Start listening on all existing sockets (added via "listen" configuration
 * entries).
 */
static int
tfw_listen_sock_start_all(void)
{
	int r;
	TfwListenSock *ls;

	list_for_each_entry(ls, &tfw_listen_socks, list) {
		r = tfw_listen_sock_start(ls);
		if (r) {
			TFW_ERR_ADDR("can't start listening on", &ls->addr);
			return r;
		}
	}

	return 0;
}

static void
tfw_listen_sock_stop_all(void)
{
	TfwListenSock *ls;

	list_for_each_entry(ls, &tfw_listen_socks, list) {
		BUG_ON(!ls->sk);
		ss_release(ls->sk);
		ls->sk = NULL;
	}

	/*
	 * TODO #116, #254
	 * Now all listening sockets are closed, so no new connections
	 * can appear. Close all established client connections. After
	 * that server connections can safely be closed as they have
	 * no users any more.
	 */
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

int
tfw_sock_check_listeners(void)
{
	TFW_DBG3("Call %s\n", __func__);
	return tfw_sg_for_each_srv(tfw_sock_check_lst);
}

/*
 * ------------------------------------------------------------------------
 *	configuration handling
 * ------------------------------------------------------------------------
 */

static int
tfw_sock_clnt_cfg_handle_listen(TfwCfgSpec *cs, TfwCfgEntry *ce)
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
	r = tfw_cfg_parse_int(in_str, &port);
	if (!r) {
		r = tfw_cfg_check_range(port, 0, 65535);
		if (r)
			goto parse_err;

		/* For single port, use 0.0.0.0:port (IPv4, but not IPv6). */
		addr.v4.sin_family = AF_INET;
		addr.v4.sin_addr.s_addr = INADDR_ANY;
		addr.v4.sin_port = htons(port);
	} else {
		r = tfw_addr_pton(&TFW_STR_FROM(in_str), &addr);
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

	if (!strcasecmp(in_str, "http"))
		return tfw_listen_sock_add(&addr, TFW_FSM_HTTP);
	else if (!strcasecmp(in_str, "https"))
		return tfw_listen_sock_add(&addr, TFW_FSM_HTTPS);
	else
		goto parse_err;

parse_err:
	TFW_ERR("Unable to parse 'listen' value: '%s'\n",
		in_str ? in_str : "No value specified");
	return -EINVAL;
}

static int
tfw_sock_clnt_cfg_handle_keepalive(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;

	r = tfw_cfg_check_val_n(ce, 1);
	if (r)
		return -EINVAL;

	r = tfw_cfg_parse_int(ce->vals[0], &tfw_cli_cfg_ka_timeout);
	if (r) {
		TFW_ERR("Unable to parse 'keepalive_timeout' value: '%s'\n",
			ce->vals[0]
			? ce->vals[0]
			: "No value specified");
		return -EINVAL;
	}

	if (tfw_cli_cfg_ka_timeout < 0) {
		TFW_ERR("Unable to parse 'keepalive_timeout' value: '%s'\n",
			"Value less the zero");
		return -EINVAL;
	}

	return 0;
}

static void
tfw_sock_clnt_cfg_cleanup_listen(TfwCfgSpec *cs)
{
	tfw_listen_sock_del_all();
}

TfwCfgMod tfw_sock_clnt_cfg_mod  = {
	.name	= "sock_clnt",
	.start	= tfw_listen_sock_start_all,
	.stop	= tfw_listen_sock_stop_all,
	.specs	= (TfwCfgSpec[]){
		{
			"listen",
			"80",
			tfw_sock_clnt_cfg_handle_listen,
			.allow_repeat = true,
			.cleanup = tfw_sock_clnt_cfg_cleanup_listen
		},
		{
			"keepalive_timeout",
			"75",
			tfw_sock_clnt_cfg_handle_keepalive,
			.allow_repeat = false,
			.cleanup = tfw_sock_clnt_cfg_cleanup_listen
		},
		{}
	}
};

/*
 * ------------------------------------------------------------------------
 *	init/exit
 * ------------------------------------------------------------------------
 */

int
tfw_sock_clnt_init(void)
{
	BUG_ON(tfw_cli_conn_cache);
	tfw_cli_conn_cache = kmem_cache_create("tfw_cli_conn_cache",
					       sizeof(TfwCliConnection),
					       0, 0, NULL);
	return !tfw_cli_conn_cache ? -ENOMEM : 0;
}

void
tfw_sock_clnt_exit(void)
{
	kmem_cache_destroy(tfw_cli_conn_cache);
}
