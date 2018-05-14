/**
 *		Tempesta FW
 *
 * Transport Layer Security (TLS) interfaces to Tempesta TLS.
 *
 * Copyright (C) 2015-2018 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#include "cfg.h"
#include "connection.h"
#include "client.h"
#include "tls.h"

#define tls_dbg(c, fmt, ...)					\
	TFW_DBG("TLS(%p,%p):%s " fmt "\n", c, c->sk, __func__, ## __VA_ARGS__)
#define tls_err(c, fmt, ...)					\
	TFW_ERR("TLS(%p,%p):%s " fmt "\n", c, c->sk, __func__, ## __VA_ARGS__)

#define MAX_TLS_PAYLOAD		1460

typedef struct {
	mbedtls_ssl_config	cfg;
	mbedtls_x509_crt	crt;
	mbedtls_pk_context	key;
} TfwTls;

static TfwTls tfw_tls;

static inline int
ttls_ssl_handshake(TfwTlsContext *tls)
{
	int r;

	spin_lock(&tls->lock);
	r = mbedtls_ssl_handshake(&tls->ssl);
	spin_unlock(&tls->lock);

	return r;
}

static inline int
ttls_ssl_read(TfwTlsContext *tls, unsigned char *data, size_t size)
{
	int r;

	spin_lock(&tls->lock);
	r = mbedtls_ssl_read(&tls->ssl, data, size);
	spin_unlock(&tls->lock);

	return r;
}

static inline int
ttls_ssl_write(TfwTlsContext *tls, const unsigned char *data, size_t size)
{
	int r;

	spin_lock(&tls->lock);
	r = mbedtls_ssl_write(&tls->ssl, data, size);
	spin_unlock(&tls->lock);

	return r;
}

static inline int
ttls_ssl_close_notify(TfwTlsContext *tls)
{
	int r;

	spin_lock(&tls->lock);
	r = mbedtls_ssl_close_notify(&tls->ssl);
	spin_unlock(&tls->lock);

	return r;
}

/**
 * TODO Decrypted response messages should be directly placed in TDB area
 * to avoid copying.
 */
static int
tfw_tls_msg_process(void *conn, const TfwFsmData *data)
{
	int r;
	TfwConn *c = conn;
	TfwTlsContext *tls = tfw_tls_context(c);
	struct sk_buff *skb = data->skb;

	tls_dbg(c, "=>");

	ss_skb_queue_tail(&tls->rx_queue, skb);

	r = ttls_ssl_handshake(tls);
	if (r == MBEDTLS_ERR_SSL_CONN_EOF) {
		return TFW_PASS; /* more data needed */
	} else if (r == 0) {
		struct sk_buff *nskb;
		TfwFsmData data = {};

		nskb = alloc_skb(MAX_TCP_HEADER + MAX_TLS_PAYLOAD, GFP_ATOMIC);
		if (unlikely(!nskb))
			return TFW_BLOCK;

		skb_reserve(nskb, MAX_TCP_HEADER);
		skb_put(nskb, MAX_TLS_PAYLOAD);

		r = ttls_ssl_read(tls, nskb->data, MAX_TLS_PAYLOAD);
		if (r == MBEDTLS_ERR_SSL_WANT_READ ||
		    r == MBEDTLS_ERR_SSL_WANT_WRITE)
		{
			kfree_skb(nskb);
			return TFW_PASS;
		} else if (r <= 0) {
			kfree_skb(nskb);
			return r ? TFW_BLOCK : TFW_PASS;
		}

		tls_dbg(c, "-- got %d data bytes (%.*s)", r, r, nskb->data);

		skb_trim(nskb, r);

		/* FIXME skb leakage: seems either @skb or @nskb isn't freed. */
		data.skb = nskb;
		r = tfw_gfsm_move(&c->state, TFW_TLS_FSM_DATA_READY, &data);
		if (r == TFW_BLOCK)
			return TFW_BLOCK;

		return TFW_PASS;
	}

	tls_err(c, "-- handshake failed (%x)", -r);

	return TFW_BLOCK;
}


/**
 * Send @buf of length @len using TLS context @tls.
 */
static inline int
tfw_tls_send_buf(TfwConn *c, const unsigned char *buf, size_t len)
{
	int r;
	TfwTlsContext *tls = tfw_tls_context(c);

	tls_dbg(c, "=>");

	while ((r = ttls_ssl_write(tls, buf, len)) > 0) {
		if (r == len)
			return 0;
		buf += r;
		len -= r;
	}

	tls_err(c, "-- write failed (%x)", -r);

	return -EINVAL;
}

/**
 * Send @skb using TLS context @tls.
 */
static inline int
tfw_tls_send_skb(TfwConn *c, struct sk_buff *skb)
{
	int i;

	tls_dbg(c, "=>");

	if (skb_headlen(skb)) {
		if (tfw_tls_send_buf(c, skb->data, skb_headlen(skb)))
		    return -EINVAL;
	}

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		const skb_frag_t *f = &skb_shinfo(skb)->frags[i];
		if (tfw_tls_send_buf(c, skb_frag_address(f), f->size))
		    return -EINVAL;
	}

	kfree_skb(skb);

	return 0;
}

/**
 * Callback function which is called by TLS library.
 */
static int
tfw_tls_send_cb(void *conn, const unsigned char *buf, size_t len)
{
	TfwConn *c = conn;
	TfwTlsContext *tls = tfw_tls_context(c);
	struct sk_buff *skb;

	tls_dbg(c, "=>");

	skb = alloc_skb(MAX_TCP_HEADER + len, GFP_ATOMIC);
	if (unlikely(!skb))
		return -ENOMEM;

	skb_reserve(skb, MAX_TCP_HEADER);
	skb_put(skb, len);

	if (unlikely(skb_store_bits(skb, 0, buf, len)))
		BUG();

	ss_skb_queue_tail(&tls->tx_queue, skb);
	if (ss_send(c->sk, &tls->tx_queue, 0))
		return -EIO;

	tls_dbg(c, "-- %lu bytes sent", len);

	return len;
}

/**
 * Callback function which is called by TLS library.
 */
static int
tfw_tls_recv_cb(void *conn, unsigned char *buf, size_t len)
{
	TfwConn *c = conn;
	TfwTlsContext *tls = tfw_tls_context(c);
	struct sk_buff *skb = ss_skb_peek_tail(&tls->rx_queue);

	tls_dbg(c, "=>");

	if (unlikely(!skb))
		return 0;

	len = min_t(size_t, skb->len, len);
	if (unlikely(skb_copy_bits(skb, 0, buf, len)))
		BUG();

	pskb_pull(skb, len);

	if (unlikely(!skb->len)) {
		ss_skb_unlink(&tls->rx_queue, skb);
		kfree_skb(skb);
	}

	tls_dbg(c, "-- %lu bytes rcvd", len);

	return len;
}

static void
tfw_tls_conn_dtor(TfwConn *c)
{
	TfwTlsContext *tls = tfw_tls_context(c);

	mbedtls_ssl_free(&tls->ssl);
	tfw_cli_conn_release((TfwCliConn *)c);
}

static int
tfw_tls_conn_init(TfwConn *c)
{
	int r;
	TfwTlsContext *tls = tfw_tls_context(c);

	tls_dbg(c, "=>");

	mbedtls_ssl_init(&tls->ssl);

	tls->rx_queue = tls->tx_queue = NULL;

	r = mbedtls_ssl_setup(&tls->ssl, &tfw_tls.cfg);
	if (r) {
		TFW_ERR("TLS:%p setup failed (%x)\n", tls, -r);
		return -EINVAL;
	}

	mbedtls_ssl_set_bio(&tls->ssl, c,
			    tfw_tls_send_cb, tfw_tls_recv_cb, NULL);

	if (tfw_conn_hook_call(TFW_FSM_HTTP, c, conn_init))
		return -EINVAL;

	spin_lock_init(&tls->lock);
	tfw_gfsm_state_init(&c->state, c, TFW_TLS_FSM_INIT);

	/* Set the destructor */
	c->destructor = (void *)tfw_tls_conn_dtor;

	return 0;
}

static void
tfw_tls_conn_drop(TfwConn *c)
{
	TfwTlsContext *tls = tfw_tls_context(c);

	tls_dbg(c, "=>");

	tfw_conn_hook_call(TFW_FSM_HTTP, c, conn_drop);

	ttls_ssl_close_notify(tls);
}

static int
tfw_tls_conn_send(TfwConn *c, TfwMsg *msg)
{
	struct sk_buff *skb;
	TfwTlsContext *tls = tfw_tls_context(c);

	tls_dbg(c, "=>");

	while ((skb = ss_skb_dequeue(&msg->skb_head))) {
		if (tfw_tls_send_skb(c, skb)) {
			kfree_skb(skb);
			return -EINVAL;
		}
	}

	if (msg->ss_flags & SS_F_CONN_CLOSE)
		ttls_ssl_close_notify(tls);

	return 0;
}

static TfwConnHooks tls_conn_hooks = {
	.conn_init	= tfw_tls_conn_init,
	.conn_drop	= tfw_tls_conn_drop,
	.conn_send	= tfw_tls_conn_send,
};

/*
 * ------------------------------------------------------------------------
 *	TLS library configuration
 * ------------------------------------------------------------------------
 */

#if defined(DEBUG)
static void
tfw_tls_dbg_cb(void *ctx, int level, const char *file, int line, const char *str)
{
	((void) ctx);
	if (level < DEBUG)
		printk("[mbedtls] %s:%d -- %s\n", file, line, str);
}
#endif

static int
tfw_tls_rnd_cb(void *rnd, unsigned char *out, size_t len)
{
	/* TODO: improve random generation. */
	get_random_bytes(out, len);
	return 0;
}

static int
tfw_tls_do_init(void)
{
	int r;

	mbedtls_ssl_config_init(&tfw_tls.cfg);
	r = mbedtls_ssl_config_defaults(&tfw_tls.cfg,
					MBEDTLS_SSL_IS_SERVER,
					MBEDTLS_SSL_TRANSPORT_STREAM,
					MBEDTLS_SSL_PRESET_DEFAULT);
	if (r) {
		TFW_ERR_NL("TLS: can't set config defaults (%x)\n", -r);
		return -EINVAL;
	}

#if defined(DEBUG)
	mbedtls_debug_set_threshold(DEBUG);
	mbedtls_ssl_conf_dbg(&tfw_tls.cfg, tfw_tls_dbg_cb, NULL);
#endif
	mbedtls_ssl_conf_rng(&tfw_tls.cfg, tfw_tls_rnd_cb, NULL);

	return 0;
}

static void
tfw_tls_do_cleanup(void)
{
	mbedtls_x509_crt_free(&tfw_tls.crt);
	mbedtls_pk_free(&tfw_tls.key);
	mbedtls_ssl_config_free(&tfw_tls.cfg);
}

/*
 * ------------------------------------------------------------------------
 *	configuration handling
 * ------------------------------------------------------------------------
 */

/* TLS configuration state. */
#define TFW_TLS_CFG_F_DISABLED	0
#define TFW_TLS_CFG_F_REQUIRED	1
#define TFW_TLS_CFG_F_CERT	2
#define TFW_TLS_CFG_F_CKEY	4
#define TFW_TLS_CFG_M_ALL	(TFW_TLS_CFG_F_CERT | TFW_TLS_CFG_F_CKEY)

static unsigned int tfw_tls_cgf = TFW_TLS_CFG_F_DISABLED;

void
tfw_tls_cfg_require(void)
{
	tfw_tls_cgf |= TFW_TLS_CFG_F_REQUIRED;
}

static int
tfw_tls_start(void)
{
	int r;

	if (tfw_runstate_is_reconfig())
		return 0;

	mbedtls_ssl_conf_ca_chain(&tfw_tls.cfg, tfw_tls.crt.next, NULL);
	r = mbedtls_ssl_conf_own_cert(&tfw_tls.cfg, &tfw_tls.crt, &tfw_tls.key);
	if (r) {
		TFW_ERR_NL("TLS: can't set own certificate (%x)\n", -r);
		return -EINVAL;
	}

	return 0;
}

/**
 * Handle 'ssl_certificate <path>' config entry.
 */
static int
tfw_cfgop_ssl_certificate(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;
	void *crt_data;
	size_t crt_size;

	mbedtls_x509_crt_init(&tfw_tls.crt);

	if (ce->attr_n) {
		TFW_ERR_NL("%s: Arguments may not have the \'=\' sign\n",
			   cs->name);
		return -EINVAL;
	}
	if (ce->val_n != 1) {
		TFW_ERR_NL("%s: Invalid number of arguments: %d\n",
			   cs->name, (int)ce->val_n);
		return -EINVAL;
	}

	crt_data = tfw_cfg_read_file((const char *)ce->vals[0], &crt_size);
	if (!crt_data) {
		TFW_ERR_NL("%s: Can't read certificate file '%s'\n",
			   ce->name, (const char *)ce->vals[0]);
		return -EINVAL;
	}

	r = mbedtls_x509_crt_parse(&tfw_tls.crt,
				   (const unsigned char *)crt_data,
				   crt_size);
	vfree(crt_data);

	if (r) {
		TFW_ERR_NL("%s: Invalid certificate specified (%x)\n",
			   cs->name, -r);
		return -EINVAL;
	}
	tfw_tls_cgf |= TFW_TLS_CFG_F_CERT;

	return 0;
}

static void
tfw_cfgop_cleanup_ssl_certificate(TfwCfgSpec *cs)
{
	mbedtls_x509_crt_free(&tfw_tls.crt);
}

/**
 * Handle 'ssl_certificate_key <path>' config entry.
 */
static int
tfw_cfgop_ssl_certificate_key(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;
	void *key_data;
	size_t key_size;

	mbedtls_pk_init(&tfw_tls.key);

	if (ce->attr_n) {
		TFW_ERR_NL("%s: Arguments may not have the \'=\' sign\n",
			   cs->name);
		return -EINVAL;
	}
	if (ce->val_n != 1) {
		TFW_ERR_NL("%s: Invalid number of arguments: %d\n",
			   cs->name, (int)ce->val_n);
		return -EINVAL;
	}

	key_data = tfw_cfg_read_file((const char *)ce->vals[0], &key_size);
	if (!key_data) {
		TFW_ERR_NL("%s: Can't read certificate file '%s'\n",
			   ce->name, (const char *)ce->vals[0]);
		return -EINVAL;
	}

	r = mbedtls_pk_parse_key(&tfw_tls.key,
				 (const unsigned char *)key_data,
				 key_size, NULL, 0);
	vfree(key_data);

	if (r) {
		TFW_ERR_NL("%s: Invalid private key specified (%x)\n",
			   cs->name, -r);
		return -EINVAL;
	}
	tfw_tls_cgf |= TFW_TLS_CFG_F_CKEY;

	return 0;
}

static void
tfw_cfgop_cleanup_ssl_certificate_key(TfwCfgSpec *cs)
{
	mbedtls_pk_free(&tfw_tls.key);
}

static int
tfw_tls_cfgend(void)
{
	if (!(tfw_tls_cgf & TFW_TLS_CFG_F_REQUIRED)) {
		if (tfw_tls_cgf & TFW_TLS_CFG_F_REQUIRED)
			TFW_WARN_NL("TLS: no HTTPS listener,"
				    " configuration ignored\n");
		return 0;
	}

	if (!(tfw_tls_cgf & TFW_TLS_CFG_F_CERT)) {
		TFW_ERR_NL("TLS: please spcify a certificate with"
			   " tls_certificate configuration option\n");
		return -EINVAL;
	}

	if ((tfw_tls_cgf & TFW_TLS_CFG_M_ALL) != TFW_TLS_CFG_M_ALL) {
		TFW_ERR_NL("TLS: SSL certificate/key pair is incomplete\n");
		return -EINVAL;
	}

	return 0;
}

static TfwCfgSpec tfw_tls_specs[] = {
	{
		.name = "tls_certificate",
		.deflt = NULL,
		.handler = tfw_cfgop_ssl_certificate,
		.allow_none = true,
		.allow_repeat = false,
		.cleanup = tfw_cfgop_cleanup_ssl_certificate,
	},
	{
		.name = "tls_certificate_key",
		.deflt = NULL,
		.handler = tfw_cfgop_ssl_certificate_key,
		.allow_none = true,
		.allow_repeat = false,
		.cleanup = tfw_cfgop_cleanup_ssl_certificate_key,
	},
	{ 0 }
};

TfwMod tfw_tls_mod = {
	.name	= "tls",
	.cfgend = tfw_tls_cfgend,
	.start	= tfw_tls_start,
	.specs	= tfw_tls_specs,
};

/*
 * ------------------------------------------------------------------------
 *	init/exit
 * ------------------------------------------------------------------------
 */

int __init
tfw_tls_init(void)
{
	int r;

	r = tfw_tls_do_init();
	if (r)
		return -EINVAL;

	r = tfw_gfsm_register_fsm(TFW_FSM_TLS, tfw_tls_msg_process);
	if (r) {
		tfw_tls_do_cleanup();
		return -EINVAL;
	}

	tfw_connection_hooks_register(&tls_conn_hooks, TFW_FSM_TLS);
	tfw_mod_register(&tfw_tls_mod);

	return 0;
}

void
tfw_tls_exit(void)
{
	tfw_mod_unregister(&tfw_tls_mod);
	tfw_connection_hooks_unregister(TFW_FSM_TLS);
	tfw_gfsm_unregister_fsm(TFW_FSM_TLS);
	tfw_tls_do_cleanup();
}
