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
#include "msg.h"
#include "procfs.h"
#include "tls.h"

typedef struct {
	ttls_config	cfg;
	ttls_x509_crt	crt;
	ttls_pk_context	key;
} TfwTls;

static TfwTls tfw_tls;

static int
tfw_tls_msg_process(void *conn, const TfwFsmData *data)
{
	int r, parsed = 0;
	struct sk_buff *nskb = NULL, *skb = data->skb;
	unsigned int off = data->off;
	TfwConn *c = conn;
	TlsCtx *tls = tfw_tls_context(c);
	struct sk_buff *msg_skb;
	TfwFsmData data_up = {};

	BUG_ON(off >= skb->len);

	/*
	 * Perform TLS handshake if necessary and decrypt the TLS message
	 * in-place by chunks. Add skb to the list to build scatterlist if it
	 * it contains end of current message.
	 */
	spin_lock(&tls->lock);
next_msg:
	ss_skb_queue_tail(&tls->io_in.skb_list, skb);
	msg_skb = tls->io_in.skb_list;
	r = ss_skb_process(skb, off, ttls_recv, tls, &tls->io_in.chunks,
			   &parsed);
	switch (r) {
	default:
		TFW_WARN("Unrecognized TLS receive return code %d,"
			 " drop packet", r);
	case T_DROP:
		spin_unlock(&tls->lock);
		__kfree_skb(skb);
		return r;
	case T_POSTPONE:
		/*
		 * No data to pass to upper protolos, typically
		 * handshake and/or incomplete TLS record.
		 */
		spin_unlock(&tls->lock);
		return TFW_PASS;
	case T_OK:
		/*
		 * A complete TLS message decrypted and ready for upper
		 * layer protocols processing - fall throught.
		 */
		TFW_DBG("TLS got %d data bytes (%.*s) on conn=%pK\n",
			r, r, skb->data, c);
	}
	T_DBG3("%s: parsed=%d skb->len=%u\n", __func__, parsed, skb->len);

	/*
	 * Possibly there are other TLS message in the @skb - create
	 * an skb sibling and process it on the next iteration.
	 * If a part of incomplete TLS message leaves at the end of the
	 * @skb, then store the skb in the TLS context for next FSM
	 * shot.
	 *
	 * Many sibling skbs can be produced by TLS and HTTP layers
	 * together - don't coalesce them: we process messages at once
	 * and it hase sense to work with sparse skbs in HTTP
	 * adjustment logic to have some room to place a new fragments.
	 * The logic is simple because each layer works with messages
	 * from previous layer not crossing skb boundaries. The drawback
	 * is that we produce a lot of skbs causing pressure on the
	 * memory allocator.
	 *
	 * Split @skb before calling HTTP layer to chop it and not let HTTP
	 * to read after end of the message.
	 */
	if (parsed < skb->len) {
		nskb = ss_skb_split(skb, parsed);
		if (unlikely(!nskb)) {
			spin_unlock(&tls->lock);
			TFW_INC_STAT_BH(clnt.msgs_otherr);
			return T_DROP;
		}
	}

	/* At this point tls->io_in is initialized for the next record. */
	data_up.skb = msg_skb;
	data_up.off = off;
	r = tfw_gfsm_move(&c->state, TFW_TLS_FSM_DATA_READY, data);
	if (r == TFW_BLOCK) {
		spin_unlock(&tls->lock);
		kfree_skb(nskb);
		return r;
	}

	if (nskb) {
		skb = nskb;
		nskb = NULL;
		parsed = off = 0;
		goto next_msg;
	}
	spin_unlock(&tls->lock);

	return r;
}

/**
 * The callback is called by tcp_write_xmit() if @skb must be encrypted by TLS.
 * @skb is current head of the TCP send queue. @limit defines how much data
 * can be sent right now with knowledge of current congestion and the receiver's
 * advertised window. Limit can be larger than skb->len and in this case we
 * can add the next skb in the send queue to the current encrypted TLS record.
 */
int
tfw_tls_encrypt(struct sock *sk, struct sk_buff *skb, unsigned int limit)
{
	int r = -ENOMEM;
	unsigned int len, off, frags;
	unsigned char *hdr, type;
	struct sk_buff *next, *skb_tail = skb;
	TlsCtx *tls = tfw_tls_context(sk->sk_user_data);
	TlsIOCtx *io = &tls->io_out;
	struct sg_table sgt = {
		.nents = skb_shinfo(skb)->nr_frags + !!skb_headlen(skb),
	};

	T_DBG3("tcp_write_xmit() -> %s: sk=%pK skb=%pK(len=%u data_len=%u"
	       " type=%u) limit=%u\n", __func__, sk, skb, skb->len,
	       skb->data_len, tempesta_tls_skb_type(skb), limit);
	BUG_ON(!ttls_xfrm_ready(tls));
	WARN_ON_ONCE(skb->len > TLS_MAX_PAYLOAD_SIZE);

	len = skb->len + tls->xfrm.ivlen + ttls_xfrm_taglen(&tls->xfrm);
	type = tempesta_tls_skb_type(skb);
	if (!type) {
		T_WARN("%s: bad skb type %u\n", __func__, type);
		return -EINVAL;
	}

	while (!tcp_skb_is_last(sk, skb_tail)) {
		next = tcp_write_queue_next(sk, skb_tail);
		if (len + next->len > limit)
			break;
		/* Don't put different message types into the same record. */
		if (type != tempesta_tls_skb_type(next))
			break;
		len += next->len;
		sgt.nents += skb_shinfo(next)->nr_frags + !!skb_headlen(next);
		skb_tail = next;
	}
	io->msglen = len;

	sgt.sgl = kmalloc(sizeof(struct scatterlist) * sgt.nents, GFP_ATOMIC);
	if (!sgt.sgl)
		return -ENOMEM;

	if (skb_tail == skb) {
		hdr = ss_skb_expand_frags(skb, TLS_AAD_SPACE_SIZE,
					  TLS_MAX_TAG_SZ);
		if (!hdr)
			goto out;
	} else {
		hdr = ss_skb_expand_frags(skb, TLS_AAD_SPACE_SIZE, 0);
		if (!hdr)
			goto out;
		if (!ss_skb_expand_frags(skb_tail, 0, TLS_MAX_TAG_SZ))
			goto out;
	}

	off = TLS_AAD_SPACE_SIZE;
	len = skb->len - TLS_AAD_SPACE_SIZE;
	for (next = skb, frags = 0; ; ) {
		r = skb_to_sgvec(next, sgt.sgl, off, len);
		if (r <= 0)
			goto out;
		frags += 0;
		tempesta_tls_skb_clear(next);
		if (next == skb_tail)
			break;
		next = tcp_write_queue_next(sk, next);
		len = next->len;
		off = 0;
	}
	sg_mark_end(sgt.sgl + frags - 1);
	WARN_ON_ONCE(frags > sgt.nents);

	spin_lock(&tls->lock);

	ttls_write_hdr(tls, type, io->msglen, hdr);
	r = ttls_encrypt(tls, &sgt);

	spin_unlock(&tls->lock);

out:
	kfree(sgt.sgl);

	return r;
}

static void
tfw_tls_skb_set_enc(TlsCtx *tls, struct sk_buff *skb)
{
	if (ttls_xfrm_ready(tls))
		tempesta_tls_skb_settype(skb, tls->io_out.msgtype);
}

/**
 * Callback function which is called by TLS library under tls->lock.
 */
static int
tfw_tls_send(TlsCtx *tls, struct sg_table *sgt)
{
	int r, flags = 0;
	TfwTlsConn *conn = container_of(tls, TfwTlsConn, tls);
	TlsIOCtx *io = &tls->io_out;
	TfwMsgIter it;
	TfwStr str = {};

	/*
	 * Encrypted (application data) messages will be prepended by a header
	 * in tfw_tls_encrypt(), so if we have an encryption context, then we
	 * don't send the header. Otherwise (handshake message) copy the whole
	 * data with a header.
	 *
	 * During handshake (!ttls_xfrm_ready(tls)), io may contain several
	 * consequent records of the same TTLS_MSG_HANDSHAKE type. io, except
	 * msglen containing length of the last record, describes the first
	 * record.
	 */
	if (ttls_xfrm_ready(tls)) {
		str.ptr = io->__msg;
		str.len = io->msglen + TLS_MAX_TAG_SZ;
	} else {
		str.ptr = io->hdr;
		str.len = ttls_hdr_len(tls) + io->hslen;
	}
	T_DBG("TLS %lu bytes +%u segments (%u bytes) are to be sent on conn=%pK"
	      " ready=%d)\n", str.len, sgt ? sgt->nents : 0, io->msglen,
	      conn, ttls_xfrm_ready(tls));

	if ((r = tfw_msg_iter_setup(&it, &io->skb_list, str.len)))
		return r;
	if ((r = tfw_msg_write(&it, &str)))
		return r;
	/* Only one skb should has been allocated. */
	WARN_ON_ONCE(it.skb->next != io->skb_list
		     || it.skb->prev != io->skb_list);
	tfw_tls_skb_set_enc(tls, it.skb);
	if (sgt) {
		int f, i = ++it.frag;
		struct sk_buff *skb = it.skb;
		struct scatterlist *sg;

		for_each_sg(sgt->sgl, sg, sgt->nents, f) {
			if (i >= MAX_SKB_FRAGS) {
				if (!(it.skb = ss_skb_alloc(0)))
					return -ENOMEM;
				tfw_tls_skb_set_enc(tls, skb);
				ss_skb_queue_tail(&io->skb_list, skb);
				i = 0;
			}
			skb_fill_page_desc(skb, i++, sg_page(sg), sg->offset,
					   sg->length);
			ss_skb_adjust_data_len(skb, sg->length);
			T_DBG3("fill skb frag %d by %pK,len=%u in"
			       " skb=%pK,len=%u\n",
			       i - 1, sg_virt(sg), sg->length, skb, skb->len);
		}
	}

	return ss_send(conn->cli_conn.sk, &io->skb_list, flags);
}

static void
tfw_tls_conn_dtor(void *c)
{
	TlsCtx *tls = tfw_tls_context(c);

	ttls_ctx_clear(tls);
	tfw_cli_conn_release((TfwCliConn *)c);
}

static int
tfw_tls_conn_init(TfwConn *c)
{
	int r;
	TlsCtx *tls = tfw_tls_context(c);

	if ((r = ttls_ctx_init(tls, &tfw_tls.cfg))) {
		TFW_ERR("TLS (%pK) setup failed (%x)\n", tls, -r);
		return -EINVAL;
	}

	if (tfw_conn_hook_call(TFW_FSM_HTTP, c, conn_init))
		return -EINVAL;

	tfw_gfsm_state_init(&c->state, c, TFW_TLS_FSM_INIT);

	c->destructor = tfw_tls_conn_dtor;

	return 0;
}

static void
tfw_tls_conn_drop(TfwConn *c)
{
	TlsCtx *tls = tfw_tls_context(c);

	tfw_conn_hook_call(TFW_FSM_HTTP, c, conn_drop);

	spin_lock(&tls->lock);
	ttls_close_notify(tls);
	spin_unlock(&tls->lock);
}

/**
 * Send the @msg skbs as is - tcp_write_xmit() will care about encryption,
 * but attach TLS alert message at the end of the skb list to notify the peer
 * about connection closing if we're going to close the client connection.
 */
static int
tfw_tls_conn_send(TfwConn *c, TfwMsg *msg)
{
	int r;
	TlsCtx *tls = tfw_tls_context(c);

	if ((r = ss_send(c->sk, &msg->skb_head, msg->ss_flags)))
		return r;

	if (msg->ss_flags & SS_F_CONN_CLOSE) {
		spin_lock(&tls->lock);
		r = ttls_close_notify(tls);
		spin_unlock(&tls->lock);
	}

	return r;
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
static int
tfw_tls_do_init(void)
{
	int r;

	ttls_config_init(&tfw_tls.cfg);
	/* Use cute ECDHE-ECDSA-AES128-GCM-SHA256 by default. */
	r = ttls_config_defaults(&tfw_tls.cfg, TTLS_IS_SERVER,
				 TTLS_TRANSPORT_STREAM);
	if (r) {
		TFW_ERR_NL("TLS: can't set config defaults (%x)\n", -r);
		return -EINVAL;
	}

	/*
	 * TODO #715 set SNI callback with ttls_conf_sni() to get per-vhost
	 * certificates.
	 */

	return 0;
}

static void
tfw_tls_do_cleanup(void)
{
	ttls_x509_crt_free(&tfw_tls.crt);
	ttls_pk_free(&tfw_tls.key);
	ttls_config_free(&tfw_tls.cfg);
}

/*
 * ------------------------------------------------------------------------
 *	configuration handling
 * ------------------------------------------------------------------------
 */
/* TLS configuration state. */
#define TFW_TLS_CFG_F_DISABLED	0U
#define TFW_TLS_CFG_F_REQUIRED	1U
#define TFW_TLS_CFG_F_CERT	2U
#define TFW_TLS_CFG_F_CKEY	4U
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

	ttls_conf_ca_chain(&tfw_tls.cfg, tfw_tls.crt.next, NULL);
	r = ttls_conf_own_cert(&tfw_tls.cfg, &tfw_tls.crt, &tfw_tls.key);
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

	ttls_x509_crt_init(&tfw_tls.crt);

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

	r = ttls_x509_crt_parse(&tfw_tls.crt, (unsigned char *)crt_data,
				crt_size);

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
	ttls_x509_crt_free(&tfw_tls.crt);
	tfw_tls_cgf &= ~TFW_TLS_CFG_F_CERT;
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

	ttls_pk_init(&tfw_tls.key);

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

	r = ttls_pk_parse_key(&tfw_tls.key, (const unsigned char *)key_data,
			      key_size);
	free_pages((unsigned long)key_data, get_order(key_size));

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
	ttls_pk_free(&tfw_tls.key);
	tfw_tls_cgf &= ~TFW_TLS_CFG_F_CKEY;
}

static int
tfw_tls_cfgend(void)
{
	if (!(tfw_tls_cgf & TFW_TLS_CFG_F_REQUIRED)) {
		if (tfw_tls_cgf)
			TFW_WARN_NL("TLS: no HTTPS listener,"
				    " configuration ignored\n");
		return 0;
	}
	if (!(tfw_tls_cgf & TFW_TLS_CFG_F_CERT)) {
		TFW_ERR_NL("TLS: please specify a certificate with"
			   " tls_certificate configuration option\n");
		return -EINVAL;
	}
	if (!(tfw_tls_cgf & TFW_TLS_CFG_F_CKEY)) {
		TFW_ERR_NL("TLS: please specify a certificate key with"
			   " tls_certificate_key configuration option\n");
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

	ttls_register_bio(tfw_tls_send);

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
