/*
 *		Tempesta FW
 *
 * HTTP session management.
 *
 * Typically Web applications identify HTTP sessions using special session ID
 * cookies. Tempesta does this using sticky cookies. So HTTP session contains
 * at least its timestamp and secure HMAC over User-Agent, client IP address
 * and the timestamp - the hash is used to identify the session.
 *
 * HTTP sessions are used for client security identification (e.g. DDoS cookie
 * challenge), safe load balancing for session oriented Web apps and so on.
 * The term 'Client' is actually vague. Different human clients can be behind
 * shared proxy having the same source IP (i.e. the same TfwClient descriptor).
 * The same human client can use different browsers, so they send different
 * User-Agent headers and use different sticky cookies. X-Forwarded-For header
 * value can be used to cope the non anonymous forward proxy problem and
 * identify real clients.
 *
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
#include <crypto/hash.h>
#include <linux/ctype.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/vmalloc.h>

#include "lib/hash.h"
#include "lib/str.h"
#include "addr.h"
#include "cfg.h"
#include "client.h"
#include "http_msg.h"
#include "http_sess.h"
#include "filter.h"

#define STICKY_NAME_MAXLEN	(32)
#define STICKY_NAME_DEFAULT	"__tfw"
#define STICKY_KEY_MAXLEN	FIELD_SIZEOF(TfwHttpSess, hmac)

#define SESS_HASH_BITS		17
#define SESS_HASH_SZ		(1 << SESS_HASH_BITS)

/**
 * @name		- name of sticky cookie;
 * @name_eq		- @name plus "=" to make some operations faster;
 * @sess_lifetime	- session lifetime in seconds;
 * @max_misses		- maximum count of requests with invalid cookie;
 * @tmt_sec		- maximum time (in seconds) to wait the request
 *			  with valid cookie;
 */
typedef struct {
	TfwStr		name;
	TfwStr		name_eq;
	unsigned int	sess_lifetime;
	unsigned int	max_misses;
	unsigned int	tmt_sec;
	u_int		enabled : 1,
			enforce : 1;
} TfwCfgSticky;


/**
 * Temporal storage for calculated redirection mark value.
 *
 * @att_no		- number of redirection attempts;
 * @ts			- timestamp for the first redirection attempt;
 * @hmac		- calculated HMAC value for redirection mark;
 */
typedef struct {
	unsigned int	att_no;
	unsigned long	ts;
	unsigned char	hmac[STICKY_KEY_MAXLEN];
} __attribute__((packed)) RedirMarkVal;

/**
 * Temporal storage for calculated sticky cookie values.
 *
 * @ts			- timestamp of the session beginning;
 * @hmac		- calculated HMAC value for cookie value;
 */
typedef struct {
	unsigned long	ts;
	unsigned char	hmac[STICKY_KEY_MAXLEN];
} __attribute__((packed)) StickyVal;

typedef struct {
	struct hlist_head	list;
	spinlock_t		lock;
} SessHashBucket;

static TfwCfgSticky tfw_cfg_sticky;
/* Secret server value to generate reliable client identifiers. */
static struct crypto_shash *tfw_sticky_shash;
static char tfw_sticky_key[STICKY_KEY_MAXLEN];
static bool tfw_cfg_sticky_sess = false;

static SessHashBucket sess_hash[SESS_HASH_SZ] = {
	[0 ... (SESS_HASH_SZ - 1)] = {
		HLIST_HEAD_INIT,
	}
};

static struct kmem_cache *sess_cache;

/**
 * JavaScript challenge.
 *
 * To pass JS challenge client must repeat it's request in exact time frame
 * specified by JS code.
 *
 * @body	- body (html with JavaScript code);
 * @delay_min	- minimal timeout client must wait before repeat the request,
 *		  in jiffies;
 * @delay_limit	- maximum time required to deliver request form a client to the
 *		  Tempesta, in jiffies;
 * @delay_range	- time interval starting after @delay_min for a client to make
 *		  a repeated request, in msecs;
 * @st_code	- status code for response with JS challenge;
 */
typedef struct {
	TfwStr		body;
	unsigned long	delay_min;
	unsigned long	delay_limit;
	unsigned long	delay_range;
	unsigned short	st_code;
} TfwCfgJsCh;

static TfwCfgJsCh *tfw_cfg_js_ch = NULL;
static const unsigned int tfw_cfg_jsch_code_dflt = 503;
#define TFW_CFG_JS_PATH "/etc/tempesta/js_challenge.html"

static unsigned short tfw_cfg_redirect_st_code;
static const unsigned short tfw_cfg_redirect_st_code_dflt = 302;

/**
 * Normal browser must be able to execute the challenge: not all requests
 * can be challenged, e.g. images - a browser won't execute the JS code if
 * receives the challenge. Send redirect only for requests with
 * 'Accept: text/html' and GET method.
 */
static bool
tfw_http_sticky_redirect_applied(TfwHttpReq *req)
{
	if (!tfw_cfg_js_ch)
		return true;

	return (req->method == TFW_HTTP_METH_GET)
		&& test_bit(TFW_HTTP_B_ACCEPT_HTML, req->flags);
}

/*
 * Create redirect mark in following form:
 *
 *	<attempt_no> | <timestamp> | HMAC(Secret, attempt_no, timestamp)
 *
 * Field <attempt_no> is required to track redirection limit, and <timestamp> is
 * needed to detect bots, who repeat inital redirect mark in all subsequent
 * requests.
 */
static void
tfw_http_redir_mark_prepare(RedirMarkVal *mv, char *buf, unsigned int buf_len,
			    TfwStr *chunks, unsigned int ch_len, TfwStr *rmark)
{
	unsigned int att_be32 = cpu_to_be32(mv->att_no);
	unsigned long ts_be64 = cpu_to_be64(mv->ts);
	DEFINE_TFW_STR(s_sl, "/");
	DEFINE_TFW_STR(s_eq, "=");

	bin2hex(buf, &att_be32, sizeof(att_be32));
	bin2hex(&buf[sizeof(att_be32) * 2], &ts_be64, sizeof(ts_be64));
	bin2hex(&buf[(sizeof(att_be32) + sizeof(ts_be64)) * 2],
		mv->hmac, sizeof(mv->hmac));

	bzero_fast(chunks, ch_len);
	chunks[0] = s_sl;
	chunks[1] = tfw_cfg_sticky.name;
	chunks[2] = s_eq;
	chunks[3].data = buf;
	chunks[3].len = buf_len;

	rmark->chunks = chunks;
	rmark->len = chunks[0].len;
	rmark->len += chunks[1].len;
	rmark->len += chunks[2].len;
	rmark->len += chunks[3].len;
	rmark->nchunks = 4;
}

static int
tfw_http_sticky_build_redirect(TfwHttpReq *req, StickyVal *sv, RedirMarkVal *mv)
{
	unsigned long ts_be64 = cpu_to_be64(sv->ts);
	TfwStr c_chunks[3], m_chunks[4], cookie = { 0 }, rmark = { 0 };
	DEFINE_TFW_STR(s_eq, "=");
	TfwHttpResp *resp;
	char c_buf[sizeof(*sv) * 2], m_buf[sizeof(*mv) * 2];
	TfwStr *body = tfw_cfg_js_ch ? &tfw_cfg_js_ch->body : NULL;
	int r;

	WARN_ON_ONCE(!list_empty(&req->fwd_list));
	WARN_ON_ONCE(!list_empty(&req->nip_list));

	/*
	 * TODO: #598 rate limit requests with invalid cookie value.
	 * Non-challengeable requests also must be rate limited.
	 */

	if (!tfw_http_sticky_redirect_applied(req))
		return TFW_HTTP_SESS_JS_NOT_SUPPORTED;

	if (!(resp = tfw_http_msg_alloc_resp_light(req)))
		return -ENOMEM;

	if (mv)
		tfw_http_redir_mark_prepare(mv, m_buf, sizeof(m_buf), m_chunks,
					    sizeof(m_chunks), &rmark);
	/*
	 * Form the cookie as:
	 *
	 * 	<timestamp> | HMAC(Secret, User-Agent, timestamp, Client IP)
	 *
	 * Open <timestamp> is required to be able to recalculate secret HMAC.
	 * Since the secret is unknown for the attackers, they're still unable
	 * to recalculate HMAC while we don't need to store session information
	 * until we receive correct cookie value.
	 */
	bin2hex(c_buf, &ts_be64, sizeof(ts_be64));
	bin2hex(&c_buf[sizeof(ts_be64) * 2], sv->hmac, sizeof(sv->hmac));

	bzero_fast(c_chunks, sizeof(c_chunks));
	c_chunks[0] = tfw_cfg_sticky.name;
	c_chunks[1] = s_eq;
	c_chunks[2].data = c_buf;
	c_chunks[2].len = sizeof(*sv) * 2;

	cookie.chunks = c_chunks;
	cookie.len = c_chunks[0].len + c_chunks[1].len + c_chunks[2].len;
	cookie.nchunks = 3;

	r = tfw_http_prep_redirect((TfwHttpMsg *)resp, tfw_cfg_redirect_st_code,
				   &rmark, &cookie, body);
	if (r) {
		tfw_http_msg_free((TfwHttpMsg *)resp);
		return TFW_HTTP_SESS_FAILURE;
	}

	/*
	 * Don't send @resp now: cookie check take place on very early @req
	 * processing stage, store @resp as @req->resp, the response will be
	 * sent as soon as @req will be fully processed.
	 */
	return TFW_HTTP_SESS_REDIRECT_NEED;
}

static int
search_cookie(TfwPool *pool, const TfwStr *cookie, TfwStr *val)
{
	const char *const cstr = tfw_cfg_sticky.name_eq.data;
	const unsigned long clen = tfw_cfg_sticky.name_eq.len;
	TfwStr *chunk, *end;
	TfwStr tmp = { .flags = 0, };
	unsigned int n = cookie->nchunks;

	BUG_ON(!TFW_STR_PLAIN(&tfw_cfg_sticky.name_eq));

	/* Search cookie name. */
	end = cookie->chunks + cookie->nchunks;
	for (chunk = cookie->chunks; chunk != end; ++chunk, --n) {
		if (!(chunk->flags & TFW_STR_NAME))
			continue;
		/*
		 * Create a temporary compound string, starting with this
		 * chunk. The total string length is not used here, so it
		 * is not set.
		 */
		tmp.chunks = chunk;
		tmp.nchunks = n;
		if (tfw_str_eq_cstr(&tmp, cstr, clen, TFW_STR_EQ_PREFIX))
			break;
	}
	if (chunk == end)
		return 0;

	/* Search cookie value, starting with next chunk. */
	for (++chunk; chunk != end; ++chunk)
		if (chunk->flags & TFW_STR_VALUE)
			break;
	/*
	 * The party can send us zero-value cookie,
	 * treat this as not found cookie.
	 */
	if (unlikely(chunk == end))
		return 0;

	tfw_str_collect_cmp(chunk, end, val, ";");

	return 1;
}

/*
 * Find Tempesta sticky cookie in an HTTP message.
 *
 * Return 1 if the cookie is found.
 * Return 0 if the cookie is NOT found.
 */
static int
tfw_http_sticky_get(TfwHttpReq *req, TfwStr *cookie_val)
{
	TfwStr value = { 0 };
	TfwStr *hdr;

	/*
	 * Find a 'Cookie:' header field in the request. Then search for
	 * Tempesta sticky cookie within the field. Note that there can
	 * be only one "Cookie:" header field. See RFC 6265 section 5.4.
	 * NOTE: Irrelevant here, but there can be multiple 'Set-Cookie"
	 * header fields as an exception. See RFC 7230 section 3.2.2.
	 */
	hdr = &req->h_tbl->tbl[TFW_HTTP_HDR_COOKIE];
	if (TFW_STR_EMPTY(hdr))
		return 0;
	tfw_http_msg_clnthdr_val(hdr, TFW_HTTP_HDR_COOKIE, &value);

	return search_cookie(req->pool, &value, cookie_val);
}

#ifdef DEBUG
#define TFW_DBG_PRINT_STICKY_COOKIE(addr, ua, sv)			\
do {									\
	char abuf[TFW_ADDR_STR_BUF_SIZE] = {0};				\
	char hbuf[STICKY_KEY_MAXLEN * 2] = {0};				\
	tfw_addr_fmt(addr, TFW_NO_PORT, abuf);				\
	bin2hex(hbuf, tfw_sticky_key, STICKY_KEY_MAXLEN);		\
	TFW_DBG("http_sess: calculate sticky cookie for %s,"		\
		" ts=%#lx(now=%#lx)...\n", abuf, (sv)->ts, jiffies);	\
	TFW_DBG("\t...secret: %.*s\n", (int)STICKY_KEY_MAXLEN * 2, hbuf);\
	tfw_str_dprint(ua, "\t...User-Agent");				\
} while (0)
#else
#define TFW_DBG_PRINT_STICKY_COOKIE(addr, ua, sv)
#endif

/*
 * Create Tempesta sticky cookie value.
 *
 * Tempesta sticky cookie is based on:
 * - HTTP request source IP address;
 * - HTTP request User-Agent string;
 * - Current timestamp;
 * - The secret key;
 */
static int
__sticky_calc(TfwHttpReq *req, StickyVal *sv)
{
	int r;
	TfwStr ua_value = { 0 };
	TfwAddr *addr = &req->conn->peer->addr;
	TfwStr *hdr, *c, *end;
	SHASH_DESC_ON_STACK(shash_desc, tfw_sticky_shash);

	/* User-Agent header field is not mandatory and may be missing. */
	hdr = &req->h_tbl->tbl[TFW_HTTP_HDR_USER_AGENT];
	if (!TFW_STR_EMPTY(hdr))
		tfw_http_msg_clnthdr_val(hdr, TFW_HTTP_HDR_USER_AGENT,
					 &ua_value);

	shash_desc->tfm = tfw_sticky_shash;
	shash_desc->flags = 0;

	TFW_DBG_PRINT_STICKY_COOKIE(addr, &ua_value, sv);

	if ((r = crypto_shash_init(shash_desc)))
		return r;

	r = crypto_shash_update(shash_desc, (u8 *)tfw_addr_sa(addr),
	                        tfw_addr_sa_len(addr));
	if (r)
		return r;
	if (ua_value.len) {
		TFW_STR_FOR_EACH_CHUNK(c, &ua_value, end) {
			r = crypto_shash_update(shash_desc, c->data, c->len);
			if (r)
				return r;
		}
	}
	return crypto_shash_finup(shash_desc, (u8 *)&sv->ts, sizeof(sv->ts),
				  sv->hmac);
}

static int
tfw_http_sticky_calc(TfwHttpReq *req, StickyVal *sv)
{
	sv->ts = jiffies;

	return __sticky_calc(req, sv);
}

/*
 * Add Tempesta sticky cookie to an HTTP response.
 *
 * Create a complete 'Set-Cookie:' header field, and add it
 * to the HTTP response' header block.
 */
static int
tfw_http_sticky_add(TfwHttpResp *resp)
{
	static const unsigned int len = sizeof(StickyVal) * 2;
	int r;
	TfwHttpSess *sess = resp->req->sess;
	unsigned long ts_be64 = cpu_to_be64(sess->ts);
	char buf[len];
	TfwStr set_cookie = {
		.chunks = (TfwStr []) {
			{ .data = S_F_SET_COOKIE, .len = SLEN(S_F_SET_COOKIE) },
			{ .data = tfw_cfg_sticky.name_eq.data,
			  .len = tfw_cfg_sticky.name_eq.len },
			{ .data = buf, .len = len },
		},
		.len = SLEN(S_F_SET_COOKIE) + tfw_cfg_sticky.name_eq.len + len,
		.eolen = 2,
		.nchunks = 3
	};

	/* See comment from tfw_http_sticky_build_redirect(). */
	bin2hex(buf, &ts_be64, sizeof(ts_be64));
	bin2hex(&buf[sizeof(ts_be64) * 2], sess->hmac, sizeof(sess->hmac));

	TFW_DBG("%s: \"" S_F_SET_COOKIE "%.*s=%.*s\"\n", __func__,
		PR_TFW_STR(&tfw_cfg_sticky.name), len, buf);

	r = tfw_http_msg_hdr_add((TfwHttpMsg *)resp, &set_cookie);
	if (r)
		TFW_WARN("Cannot add \"" S_F_SET_COOKIE "%.*s=%.*s\"\n",
			 PR_TFW_STR(&tfw_cfg_sticky.name), len, buf);
	return r;
}

/*
 * Calculate HMAC value for redirection mark.
 *
 * HMAC value is based on:
 * - Number of attempts for session establishing;
 * - Timestamp of first attempt;
 * - Secret key.
 */
static int
__redir_hmac_calc(RedirMarkVal *mv)
{
	int r;
	SHASH_DESC_ON_STACK(shash_desc, tfw_sticky_shash);

	shash_desc->tfm = tfw_sticky_shash;
	shash_desc->flags = 0;

	TFW_DBG("http_sess: calculate redirection mark: ts=%#lx(now=%#lx),"
		" att_no=%#x\n", mv->ts, jiffies, mv->att_no);

	if ((r = crypto_shash_init(shash_desc)))
		return r;
	r = crypto_shash_update(shash_desc, (u8 *)&mv->att_no, sizeof(mv->att_no));
	if (r)
		return r;
	return crypto_shash_finup(shash_desc, (u8 *)&mv->ts, sizeof(mv->ts),
				  mv->hmac);
}

static int
tfw_http_redir_mark_get(TfwHttpReq *req, TfwStr *out_val)
{
	TfwStr *mark = &req->mark;
	TfwStr *c, *end;

	if (TFW_STR_EMPTY(mark))
		return 0;

	/* Find the value chunk. */
	end = mark->chunks + mark->nchunks;
	for (c = mark->chunks; c != end; ++c)
		if (c->flags & TFW_STR_VALUE)
			break;

	BUG_ON(c == end);

	tfw_str_collect_cmp(c, end, out_val, NULL);

	return 1;
}

#define sess_warn(check, addr, fmt, ...)				\
	TFW_WARN_MOD_ADDR(http_sess, check, addr, TFW_NO_PORT, fmt,	\
	                  ##__VA_ARGS__)

/* The set of macros for parsing hex strings of following format:
 *
 *    <value_1> | <value_2> | ... | <value_n> | HMAC_value
 *
 * and HMAC value verification. In 'HEX_STR_TO_BIN_HMAC()' macro the
 * 'hmac' parameter must contain newly recalculated HMAC value.
 */
#define HEX_STR_TO_BIN_INIT(tr, c, str, end)				\
	tr = NULL;							\
	TFW_STR_FOR_EACH_CHUNK_INIT(c, str, end);

#define HEX_STR_TO_BIN_GET(obj, f)					\
({									\
	int count = 0;							\
	if (c >= end)							\
		goto end_##f;						\
	if (!tr)							\
		tr = c->data;						\
	for (;;) {							\
		for ( ; tr < (unsigned char *)c->data + c->len; ++tr) {	\
			if (count++ == sizeof((obj)->f) * 2)		\
				goto end_##f;				\
			(obj)->f = ((obj)->f << 4) + hex_to_bin(*tr);	\
		}							\
		++c;							\
		if (c >= end)						\
			break;						\
		tr = c->data;						\
	}								\
end_##f:								\
	;								\
})

#define HEX_STR_TO_BIN_HMAC(hmac, ts, addr)				\
({									\
	unsigned char b;						\
	int i = 0, hi = 1, r = TFW_HTTP_SESS_SUCCESS;			\
									\
	if (c >= end)							\
		goto end;						\
	for (;;) {							\
		for ( ; tr < (unsigned char *)c->data + c->len; ++tr) {	\
			b = hi ? hex_asc_hi((hmac)[i])			\
			       : hex_asc_lo((hmac)[i]);			\
			if (b != *tr) {					\
				int n = sizeof(hmac) * 2;		\
				char buf[n];				\
				bin2hex(buf, hmac, sizeof(hmac));	\
				sess_warn("bad received HMAC value",	\
					  addr, ": %c(pos=%d),"		\
					  " ts=%#lx orig_hmac=[%.*s]\n", \
					  *tr, i, ts, n, buf);		\
				r = TFW_HTTP_SESS_VIOLATE;		\
				goto end;				\
			}						\
			hi = !hi;					\
			i += hi;					\
		}							\
		++c;							\
		if (c >= end)						\
			break;						\
		tr = c->data;						\
	}								\
	BUG_ON(i != STICKY_KEY_MAXLEN);					\
end:									\
	r;								\
})

/**
 * Verify found redirection mark.
 */
static int
tfw_http_redir_mark_verify(TfwHttpReq *req, TfwStr *mark_val, RedirMarkVal *mv)
{
	unsigned char *tr;
	TfwAddr *addr = &req->conn->peer->addr;
	TfwStr *c, *end;

	TFW_DBG("Redirection mark found%s: \"%.*s\"\n",
		TFW_STR_PLAIN(mark_val) ? "" : ", starts with",
		TFW_STR_PLAIN(mark_val) ?
			(int)mark_val->len :
			(int)mark_val->chunks->len,
		TFW_STR_PLAIN(mark_val) ?
			mark_val->data :
			mark_val->chunks->data);

	if (mark_val->len != sizeof(RedirMarkVal) * 2) {
		sess_warn("bad length of redirection mark", addr,
			  ": %lu(%lu)\n", mark_val->len,
			  sizeof(RedirMarkVal) * 2);
		return TFW_HTTP_SESS_VIOLATE;
	}

	HEX_STR_TO_BIN_INIT(tr, c, mark_val, end);
	HEX_STR_TO_BIN_GET(mv, att_no);
	HEX_STR_TO_BIN_GET(mv, ts);

	if (__redir_hmac_calc(mv))
		return TFW_HTTP_SESS_VIOLATE;

	return HEX_STR_TO_BIN_HMAC(mv->hmac, mv->ts, addr);
}

/*
 * Find special redirection mark in request, calculate actual mark,
 * match them and check redirection counts and timestamp (if configured).
 * If limits are exceeded, the IP-address of corresponding client will
 * be blocked. This verifications are intended only for enforce mode.
 */
static int
tfw_http_sess_check_redir_mark(TfwHttpReq *req, RedirMarkVal *mv)
{
	TfwStr mark_val = {};

	if (tfw_http_redir_mark_get(req, &mark_val)) {
		if (tfw_http_redir_mark_verify(req, &mark_val, mv)
		    || ++mv->att_no > tfw_cfg_sticky.max_misses
		    || (tfw_cfg_sticky.tmt_sec
		        && mv->ts + HZ * (unsigned long)tfw_cfg_sticky.tmt_sec
		           < jiffies))
		{
			tfw_filter_block_ip(&req->conn->peer->addr);
			return TFW_HTTP_SESS_VIOLATE;
		}
		bzero_fast(mv->hmac, sizeof(mv->hmac));
	} else {
		mv->ts = jiffies;
		mv->att_no = 1;
	}

	if (__redir_hmac_calc(mv))
		return TFW_HTTP_SESS_FAILURE;

	return TFW_HTTP_SESS_SUCCESS;
}

/*
 * No Tempesta sticky cookie found.
 *
 * Calculate Tempesta sticky cookie and send redirection to the client if
 * enforcement is configured. Since the client can be malicious, we don't
 * store anything for now. HTTP session will be created when the client
 * is successfully solves the cookie challenge. Also, in enforcement
 * configured case the count of requests without cookie and timeout are
 * checked (via special mark set in front of location URI in the response
 * of during redirection); if the configured limit or timeout is exhausted,
 * client will be blocked.
 */
static int
tfw_http_sticky_notfound(TfwHttpReq *req)
{
	int r;
	StickyVal sv = {};
	RedirMarkVal mv = {}, *mvp = NULL;

	/*
	 * In enforced mode, ensure that backend server receives
	 * requests that always carry Tempesta sticky cookie.
	 * If cookie is absent in request, return an HTTP 302
	 * response to the client that has the same host, URI,
	 * and includes 'Set-Cookie' header. If enforced mode
	 * is disabled, forward request to a backend server.
	 */
	if (!tfw_cfg_sticky.enforce)
		return TFW_HTTP_SESS_SUCCESS;

	/*
	 * If configured, ensure that limit for requests without
	 * cookie and timeout for redirections are not exhausted.
	 */
	if (tfw_cfg_sticky.max_misses) {
		mvp = &mv;
		if ((r = tfw_http_sess_check_redir_mark(req, mvp)))
			return r;
	}

	/* Create Tempesta sticky cookie and store it */
	if (tfw_http_sticky_calc(req, &sv) != 0)
		return TFW_HTTP_SESS_FAILURE;

	return tfw_http_sticky_build_redirect(req, &sv, mvp);
}

/**
 * Verify found Tempesta sticky cookie.
 */
static int
tfw_http_sticky_verify(TfwHttpReq *req, TfwStr *value, StickyVal *sv)
{
	int r;
	unsigned char *tr;
	TfwAddr *addr = &req->conn->peer->addr;
	TfwStr *c, *end;

	TFW_DBG("Sticky cookie found%s: \"%.*s\"\n",
		TFW_STR_PLAIN(value) ? "" : ", starts with",
		TFW_STR_PLAIN(value) ?
			(int)value->len :
			(int)value->chunks->len,
		TFW_STR_PLAIN(value) ?
			value->data :
			value->chunks->data);

	if (value->len != sizeof(StickyVal) * 2) {
		sess_warn("bad sticky cookie length", addr, ": %lu(%lu)\n",
			  value->len, sizeof(StickyVal) * 2);
		tfw_http_sticky_calc(req, sv);
		return TFW_HTTP_SESS_VIOLATE;
	}

	HEX_STR_TO_BIN_INIT(tr, c, value, end);
	HEX_STR_TO_BIN_GET(sv, ts);

	if (__sticky_calc(req, sv))
		return TFW_HTTP_SESS_VIOLATE;

	if ((r = HEX_STR_TO_BIN_HMAC(sv->hmac, sv->ts, addr)))
		return r;

	/* Sticky cookie is found and verified, now we can set the flag. */
	__set_bit(TFW_HTTP_B_HAS_STICKY, req->flags);

	return r;
}

/*
 * Process Tempesta sticky cookie in an HTTP request.
 */
static int
tfw_http_sticky_req_process(TfwHttpReq *req, StickyVal *sv)
{
	int r;
	TfwStr cookie_val = {};

	/*
	 * See if the Tempesta sticky cookie is present in the request,
	 * and act depending on the result.
	 */
	r = tfw_http_sticky_get(req, &cookie_val);
	if (r < 0)
		return r;
	if (r == 0)
		return tfw_http_sticky_notfound(req);
	if (r == 1) {
		/*
		 * Verify sticky cookie value: if it's wrong, then this can be
		 * an attack as well as changed Tempesta or whatever else.
		 * The first case must be properly handled by Frang limit
		 * (TODO #598), your ever can limit number of invalid sticky
		 * cookie tries to 1. While we just send normal 302 redirect to
		 * keep user experience intact.
		 */
		if (tfw_http_sticky_verify(req, &cookie_val, sv)) {
			RedirMarkVal mv = {}, *mvp = NULL;
			if (tfw_cfg_sticky.max_misses) {
				mvp = &mv;
				if ((r = tfw_http_sess_check_redir_mark(req, mvp)))
					return r;
			}
			return tfw_http_sticky_build_redirect(req, sv, mvp);
		}
		return TFW_HTTP_SESS_SUCCESS;
	}
	TFW_WARN("Multiple Tempesta sticky cookies found: %d\n", r);

	return TFW_HTTP_SESS_FAILURE;
}

/*
 *  Remove redirection mark from request.
 */
int
tfw_http_sess_req_process(TfwHttpReq *req)
{
	if (!tfw_cfg_sticky.max_misses || TFW_STR_EMPTY(&req->mark))
		return 0;
	return tfw_http_msg_del_str((TfwHttpMsg *)req, &req->mark);
}

/*
 * Add Tempesta sticky cookie to an HTTP response if needed.
 */
int
tfw_http_sess_resp_process(TfwHttpResp *resp)
{
	TfwHttpReq *req = resp->req;

	if (!tfw_cfg_sticky.enabled
	    || test_bit(TFW_HTTP_B_WHITELIST, req->flags))
	{
		return 0;
	}
	BUG_ON(!req->sess);

	/*
	 * RFC 6265 4.1.1 and 4.1.2 says that we should not set session cookie
	 * if it's not necessary. Since client didn't send up the cookie and
	 * it seems that we don't enforce them, we can just set the cookie in
	 * each response forwarded to the client.
	 */
	if (test_bit(TFW_HTTP_B_HAS_STICKY, req->flags))
		return 0;
	return tfw_http_sticky_add(resp);
}

/**
 * Release pinned server to allow destroying servers and groups removed from
 * current configuration.
 */
static void
tfw_http_sess_unpin_srv(TfwStickyConn *st_conn)
{
	TfwServer *srv;

	if (!st_conn->srv_conn)
		return;

	srv = (TfwServer *)st_conn->srv_conn->peer;
	st_conn->srv_conn = NULL;
	tfw_server_unpin_sess(srv);
}

void
tfw_http_sess_put(TfwHttpSess *sess)
{
	if (atomic_dec_and_test(&sess->users)) {
		/*
		 * Use counter reached 0, so session already expired and evicted
		 * from the hash table.
		 */
		tfw_http_sess_unpin_srv(&sess->st_conn);
		kmem_cache_free(sess_cache, sess);
	}
}

bool
tfw_http_sess_max_misses(void)
{
	return tfw_cfg_sticky.max_misses > 0;
}

unsigned int
tfw_http_sess_mark_size(void)
{
	return sizeof(RedirMarkVal) * 2;
}

TfwStr *
tfw_http_sess_mark_name(void)
{
	return &tfw_cfg_sticky.name_eq;
}

/**
 * Remove a session from hash bucket. @sess may become invalid after the
 * function call.
 */
static void
tfw_http_sess_remove(TfwHttpSess *sess)
{
	hash_del(&sess->hentry);
	tfw_http_sess_put(sess);
}

/**
 * Challenged client must not send request before challenging timeout passed.
 */
static int
tfw_http_sess_check_jsch(StickyVal *sv, TfwHttpReq* req)
{
	unsigned long min_time, max_time;

	if (!tfw_cfg_js_ch)
		return 0;

	/*
	 * When a client calculates it's own random delay, it uses range value
	 * encoded as msecs, we have to use the same, to have exactly the same
	 * calculation results. See etc/js_challenge.js.tpl .
	 */
	min_time = sv->ts + tfw_cfg_js_ch->delay_min
			+ msecs_to_jiffies(sv->ts % tfw_cfg_js_ch->delay_range);
	max_time = min_time + tfw_cfg_js_ch->delay_limit;
	if (time_in_range(req->jrxtstamp, min_time, max_time))
		return 0;

	if (tfw_http_sticky_redirect_applied(req)) {
		TFW_DBG("sess: jsch block: request received outside allowed "
			"time range.\n");
		return TFW_HTTP_SESS_VIOLATE;
	}
	else {
		TFW_DBG("sess: jsch drop: non-challegeable resource was "
			"requested outside allowed time range.\n");
		return TFW_HTTP_SESS_JS_NOT_SUPPORTED;
	}
}

/**
 * Obtains appropriate HTTP session for the request based on Sticky cookies.
 * Return TFW_HTTP_SESS_* enum or error code on internal errors.
 */
int
tfw_http_sess_obtain(TfwHttpReq *req)
{
	int r;
	unsigned long key;
	TfwHttpSess *sess;
	SessHashBucket *hb;
	struct hlist_node *tmp;
	StickyVal sv = { };

	if (!tfw_cfg_sticky.enabled
	    || test_bit(TFW_HTTP_B_WHITELIST, req->flags))
	{
		return TFW_HTTP_SESS_SUCCESS;
	}

	if ((r = tfw_http_sticky_req_process(req, &sv)))
		return r;

	/*
	 * Sticky cookie can be not enforced and we still have to allocate new
	 * session for requests w/o session cookie. It means that malicious user
	 * can always send us requests w/o session cookie. HMAC will be
	 * different due to different ingress timestamps, so DoS is very
	 * possible. The only thing which we can do is to enforce the cookie.
	 * However, we can lose innocent clients w/ disabled cookies.
	 * We leave this for administrator decision or more progressive DDoS
	 * mitigation techniques.
	 */

	if (!sv.ts) {
		/* No sticky cookie in request and no enforcement. */
		if (tfw_http_sticky_calc(req, &sv))
			return TFW_HTTP_SESS_FAILURE;
	}

	key = hash_calc(sv.hmac, sizeof(sv.hmac));
	hb = &sess_hash[hash_min(key, SESS_HASH_BITS)];

	spin_lock(&hb->lock);

	hlist_for_each_entry_safe(sess, tmp, &hb->list, hentry) {
		/* Collect garbage first to not to return expired session. */
		if (sess->expires < jiffies) {
			tfw_http_sess_remove(sess);
			continue;
		}

		if (!memcmp_fast(sv.hmac, sess->hmac, sizeof(sess->hmac)))
			goto found;
	}

	if ((r = tfw_http_sess_check_jsch(&sv, req))) {
		spin_unlock(&hb->lock);
		return r;
	}

	if (!(sess = kmem_cache_alloc(sess_cache, GFP_ATOMIC))) {
		spin_unlock(&hb->lock);
		return -ENOMEM;
	}

	memcpy_fast(sess->hmac, sv.hmac, sizeof(sv.hmac));
	hlist_add_head(&sess->hentry, &hb->list);
	/*
	 * Sessions are removed by the garbage collection above, so the hash
	 * table is initial user of the session plus to the function caller.
	 */
	atomic_set(&sess->users, 1);
	sess->ts = sv.ts;
	sess->expires =
		sv.ts + (unsigned long)tfw_cfg_sticky.sess_lifetime * HZ;
	sess->st_conn.srv_conn = NULL;
	rwlock_init(&sess->st_conn.lock);

	TFW_DBG("new session %p\n", sess);

found:
	atomic_inc(&sess->users);

	spin_unlock(&hb->lock);

	req->sess = sess;

	return TFW_HTTP_SESS_SUCCESS;
}

static void
tfw_http_sess_set_expired(TfwHttpSess *sess)
{
	sess->expires = 0;
}

void
tfw_http_sess_use_sticky_sess(bool use)
{
	WRITE_ONCE(tfw_cfg_sticky_sess, use);
}

static bool
tfw_http_sess_has_sticky_sess(void)
{
	return READ_ONCE(tfw_cfg_sticky_sess);
}

/**
 * Try to reuse last used connection or last used server.
 */
static inline TfwSrvConn *
__try_conn(TfwMsg *msg, TfwSrvConn *srv_conn)
{
	TfwServer *srv;

	if (unlikely(!srv_conn))
		return NULL;

	srv = (TfwServer *)srv_conn->peer;
	if (tfw_srv_suspended(srv))
		return NULL;

	if (!tfw_srv_conn_restricted(srv_conn)
	    && !tfw_srv_conn_queue_full(srv_conn)
	    && !tfw_srv_conn_hasnip(srv_conn)
	    && tfw_srv_conn_get_if_live(srv_conn))
	{
		return srv_conn;
	}

	/*
	 * Try to sched from the same server. The server may be removed from
	 * server group, see comment for TfwStickyConn.
	 */
	return srv->sg->sched->sched_srv_conn(msg, srv);
}

/**
 * Pin HTTP session to specified server. Called under write lock.
 */
static void
tfw_http_sess_pin_srv(TfwStickyConn *st_conn, TfwSrvConn *srv_conn)
{
	TfwServer *srv;

	tfw_http_sess_unpin_srv(st_conn);

	if (!srv_conn)
		return;

	srv = (TfwServer *)srv_conn->peer;
	if (srv->sg->flags & TFW_SRV_STICKY) {
		tfw_server_pin_sess(srv);
		st_conn->srv_conn = srv_conn;
	}
}

/**
 * Find an outgoing connection for client with Tempesta sticky cookie.
 * @sess is not null when calling the function.
 *
 * Reuse req->sess->st_conn.srv_conn if it is alive. If not,
 * then get a new connection for the same server.
 */
TfwSrvConn *
tfw_http_sess_get_srv_conn(TfwMsg *msg)
{
	TfwHttpSess *sess = ((TfwHttpReq *)msg)->sess;
	TfwStickyConn *st_conn;
	TfwSrvConn *srv_conn;

	BUG_ON(!sess);
	st_conn = &sess->st_conn;

	read_lock(&st_conn->lock);

	/* The session pinning won't be needed, avoid write_lock(). */
	if (!st_conn->srv_conn && !tfw_http_sess_has_sticky_sess()) {
		read_unlock(&st_conn->lock);
		return tfw_vhost_get_srv_conn(msg);
	}

	if ((srv_conn = __try_conn(msg, st_conn->srv_conn))) {
		read_unlock(&st_conn->lock);
		return srv_conn;
	}

	read_unlock(&st_conn->lock);
	write_lock(&st_conn->lock);
	/*
	 * Sessions was pinned to a new connection (or server returned back
	 * online) while we were trying for a lock.
	 */
	if ((srv_conn = __try_conn(msg, st_conn->srv_conn))) {
		write_unlock(&st_conn->lock);
		return srv_conn;
	}

	if (st_conn->srv_conn) {
		/* Failed to sched from the same server. */
		TfwServer *srv = (TfwServer *)st_conn->srv_conn->peer;
		char addr_str[TFW_ADDR_STR_BUF_SIZE] = { 0 };

		tfw_addr_ntop(&srv->addr, addr_str, sizeof(addr_str));

		if (!(srv->sg->flags & TFW_SRV_STICKY_FAILOVER))
		{
			/*
			 * Server is removed and disconnected, it will never
			 * go up again, expire session to force releasing of
			 * the server instance. unpin_srv() will be called in
			 * session destructor (tfw_http_sess_put()).
			 */
			if (unlikely(test_bit(TFW_CFG_B_DEL, &srv->flags))) {
				TFW_LOG("sticky sched: server %s"
					" was removed, set session expired\n",
					addr_str);
				tfw_http_sess_set_expired(sess);
				goto err;
			}
			TFW_ERR("sticky sched: pinned server %s in group '%s'"
				" is down\n",
				addr_str, srv->sg->name);
			goto err;
		}
		TFW_WARN("sticky sched: pinned server %s in group '%s'"
			 " is down, try find other server\n",
			 addr_str, srv->sg->name);
	}

	srv_conn = tfw_vhost_get_srv_conn(msg);
	tfw_http_sess_pin_srv(st_conn, srv_conn);
err:
	write_unlock(&st_conn->lock);

	return srv_conn;
}

static int
tfw_cfgop_sticky(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	size_t i, len;
	const char *key, *val, *name_val = STICKY_NAME_DEFAULT;
	int r;

	TFW_CFG_ENTRY_FOR_EACH_ATTR(ce, i, key, val) {
		if (!strcasecmp(key, "name")) {
			name_val = val;
		} else if (!strcasecmp(key, "max_misses")) {
			r = tfw_cfg_parse_uint(val, &tfw_cfg_sticky.max_misses);
			if (r)
				return r;
		} else if (!strcasecmp(key, "timeout")) {
			r = tfw_cfg_parse_uint(val, &tfw_cfg_sticky.tmt_sec);
			if (r)
				return r;
		} else {
			TFW_ERR_NL("%s: unsupported argument: '%s=%s'.\n",
				   cs->name, key, val);
			return -EINVAL;
		}
	}

	len = strlen(name_val);
	if (len == 0 || len > STICKY_NAME_MAXLEN)
		return -EINVAL;
	memcpy(tfw_cfg_sticky.name.data, name_val, len);
	tfw_cfg_sticky.name.len = len;
	tfw_cfg_sticky.name_eq.data[len] = '=';
	tfw_cfg_sticky.name_eq.len = len + 1;

	TFW_CFG_ENTRY_FOR_EACH_VAL(ce, i, val) {
		if (!strcasecmp(val, "enforce")) {
			tfw_cfg_sticky.enforce = 1;
		} else {
			TFW_ERR_NL("%s: unsupported argument: '%s'\n",
				   cs->name, val);
			return -EINVAL;
		}
	}

	if (tfw_cfg_sticky.max_misses && !tfw_cfg_sticky.enforce) {
		TFW_ERR_NL("%s: 'max_misses' can be enabled only in"
			   " 'enforce' mode\n", cs->name);
		return -EINVAL;
	}
	if (tfw_cfg_sticky.tmt_sec && !tfw_cfg_sticky.max_misses) {
		TFW_ERR_NL("%s: 'timeout' can be specified only with"
			   " 'max_misses' attribute\n", cs->name);
		return -EINVAL;
	}

	return 0;
}

static void
tfw_cfgop_cleanup_sticky(TfwCfgSpec *cs)
{
	int i;

	for (i = 0; i < SESS_HASH_SZ; ++i) {
		TfwHttpSess *sess;
		struct hlist_node *tmp;
		SessHashBucket *hb = &sess_hash[i];

		hlist_for_each_entry_safe(sess, tmp, &hb->list, hentry)
			tfw_http_sess_remove(sess);
	}
	memset(tfw_cfg_sticky.name.data, 0, STICKY_NAME_MAXLEN + 1);
	tfw_cfg_sticky.name.len = tfw_cfg_sticky.name_eq.len = 0;
	tfw_cfg_sticky.enforce = 0;
	tfw_cfg_sticky.max_misses = 0;
	tfw_cfg_sticky.tmt_sec = 0;
}

static int
tfw_cfgop_sticky_secret(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;
	unsigned int len = (unsigned int)strlen(ce->vals[0]);

	if (tfw_cfg_check_single_val(ce))
		return -EINVAL;
	if (len > STICKY_KEY_MAXLEN)
		return -EINVAL;

	if (len) {
		memset(tfw_sticky_key, 0, STICKY_KEY_MAXLEN);
		memcpy(tfw_sticky_key, ce->vals[0], len);
	}
	else {
		get_random_bytes(tfw_sticky_key, sizeof(tfw_sticky_key));
		len = sizeof(tfw_sticky_key);
	}

	r = crypto_shash_setkey(tfw_sticky_shash, (u8 *)tfw_sticky_key, len);
	if (r)
		return r;

	return 0;
}

static int
tfw_cfgop_sess_lifetime(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;

	r = tfw_cfg_set_int(cs, ce);
	/*
	 * "sess_lifetime 0;" means unlimited session lifetime,
	 * set tfw_cfg_sticky.sess_lifetime to maximum value.
	*/
	if (!r && !tfw_cfg_sticky.sess_lifetime)
		tfw_cfg_sticky.sess_lifetime = UINT_MAX;

	return r;
}

static inline int
tfw_cfgop_jsch_parse(TfwCfgSpec *cs, const char *key, const char *val,
		     unsigned int *uint_val)
{
	int r;

	if ((r = tfw_cfg_parse_uint(val, uint_val)))
		return r;

	return 0;
}

static int
tfw_cfg_op_jsch_parse_resp_code(TfwCfgSpec *cs, const char *val)
{
	int r, int_val;

	if ((r = tfw_cfg_parse_int(val, &int_val)))
		return r;
	if ((r = tfw_cfg_check_range(int_val, 100, 599)))
		return r;
	tfw_cfg_js_ch->st_code = int_val;

	return 0;
}

static void
tfw_cfgop_jsch_set_delay_limit(TfwCfgSpec *cs)
{
	const unsigned long min_limit	= msecs_to_jiffies(100);
	const unsigned long max_hc_p	= 10;
	const unsigned long max_limit	=
		msecs_to_jiffies(tfw_cfg_js_ch->delay_range) * max_hc_p / 100;
	unsigned long hc_prob;

	if (!tfw_cfg_js_ch->delay_limit) {
		tfw_cfg_js_ch->delay_limit = max_limit;
	}
	if (tfw_cfg_js_ch->delay_limit < min_limit) {
		TFW_WARN_NL("%s: 'delay_limit' is too low, many slow/distant "
			    "clients will be blocked. "
			    "Minimum recommended value is %u, "
			    "but %u is provided\n",
			    cs->name,
			    jiffies_to_msecs(min_limit),
			    jiffies_to_msecs(tfw_cfg_js_ch->delay_limit));
	}
	hc_prob = tfw_cfg_js_ch->delay_limit * 100
			/ msecs_to_jiffies(tfw_cfg_js_ch->delay_range);
	if (hc_prob > max_hc_p) {
		TFW_WARN_NL("%s: 'delay_limit' is too big, attacker may "
			    "hardcode bots and breach the JavaScript challenge "
			    "with %lu%% success probability\n",
			    cs->name, hc_prob);
	}
}

static int
tfw_cfgop_jsch_set_body(TfwCfgSpec *cs, const char *script)
{
	char *body_data;
	size_t sz;

	body_data = tfw_http_msg_body_dup(script, &sz);
	if (!body_data) {
		kfree(tfw_cfg_js_ch);
		tfw_cfg_js_ch = NULL;
		return -ENOMEM;
	}
	tfw_cfg_js_ch->body.len = sz;
	tfw_cfg_js_ch->body.data = body_data;

	return 0;
}

static int
tfw_cfgop_js_challenge(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	unsigned int uint_val;
	int i, r;
	const char *key, *val;

	tfw_cfg_js_ch = kzalloc(sizeof(TfwCfgJsCh), GFP_KERNEL);
	if (!tfw_cfg_js_ch) {
		TFW_ERR_NL("%s: can't alloc memory\n", cs->name);
		return -ENOMEM;
	}

	if (ce->val_n > 1) {
		TFW_ERR_NL("invalid number of values; 1 possible, got: %zu\n",
			   ce->val_n);
		return -EINVAL;
	}
	TFW_CFG_ENTRY_FOR_EACH_ATTR(ce, i, key, val) {
		if (!strcasecmp(key, "delay_min")) {
			if ((r = tfw_cfgop_jsch_parse(cs, key, val, &uint_val)))
				return r;
			tfw_cfg_js_ch->delay_min = msecs_to_jiffies(uint_val);
		} else if (!strcasecmp(key, "delay_range")) {
			if ((r = tfw_cfgop_jsch_parse(cs, key, val, &uint_val)))
				return r;
			tfw_cfg_js_ch->delay_range = uint_val;
		} else if (!strcasecmp(key, "delay_limit")) {
			if ((r = tfw_cfgop_jsch_parse(cs, key, val, &uint_val)))
				return r;
			tfw_cfg_js_ch->delay_limit = msecs_to_jiffies(uint_val);
		} else if (!strcasecmp(key, "resp_code")) {
			if ((r = tfw_cfg_op_jsch_parse_resp_code(cs, val)))
				return r;
		} else {
			TFW_ERR_NL("%s: unsupported argument: '%s=%s'.\n",
				   cs->name, key, val);
			return -EINVAL;
		}
	}
	if (!tfw_cfg_js_ch->delay_min) {
		TFW_ERR_NL("%s: required argument 'delay_min' not set.\n",
			   cs->name);
		return -EINVAL;
	}
	if (!tfw_cfg_js_ch->delay_range) {
		TFW_ERR_NL("%s: required argument 'delay_range' not set.\n",
			   cs->name);
		return -EINVAL;
	}
	if (!tfw_cfg_js_ch->st_code)
		tfw_cfg_js_ch->st_code = tfw_cfg_jsch_code_dflt;

	tfw_cfgop_jsch_set_delay_limit(cs);

	return tfw_cfgop_jsch_set_body(cs,
				       ce->val_n ? ce->vals[0] : TFW_CFG_JS_PATH);
}

static void
tfw_cfgop_cleanup_js_challenge(TfwCfgSpec *cs)
{
	if (!tfw_cfg_js_ch)
		return;

	if (tfw_cfg_js_ch->body.data)
		free_pages((unsigned long)tfw_cfg_js_ch->body.data,
			   get_order(tfw_cfg_js_ch->body.len));
	kfree(tfw_cfg_js_ch);
	tfw_cfg_js_ch = NULL;
}

static int
tfw_http_sess_cfgend(void)
{
	if (tfw_cfg_js_ch && TFW_STR_EMPTY(&tfw_cfg_sticky.name)) {
		TFW_ERR_NL("JavaScript challenge requires sticky cookies "
			   "enabled\r\n");
		return -EINVAL;
	}
	if (tfw_cfg_js_ch) {
		tfw_cfg_sticky.enforce = true;
		tfw_cfg_redirect_st_code = tfw_cfg_js_ch->st_code;
	} else {
		tfw_cfg_redirect_st_code = tfw_cfg_redirect_st_code_dflt;
	}

	return 0;
}

static int
tfw_http_sess_start(void)
{
	if (tfw_runstate_is_reconfig())
		return 0;
	tfw_cfg_sticky.enabled = !TFW_STR_EMPTY(&tfw_cfg_sticky.name);

	return 0;
}

static void
tfw_http_sess_stop(void)
{
	if (tfw_runstate_is_reconfig())
		return;
	tfw_cfg_sticky.enabled = 0;
}

static TfwCfgSpec tfw_http_sess_specs[] = {
	{
		.name = "sticky",
		.handler = tfw_cfgop_sticky,
		.cleanup = tfw_cfgop_cleanup_sticky,
		.allow_none = true,
	},
	{
		.name = "sticky_secret",
		.deflt = "\"\"",
		.handler = tfw_cfgop_sticky_secret,
		.allow_none = true,
	},
	{
		/* Value is parsed as int, set max to INT_MAX*/
		.name = "sess_lifetime",
		.deflt = "0",
		.handler = tfw_cfgop_sess_lifetime,
		.dest = &tfw_cfg_sticky.sess_lifetime,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, INT_MAX },
		},
		.allow_none = true,
	},
	{
		.name = "js_challenge",
		.handler = tfw_cfgop_js_challenge,
		.cleanup = tfw_cfgop_cleanup_js_challenge,
		.allow_none = true,
	},
	{ 0 }
};

TfwMod tfw_http_sess_mod = {
	.name	= "http_sess",
	.cfgend = tfw_http_sess_cfgend,
	.start	= tfw_http_sess_start,
	.stop	= tfw_http_sess_stop,
	.specs	= tfw_http_sess_specs,
};

int __init
tfw_http_sess_init(void)
{
	int i, ret = -ENOMEM;
	u_char *ptr;

	if ((ptr = kzalloc(STICKY_NAME_MAXLEN + 1, GFP_KERNEL)) == NULL)
		return -ENOMEM;

	tfw_cfg_sticky.name.data = tfw_cfg_sticky.name_eq.data = ptr;
	tfw_cfg_sticky.name.len = tfw_cfg_sticky.name_eq.len = 0;

	tfw_sticky_shash = crypto_alloc_shash("hmac(sha1)", 0, 0);
	if (IS_ERR(tfw_sticky_shash)) {
		pr_err("shash allocation failed\n");
		ret = (int)PTR_ERR(tfw_sticky_shash);
		goto err;
	}

	sess_cache = kmem_cache_create("tfw_sess_cache", sizeof(TfwHttpSess),
				       0, 0, NULL);
	if (!sess_cache)
		goto err_shash;

	/*
	 * Dynamically initialize hash table spinlocks to avoid lockdep leakage
	 * (see Troubleshooting in Documentation/locking/lockdep-design.txt).
	 */
	for (i = 0; i < SESS_HASH_SZ; ++i)
		spin_lock_init(&sess_hash[i].lock);

	tfw_mod_register(&tfw_http_sess_mod);

	return 0;

err_shash:
	crypto_free_shash(tfw_sticky_shash);
err:
	kfree(tfw_cfg_sticky.name.data);
	return ret;
}

void
tfw_http_sess_exit(void)
{
	tfw_mod_unregister(&tfw_http_sess_mod);
	kmem_cache_destroy(sess_cache);
	kfree(tfw_cfg_sticky.name.data);
	memset(&tfw_cfg_sticky, 0, sizeof(tfw_cfg_sticky));
	crypto_free_shash(tfw_sticky_shash);
}
