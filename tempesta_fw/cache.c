/**
 *		Tempesta FW
 *
 * HTTP cache (RFC 7234).
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2020 Tempesta Technologies, Inc.
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
#include <linux/freezer.h>
#include <linux/irq_work.h>
#include <linux/ipv6.h>
#include <linux/kthread.h>
#include <linux/tcp.h>
#include <linux/topology.h>

#include "tdb.h"

#include "lib/str.h"
#include "tempesta_fw.h"
#include "vhost.h"
#include "cache.h"
#include "http_msg.h"
#include "http_sess.h"
#include "procfs.h"
#include "sync_socket.h"
#include "work_queue.h"
#include "lib/common.h"

#if MAX_NUMNODES > ((1 << 16) - 1)
#warning "Please set CONFIG_NODES_SHIFT to less than 16"
#endif

static const int tfw_cache_spec_headers_304[] = {
	[0 ... TFW_HTTP_HDR_RAW] = 0,
	[TFW_HTTP_HDR_ETAG] = 1,
};
static const TfwStr tfw_cache_raw_headers_304[] = {
	TFW_STR_STRING("cache-control:"),
	TFW_STR_STRING("content-location:"),
	TFW_STR_STRING("date:"),
	TFW_STR_STRING("expires:"),
	TFW_STR_STRING("last-modified:"),
	TFW_STR_STRING("vary:"),
	/* Etag are Spec headers */
};
#define TFW_CACHE_304_SPEC_HDRS_NUM	1	/* ETag. */
#define TFW_CACHE_304_HDRS_NUM						\
	ARRAY_SIZE(tfw_cache_raw_headers_304) + TFW_CACHE_304_SPEC_HDRS_NUM


/* Flags stored in a Cache Entry. */
#define TFW_CE_MUST_REVAL	0x0001		/* MUST revalidate if stale. */

/*
 * @trec	- Database record descriptor;
 * @key_len	- length of key (URI + Host header);
 * @status_len	- length of response status code;
 * @rph_len	- length of response reason phrase;
 * @hdr_num	- number of headers;
 * @hdr_len	- length of whole headers data;
 * @hdr_h2_off	- start of http/2-only headers in the headers list;
 * @body_len	- length of the response body;
 * @method	- request method, part of the key;
 * @flags	- various cache entry flags;
 * @age		- the value of response Age: header field;
 * @date	- the value of response Date: header field;
 * @req_time	- the time the request was issued;
 * @resp_time	- the time the response was received;
 * @lifetime	- the cache entry's current lifetime;
 * @last_modified - the value of response Last-Modified: header field;
 * @key		- the cache entry key (URI + Host header);
 * @status	- pointer to status line;
 * @hdrs	- pointer to list of HTTP headers;
 * @body	- pointer to response body;
 * @hdrs_304	- pointers to headers used to build 304 response;
 * @version	- HTTP version of the response;
 * @resp_status - Http status of the cached response.
 * @hmflags	- flags of the response after parsing and post-processing.
 * @etag	- entity-tag, stored as a pointer to ETag header in @hdrs.
 */
typedef struct {
	TdbVRec		trec;
#define ce_body		key_len
	unsigned int	key_len;
	unsigned int	status_len;
	unsigned int	rph_len;
	unsigned int	hdr_num;
	unsigned int	hdr_h2_off;
	unsigned int	hdr_len;
	unsigned int	body_len;
	unsigned int	method: 4;
	unsigned int	flags: 28;
	time_t		age;
	time_t		date;
	time_t		req_time;
	time_t		resp_time;
	time_t		lifetime;
	time_t		last_modified;
	long		key;
	long		status;
	long		hdrs;
	long		body;
	long		hdrs_304[TFW_CACHE_304_HDRS_NUM];
	DECLARE_BITMAP	(hmflags, _TFW_HTTP_FLAGS_NUM);
	unsigned char	version;
	unsigned short	resp_status;
	TfwStr		etag;
} TfwCacheEntry;

#define CE_BODY_SIZE							\
	(sizeof(TfwCacheEntry) - offsetof(TfwCacheEntry, ce_body))

/**
 * String header for cache entries used for TfwStr serialization.
 *
 * @flags	- only TFW_STR_DUPLICATE or zero;
 * @len		- string length or number of duplicates;
 */
typedef struct {
	unsigned long	flags : 8,
			len : 56;
} TfwCStr;

#define TFW_CSTR_MAXLEN		(1UL << 56)
#define TFW_CSTR_HDRLEN		(sizeof(TfwCStr))

/* Work to copy response body to database. */
typedef struct {
	TfwHttpMsg		*msg;
	tfw_http_cache_cb_t	action;
	unsigned long		__unused[2];
} TfwCWork;

typedef struct {
	struct tasklet_struct	tasklet;
	struct irq_work		ipi_work;
	TfwRBQueue		wq;
} TfwWorkTasklet;

static struct {
	int cache;
	unsigned int methods;
	unsigned int db_size;
	const char *db_path;
} cache_cfg __read_mostly;

/* Cache modes. */
enum {
	TFW_CACHE_NONE = 0,
	TFW_CACHE_SHARD,
	TFW_CACHE_REPLICA,
};

typedef struct {
	int		cpu[NR_CPUS];
	atomic_t	cpu_idx;
	unsigned int	nr_cpus;
	TDB		*db;
} CaNode;

static CaNode c_nodes[MAX_NUMNODES];

typedef int tfw_cache_write_actor_t(TDB *, TdbVRec **, TfwHttpResp *, char **,
				    size_t, TfwDecodeCacheIter *);
/*
 * TODO the thread doesn't do anything for now, however, kthread_stop() crashes
 * on restarts, so comment to logic out.
 */
#if 0
static struct task_struct *cache_mgr_thr;
#endif
static DEFINE_PER_CPU(TfwWorkTasklet, cache_wq);

#define RESP_BUF_LEN		128

static DEFINE_PER_CPU(char[RESP_BUF_LEN], g_c_buf);

static TfwStr g_crlf = { .data = S_CRLF, .len = SLEN(S_CRLF) };

/* Iterate over request URI and Host header to process request key. */
#define TFW_CACHE_REQ_KEYITER(c, uri_path, host, u_end, h_start, h_end)	\
	if (TFW_STR_PLAIN(uri_path)) {					\
		c = uri_path;						\
		u_end = (uri_path) + 1;					\
	} else {							\
		c = (uri_path)->chunks;					\
		u_end = (uri_path)->chunks + (uri_path)->nchunks;	\
	}								\
	if (!TFW_STR_EMPTY(host)) {					\
		BUG_ON(TFW_STR_PLAIN(host));				\
		h_start = (host)->chunks;				\
		h_end = (host)->chunks + (host)->nchunks;		\
	} else {							\
		h_start = h_end = u_end;				\
	}								\
	for ( ; c != h_end; ++c, c = (c == u_end) ? h_start : c)

/*
 * The mask of non-cacheable methods per RFC 7231 4.2.3.
 * Safe methods that do not depend on a current or authoritative response
 * are defined as cacheable: GET, HEAD, and POST.
 * Note: caching of POST method responses is not supported at this time.
 * Issue #506 describes, which steps must be made to support caching of POST
 * requests.
 */
static unsigned int tfw_cache_nc_methods =
		~((1 << TFW_HTTP_METH_GET) | (1 << TFW_HTTP_METH_HEAD));

static inline bool
__cache_method_nc_test(tfw_http_meth_t method)
{
	BUILD_BUG_ON(sizeof(tfw_cache_nc_methods) * BITS_PER_BYTE
		     < _TFW_HTTP_METH_COUNT);

	return tfw_cache_nc_methods & (1 << method);
}

static inline void
__cache_method_add(tfw_http_meth_t method)
{
	cache_cfg.methods |= (1 << method);
}

static inline bool
__cache_method_test(tfw_http_meth_t method)
{
	return cache_cfg.methods & (1 << method);
}

bool
tfw_cache_msg_cacheable(TfwHttpReq *req)
{
	return cache_cfg.cache && __cache_method_test(req->method);
}

/**
 * Get NUMA node by the cache key.
 * The function gives different results if number of nodes changes,
 * e.g. due to hot-plug CPU. Cache eviction restores memory acquired by
 * inaccessible entries. The event of new/dead CPU is rare, so there is
 * no sense to use expensive rendezvous hashing.
 */
static unsigned short
tfw_cache_key_node(unsigned long key)
{
	return key % num_online_nodes();
}

/**
 * Just choose any CPU for each node to use queue_work_on() for
 * nodes scheduling. Reserve 0th CPU for other tasks.
 */
static void
tfw_init_node_cpus(void)
{
	int cpu, node;

	for_each_online_cpu(cpu) {
		node = cpu_to_node(cpu);
		c_nodes[node].cpu[c_nodes[node].nr_cpus++] = cpu;
	}
}

static TDB *
node_db(void)
{
	return c_nodes[numa_node_id()].db;
}

/**
 * Get a CPU identifier from @node to schedule a work.
 * The request should be processed on remote node, use round robin strategy
 * to distribute such requests.
 *
 * Note that atomic_t is a signed 32-bit value, and it's intentionally
 * cast to unsigned type value before taking a modulo operation.
 * If this place becomes a hot spot, then @cpu_idx may be made per_cpu.
 */
static int
tfw_cache_sched_cpu(TfwHttpReq *req)
{
	CaNode *node = &c_nodes[req->node];
	unsigned int idx = atomic_inc_return(&node->cpu_idx);

	return node->cpu[idx % node->nr_cpus];
}

/*
 * Find caching policy in specific vhost and location.
 */
static int
tfw_cache_policy(TfwVhost *vhost, TfwLocation *loc, TfwStr *arg)
{
	TfwCaPolicy *capo;

	/* Search locations in current vhost. */
	if (loc && loc->capo_sz) {
		if ((capo = tfw_capolicy_match(loc, arg)))
			return capo->cmd;
	}

	/*
	 * Search default policies in current vhost.
	 * If there's none, then search global default policies.
	 */
	loc = vhost->loc_dflt;
	if (loc && loc->capo_sz) {
		if ((capo = tfw_capolicy_match(loc, arg)))
			return capo->cmd;
	} else {
		TfwVhost *vhost_dflt = vhost->vhost_dflt;
		if (!vhost_dflt)
			return TFW_D_CACHE_BYPASS;

		loc = vhost_dflt->loc_dflt;
		if (loc && loc->capo_sz) {
			if ((capo = tfw_capolicy_match(loc, arg)))
				return capo->cmd;
		}
	}

	return TFW_D_CACHE_BYPASS;
}

/*
 * Decide if the cache can be employed. For a request that means
 * that it can be served from cache if there's a cached response.
 * For a response it means that the response can be stored in cache.
 *
 * Various cache action/control directives are consulted when making
 * the resulting decision.
 */
static bool
tfw_cache_employ_req(TfwHttpReq *req)
{
	int cmd = tfw_cache_policy(req->vhost, req->location, &req->uri_path);

	if (cmd == TFW_D_CACHE_BYPASS) {
		req->cache_ctl.flags |= TFW_HTTP_CC_CFG_CACHE_BYPASS;
		return false;
	}
	/* cache_fulfill - work as usual in cache mode. */
	BUG_ON(cmd != TFW_D_CACHE_FULFILL);

	if (req->cache_ctl.flags & TFW_HTTP_CC_NO_CACHE)
		/*
		 * TODO: RFC 7234 4. "... a cache MUST NOT reuse a stored
		 * response, unless... the request does not contain the no-cache
		 * pragma, nor the no-cache cache directive unless the stored
		 * response is successfully validated."
		 *
		 * We can validate the stored response and serve request from
		 * cache. This reduces traffic to origin server.
		 */
		return false;

	return true;
}

/**
 * Check whether the response status code is defined as cacheable by default
 * by RFC 7231 6.1.
 */
static inline bool
tfw_cache_status_bydef(TfwHttpResp *resp)
{
	/*
	 * TODO: Add 206 (Partial Content) status. Requires support
	 * of incomplete responses, Range: and Content-Range: header
	 * fields, and RANGE request method.
	 */
	switch (resp->status) {
	case 200: case 203: case 204:
	case 300: case 301:
	case 404: case 405: case 410: case 414:
	case 501:
		return true;
	}
	return false;
}

static bool
tfw_cache_employ_resp(TfwHttpResp *resp)
{
	TfwHttpReq *req = resp->req;

#define CC_REQ_DONTCACHE				\
	(TFW_HTTP_CC_CFG_CACHE_BYPASS | TFW_HTTP_CC_NO_STORE)
#define CC_RESP_DONTCACHE				\
	(TFW_HTTP_CC_NO_STORE | TFW_HTTP_CC_PRIVATE	\
	 | TFW_HTTP_CC_NO_CACHE)
#define CC_RESP_CACHEIT					\
	(TFW_HTTP_CC_HDR_EXPIRES | TFW_HTTP_CC_MAX_AGE	\
	 | TFW_HTTP_CC_S_MAXAGE | TFW_HTTP_CC_PUBLIC)
#define CC_RESP_AUTHCAN					\
	(TFW_HTTP_CC_S_MAXAGE | TFW_HTTP_CC_PUBLIC	\
	 | TFW_HTTP_CC_MUST_REVAL | TFW_HTTP_CC_PROXY_REVAL)
	/*
	 * TODO: Response no-cache -- should be cached.
	 * Should turn on unconditional revalidation.
	 */
	if (req->cache_ctl.flags & CC_REQ_DONTCACHE)
		return false;
	if (resp->cache_ctl.flags & CC_RESP_DONTCACHE)
		return false;
	if (!(req->cache_ctl.flags & TFW_HTTP_CC_IS_PRESENT)
	    && (req->cache_ctl.flags & TFW_HTTP_CC_PRAGMA_NO_CACHE))
		return false;
	if (!(resp->cache_ctl.flags & TFW_HTTP_CC_IS_PRESENT)
	    && (resp->cache_ctl.flags & TFW_HTTP_CC_PRAGMA_NO_CACHE))
		return false;
	if ((req->cache_ctl.flags & TFW_HTTP_CC_HDR_AUTHORIZATION)
	    && !(req->cache_ctl.flags & CC_RESP_AUTHCAN))
		return false;
	if (!(resp->cache_ctl.flags & CC_RESP_CACHEIT)
	    && !tfw_cache_status_bydef(resp))
		return false;
#undef CC_RESP_AUTHCAN
#undef CC_RESP_CACHEIT
#undef CC_RESP_DONTCACHE
#undef CC_REQ_DONTCACHE

	return true;
}

/*
 * Calculate freshness lifetime according to RFC 7234 4.2.1.
 */
static time_t
tfw_cache_calc_lifetime(TfwHttpResp *resp)
{
	time_t lifetime;

	if (resp->cache_ctl.flags & TFW_HTTP_CC_S_MAXAGE)
		lifetime = resp->cache_ctl.s_maxage;
	else if (resp->cache_ctl.flags & TFW_HTTP_CC_MAX_AGE)
		lifetime = resp->cache_ctl.max_age;
	else if (resp->cache_ctl.flags & TFW_HTTP_CC_HDR_EXPIRES)
		lifetime = resp->cache_ctl.expires - resp->date;
	else
		/* For now, set "unlimited" lifetime in this case. */
		lifetime = UINT_MAX;	/* TODO: Heuristic lifetime. */

	return lifetime;
}

/*
 * Calculate the current entry age according to RFC 7234 4.2.3.
 */
static time_t
tfw_cache_entry_age(TfwCacheEntry *ce)
{
	time_t apparent_age = max_t(time_t, 0, ce->resp_time - ce->date);
	time_t corrected_age = ce->age + ce->resp_time - ce->req_time;
	time_t initial_age = max(apparent_age, corrected_age);
	return (initial_age + tfw_current_timestamp() - ce->resp_time);
}

/*
 * Given Cache Control arguments in the request and the response,
 * as well as the stored cache entry parameters, determine if the
 * cache entry is live and may be served to a client. For that,
 * the cache entry freshness is calculated according to RFC 7234
 * 4.2, 5.2.1.1, 5.2.1.2, and 5.2.1.3.
 *
 * Returns the value of calculated cache entry lifetime if the entry
 * is live and may be served to a client. Returns zero if the entry
 * may not be served.
 *
 * Note that if the returned value of lifetime is greater than
 * ce->lifetime, then the entry is stale but still may be served
 * to a client, provided that the cache policy allows that.
 */
static time_t
tfw_cache_entry_is_live(TfwHttpReq *req, TfwCacheEntry *ce)
{
	time_t ce_age = tfw_cache_entry_age(ce);
	time_t ce_lifetime, lt_fresh = UINT_MAX;

	if (ce->lifetime <= 0)
		return 0;

#define CC_LIFETIME_FRESH	(TFW_HTTP_CC_MAX_AGE | TFW_HTTP_CC_MIN_FRESH)
	if (req->cache_ctl.flags & CC_LIFETIME_FRESH) {
		time_t lt_max_age = UINT_MAX, lt_min_fresh = UINT_MAX;
		if (req->cache_ctl.flags & TFW_HTTP_CC_MAX_AGE)
			lt_max_age = req->cache_ctl.max_age;
		if (req->cache_ctl.flags & TFW_HTTP_CC_MIN_FRESH)
			lt_min_fresh = ce->lifetime - req->cache_ctl.min_fresh;
		lt_fresh = min(lt_max_age, lt_min_fresh);
	}
	if (!(req->cache_ctl.flags & TFW_HTTP_CC_MAX_STALE)) {
		ce_lifetime = min(lt_fresh, ce->lifetime);
	} else {
		time_t lt_max_stale = ce->lifetime + req->cache_ctl.max_stale;
		ce_lifetime = min(lt_fresh, lt_max_stale);
	}
#undef CC_LIFETIME_FRESH

	return ce_lifetime > ce_age ? ce_lifetime : 0;
}

static bool
tfw_cache_cond_none_match(TfwHttpReq *req, TfwCacheEntry *ce)
{
	TfwStr match_list, iter;

	if (TFW_STR_EMPTY(&ce->etag))
		return true;

	if (req->cond.flags & TFW_HTTP_COND_ETAG_ANY)
		return false;

	match_list = req->h_tbl->tbl[TFW_HTTP_HDR_IF_NONE_MATCH];
	iter = tfw_str_next_str_val(&match_list);

	while (!TFW_STR_EMPTY(&iter)) {
		/* RFC 7232 3.2: Weak validation. Don't check WEAK tagging. */
		if (!tfw_strcmpspn(&iter, &ce->etag, '"'))
			return false;

		iter = tfw_str_next_str_val(&iter);
	}

	return true;
}

/**
 * Add a new header with size of @len starting from @data to HTTP response @resp,
 * expanding the @resp with new skb/frags if needed.
 */
static int
tfw_cache_h2_write(TDB *db, TdbVRec **trec, TfwHttpResp *resp, char **data,
		   size_t len, TfwDecodeCacheIter *dc_iter)
{
	TfwStr c = { 0 };
	TdbVRec *tr = *trec;
	TfwHttpTransIter *mit = &resp->mit;
	TfwMsgIter *it = &mit->iter;
	int r = 0, copied = 0;

	while (1)  {
		c.data = *data;
		c.len = min(tr->data + tr->len - *data, (long)(len - copied));
		if (!dc_iter->skip) {
			r = tfw_http_msg_expand_data(it, &resp->msg.skb_head,
						     &c, &mit->start_off);
			if (unlikely(r))
				break;

			dc_iter->acc_len += c.len;
		}

		copied += c.len;
		*data += c.len;

		T_DBG3("%s: len='%zu', copied='%d', dc_iter->acc_len='%lu',"
		       " dc_iter->skip='%d'\n", __func__, len, copied,
		       dc_iter->acc_len, dc_iter->skip);

		if (copied == len)
			break;

		tr = *trec = tdb_next_rec_chunk(db, tr);
		BUG_ON(!tr);
		*data = tr->data;
	}

	return r;
}

/**
 * Same as @tfw_cache_h2_write(), but also decode the header from HTTP/2 format
 * before writing it into the response (used e.g. for HTTP/1.1-response creation
 * from cache).
 */
static int
tfw_cache_h2_decode_write(TDB *db, TdbVRec **trec, TfwHttpResp *resp,
			  char **data, size_t len, TfwDecodeCacheIter *dc_iter)
{
	unsigned long m_len;
	TdbVRec *tr = *trec;
	int r = 0, acc = 0;
	TfwHPack hp = {};

	while (1)  {
		m_len = min(tr->data + tr->len - *data, (long)(len - acc));
		if (!dc_iter->skip) {
			r = tfw_hpack_cache_decode_expand(&hp, resp, *data,
							  m_len, dc_iter);
			if (unlikely(r))
				break;
		}

		acc += m_len;
		*data += m_len;
		if (acc == len) {
			bzero_fast(dc_iter->__off,
				   sizeof(*dc_iter)
				   - offsetof(TfwDecodeCacheIter, __off));
			break;
		}

		tr = *trec = tdb_next_rec_chunk(db, tr);
		BUG_ON(!tr);
		*data = tr->data;
	}

	return r;
}

static int
tfw_cache_set_status(TDB *db, TfwCacheEntry *ce, TfwHttpResp *resp,
		     TdbVRec **trec, char **p, unsigned long *acc_len)
{
	int r;
	TfwMsgIter *it = &resp->mit.iter;
	struct sk_buff **skb_head = &resp->msg.skb_head;
	bool h2_mode = TFW_MSG_H2(resp->req);
	TfwDecodeCacheIter dc_iter = {};

	if (h2_mode)
		resp->mit.start_off = FRAME_HEADER_SIZE;
	else
		dc_iter.skip = true;


	r = tfw_cache_h2_write(db, trec, resp, p, ce->status_len, &dc_iter);
	if (unlikely(r))
		return r;

	if (!h2_mode) {
		char buf[H2_STAT_VAL_LEN];
		TfwStr s_line = {
			.chunks = (TfwStr []){
				{ .data = S_0, .len = SLEN(S_0) },
				{ .data = buf, .len =  H2_STAT_VAL_LEN}
			},
			.len = SLEN(S_0) + H2_STAT_VAL_LEN,
			.nchunks = 2
		};

		if (!tfw_ultoa(ce->resp_status, __TFW_STR_CH(&s_line, 1)->data,
			       H2_STAT_VAL_LEN))
			return -E2BIG;

		r = tfw_http_msg_expand_data(it, skb_head, &s_line, NULL);
		if (unlikely(r))
			return r;

		*acc_len += s_line.len;
	}

	dc_iter.skip = h2_mode ? true : false;

	r = tfw_cache_h2_write(db, trec, resp, p, ce->rph_len, &dc_iter);
	if (unlikely(r))
		return r;

	*acc_len += dc_iter.acc_len;

	if (!h2_mode) {
		r = tfw_http_msg_expand_data(it, skb_head, &g_crlf, NULL);
		if (unlikely(r))
			return r;

		*acc_len += g_crlf.len;
	}

	return 0;
}

/**
 * Write HTTP header to skb data.
 */
static int
tfw_cache_build_resp_hdr(TDB *db, TfwHttpResp *resp, TfwHdrMods *hmods,
			 TdbVRec **trec, char **p, unsigned long *acc_len,
			 bool skip)
{
	tfw_cache_write_actor_t *write_actor;
	TfwCStr *s = (TfwCStr *)*p;
	TfwHttpReq *req = resp->req;
	TfwDecodeCacheIter dc_iter = { .h_mods = hmods, .skip = skip};
	int d, dn, r = 0;

	BUG_ON(!req);

	write_actor = !TFW_MSG_H2(req) || dc_iter.h_mods
		? tfw_cache_h2_decode_write
		: tfw_cache_h2_write;

	*p += TFW_CSTR_HDRLEN;
	BUG_ON(*p > (*trec)->data + (*trec)->len);

	if (likely(!(s->flags & TFW_STR_DUPLICATE))) {
		r = write_actor(db, trec, resp, p, s->len, &dc_iter);
		if (likely(!r))
			*acc_len += dc_iter.acc_len;
		return r;
	}

	/* Process duplicated headers. */
	dn = s->len;
	for (d = 0; d < dn; ++d) {
		s = (TfwCStr *)*p;
		BUG_ON(s->flags);
		*p += TFW_CSTR_HDRLEN;
		r = write_actor(db, trec, resp, p, s->len, &dc_iter);
		if (unlikely(r))
			break;
	}
	*acc_len += dc_iter.acc_len;

	return r;
}

/**
 * RFC 7232 Section-4.1: The server generating a 304 response MUST generate:
 * Cache-Control, Content-Location, Date, ETag, Expires, and Vary.
 * Last-Modified might be used if the response does not have an ETag field.
 *
 * The 304 response should be as short as possible, we don't need to add
 * extra headers.
 */
static void
tfw_cache_send_304(TfwHttpReq *req, TfwCacheEntry *ce)
{
	char *p;
	int r, i;
	TfwMsgIter *it;
	TfwHttpResp *resp;
	struct sk_buff **skb_head;
	unsigned int stream_id = 0;
	unsigned long h_len = 0;
	TdbVRec *trec = &ce->trec;
	TDB *db = node_db();

	WARN_ON_ONCE(!list_empty(&req->fwd_list));
	WARN_ON_ONCE(!list_empty(&req->nip_list));

	if (!(resp = tfw_http_msg_alloc_resp_light(req)))
		goto err_create;

	it = &resp->mit.iter;
	skb_head = &resp->msg.skb_head;

	if (!TFW_MSG_H2(req)) {
		r = tfw_http_prep_304(req, skb_head, it);
		if (unlikely(r))
			goto err_setup;
	} else {
		stream_id = tfw_h2_stream_id_close(req, HTTP2_HEADERS,
						   HTTP2_F_END_STREAM);
		if (unlikely(!stream_id))
			goto err_setup;

		resp->mit.start_off = FRAME_HEADER_SIZE;

		r = tfw_h2_resp_status_write(resp, 304, TFW_H2_TRANS_EXPAND,
					     true);
		if (unlikely(r))
			goto err_setup;
	}

	/* Put 304 headers */
	for (i = 0; i < ARRAY_SIZE(ce->hdrs_304); ++i) {
		if (!ce->hdrs_304[i])
			continue;

		p = TDB_PTR(db->hdr, ce->hdrs_304[i]);
		while (trec && (p > trec->data + trec->len))
			trec = tdb_next_rec_chunk(db, trec);
		BUG_ON(!trec);

		if (tfw_cache_build_resp_hdr(db, resp, NULL, &trec, &p, &h_len,
					     false))
		{
			goto err_setup;
		}
	}

	if (!TFW_MSG_H2(req)) {
		if (tfw_http_msg_expand_data(it, skb_head, &g_crlf, NULL))
			goto err_setup;

		tfw_http_resp_fwd(resp);

		return;
	}

	if (tfw_h2_frame_local_resp(resp, stream_id, h_len, NULL))
		goto err_setup;

	tfw_h2_resp_fwd(resp);

	return;
err_setup:
	T_WARN("Can't build 304 response, key=%lx\n", ce->key);
	tfw_http_msg_free((TfwHttpMsg *)resp);
err_create:
	tfw_http_resp_build_error(req);
}

/**
 * Received request can contain validation information. Process it according to
 * RFC 7234 Section 4.3.2.
 *
 * Return value:
 *	@true: @req can be served from cache;
 *	@false: Response was sent to client (412 or 304).
 */
static bool
tfw_handle_validation_req(TfwHttpReq *req, TfwCacheEntry *ce)
{
	if ((ce->resp_status != 200) && (ce->resp_status != 206))
		return true;
	/* RFC 7232 Section 5. */
	/* TODO: Add CONNECT */
	if ((req->method == TFW_HTTP_METH_OPTIONS)
	    || (req->method == TFW_HTTP_METH_TRACE))
		return true;

	/* If-None-Match: */
	if (!TFW_STR_EMPTY(&req->h_tbl->tbl[TFW_HTTP_HDR_IF_NONE_MATCH])) {
		if (!tfw_cache_cond_none_match(req, ce)) {
			if ((req->method == TFW_HTTP_METH_GET)
			    || (req->method == TFW_HTTP_METH_HEAD))
				tfw_cache_send_304(req, ce);
			else
				tfw_http_send_resp(req, 412,
						   "request validation: "
						   "precondition failed");

			return false;
		}
	}
	/* If-Modified-Since: */
	else if (req->cond.m_date
		 && ((req->method == TFW_HTTP_METH_GET)
		     || (req->method == TFW_HTTP_METH_HEAD)))
	{
		bool send_304 = false;

		if (ce->last_modified) {
			if (ce->last_modified <= req->cond.m_date)
				send_304 = true;
		}
		else if (ce->date) {
			if (ce->date <= req->cond.m_date)
				send_304 = true;
		}
		else {
			if (ce->resp_time <= req->cond.m_date)
				send_304 = true;
		}

		if (send_304) {
			tfw_cache_send_304(req, ce);
			return false;
		}
	}
	/* TODO #499: Range GET requests. RFC 7232 Section 6, step 5. */

	return true;
}

static bool
tfw_cache_entry_key_eq(TDB *db, TfwHttpReq *req, TfwCacheEntry *ce)
{
	/* Record key starts at first data chunk. */
	int n, c_off = 0, t_off;
	TdbVRec *trec = &ce->trec;
	TfwStr *c, *h_start, *u_end, *h_end;
	TfwStr host_val, *host = &req->h_tbl->tbl[TFW_HTTP_HDR_HOST];

	if ((req->method != TFW_HTTP_METH_PURGE) && (ce->method != req->method))
		return false;

	/*
	 * Get 'host' header value (from HTTP/2 or HTTP/1.1 request) for
	 * strict comparison.
	 */
	tfw_http_msg_clnthdr_val(req, host, TFW_HTTP_HDR_HOST, &host_val);

	if (req->uri_path.len + host_val.len != ce->key_len)
		return false;

	t_off = CE_BODY_SIZE;
	TFW_CACHE_REQ_KEYITER(c, &req->uri_path, &host_val, u_end, h_start,
			      h_end)
	{
		if (!trec)
			return false;
this_chunk:
		n = min(c->len - c_off, (unsigned long)trec->len - t_off);
		/* Cache key is stored in lower case. */
		if (tfw_cstricmp_2lc(c->data + c_off, trec->data + t_off, n))
			return false;
		c_off = (n == c->len - c_off) ? 0 : c_off + n;
		if (n == trec->len - t_off) {
			t_off = 0;
			trec = tdb_next_rec_chunk(db, trec);
			if (trec && c_off)
				goto this_chunk;
		} else {
			t_off += n;
		}
	}

	return true;
}

static TfwCacheEntry *
tfw_cache_dbce_get(TDB *db, TdbIter *iter, TfwHttpReq *req)
{
	TfwCacheEntry *ce;
	unsigned long key = tfw_http_req_key_calc(req);

	*iter = tdb_rec_get(db, key);
	if (TDB_ITER_BAD(*iter)) {
		TFW_INC_STAT_BH(cache.misses);
		return NULL;
	}
	/*
	 * Cache may store one or more responses to the effective Request URI.
	 * Basically, it is sufficient to store only the most recent response and
	 * remove other representations from cache. (RFC 7234 4: When more than
	 * one suitable response is stored, a cache MUST use the most recent
	 * response) But there are still some cases when it is needed to store
	 * more than one representation:
	 *   - If selected representation of the effective Request URI depends
	 *     on client capabilities. See RFC 7234 4.1 (Vary Header).
	 *   - If origin server has several states of the resource, so during
	 *     revalidation we can get the current state without downloading the
	 *     full representation. This can reduce traffic to origin server.
	 *     See RFC 7323 2.1 for the example.
	 *
	 * TODO: tfw_cache_entry_key_eq() should be extended to support
	 * secondary keys (#508) and to skip not current representations.
	 * Currently this function is used in two cases: to serve client and to
	 * invalidate all cached responses (purge method).
	 */
	ce = (TfwCacheEntry *)iter->rec;
	do {
		/*
		 * Basically we don't need to compare keys if only one record
		 * is in the bucket. Checking for next record instead of
		 * comparing the keys would has sense for long URI, but
		 * performance benchmarks don't show any improvement.
		 */
		if (tfw_cache_entry_key_eq(db, req, ce))
			break;
		tdb_rec_next(db, iter);
		if (!(ce = (TfwCacheEntry *)iter->rec)) {
			TFW_INC_STAT_BH(cache.misses);
			return NULL;
		}
	} while (true);

	return ce;
}

static inline void
tfw_cache_dbce_put(TfwCacheEntry *ce)
{
	if (ce)
		tdb_rec_put(ce);
}

/**
 * Copies plain TfwStr @src to TdbRec @trec.
 * @return number of copied bytes (@src length).
 *
 * The function copies part of some large data of length @tot_len,
 * so it tries to minimize total number of allocations regardless
 * how many chunks are copied.
 */
static long
__tfw_cache_strcpy(char **p, TdbVRec **trec, TfwStr *src, size_t tot_len,
		   void cpy(void *dest, const void *src, size_t n))
{
	long copied = 0;

	while (copied < src->len) {
		int room = (*trec)->data + (*trec)->len - *p;
		BUG_ON(room < 0);
		if (!room) {
			BUG_ON(tot_len < copied);
			*trec = tdb_entry_add(node_db(), *trec,
					      tot_len - copied);
			if (!*trec)
				return -ENOMEM;
			*p = (*trec)->data;
			room = (*trec)->len;
		}

		T_DBG3("Cache: copy [%.*s](%lu) to rec=%p(len=%u, next=%u),"
		       " p=%p tot_len=%lu room=%d copied=%ld\n",
		       PR_TFW_STR(src), src->len, *trec, (*trec)->len,
		       (*trec)->chunk_next, *p, tot_len, room, copied);

		room = min((unsigned long)room, src->len - copied);
		cpy(*p, src->data + copied, room);
		*p += room;
		copied += room;
	}

	return copied;
}

/**
 * We need the function wrapper if memcpy() is defined as __inline_memcpy().
 */
static void
__tfw_memcpy(void *dst ,const void *src, size_t n)
{
	memcpy_fast(dst, src, n);
}

static inline long
tfw_cache_strcpy(char **p, TdbVRec **trec, TfwStr *src, size_t tot_len)
{
	return __tfw_cache_strcpy(p, trec, src, tot_len, __tfw_memcpy);
}

/**
 * The same as tfw_cache_strcpy(), but copies @src with lower case conversion.
 */
static inline long
tfw_cache_strcpy_lc(char **p, TdbVRec **trec, TfwStr *src, size_t tot_len)
{
	return __tfw_cache_strcpy(p, trec, src, tot_len, tfw_cstrtolower);
}

#define CSTR_MOVE_HDR()				\
do {						\
	cs = (TfwCStr *)*p;			\
	*p += TFW_CSTR_HDRLEN;			\
	*tot_len -= TFW_CSTR_HDRLEN;		\
	ce->hdr_len += TFW_CSTR_HDRLEN;		\
} while (0)

#define CSTR_WRITE_HDR(f, l)			\
do {						\
	cs->flags = f;				\
	cs->len = l;				\
} while (0)

/**
 * Copies plain or compound (chunked) TfwStr @src to TdbRec @trec.
 *
 * @src is copied
 * @return number of copied bytes on success and negative value otherwise.
 */
static int
tfw_cache_h2_copy_str_common(unsigned int *acc_len, char **p, TdbVRec **trec,
                             TfwStr *src, size_t *tot_len,
                             long cache_strcpy(char **p, TdbVRec **trec,
                                               TfwStr *src, size_t tot_len))
{
	long n;
	TfwStr *c, *end;

	BUG_ON(TFW_STR_DUP(src));

	if (unlikely(!src->len))
		return 0;

	TFW_STR_FOR_EACH_CHUNK(c, src, end) {
		if ((n = cache_strcpy(p, trec, c, *tot_len)) < 0) {
			T_ERR("Cache: cannot copy chunk of HTTP/2 string\n");
			return -ENOMEM;
		}

		*tot_len -= n;
		*acc_len += n;
	}

	return 0;
}

static int
tfw_cache_h2_copy_str(unsigned int *acc_len, char **p, TdbVRec **trec,
                      TfwStr *src, size_t *tot_len)
{
	return tfw_cache_h2_copy_str_common(acc_len, p, trec, src, tot_len,
	                                    tfw_cache_strcpy);
}

static int
tfw_cache_h2_copy_str_lc(unsigned int *acc_len, char **p, TdbVRec **trec,
                         TfwStr *src, size_t *tot_len)
{
	return tfw_cache_h2_copy_str_common(acc_len, p, trec, src, tot_len,
	                                    tfw_cache_strcpy_lc);
}

static inline int
tfw_cache_h2_copy_int(unsigned int *acc_len, unsigned long src,
		      unsigned short max, char **p, TdbVRec **trec,
		      size_t *tot_len)
{
	int r;
	TfwHPackInt hp_int;
	TfwStr str = {};

	write_int(src, max, 0, &hp_int);

	str.data = hp_int.buf;
	str.len = hp_int.sz;

	if ((r = tfw_cache_h2_copy_str(acc_len, p, trec, &str, tot_len)))
		return r;

	return 0;
}

/**
 * Deep HTTP header copy to TdbRec.
 * @hdr is copied in depth first fashion to speed up upcoming scans.
 * @return number of copied bytes on success and negative value otherwise.
 */
static long
tfw_cache_h2_copy_hdr(TfwCacheEntry *ce, char **p, TdbVRec **trec, TfwStr *hdr,
		      size_t *tot_len)
{
	TfwCStr *cs;
	long n = sizeof(TfwCStr);
	unsigned short st_index = 0;
	bool dupl = TFW_STR_DUP(hdr);
	unsigned int init_len = ce->hdr_len;
	TfwStr s_nm, s_val, *dup, *dup_end;

	T_DBG3("%s: ce=[%p] p=[%p], trec=[%p], tot_len='%zu'\n", __func__, ce,
	       *p, *trec, *tot_len);

	if (likely(!dupl)) {
		unsigned long h_len;

		TFW_STR_INIT(&s_nm);
		TFW_STR_INIT(&s_val);
		tfw_http_hdr_split(hdr, &s_nm, &s_val, true);

		st_index = hdr->hpack_idx;
		h_len = tfw_h2_hdr_size(s_nm.len, s_val.len, st_index);

		/* Don't split short strings. */
		if (sizeof(TfwCStr) + h_len <= L1_CACHE_BYTES)
			n += h_len;
	}

	*p = tdb_entry_get_room(node_db(), trec, *p, n, *tot_len);
	if (unlikely(!*p)) {
		T_WARN("Cache: cannot allocate TDB space\n");
		return -ENOMEM;
	}

	if (TFW_STR_DUP(hdr)) {
		CSTR_MOVE_HDR();
		CSTR_WRITE_HDR(TFW_STR_DUPLICATE, hdr->nchunks);
	}

	TFW_STR_FOR_EACH_DUP(dup, hdr, dup_end) {
		unsigned int prev_len;

		if (dupl) {
			TFW_STR_INIT(&s_nm);
			TFW_STR_INIT(&s_val);
			tfw_http_hdr_split(dup, &s_nm, &s_val, true);
			st_index = dup->hpack_idx;
		}
		CSTR_MOVE_HDR();
		prev_len = ce->hdr_len;

		if (st_index) {
			if (tfw_cache_h2_copy_int(&ce->hdr_len, st_index, 0xF,
						  p, trec, tot_len))
				return -ENOMEM;
		}
		else {
			if (tfw_cache_h2_copy_int(&ce->hdr_len, 0, 0xF, p, trec,
						  tot_len)
			    || tfw_cache_h2_copy_int(&ce->hdr_len, s_nm.len,
						     0x7f, p, trec, tot_len)
			    || tfw_cache_h2_copy_str_lc(&ce->hdr_len, p, trec,
			                                &s_nm, tot_len))
				return -ENOMEM;
		}

		if (tfw_cache_h2_copy_int(&ce->hdr_len, s_val.len, 0x7f, p,
					  trec, tot_len)
		    || tfw_cache_h2_copy_str(&ce->hdr_len, p, trec, &s_val,
					     tot_len))
			return -ENOMEM;

		CSTR_WRITE_HDR(0, ce->hdr_len - prev_len);
	}

	T_DBG3("%s: p=[%p], trec=[%p], ce->hdr_len='%u', tot_len='%zu'\n",
	       __func__, *p, *trec, ce->hdr_len, *tot_len);

	return ce->hdr_len - init_len;
}

static long
tfw_cache_h2_add_hdr(TfwCacheEntry *ce, char **p, TdbVRec **trec,
		     unsigned short st_idx, TfwStr *val, size_t *tot_len)
{
	TfwCStr *cs;
	unsigned long len;
	unsigned int prev_len = ce->hdr_len;
	long n = TFW_CSTR_HDRLEN;

	BUG_ON(!st_idx || TFW_STR_EMPTY(val));

	len = tfw_hpack_int_size(st_idx, 0xF)
		+ tfw_hpack_int_size(val->len, 0x7F)
		+ val->len;

	if (unlikely(len >= TFW_CSTR_MAXLEN)) {
		T_WARN("Cache: trying to store too big string %lx\n", len);
		return -E2BIG;
	}

	/* Don't split short strings. */
	if (TFW_CSTR_HDRLEN + len <= L1_CACHE_BYTES)
		n += len;

	*p = tdb_entry_get_room(node_db(), trec, *p, n, *tot_len);
	if (unlikely(!*p)) {
		T_WARN("jCache: cannot allocate TDB space\n");
		return -ENOMEM;
	}

	CSTR_MOVE_HDR();

	if (tfw_cache_h2_copy_int(&ce->hdr_len, st_idx, 0xF, p, trec, tot_len))
		return -ENOMEM;

	if (tfw_cache_h2_copy_int(&ce->hdr_len, val->len, 0x7f, p, trec,
				  tot_len))
		return -ENOMEM;

	if (tfw_cache_h2_copy_str(&ce->hdr_len, p, trec, val, tot_len))
		return -ENOMEM;

	CSTR_WRITE_HDR(0, ce->hdr_len - prev_len - TFW_CSTR_HDRLEN);

	return ce->hdr_len - prev_len;
}

/**
 * Fill @ce->etag with entity-tag value. RFC 7232 Section-2.3 doesn't limit
 * etag size, so can't just have a copy of entity-tag value somewhere in @ce,
 * instead fill @ce->etag TfwStr to correct offset in @ce->hdrs. Also set
 * WEAK tag to the first chunk of @ce->etag if applied. This is needed for Range
 * requests.
 *
 * @h_off, @h_trec	- supposed offset and record of stored 'ETag:' header;
 * @curr_p, @curr_rec	- used to store compound @ce->etag.
 */
static int
__set_etag(TfwCacheEntry *ce, TfwHttpResp *resp, long h_off, TdbVRec *h_trec,
	   char *curr_p, TdbVRec **curr_trec)
{
	char *e_p;
	size_t c_size;
	TDB *db = node_db();
	size_t len = 0;
	unsigned short flags = 0;
	TfwStr h_val, *c, *end, *h = &resp->h_tbl->tbl[TFW_HTTP_HDR_ETAG];
	TfwStr s_dummy = {}, s_val = {};

#define CHECK_REC_SPACE()						\
	while (c_size) {						\
		size_t tail = h_trec->len - (e_p - h_trec->data);	\
		if (c_size > tail) {					\
			c_size -= tail;					\
			h_trec = tdb_next_rec_chunk(db, h_trec);	\
			e_p = h_trec->data;				\
		} else {						\
			e_p += c_size;					\
			c_size = 0;					\
		}							\
	}

	if (TFW_STR_EMPTY(h))
		return 0;

	tfw_http_msg_srvhdr_val(h, TFW_HTTP_HDR_ETAG, &h_val);

	/* Update supposed Etag offset to real value. */
	/* FIXME: #803 */
	e_p = TDB_PTR(db->hdr, h_off);
	if (e_p + TFW_CSTR_HDRLEN > h_trec->data + h_trec->len) {
		h_trec = tdb_next_rec_chunk(db, h_trec);
		e_p = h_trec->data;
	}
	/*
	 * Skip anything that is not etag value. Note, since headers are
	 * stored in cache in HTTP/2 representation (and the name of 'etag'
	 * header is always statically indexed), we should also skip index
	 * and value length fields; the 'etag' header has the 34 index in
	 * HPACK static table, thus we definitely now here, that it will
	 * occupy 2 bytes (RFC 7541 section 6.2.2).
	 */
	e_p += TFW_CSTR_HDRLEN;
	tfw_http_hdr_split(h, &s_dummy, &s_val, true);
	c_size = 2 + tfw_hpack_int_size(s_val.len, 0x7F);
	CHECK_REC_SPACE();
	TFW_STR_FOR_EACH_CHUNK(c, &h_val, end) {
		if (c->flags & TFW_STR_VALUE) {
			flags = c->flags;
			break;
		}
		c_size = c->len;
		CHECK_REC_SPACE();
	}
	for ( ; (c < end) && (c->flags & TFW_STR_VALUE); ++c)
		len += c->len;

	/* Create TfWStr that contains only entity-tag value. */
	ce->etag.data = e_p;
	ce->etag.flags = flags;
	ce->etag.len = min(len, (size_t)(h_trec->len -
					 (e_p - h_trec->data)));
	len -= ce->etag.len;

	while (len) {
		h_trec = tdb_next_rec_chunk(db, h_trec);
		e_p = h_trec->data;
		c = tfw_str_add_compound(resp->pool, &ce->etag);
		if (!c)
			return -ENOMEM;
		c->data = e_p;
		c->len = min(len, (size_t)(h_trec->len -
					   (e_p - h_trec->data)));
		len -= c->len;
	}

	/* Compound string was allocated in resp->pool, move to cache entry. */
	if (!TFW_STR_PLAIN(&ce->etag)) {
		len = sizeof(TfwStr *) * ce->etag.nchunks;
		curr_p = tdb_entry_get_room(node_db(), curr_trec, curr_p, len,
					    len);
		if (!curr_p)
			return -ENOMEM;
		memcpy_fast(curr_p, ce->etag.data, len);
		ce->etag.data = curr_p;
		/* Old ce->etag.data will be destroyed with resp. */
	}

	return 0;

#undef CHECK_REC_SPACE
}

/**
 * Check if the header @hdr must be present in 304 response. If yes save its
 * offset in cache entry @ce for fast creation of 304 response in
 * tfw_cahe_send_304().
 */
static bool
__save_hdr_304_off(TfwCacheEntry *ce, TfwHttpResp *resp, TfwStr *hdr, long off)
{
	int i;
	unsigned int num;
	const TfwStr *match;

	if (TFW_STR_EMPTY(hdr))
		return false;

	num = hdr - resp->h_tbl->tbl;
	if (num < TFW_HTTP_HDR_RAW) {
		if (!tfw_cache_spec_headers_304[num])
			return false;

		for (i = 0; ce->hdrs_304[i]; ++i)
			;
		ce->hdrs_304[i] = off;
		return true;
	}

	match = tfw_http_msg_find_hdr(hdr, tfw_cache_raw_headers_304);
	if (match) {
		unsigned char sc = *(unsigned char *)match->data;

		/* RFC 7234 4.1: Don't send Last-Modified if ETag is present. */
		 if ((sc == 'l')
		     && !TFW_STR_EMPTY(&resp->h_tbl->tbl[TFW_HTTP_HDR_ETAG]))
			return false;

		i = match - tfw_cache_raw_headers_304;
		ce->hdrs_304[i + TFW_CACHE_304_SPEC_HDRS_NUM] = off;
		return true;
	}

	return false;
}

/**
 * Copy response skbs to database mapped area.
 * @tot_len	- total length of actual data to write w/o TfwCStr's etc;
 * @rph		- response reason-phrase to be saved in the cache.
 *
 * It's nasty to copy data on CPU, but we can't use DMA for mmaped file
 * as well as for unaligned memory areas.
 */
static int
tfw_cache_copy_resp(TfwCacheEntry *ce, TfwHttpResp *resp, TfwStr *rph,
		    size_t tot_len)
{
	int r, i;
	char *p;
	unsigned short status_idx;
	TfwStr *field, *h, *end1, *end2;
	TDB *db = node_db();
	TdbVRec *trec = &ce->trec, *etag_trec = NULL;
	long n, etag_off = 0;
	TfwHttpReq *req = resp->req;
	TfwGlobal *g_vhost = tfw_vhost_get_global();
	TfwStr h_val, *host = &req->h_tbl->tbl[TFW_HTTP_HDR_HOST];
	TfwStr val_srv = TFW_STR_STRING(TFW_SERVER);
	TfwStr val_via = {
		.chunks = (TfwStr []) {
			{ .data = S_VIA_H2_PROTO, .len = SLEN(S_VIA_H2_PROTO) },
			{ .data = *this_cpu_ptr(&g_c_buf),
			  .len = g_vhost->hdr_via_len },
		},
		.len = SLEN(S_VIA_H2_PROTO) + g_vhost->hdr_via_len,
		.nchunks = 2
	};

	p = (char *)(ce + 1);
	tot_len -= CE_BODY_SIZE;

	/* Write record key (URI + Host header). */
	ce->key = TDB_OFF(db->hdr, p);
	ce->key_len = 0;

	/*
	 * Get 'host' header value (from HTTP/2 or HTTP/1.1 request) for
	 * strict comparison.
	 */
	tfw_http_msg_clnthdr_val(req, host, TFW_HTTP_HDR_HOST, &h_val);
	TFW_CACHE_REQ_KEYITER(field, &req->uri_path, &h_val, end1, h, end2) {
		if ((n = tfw_cache_strcpy_lc(&p, &trec, field, tot_len)) < 0) {
			T_ERR("Cache: cannot copy request key\n");
			return -ENOMEM;
		}
		BUG_ON(n > tot_len);
		tot_len -= n;
		ce->key_len += n;
	}

	/* Request method is a part of the cache record key. */
	ce->method = req->method;

	/* Write ':status' pseudo-header. */
	ce->status = TDB_OFF(db->hdr, p);
	status_idx = tfw_h2_pseudo_index(resp->status);
	if (status_idx) {
		TfwHPackInt hp_idx;
		TfwStr str = {};

		write_int(status_idx, 0x7F, 0x80, &hp_idx);
		str.data = hp_idx.buf;
		str.len = hp_idx.sz;

		if (tfw_cache_h2_copy_str(&ce->status_len, &p, &trec, &str,
					  &tot_len))
			return -ENOMEM;
	} else {
		char buf[H2_STAT_VAL_LEN];
		TfwStr str = {
			.data = buf,
			.len = H2_STAT_VAL_LEN
		};

		/*
		 * If the ':status' pseudo-header is not fully indexed, set
		 * the default static index (8) just for the name.
		 */
		if (tfw_cache_h2_copy_int(&ce->status_len, 8, 0xF, &p, &trec,
					  &tot_len)
		    || tfw_cache_h2_copy_int(&ce->status_len, H2_STAT_VAL_LEN,
					     0x7f, &p, &trec, &tot_len))
			return -ENOMEM;

		if (!tfw_ultoa(resp->status, str.data, H2_STAT_VAL_LEN))
			return -E2BIG;

		if (tfw_cache_h2_copy_str(&ce->status_len, &p, &trec, &str,
					  &tot_len))
			return -ENOMEM;
	}

	if (tfw_cache_h2_copy_str(&ce->rph_len, &p, &trec, rph, &tot_len))
		return -ENOMEM;

	ce->hdrs = TDB_OFF(db->hdr, p);
	ce->hdr_len = 0;
	ce->hdr_num = resp->h_tbl->off;
	FOR_EACH_HDR_FIELD_FROM(field, end1, resp, TFW_HTTP_HDR_REGULAR) {
		int hid = field - resp->h_tbl->tbl;
		/*
		 * Skip hop-by-hop headers. Also skip 'Server' header (with
		 * possible duplicates), since we will substitute it with our
		 * version of this header.
		 */
		if ((field->flags & TFW_STR_HBH_HDR)
		    || hid == TFW_HTTP_HDR_SERVER
		    || TFW_STR_EMPTY(field))
		{
			--ce->hdr_num;
			continue;
		}

		if (hid == TFW_HTTP_HDR_ETAG) {
			/* Must be updated after tfw_cache_h2_copy_hdr(). */
			etag_off = TDB_OFF(db->hdr, p);
			etag_trec = trec;
		}

		__save_hdr_304_off(ce, resp, field, TDB_OFF(db->hdr, p));

		n = tfw_cache_h2_copy_hdr(ce, &p, &trec, field, &tot_len);
		if (unlikely(n < 0))
			return n;
	}

	/* Add 'server' header. */
	n = tfw_cache_h2_add_hdr(ce, &p, &trec, 54, &val_srv, &tot_len);
	if (unlikely(n < 0))
		return n;

	/* Headers added only for h2 responses. */
	/* Add 'via' header. */
	memcpy_fast(__TFW_STR_CH(&val_via, 1)->data, g_vhost->hdr_via,
		    g_vhost->hdr_via_len);
	n = tfw_cache_h2_add_hdr(ce, &p, &trec, 60, &val_via, &tot_len);
	if (unlikely(n < 0))
		return n;

	ce->hdr_h2_off = ce->hdr_num + 1;
	ce->hdr_num += 2;

	/* Write HTTP response body. */
	ce->body = TDB_OFF(db->hdr, p);
	r = tfw_cache_h2_copy_str(&ce->body_len, &p, &trec, &resp->body,
				  &tot_len);
	if (unlikely(r)) {
		T_ERR("Cache: cannot copy HTTP body\n");
		return -ENOMEM;
	}

	if (WARN_ON_ONCE(tot_len != 0))
		return -EINVAL;

	ce->version = resp->version;
	tfw_http_copy_flags(ce->hmflags, resp->flags);

	if (resp->cache_ctl.flags
	    & (TFW_HTTP_CC_MUST_REVAL | TFW_HTTP_CC_PROXY_REVAL))
		ce->flags |= TFW_CE_MUST_REVAL;
	ce->date = resp->date;
	ce->age = resp->cache_ctl.age;
	ce->req_time = req->cache_ctl.timestamp;
	ce->resp_time = resp->cache_ctl.timestamp;
	ce->lifetime = tfw_cache_calc_lifetime(resp);
	ce->last_modified = resp->last_modified;
	ce->resp_status = resp->status;

	if ((r = __set_etag(ce, resp, etag_off, etag_trec, p, &trec))) {
		T_ERR("Cache: cannot copy entity-tag\n");
		return r;
	}

	/* Update offsets of 304 headers to real values */
	/* FIXME: #803 */
	trec = &ce->trec;
	for (i = 0; i < ARRAY_SIZE(ce->hdrs_304); ++i) {
		if (!ce->hdrs_304[i])
			continue;

		p = TDB_PTR(db->hdr, ce->hdrs_304[i]);
		while (trec && (p + TFW_CSTR_HDRLEN > trec->data + trec->len)) {
			trec = tdb_next_rec_chunk(db, trec);
		}
		BUG_ON(!trec);

		ce->hdrs_304[i] = TDB_OFF(db->hdr, p);
	}

	T_DBG("Cache copied msg: content-length=%lu msg_len=%lu, ce=%p"
	      " (len=%u key_len=%u status_len=%u hdr_num=%u hdr_len=%u"
	      " key_off=%ld status_off=%ld hdrs_off=%ld body_off=%ld)\n",
	      resp->content_length, resp->msg.len, ce, ce->trec.len,
	      ce->key_len, ce->status_len, ce->hdr_num, ce->hdr_len,
	      ce->key, ce->status, ce->hdrs, ce->body);

	return 0;
}

static long
__cache_entry_size(TfwHttpResp *resp)
{
	TfwStr host_val, *hdr, *hdr_end;
	TfwHttpReq *req = resp->req;
	long size, res_size = CE_BODY_SIZE;
	TfwStr *host = &req->h_tbl->tbl[TFW_HTTP_HDR_HOST];
	unsigned long via_sz = SLEN(S_VIA_H2_PROTO)
		+ tfw_vhost_get_global()->hdr_via_len;

	/* Add compound key size */
	res_size += req->uri_path.len;
	tfw_http_msg_clnthdr_val(req, host, TFW_HTTP_HDR_HOST, &host_val);
	res_size += host_val.len;

	/*
	 * Add the length of ':status' pseudo-header: one byte if fully indexed,
	 * or five bytes (one byte for name index, one for status code length
	 * and three for status code itself) if only name is indexed.
	 */
	++res_size;
	res_size += (1 + H2_STAT_VAL_LEN) * !tfw_h2_pseudo_index(resp->status);

	/* Add all the headers size */
	FOR_EACH_HDR_FIELD_FROM(hdr, hdr_end, resp, TFW_HTTP_HDR_REGULAR) {
		TfwStr *d, *d_end;
		int hid = hdr - resp->h_tbl->tbl;
		/*
		 * Skip hop-by-hop headers. Also skip 'Server' header (with
		 * possible duplicates), since we will substitute it with our
		 * version of this header.
		 */
		if ((hdr->flags & TFW_STR_HBH_HDR)
		    || hid == TFW_HTTP_HDR_SERVER
		    || TFW_STR_EMPTY(hdr))
			continue;

		size = sizeof(TfwCStr);

		if (!TFW_STR_DUP(hdr)) {
			TfwStr s_nm = {}, s_val = {};

			tfw_http_hdr_split(hdr, &s_nm, &s_val, true);
			size += tfw_h2_hdr_size(s_nm.len, s_val.len,
						hdr->hpack_idx);
		} else {
			TFW_STR_FOR_EACH_DUP(d, hdr, d_end) {
				TfwStr s_nm = {}, s_val = {};

				size += sizeof(TfwCStr);
				tfw_http_hdr_split(d, &s_nm, &s_val, true);
				size += tfw_h2_hdr_size(s_nm.len, s_val.len,
							d->hpack_idx);
			}
		}

		if (unlikely(size >= TFW_CSTR_MAXLEN))
			goto err;
		res_size += size;
	}

	/*
	 * Add the length of our version of 'Server' header and 'Via' header.
	 * Note, that we need two bytes for static index, since in the first
	 * byte we have only four available bits for the index (we do not use
	 * dynamic indexing during headers storing into the cache, thus `without
	 * indexing` code must be set in the first index byte, see RFC 7541
	 * section 6.2.2 for details), and the 'Server' (as well as 'Via')
	 * static index doesn't fit to that space.
	 */
	res_size += sizeof(TfwCStr);
	res_size += 2;
	res_size += tfw_hpack_int_size(SLEN(TFW_SERVER), 0x7F);
	res_size += SLEN(TFW_SERVER);

	res_size += sizeof(TfwCStr);
	res_size += 2;
	res_size += tfw_hpack_int_size(via_sz, 0x7F);
	res_size += via_sz;

	/* Add body size. */
	res_size += resp->body.len;

	return res_size;
err:
	T_WARN("Cache: trying to store too big string %ld\n", size);
	return -E2BIG;
}

static void
__cache_add_node(TDB *db, TfwHttpResp *resp, unsigned long key)
{
	size_t len;
	TfwCacheEntry *ce;
	TfwStr rph, *s_line;
	long data_len = __cache_entry_size(resp);

	if (unlikely(data_len < 0))
		return;

	/*
	 * We need to save the reason-phrase for the case of HTTP/1.1-response
	 * creation from cache. Note, that reason-phrase is always the last part
	 * of status-line with the TFW_STR_VALUE flag set.
	 */
	s_line = &resp->h_tbl->tbl[TFW_HTTP_STATUS_LINE];
	rph = tfw_str_next_str_val(s_line);
	if (WARN_ON_ONCE(TFW_STR_EMPTY(&rph)))
		return;

	data_len += rph.len;
	len = data_len;

	T_DBG3("%s: db=[%p] resp=[%p], req=[%p], key='%lu', data_len='%ld'\n",
	       __func__, db, resp, resp->req, key, data_len);

	/* TODO #788: revalidate existing entries before inserting a new one. */

	/*
	 * Try to place the cached response in single memory chunk.
	 * TDB should provide enough space to place at least head of
	 * the record key at first chunk.
	 */
	ce = (TfwCacheEntry *)tdb_entry_alloc(db, key, &len);
	BUG_ON(len <= sizeof(TfwCacheEntry));
	if (!ce)
		return;

	T_DBG3("%s: ce=[%p], alloc_len='%lu'\n", __func__, ce, len);

	if (tfw_cache_copy_resp(ce, resp, &rph, data_len)) {
		/* TODO delete the probably partially built TDB entry. */
	}
}

static void
tfw_cache_add(TfwHttpResp *resp, tfw_http_cache_cb_t action)
{
	unsigned long key;
	bool keep_skb = false;
	TfwHttpReq *req = resp->req;

	if (!tfw_cache_employ_resp(resp))
		goto out;

	key = tfw_http_req_key_calc(req);

	if (cache_cfg.cache == TFW_CACHE_SHARD) {
		BUG_ON(req->node != numa_node_id());
		__cache_add_node(node_db(), resp, key);
	} else {
		int nid;
		/*
		 * TODO probably it's better to do this in TDB per-node threads
		 * rather than in softirq...
		 */
		for_each_node_with_cpus(nid)
			__cache_add_node(c_nodes[nid].db, resp, key);
	}

	/*
	 * Cache population is synchronous now. Don't forget to set
	 * @keep_skb properly in case of asynchronous operation is being
	 * performed.
	 */

out:
	resp->msg.ss_flags |= keep_skb ? SS_F_KEEP_SKB : 0;
	action((TfwHttpMsg *)resp);
}

/**
 * Invalidate a cache entry.
 * In fact, this is implemented by making the cache entry stale.
 */
static int
tfw_cache_purge_invalidate(TfwHttpReq *req)
{
	TdbIter iter;
	TDB *db = node_db();
	TfwCacheEntry *ce = NULL;

	if (!(ce = tfw_cache_dbce_get(db, &iter, req)))
		return -ENOENT;
	ce->lifetime = 0;

	do {
		tdb_rec_next(db, &iter);
		ce = (TfwCacheEntry *)iter.rec;
		if (ce && tfw_cache_entry_key_eq(db, req, ce))
			ce->lifetime = 0;
	} while (ce);

	tfw_cache_dbce_put(ce);

	return 0;
}

/**
 * Process PURGE request method according to the configuration.
 */
static void
tfw_cache_purge_method(TfwHttpReq *req)
{
	int ret;
	TfwAddr saddr;
	TfwGlobal *g_vhost = tfw_vhost_get_global();

	/* Deny PURGE requests by default. */
	if (!(cache_cfg.cache && g_vhost->cache_purge && g_vhost->cache_purge_acl)) {
		tfw_http_send_resp(req, 403, "purge: not configured");
		return;
	}

	/* Accept requests from configured hosts only. */
	ss_getpeername(req->conn->sk, &saddr);
	if (!tfw_capuacl_match(&saddr)) {
		tfw_http_send_resp(req, 403, "purge: ACL violation");
		return;
	}

	/* Only "invalidate" option is implemented at this time. */
	switch (g_vhost->cache_purge_mode) {
	case TFW_D_CACHE_PURGE_INVALIDATE:
		ret = tfw_cache_purge_invalidate(req);
		break;
	default:
		tfw_http_send_resp(req, 403, "purge: invalid option");
		return;
	}

	if (ret)
		tfw_http_send_resp(req, 404, "purge: processing error");
	else
		tfw_http_send_resp(req, 200, "purge: success");
}

/**
 * Add page from cache into response.
 */
static int
tfw_cache_add_body_page(TfwMsgIter *it, char *p, int sz, TfwFrameHdr *frame_hdr,
			bool h2, bool last_frag)
{
	int off;
	struct page *page;

	/*
	 * @sz is guarantied to be bigger than FRAME_HEADER_SIZE if frame header
	 * is stored in cache before data. True for first fragment.
	 */
	if (h2) {
		char *new_p;
		if (!(page = alloc_page(GFP_ATOMIC))) {
			return -ENOMEM;
		}
		new_p = page_address(page);
		off = 0;
		frame_hdr->flags = last_frag ? HTTP2_F_END_STREAM : 0;
		frame_hdr->length = sz;
		memcpy_fast(new_p + FRAME_HEADER_SIZE, p, sz);
		sz += FRAME_HEADER_SIZE;
		tfw_h2_pack_frame_header(new_p, frame_hdr);
	}
	else {
		off = ((unsigned long)p & ~PAGE_MASK);
		page = virt_to_page(p);
	}

	++it->frag;
	skb_fill_page_desc(it->skb, it->frag, page, off, sz);
	skb_frag_ref(it->skb, it->frag);
	ss_skb_adjust_data_len(it->skb, sz);

	return 0;
}

/**
 * Build the message body as paged fragments of skb.
 * See do_tcp_sendpages() as reference.
 *
 * Different strategies are used to avoid extra data copying depending on
 * client connection type:
 * - for http connections - pages are reused in skbs and SKBTX_SHARED_FRAG is
 * set to avoid any data copies.
 * - for https connections - pages are reused in skbs and SKBTX_SHARED_FRAG is
 * set, but in-place crypto operations are not allowed, so data copy happens
 * right before data is pushed into network.
 * - for h2 connections - every response has unique frame header, so need to
 * copy on constructing response body from cache. SKBTX_SHARED_FRAG is left
 * unset to allow in-place crypto operations.
 *
 * Since we can't encrypt shared data in-place we always copy it, so we need
 * reserve some space in cached pages to avoid extra skb fragmentation. Since
 * body fragments are stored in cache by pages with at least cache record
 * header preceding, which is bigger than h2 frame header, it's always possible
 * to fit body fragment and h2 header into a single page. So there is no need
 * to actually reserve any space for h2 frame header.
 */
static int
tfw_cache_build_resp_body(TDB *db, TdbVRec *trec, TfwMsgIter *it, char *p,
			  unsigned long body_sz, bool h2, unsigned int stream_id)
{
	int r;
	TfwFrameHdr frame_hdr = {.stream_id = stream_id, .type = HTTP2_DATA};
	bool sh_frag = h2 ? false : true;

	if (WARN_ON_ONCE(!it->skb_head))
		return -EINVAL;
	/*
	 * If all skbs/frags are used up (see @tfw_http_msg_expand_data()),
	 * create new skb with empty frags to reference the cached body;
	 * otherwise, use next empty frag in current skb. Create a new skb, if
	 * TX flags for headers and body differ.
	 */
	if (!it->skb || (it->frag + 1 >= MAX_SKB_FRAGS)
	    || (sh_frag == !(skb_shinfo(it->skb)->tx_flags & SKBTX_SHARED_FRAG)))
	{
		if  ((r = tfw_msg_iter_append_skb(it)))
			return r;
		if (!sh_frag)
			skb_shinfo(it->skb)->tx_flags &= ~SKBTX_SHARED_FRAG;
		else
			skb_shinfo(it->skb)->tx_flags |= SKBTX_SHARED_FRAG;
	}

	while (1) {
		int off, f_size;

		off = (unsigned long)p & ~PAGE_MASK;
		f_size = trec->data + trec->len - p;
		if (f_size) {
			f_size = min(body_sz, (unsigned long)f_size);
			body_sz -= f_size;
			r = tfw_cache_add_body_page(it, p, f_size, &frame_hdr,
						    h2, !body_sz);
			if (r)
				return r;
		}
		if (!body_sz || !(trec = tdb_next_rec_chunk(db, trec)))
			break;
		/*
		 * Broken record: body is not fully copied yet, but there is
		 * no data in the next record part.
		 */
		if (WARN_ON_ONCE(!trec->len))
			return -EINVAL;
		p = trec->data;

		if (it->frag + 1 == MAX_SKB_FRAGS
		    && (r = tfw_msg_iter_append_skb(it)))
		{
			return r;
		}
	}

	return 0;
}

static int
tfw_cache_set_hdr_age(TfwHttpResp *resp, TfwCacheEntry *ce)
{
	int r;
	size_t digs;
	bool to_h2 = TFW_MSG_H2(resp->req);
	TfwHttpTransIter *mit = &resp->mit;
	struct sk_buff **skb_head = &resp->msg.skb_head;
	time_t age = tfw_cache_entry_age(ce);
	char cstr_age[TFW_ULTOA_BUF_SIZ] = {0};
	char *name = to_h2 ? "age" : "age" S_DLM;
	unsigned int nlen = to_h2 ? SLEN("age") : SLEN("age" S_DLM);
	TfwStr h_age = {
		.chunks = (TfwStr []){
			{ .data = name, .len = nlen },
			{}
		},
		.len = nlen,
		.nchunks = 2
	};

	if (!(digs = tfw_ultoa(age, cstr_age, TFW_ULTOA_BUF_SIZ))) {
		r = -E2BIG;
		goto err;
	}

	__TFW_STR_CH(&h_age, 1)->data = cstr_age;
	__TFW_STR_CH(&h_age, 1)->len = digs;
	h_age.len += digs;

	if (to_h2) {
		h_age.hpack_idx = 21;
		if ((r = tfw_hpack_encode(resp, &h_age, TFW_H2_TRANS_EXPAND,
					  false)))
			goto err;
	} else {
		if ((r = tfw_http_msg_expand_data(&mit->iter, skb_head,
						  &h_age, NULL)))
			goto err;

		if ((r = tfw_http_msg_expand_data(&mit->iter, skb_head,
						  &g_crlf, NULL)))
			goto err;
	}

	return 0;

err:
	T_WARN("Unable to add Age: header, cached response [%p] dropped"
	       " (err: %d)\n", resp, r);
	return r;
}

/**
 * Build response that can be sent via TCP socket.
 *
 * We return skbs in the cache entry response w/o setting any
 * network headers - tcp_transmit_skb() will do it for us.
 *
 * TODO Prebuild the response and use clones/copies for sending
 * (copy the list of skbs is faster than scan TDB and build TfwHttpResp).
 * TLS should encrypt the data in already prepared skbs.
 *
 * Basically, skb copy/cloning involves skb creation, so it seems performance
 * of response body creation won't change since now we just reuse TDB pages.
 * Performance benchmarks and profiling shows that cache_req_process_node()
 * is the bottleneck, so the problem is either in tfw_cache_dbce_get() or this
 * function, in headers compilation.
 * Also it seems caching prebuilt responses requires introducing
 * TfwCacheEntry->resp pointer to avoid additional indexing data structure.
 * However, the pointer must be zeroed on TDB shutdown and recovery.
 *
 * TODO use iterator and passed skbs to be called from net_tx_action.
 */
static TfwHttpResp *
tfw_cache_build_resp(TfwHttpReq *req, TfwCacheEntry *ce, time_t lifetime,
		     unsigned int stream_id)
{
	int h;
	TfwStr dummy_body = { 0 };
	TfwMsgIter *it;
	TfwHttpResp *resp;
	char *p;
	TfwHttpTransIter *mit;
	TDB *db = node_db();
	unsigned long h_len = 0;
	struct sk_buff **skb_head;
	TdbVRec *trec = &ce->trec;
	TfwHdrMods *h_mods = tfw_vhost_get_hdr_mods(req->location, req->vhost,
						    TFW_VHOST_HDRMOD_RESP);
	/*
	 * The allocated response won't be checked by any filters and
	 * is used for sending response data only, so don't initialize
	 * connection and GFSM fields.
	 */
	if (!(resp = tfw_http_msg_alloc_resp(req)))
		goto out;

	/* Copy version information and flags */
	resp->version = ce->version;
	tfw_http_copy_flags(resp->flags, ce->hmflags);

	resp->date = ce->date;

	/* Skip record key until status line. */
	for (p = TDB_PTR(db->hdr, ce->status);
	     trec && (unsigned long)(p - trec->data) > trec->len;
	     trec = tdb_next_rec_chunk(db, trec))
		;
	if (unlikely(!trec)) {
		T_WARN("Huh, partially stored cache entry (key=%lx)?\n",
		       ce->key);
		goto free;
	}

	if (tfw_cache_set_status(db, ce, resp, &trec, &p, &h_len))
		goto free;

	for (h = TFW_HTTP_HDR_REGULAR; h < ce->hdr_num; ++h) {
		bool skip = !TFW_MSG_H2(req) && (h >= ce->hdr_h2_off);

		if (tfw_cache_build_resp_hdr(db, resp, h_mods, &trec, &p,
					     &h_len, skip))
			goto free;
	}

	mit = &resp->mit;
	skb_head = &resp->msg.skb_head;
	WARN_ON_ONCE(mit->acc_len);
	it = &mit->iter;

	/*
	 * Set 'set-cookie' header if needed, for HTTP/2 or HTTP/1.1
	 * response.
	 */
	if (tfw_http_sess_resp_process(resp, true))
		goto free;
	/*
	 * RFC 7234 p.4 Constructing Responses from Caches:
	 * When a stored response is used to satisfy a request without
	 * validation, a cache MUST generate an Age header field.
	 */
	if (tfw_cache_set_hdr_age(resp, ce))
		goto free;

	if (!TFW_MSG_H2(req)) {
		/*
		 * Set additional headers and final CRLF for HTTP/1.1
		 * response.
		 *
		 * If the original message was in chunked encoding, it has been
		 * removed and chunked trailer headers are stored with arbitrary
		 * headers. Add content-length header for correct message
		 * framing.
		 */
		if (tfw_http_expand_hbh(resp, ce->resp_status)
		    || tfw_http_expand_hdr_via(resp)
		    || tfw_h1_set_loc_hdrs((TfwHttpMsg *)resp, true, true)
		    || (lifetime > ce->lifetime
			&& tfw_http_expand_stale_warn(resp))
		    || (!test_bit(TFW_HTTP_B_HDR_DATE, resp->flags)
			&& tfw_http_expand_hdr_date(resp))
		    || (test_bit(TFW_HTTP_B_CHUNKED, resp->flags)
			&& tfw_http_expand_hdr_clen(resp, ce->body_len))
		    || tfw_http_msg_expand_data(it, skb_head, &g_crlf, NULL))
		{
			goto free;
		}

		goto write_body;
	}

	/* Set additional headers for HTTP/2 response. */
	if (tfw_h2_resp_add_loc_hdrs(resp, h_mods, true)
	    || (lifetime > ce->lifetime
		&& tfw_h2_set_stale_warn(resp))
	    || (!test_bit(TFW_HTTP_B_HDR_DATE, resp->flags)
		&& tfw_h2_add_hdr_date(resp, TFW_H2_TRANS_EXPAND, true)))
		goto free;

	h_len += mit->acc_len;

	/*
	 * Split response to h2 frames. Don't write body with generic function,
	 * just indicate that we have body for correct framing.
	 */
	dummy_body.len = ce->body_len;
	if (tfw_h2_frame_local_resp(resp, stream_id, h_len, &dummy_body))
		goto free;
	it->skb = ss_skb_peek_tail(&it->skb_head);
	it->frag = skb_shinfo(it->skb)->nr_frags - 1;

write_body:
	/* Fill skb with body from cache for HTTP/2 or HTTP/1.1 response. */
	BUG_ON(p != TDB_PTR(db->hdr, ce->body));
	if (ce->body_len) {
		if (tfw_cache_build_resp_body(db, trec, it, p, ce->body_len,
					      TFW_MSG_H2(req), stream_id))
			goto free;
	}

	return resp;
free:
	tfw_http_msg_free((TfwHttpMsg *)resp);
out:
	T_WARN("Cannot use cached response, key=%lx\n", ce->key);
	TFW_INC_STAT_BH(clnt.msgs_otherr);

	return NULL;
}

static void
cache_req_process_node(TfwHttpReq *req, tfw_http_cache_cb_t action)
{
	TfwCacheEntry *ce = NULL;
	TfwHttpResp *resp = NULL;
	unsigned int id = 0;
	TDB *db = node_db();
	TdbIter iter;
	time_t lifetime;

	if (!(ce = tfw_cache_dbce_get(db, &iter, req)))
		goto out;

	if (!(lifetime = tfw_cache_entry_is_live(req, ce)))
		goto out;

	T_DBG("Cache: service request w/ key=%lx, ce=%p (len=%u key_len=%u"
	      " status_len=%u hdr_num=%u hdr_len=%u key_off=%ld"
		" status_off=%ld hdrs_off=%ld body_off=%ld)\n",
		ce->trec.key, ce, ce->trec.len, ce->key_len, ce->status_len,
		ce->hdr_num, ce->hdr_len, ce->key, ce->status, ce->hdrs,
		ce->body);
	TFW_INC_STAT_BH(cache.hits);

	if (!tfw_handle_validation_req(req, ce))
		goto put;

	/*
	 * If the stream for HTTP/2-request is already closed (due to some
	 * error or just reset from the client side), there is no sense to
	 * forward request to the server.
	 */
	if (TFW_MSG_H2(req)) {
		id = tfw_h2_stream_id(req);
		if (unlikely(!id)) {
			tfw_http_conn_msg_free((TfwHttpMsg *)req);
			goto put;
		}
	}

	resp = tfw_cache_build_resp(req, ce, lifetime, id);
	/*
	 * The stream of HTTP/2-request should be closed here since we have
	 * successfully created the resulting response from cache and will
	 * send this response to the client (without forwarding request to
	 * the backend), thus the stream will be finished.
	 */
	if (resp && TFW_MSG_H2(req)) {
		id = tfw_h2_stream_id_close(req, HTTP2_HEADERS,
					    HTTP2_F_END_STREAM);
		if (unlikely(!id)) {
			tfw_http_msg_free((TfwHttpMsg *)resp);
			tfw_http_conn_msg_free((TfwHttpMsg *)req);
			goto put;
		}
	}
out:
	if (!resp && (req->cache_ctl.flags & TFW_HTTP_CC_OIFCACHED))
		tfw_http_send_resp(req, 504, "resource not cached");
	else
		/*
		 * TODO: RFC 7234 4.3.2: Extend preconditional request headers
		 * if any with values from cached entries to revalidate stored
		 * stale responses for both: client and Tempesta.
		 */
		action((TfwHttpMsg *)req);
put:
	tfw_cache_dbce_put(ce);
}

static void
tfw_cache_do_action(TfwHttpMsg *msg, tfw_http_cache_cb_t action)
{
	TfwHttpReq *req;

	if (TFW_CONN_TYPE(msg->conn) & Conn_Srv) {
		tfw_cache_add((TfwHttpResp *)msg, action);
		return;
	}

	req = (TfwHttpReq *)msg;
	if (unlikely(req->method == TFW_HTTP_METH_PURGE))
		tfw_cache_purge_method(req);
	else
		cache_req_process_node(req, action);
}

static void
tfw_cache_ipi(struct irq_work *work)
{
	TfwWorkTasklet *ct = container_of(work, TfwWorkTasklet, ipi_work);
	clear_bit(TFW_QUEUE_IPI, &ct->wq.flags);
	tasklet_schedule(&ct->tasklet);
}

int
tfw_cache_process(TfwHttpMsg *msg, tfw_http_cache_cb_t action)
{
	int cpu;
	unsigned long key;
	TfwWorkTasklet *ct;
	TfwCWork cw;
	TfwHttpResp *resp = NULL;
	TfwHttpReq *req = (TfwHttpReq *)msg;

	if (TFW_CONN_TYPE(msg->conn) & Conn_Srv) {
		resp = (TfwHttpResp *)msg;
		req = resp->req;
	}

	if (req->method == TFW_HTTP_METH_PURGE)
		goto do_cache;
	if (!tfw_cache_msg_cacheable(req))
		goto dont_cache;
	if (!resp && !tfw_cache_employ_req(req))
		goto dont_cache;

do_cache:
	key = tfw_http_req_key_calc(req);
	req->node = (cache_cfg.cache == TFW_CACHE_SHARD)
		    ? tfw_cache_key_node(key)
		    : numa_node_id();

	/*
	 * Queue the cache work only when it must be served by a remote node.
	 * Otherwise we can do everything right now on local CPU.
	 *
	 * TODO #391: it appears that req->node is not really needed and can
	 * be eliminated from TfwHttpReq{} structure and it can easily be
	 * replaced by a local variable here.
	 */
	if (likely(req->node == numa_node_id())) {
		tfw_cache_do_action(msg, action);
		return 0;
	}

	cw.msg = msg;
	cw.action = action;
	cpu = tfw_cache_sched_cpu(req);
	ct = per_cpu_ptr(&cache_wq, cpu);

	T_DBG2("Cache: schedule tasklet w/ work: to_cpu=%d from_cpu=%d"
	       " msg=%p key=%lx\n", cpu, smp_processor_id(),
	       cw.msg, key);
	if (tfw_wq_push(&ct->wq, &cw, cpu, &ct->ipi_work, tfw_cache_ipi)) {
		T_WARN("Cache work queue overrun: [%s]\n",
		       resp ? "response" : "request");
		return -EBUSY;
	}
	return 0;

dont_cache:
	action(msg);
	return 0;
}

static void
tfw_wq_tasklet(unsigned long data)
{
	TfwWorkTasklet *ct = (TfwWorkTasklet *)data;
	TfwRBQueue *wq = &ct->wq;
	TfwCWork cw;

	while (!tfw_wq_pop(wq, &cw))
		tfw_cache_do_action(cw.msg, cw.action);

	TFW_WQ_IPI_SYNC(tfw_wq_size, wq);

	tasklet_schedule(&ct->tasklet);
}

/**
 * Cache management thread.
 * The thread loads and preprocesses static Web content using inotify (TODO).
 */
#if 0
static int
tfw_cache_mgr(void *arg)
{
	do {
		/*
		 * TODO wait while the thread is propagating disk Web data
		 * to the cache when the server starts.
		 */

		if (!freezing(current)) {
			set_current_state(TASK_INTERRUPTIBLE);
			schedule();
			__set_current_state(TASK_RUNNING);
		}
		else
			try_to_freeze();
	} while (!kthread_should_stop());

	return 0;
}
#endif

static int
tfw_cache_start(void)
{
	int i, r = 1;
	TfwGlobal *g_vhost = tfw_vhost_get_global();

	if (tfw_runstate_is_reconfig())
		return 0;
	if (!(cache_cfg.cache || g_vhost->cache_purge))
		return 0;

	for_each_node_with_cpus(i) {
		c_nodes[i].db = tdb_open(cache_cfg.db_path,
					 cache_cfg.db_size, 0, i);
		if (!c_nodes[i].db)
			goto close_db;
	}
#if 0
	cache_mgr_thr = kthread_run(tfw_cache_mgr, NULL, "tfw_cache_mgr");
	if (IS_ERR(cache_mgr_thr)) {
		r = PTR_ERR(cache_mgr_thr);
		T_ERR_NL("Can't start cache manager, %d\n", r);
		goto close_db;
	}
#endif
	tfw_init_node_cpus();

	TFW_WQ_CHECKSZ(TfwCWork);
	for_each_online_cpu(i) {
		TfwWorkTasklet *ct = &per_cpu(cache_wq, i);
		tfw_wq_init(&ct->wq, cpu_to_node(i));
		init_irq_work(&ct->ipi_work, tfw_cache_ipi);
		tasklet_init(&ct->tasklet, tfw_wq_tasklet, (unsigned long)ct);
	}

	return 0;
close_db:
	for_each_node_with_cpus(i)
		tdb_close(c_nodes[i].db);
	return r;
}

static void
tfw_cache_stop(void)
{
	int i;

	if (tfw_runstate_is_reconfig())
		return;
	if (!cache_cfg.cache)
		return;

	for_each_online_cpu(i) {
		TfwWorkTasklet *ct = &per_cpu(cache_wq, i);
		tasklet_kill(&ct->tasklet);
		irq_work_sync(&ct->ipi_work);
		tfw_wq_destroy(&ct->wq);
	}
#if 0
	kthread_stop(cache_mgr_thr);
#endif

	for_each_node_with_cpus(i)
		tdb_close(c_nodes[i].db);
}

static const TfwCfgEnum cache_http_methods_enum[] = {
	{ "copy",	TFW_HTTP_METH_COPY },
	{ "delete",	TFW_HTTP_METH_DELETE },
	{ "get",	TFW_HTTP_METH_GET },
	{ "head",	TFW_HTTP_METH_HEAD },
	{ "lock",	TFW_HTTP_METH_LOCK },
	{ "mkcol",	TFW_HTTP_METH_MKCOL },
	{ "move",	TFW_HTTP_METH_MOVE },
	{ "options",	TFW_HTTP_METH_OPTIONS },
	{ "patch",	TFW_HTTP_METH_PATCH },
	{ "post",	TFW_HTTP_METH_POST },
	{ "propfind",	TFW_HTTP_METH_PROPFIND },
	{ "proppatch",	TFW_HTTP_METH_PROPPATCH },
	{ "put",	TFW_HTTP_METH_PUT },
	{ "trace",	TFW_HTTP_METH_TRACE },
	{ "unlock",	TFW_HTTP_METH_UNLOCK },
	/* Unknown methods can't be cached. */
	{}
};

static int
tfw_cfgop_cache_methods(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	unsigned int i, method;
	const char *val;

	BUILD_BUG_ON(sizeof(cache_cfg.methods) * BITS_PER_BYTE
		     < _TFW_HTTP_METH_COUNT);
	BUILD_BUG_ON(sizeof(method) * BITS_PER_BYTE < _TFW_HTTP_METH_COUNT);

	TFW_CFG_ENTRY_FOR_EACH_VAL(ce, i, val) {
		if (tfw_cfg_map_enum(cache_http_methods_enum, val, &method)) {
			T_ERR_NL("%s: unsupported method: '%s'\n",
				   cs->name, val);
			return -EINVAL;
		}
		if (__cache_method_nc_test(method)) {
			T_WARN_NL("%s: non-cacheable method '%s' is set "
				  "as cacheable\n",
				  cs->name, val);
		}
		if (__cache_method_test(method)) {
			T_WARN_NL("%s: duplicate method: '%s'\n",
				  cs->name, val);
			continue;
		}
		__cache_method_add(method);
	}

	return 0;
}

static void
tfw_cfgop_cleanup_cache_methods(TfwCfgSpec *cs)
{
	cache_cfg.methods = 0;
}

static TfwCfgSpec tfw_cache_specs[] = {
	{
		.name = "cache",
		.deflt = "2",
		.handler = tfw_cfg_set_int,
		.dest = &cache_cfg.cache,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, 2 },
		},
	},
	{
		.name = "cache_methods",
		.deflt = "GET",
		.handler = tfw_cfgop_cache_methods,
		.allow_none = true,
		.allow_repeat = false,
		.cleanup = tfw_cfgop_cleanup_cache_methods,
	},
	{
		.name = "cache_size",
		.deflt = "268435456",
		.handler = tfw_cfg_set_int,
		.dest = &cache_cfg.db_size,
		.spec_ext = &(TfwCfgSpecInt) {
			.multiple_of = PAGE_SIZE,
			.range = { PAGE_SIZE, (1 << 30) },
		}
	},
	{
		.name = "cache_db",
		.deflt = "/opt/tempesta/db/cache.tdb",
		.handler = tfw_cfg_set_str,
		.dest = &cache_cfg.db_path,
		.spec_ext = &(TfwCfgSpecStr) {
			.len_range = { 1, PATH_MAX },
		}
	},
	{ 0 }
};

TfwMod tfw_cache_mod = {
	.name 	= "cache",
	.start	= tfw_cache_start,
	.stop	= tfw_cache_stop,
	.specs	= tfw_cache_specs,
};

int
tfw_cache_init(void)
{
	tfw_mod_register(&tfw_cache_mod);
	return 0;
}

void
tfw_cache_exit(void)
{
	tfw_mod_unregister(&tfw_cache_mod);
}
