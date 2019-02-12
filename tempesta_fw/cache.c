/**
 *		Tempesta FW
 *
 * HTTP cache (RFC 7234).
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
#include "procfs.h"
#include "sync_socket.h"
#include "work_queue.h"

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
 * @status_len	- length of response status line;
 * @hdr_num	- number of headers;
 * @hdr_len	- length of whole headers data;
 * @hdr_len_304	- length of headers data used to build 304 response;
 * @method	- request method, part of the key;
 * @flags	- various cache entry flags;
 * @age		- the value of response Age: header field;
 * @date	- the value of response Date: header field;
 * @req_time	- the time the request was issued;
 * @resp_time	- the time the response was received;
 * @lifetime	- the cache entry's current lifetime;
 * @last_modified - the value of response Last-Modified: header field;
 * @key		- the cache entry key (URI + Host header);
 * @status	- pointer to status line  (with trailing CRLFs);
 * @hdrs	- pointer to list of HTTP headers (with trailing CRLFs);
 * @body	- pointer to response body (with a prepending CRLF);
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
	unsigned int	hdr_num;
	unsigned int	hdr_len;
	unsigned int	hdr_len_304;
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

/*
 * TODO the thread doesn't do anything for now, however, kthread_stop() crashes
 * on restarts, so comment to logic out.
 */
#if 0
static struct task_struct *cache_mgr_thr;
#endif
static DEFINE_PER_CPU(TfwWorkTasklet, cache_wq);

static TfwStr g_crlf = { .data = S_CRLF, .len = SLEN(S_CRLF) };

/* Iterate over request URI and Host header to process request key. */
#define TFW_CACHE_REQ_KEYITER(c, req, u_end, h_start, h_end)		\
	if (TFW_STR_PLAIN(&req->uri_path)) {				\
		c = &req->uri_path;					\
		u_end = &req->uri_path + 1;				\
	} else {							\
		c = req->uri_path.chunks;				\
		u_end = req->uri_path.chunks				\
			+ req->uri_path.nchunks;			\
	}								\
	if (TFW_STR_PLAIN(&req->h_tbl->tbl[TFW_HTTP_HDR_HOST])) {	\
		h_start = req->h_tbl->tbl + TFW_HTTP_HDR_HOST;		\
		h_end = req->h_tbl->tbl + TFW_HTTP_HDR_HOST + 1;	\
	} else {							\
		h_start = req->h_tbl->tbl[TFW_HTTP_HDR_HOST].chunks;	\
		h_end = req->h_tbl->tbl[TFW_HTTP_HDR_HOST].chunks	\
			+ req->h_tbl->tbl[TFW_HTTP_HDR_HOST].nchunks;	\
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
	/*
	 * TODO: caching of streamed responses.
	 * Streamed response can be cached, but at any time the response
	 * can be filtered out due to connection error or frang decisions.
	 * Although incomplete cache entry might be helpful to serve ranged
	 * responses, it's cannot be used until frang explicitly allow it.
	 * TBD:
	 * Size of streamed response is limited by 'server_msg_buffering'
	 * directive to avoid memory exhaustion by single message. Same
	 * option should be provided for cache.
	 */
	if (tfw_http_msg_is_streamed((TfwHttpMsg *)resp))
		return false;

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
 * Add a new data chunk size of @len starting from @data to HTTP response @resp.
 * Properly set up @hdr if not NULL.
 */
static int
tfw_cache_write_field(TDB *db, TdbVRec **trec, TfwHttpResp *resp,
		      TfwMsgIter *it, char **data, size_t len, TfwStr *hdr)
{
	int r, copied = 0;
	TdbVRec *tr = *trec;
	TfwStr c = { 0 };

	while (1)  {
		c.data = *data;
		c.len = min(tr->data + tr->len - *data,
			    (long)(len - copied));
		r = hdr
		    ? tfw_http_msg_add_data(it, (TfwHttpMsg *)resp, hdr, &c)
		    : tfw_msg_write(it, &c);
		if (r)
			return r;

		copied += c.len;
		*data += c.len;
		if (copied == len)
			break;

		tr = *trec = tdb_next_rec_chunk(db, tr);
		BUG_ON(!tr);
		*data = tr->data;
	}

	/* Every non-empty header contains CRLF at the end. We need to translate
	 * it to { str, eolen } presentation. */
	if (hdr && hdr->len)
		tfw_str_fixup_eol(hdr, SLEN(S_CRLF));

	return 0;
}

/**
 * Write HTTP header to skb data.
 * The headers are likely to be adjusted, so copy them.
 */
static int
tfw_cache_build_resp_hdr(TDB *db, TfwHttpResp *resp, TfwStr *hdr,
			 TdbVRec **trec, TfwMsgIter *it, char **p)
{
	int r, d, dn;
	TfwStr *dups;
	TfwCStr *s = (TfwCStr *)*p;

	*p += TFW_CSTR_HDRLEN;
	BUG_ON(*p > (*trec)->data + (*trec)->len);

	if (likely(!(s->flags & TFW_STR_DUPLICATE)))
		return tfw_cache_write_field(db, trec, resp, it, p, s->len,
					     hdr);

	/* Process duplicated headers. */
	dn = s->len;
	dups = tfw_pool_alloc(resp->pool, dn * sizeof(TfwStr));
	if (!dups)
		return -ENOMEM;

	for (d = 0; d < dn; ++d) {
		s = (TfwCStr *)*p;
		BUG_ON(s->flags);
		TFW_STR_INIT(&dups[d]);
		*p += TFW_CSTR_HDRLEN;
		if ((r = tfw_cache_write_field(db, trec, resp, it, p, s->len,
					       &dups[d])))
			return r;
	}

	if (hdr) {
		hdr->chunks = dups;
		hdr->nchunks = dn;
		hdr->flags |= TFW_STR_DUPLICATE;
	}

	return 0;
}

/**
 * RFC 7232 Section-4.1: The server generating a 304 response MUST generate:
 * Cache-Control, Content-Location, Date, ETag, Expires, and Vary.
 * Last-Modified might be used if the response does not have an ETag field.
 *
 * The 304 response should be as short as possible, we don't need to add
 * extra headers with tfw_http_adjust_resp(). Use quicker tfw_msg_write()
 * instead of tfw_http_msg_add_data() used to build full response.
 */
static void
tfw_cache_send_304(TfwHttpReq *req, TfwCacheEntry *ce)
{
	TfwHttpResp *resp;
	TfwMsgIter it;
	int i;
	char *p;
	TdbVRec *trec = &ce->trec;
	TDB *db = node_db();

	WARN_ON_ONCE(!list_empty(&req->fwd_list));
	WARN_ON_ONCE(!list_empty(&req->nip_list));

	if (!(resp = tfw_http_msg_alloc_resp_light(req)))
		goto err_create;

	if (tfw_http_prep_304((TfwHttpMsg *)resp, req, &it,
			      ce->hdr_len_304))
		goto err_setup;

	/* Put 304 headers */
	for (i = 0; i < ARRAY_SIZE(ce->hdrs_304); ++i) {
		if (!ce->hdrs_304[i])
			continue;

		p = TDB_PTR(db->hdr, ce->hdrs_304[i]);
		while (trec && (p > trec->data + trec->len))
			trec = tdb_next_rec_chunk(db, trec);
		BUG_ON(!trec);

		if (tfw_cache_build_resp_hdr(db, resp, NULL, &trec, &it, &p))
			goto err_setup;
	}

	if (tfw_msg_write(&it, &g_crlf))
		goto err_setup;

	tfw_http_resp_fwd(resp);

	return;
err_setup:
	TFW_WARN("Can't build 304 response, key=%lx\n", ce->key);
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

	if ((req->method != TFW_HTTP_METH_PURGE) && (ce->method != req->method))
		return false;
	if (req->uri_path.len
	    + req->h_tbl->tbl[TFW_HTTP_HDR_HOST].len != ce->key_len)
		return false;

	t_off = CE_BODY_SIZE;
	TFW_CACHE_REQ_KEYITER(c, req, u_end, h_start, h_end) {
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

static void
tfw_cache_str_write_hdr(const TfwStr *str, char *p)
{
	TfwCStr *s = (TfwCStr *)p;

	if (TFW_STR_DUP(str)) {
		s->flags = TFW_STR_DUPLICATE;
		s->len = str->nchunks;
	} else {
		s->flags = 0;
		s->len = str->len ? str->len + SLEN(S_CRLF) : 0;
	}
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

		TFW_DBG3("Cache: copy [%.*s](%lu) to rec=%p(len=%u, next=%u),"
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

/**
 * Copies plain or compound (chunked) TfwStr @src to TdbRec @trec may be
 * appending EOL marker at the end.
 *
 * @src is copied (possibly with EOL appended)
 * @return number of copied bytes on success and negative value otherwise.
 */
static long
tfw_cache_strcpy_eol(char **p, TdbVRec **trec,
		   TfwStr *src, size_t *tot_len, bool eol)
{
	long n, copied = 0;
	TfwStr *c, *end;

	BUG_ON(TFW_STR_DUP(src));

	if (unlikely(!src->len))
		return 0;

	TFW_STR_FOR_EACH_CHUNK(c, src, end) {
		if ((n = tfw_cache_strcpy(p, trec, c, *tot_len)) < 0) {
			TFW_ERR("Cache: cannot copy chunk of string\n");
			return -ENOMEM;
		}
		*tot_len -= n;
		copied += n;
	}

	if (eol) {
		if ((n = tfw_cache_strcpy(p, trec, &g_crlf, *tot_len)) < 0)
			return -ENOMEM;
		BUG_ON(n != SLEN(S_CRLF));
		*tot_len -= n;
		copied += n;
	}

	return copied;
}

/**
 * Deep HTTP header copy to TdbRec.
 * @src is copied in depth first fashion to speed up upcoming scans.
 * @return number of copied bytes on success and negative value otherwise.
 */
static long
tfw_cache_copy_hdr(char **p, TdbVRec **trec, TfwStr *src, size_t *tot_len)
{
	long n = sizeof(TfwCStr), copied;
	TfwStr *dup, *dup_end;

	if (unlikely(src->len >= TFW_CSTR_MAXLEN)) {
		TFW_WARN("Cache: trying to store too big string %lx\n",
			 src->len);
		return -E2BIG;
	}
	/* Don't split short strings. */
	if (likely(!TFW_STR_DUP(src))
	    && sizeof(TfwCStr) + src->len <= L1_CACHE_BYTES)
		n += src->len;

#define CSTR_WRITE_HDR(str)			\
	tfw_cache_str_write_hdr(str, *p);	\
	*p += TFW_CSTR_HDRLEN;			\
	*tot_len -= TFW_CSTR_HDRLEN;		\
	copied = TFW_CSTR_HDRLEN;

	*p = tdb_entry_get_room(node_db(), trec, *p, n, *tot_len);
	if (!*p) {
		TFW_WARN("Cache: cannot allocate TDB space\n");
		return -ENOMEM;
	}

	CSTR_WRITE_HDR(src);

	if (!TFW_STR_DUP(src)) {
		if ((n = tfw_cache_strcpy_eol(p, trec, src, tot_len, 1)) < 0)
			return n;
		return copied + n;
	}

	TFW_STR_FOR_EACH_DUP(dup, src, dup_end) {
		CSTR_WRITE_HDR(dup);
		if ((n = tfw_cache_strcpy_eol(p, trec, dup, tot_len, 1)) < 0)
			return n;
		copied += n;
	}

	return copied;
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
	size_t len = 0;
	TfwStr etag_val, *c, *end, *h = &resp->h_tbl->tbl[TFW_HTTP_HDR_ETAG];
	TDB *db = node_db();

	if (TFW_STR_EMPTY(h))
		return 0;
	etag_val = tfw_str_next_str_val(h); /* not empty after http parser. */

	/* Update supposed Etag offset to real value. */
	/* FIXME: #803 */
	e_p = TDB_PTR(db->hdr, h_off);
	if (e_p + TFW_CSTR_HDRLEN > h_trec->data + h_trec->len) {
		h_trec = tdb_next_rec_chunk(db, h_trec);
		e_p = h_trec->data;
	}
	/* Skip anything that is not a etag value. */
	e_p += TFW_CSTR_HDRLEN;
	TFW_STR_FOR_EACH_CHUNK(c, h, end) {
		size_t c_size = c->len;

		if (c->flags & TFW_STR_VALUE)
			break;
		while (c_size) {
			size_t tail = h_trec->len - (e_p - h_trec->data);
			if (c_size > tail) {
				c_size -= tail;
				h_trec = tdb_next_rec_chunk(db, h_trec);
				e_p = h_trec->data;
			}
			else {
				e_p += c_size;
				c_size = 0;
			}
		}
	}
	for ( ; (c < end) && (c->flags & TFW_STR_VALUE); ++c)
		len += c->len;

	/* Create TfWStr that contains only entity-tag value. */
	ce->etag.data = e_p;
	ce->etag.flags = TFW_STR_CHUNK(&etag_val, 0)->flags;
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
 * @tot_len - total length of actual data to write w/o TfwCStr's etc.
 *
 * It's nasty to copy data on CPU, but we can't use DMA for mmaped file
 * as well as for unaligned memory areas.
 *
 * TODO Store the cache entries as a templates with placeholders for
 * changeable headers. That we can faster build the final answers instead
 * of adjusting skb's.
 */
static int
tfw_cache_copy_resp(TfwCacheEntry *ce, TfwHttpResp *resp, size_t tot_len)
{
	TfwHttpReq *req = resp->req;
	long n, etag_off = 0;
	char *p;
	TdbVRec *trec = &ce->trec, *etag_trec = NULL;
	TDB *db = node_db();
	TfwStr *field, *h, *end1, *end2, empty = {};
	int r, i;

	p = (char *)(ce + 1);
	tot_len -= CE_BODY_SIZE;

	/* Write record key (URI + Host header). */
	ce->key = TDB_OFF(db->hdr, p);
	ce->key_len = 0;
	TFW_CACHE_REQ_KEYITER(field, req, end1, h, end2) {
		if ((n = tfw_cache_strcpy_lc(&p, &trec, field, tot_len)) < 0) {
			TFW_ERR("Cache: cannot copy request key\n");
			return -ENOMEM;
		}
		BUG_ON(n > tot_len);
		tot_len -= n;
		ce->key_len += n;
	}
	/* Request method is a part of the cache record key. */
	ce->method = req->method;

	ce->status = TDB_OFF(db->hdr, p);
	if ((n = tfw_cache_strcpy_eol(&p, &trec, &resp->s_line, &tot_len, 1)) < 0) {
		TFW_ERR("Cache: cannot copy HTTP status line\n");
		return -ENOMEM;
	}
	ce->status_len += n;

	ce->hdrs = TDB_OFF(db->hdr, p);
	ce->hdr_len = 0;
	ce->hdr_num = resp->h_tbl->off;
	FOR_EACH_HDR_FIELD(field, end1, resp) {
		bool hdr_304 = false;

		/* Skip hop-by-hop headers. */
		if (!(field->flags & TFW_STR_HBH_HDR)) {
			h = field;
		} else if (field - resp->h_tbl->tbl < TFW_HTTP_HDR_RAW) {
			h = &empty;
		} else {
			--ce->hdr_num;
			continue;
		}
		if (field - resp->h_tbl->tbl == TFW_HTTP_HDR_ETAG) {
			/* Must be updated after tfw_cache_copy_hdr(). */
			etag_off = TDB_OFF(db->hdr, p);
			etag_trec = trec;
		}
		hdr_304 = __save_hdr_304_off(ce, resp, field,
					     TDB_OFF(db->hdr, p));

		n = tfw_cache_copy_hdr(&p, &trec, h, &tot_len);
		if (n < 0) {
			TFW_ERR("Cache: cannot copy HTTP header\n");
			return -ENOMEM;
		} else if (hdr_304) {
			ce->hdr_len_304 += n;
		}
		ce->hdr_len += n;
	}

	/* Write HTTP response body. */
	ce->body = TDB_OFF(db->hdr, p);
	n = tfw_cache_strcpy_eol(&p, &trec, &resp->body, &tot_len,
				 test_bit(TFW_HTTP_B_CHUNKED, resp->flags));
	if (n < 0) {
		TFW_ERR("Cache: cannot copy HTTP body\n");
		return -ENOMEM;
	}
	BUG_ON(tot_len != 0);

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
		TFW_ERR("Cache: cannot copy entity-tag\n");
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

	TFW_DBG("Cache copied msg: content-length=%lu msg_len=%lu, ce=%p"
		" (len=%u key_len=%u status_len=%u hdr_num=%u hdr_len=%u"
		" key_off=%ld status_off=%ld hdrs_off=%ld body_off=%ld)\n",
		resp->content_length, resp->msg.len, ce, ce->trec.len,
		ce->key_len, ce->status_len, ce->hdr_num, ce->hdr_len,
		ce->key, ce->status, ce->hdrs, ce->body);

	return 0;
}

static size_t
__cache_entry_size(TfwHttpResp *resp)
{
	TfwHttpReq *req = resp->req;
	size_t size = CE_BODY_SIZE;
	TfwStr *h, *hdr, *hdr_end, *dup, *dup_end, empty = {};

	/* Add compound key size */
	size += req->uri_path.len;
	size += req->h_tbl->tbl[TFW_HTTP_HDR_HOST].len;

	/* Add all the headers size */
	FOR_EACH_HDR_FIELD(hdr, hdr_end, resp) {
		/* Skip hop-by-hop headers. */
		if (!(hdr->flags & TFW_STR_HBH_HDR))
			h = hdr;
		else if (hdr - resp->h_tbl->tbl < TFW_HTTP_HDR_RAW)
			h = &empty;
		else
			continue;

		if (!TFW_STR_DUP(h)) {
			size += sizeof(TfwCStr);
			size += h->len ? (h->len + SLEN(S_CRLF)) : 0;
		} else {
			size += sizeof(TfwCStr);
			TFW_STR_FOR_EACH_DUP(dup, h, dup_end) {
				size += sizeof(TfwCStr);
				size += dup->len + SLEN(S_CRLF);
			}
		}
	}

	/* Add status line length + CRLF */
	size += resp->s_line.len + SLEN(S_CRLF);

	/* Add body size accounting CRLF after the last chunk */
	size += resp->body.len;
	if (test_bit(TFW_HTTP_B_CHUNKED, resp->flags))
		size += SLEN(S_CRLF);

	return size;
}

static void
__cache_add_node(TDB *db, TfwHttpResp *resp, unsigned long key)
{
	TfwCacheEntry *ce;
	size_t data_len = __cache_entry_size(resp);
	size_t len = data_len;

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

	TFW_DBG3("cache db=%p resp=%p/req=%p/ce=%p: alloc_len=%lu\n",
		 db, resp, resp->req, ce, len);

	if (tfw_cache_copy_resp(ce, resp, data_len)) {
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
 * Build the message body as paged fragments of skb.
 * See do_tcp_sendpages() as reference.
 */
static int
tfw_cache_build_resp_body(TDB *db, TfwHttpResp *resp, TdbVRec *trec,
			  TfwMsgIter *it, char *p)
{
	int off, f_size, r;
	skb_frag_t *frag;

	BUG_ON(!it->skb);
	frag = &skb_shinfo(it->skb)->frags[it->frag];
	if (skb_frag_size(frag))
		++it->frag;
	if (it->frag >= MAX_SKB_FRAGS - 1
	    && (r = tfw_http_msg_setup((TfwHttpMsg *)resp, it, 0)))
		return r;

	while (1) {
		if (it->frag == MAX_SKB_FRAGS
		    && (r = tfw_http_msg_setup((TfwHttpMsg *)resp, it, 0)))
			return r;

		/* TDB keeps data by pages and we can reuse the pages. */
		off = (unsigned long)p & ~PAGE_MASK;
		f_size = trec->data + trec->len - p;
		if (f_size) {
			skb_fill_page_desc(it->skb, it->frag, virt_to_page(p),
					   off, f_size);
			skb_frag_ref(it->skb, it->frag);
			ss_skb_adjust_data_len(it->skb, f_size);

			if (__tfw_http_msg_add_str_data((TfwHttpMsg *)resp,
							&resp->body, p, f_size,
							it->skb))
				return - ENOMEM;
			++it->frag;
		}
		if (!(trec = tdb_next_rec_chunk(db, trec)))
			break;
		BUG_ON(trec && !f_size);
		p = trec->data;
	}

	return 0;
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
tfw_cache_build_resp(TfwHttpReq *req, TfwCacheEntry *ce)
{
	int h;
	char *p;
	TfwHttpResp *resp;
	TdbVRec *trec = &ce->trec;
	TDB *db = node_db();
	TfwMsgIter it;

	/*
	 * The allocated response won't be checked by any filters and
	 * is used for sending response data only, so don't initialize
	 * connection and GFSM fields.
	 */
	if (!(resp = tfw_http_msg_alloc_resp(req)))
		return NULL;
	if (tfw_http_msg_setup((TfwHttpMsg *)resp, &it, ce->hdr_len + 2))
		goto free;

	/*
	 * Allocate HTTP headers table of proper size.
	 * There were no other allocations since the table is allocated,
	 * so realloc() just grows the table and returns the same pointer.
	 */
	h = (ce->hdr_num + 2 * TFW_HTTP_HDR_NUM - 1) & ~(TFW_HTTP_HDR_NUM - 1);
	p = tfw_pool_realloc(resp->pool, resp->h_tbl, TFW_HHTBL_SZ(1),
			     TFW_HHTBL_EXACTSZ(h));
	BUG_ON(p != (char *)resp->h_tbl);

	/* Skip record key until status line. */
	for (p = TDB_PTR(db->hdr, ce->status);
	     trec && (unsigned long)(p - trec->data) > trec->len;
	     trec = tdb_next_rec_chunk(db, trec))
		;
	if (unlikely(!trec)) {
		TFW_WARN("Huh, partially stored cache entry (key=%lx)?\n",
			 ce->key);
		goto err;
	}

	if (tfw_cache_write_field(db, &trec, resp, &it, &p,
				  ce->status_len, &resp->s_line))
		goto err;

	resp->h_tbl->off = ce->hdr_num;
	for (h = 0; h < ce->hdr_num; ++h) {
		TFW_STR_INIT(resp->h_tbl->tbl + h);
		if (tfw_cache_build_resp_hdr(db, resp, resp->h_tbl->tbl + h,
					     &trec, &it, &p))
			goto err;
	}

	if (tfw_http_msg_add_data(&it, (TfwHttpMsg *)resp, &resp->crlf,
				  &g_crlf))
		goto err;

	BUG_ON(p != TDB_PTR(db->hdr, ce->body));
	if (tfw_cache_build_resp_body(db, resp, trec, &it, p))
		goto err;

	resp->version = ce->version;
	tfw_http_copy_flags(resp->flags, ce->hmflags);

	return resp;
err:
	TFW_WARN("Cannot use cached response, key=%lx\n", ce->key);
free:
	tfw_http_msg_free((TfwHttpMsg *)resp);
	return NULL;
}

static inline int
tfw_cache_set_hdr_age(TfwHttpMsg *hmresp, TfwCacheEntry *ce)
{
	size_t digs;
	char cstr_age[TFW_ULTOA_BUF_SIZ] = {0};
	time_t age = tfw_cache_entry_age(ce);

	if (!(digs = tfw_ultoa(age, cstr_age, TFW_ULTOA_BUF_SIZ)))
		return -E2BIG;

	return tfw_http_msg_hdr_xfrm(hmresp, "Age", sizeof("Age") - 1,
				     cstr_age, digs, TFW_HTTP_HDR_RAW, 0);
}

static void
cache_req_process_node(TfwHttpReq *req, tfw_http_cache_cb_t action)
{
	TfwCacheEntry *ce = NULL;
	TfwHttpResp *resp = NULL;
	TDB *db = node_db();
	TdbIter iter;
	time_t lifetime;

	if (!(ce = tfw_cache_dbce_get(db, &iter, req)))
		goto out;

	if (!(lifetime = tfw_cache_entry_is_live(req, ce)))
		goto out;

	TFW_DBG("Cache: service request w/ key=%lx, ce=%p (len=%u key_len=%u"
		" status_len=%u hdr_num=%u hdr_len=%u key_off=%ld"
		" status_off=%ld hdrs_off=%ld body_off=%ld)\n",
		ce->trec.key, ce, ce->trec.len, ce->key_len, ce->status_len,
		ce->hdr_num, ce->hdr_len, ce->key, ce->status, ce->hdrs,
		ce->body);
	TFW_INC_STAT_BH(cache.hits);

	if (!tfw_handle_validation_req(req, ce))
		goto put;

	if (!(resp = tfw_cache_build_resp(req, ce)))
		goto out;
	/*
	 * RFC 7234 p.4 Constructing Responses from Caches:
	 * When a stored response is used to satisfy a request without
	 * validation, a cache MUST generate an Age header field.
	 */
	if (tfw_cache_set_hdr_age((TfwHttpMsg *)resp, ce)) {
		TFW_WARN("Unable to add Age: header, cached"
			 " response [%p] dropped\n", resp);
		TFW_INC_STAT_BH(clnt.msgs_otherr);
		tfw_http_msg_free((TfwHttpMsg *)resp);
		resp = NULL;
		goto out;
	}
	if (lifetime > ce->lifetime)
		__set_bit(TFW_HTTP_B_RESP_STALE, resp->flags);
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

	TFW_DBG2("Cache: schedule tasklet w/ work: to_cpu=%d from_cpu=%d"
		 " msg=%p key=%lx\n", cpu, smp_processor_id(),
		 cw.msg, key);
	if (tfw_wq_push(&ct->wq, &cw, cpu, &ct->ipi_work, tfw_cache_ipi)) {
		TFW_WARN("Cache work queue overrun: [%s]\n",
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
		TFW_ERR_NL("Can't start cache manager, %d\n", r);
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
			TFW_ERR_NL("%s: unsupported method: '%s'\n",
				   cs->name, val);
			return -EINVAL;
		}
		if (__cache_method_nc_test(method)) {
			TFW_WARN_NL("%s: non-cacheable method '%s' is set "
				    "as cacheable\n",
				   cs->name, val);
		}
		if (__cache_method_test(method)) {
			TFW_WARN_NL("%s: duplicate method: '%s'\n",
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
