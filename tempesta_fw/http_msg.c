/**
 *		Tempesta FW
 *
 * HTTP message manipulation helpers for the protocol processing.
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2021 Tempesta Technologies, Inc.
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
#include <linux/ctype.h>

#undef DEBUG
#if DBG_HTTP_PARSER > 0
#define DEBUG DBG_HTTP_PARSER
#endif

#include "lib/str.h"
#include "gfsm.h"
#include "http_msg.h"
#include "http_parser.h"
#include "ss_skb.h"

/**
 * Build TfwStr representing HTTP header.
 * @name	- header name without ':';
 * @value	- header value;
 */
TfwStr *
tfw_http_msg_make_hdr(TfwPool *pool, const char *name, const char *val)
{
	size_t n_len = strlen(name);
	size_t v_len = val ? strlen(val) : 0;
	size_t n;
	TfwStr *hdr, *h_c;
	char *data;

	n = ((val ? 2 : 1) + 1) * sizeof(TfwStr) + n_len + v_len;
	hdr = (TfwStr *)tfw_pool_alloc(pool, n);
	if (!hdr)
		return NULL;
	TFW_STR_INIT(hdr);

	hdr->len = n_len + v_len;
	hdr->eolen = 2;
	hdr->nchunks = (val ? 2 : 1);
	hdr->chunks = hdr + 1;
	data = (char *)(TFW_STR_LAST(hdr) + 1);

	h_c = TFW_STR_CHUNK(hdr, 0);

	TFW_STR_INIT(h_c);
	h_c->data = data;
	h_c->len = n_len;
	tfw_cstrtolower_wo_avx2(data, name, n_len);

	if (val) {
		data += h_c->len;
		++h_c;

		TFW_STR_INIT(h_c);
		h_c->data = data;
		h_c->len = v_len;
		h_c->flags = TFW_STR_HDR_VALUE;
		memcpy(data, val, v_len);
	}

	return hdr;
}

/**
 * Find @hdr in @array. @array must be sorted in alphabetical
 * order. Similar to bsearch().
 */
const void *
__tfw_http_msg_find_hdr(const TfwStr *hdr, const void *array, size_t n,
			size_t member_sz)
{
	size_t start = 0, end = n;
	int result, fc;
	const TfwStr *h;

	if (!TFW_STR_DUP(hdr))
		h = hdr;
	else
		h = hdr->chunks;
	fc = tolower(*(unsigned char *)(TFW_STR_CHUNK(h, 0)->data));

	while (start < end) {
		size_t mid = start + (end - start) / 2;
		const TfwStr *sh = array + mid * member_sz;
		int sc = *(unsigned char *)sh->data;

		result = fc - sc;
		if (!result)
			result = tfw_stricmpspn(h, sh, ':');

		if (result < 0)
			end = mid;
		else if (result > 0)
			start = mid + 1;
		else
			return sh;
	}

	return NULL;
}
EXPORT_SYMBOL(__tfw_http_msg_find_hdr);

typedef struct {
	TfwStr			hdr;	/* Header name. */
	unsigned int		id;	/* id in TfwHttpHdrTbl */
} TfwHdrDef;
#define TfwStrDefV(v, id)	{{ .data = (v), NULL, sizeof(v) - 1, 0 }, (id) }

static inline unsigned int
__tfw_http_msg_spec_hid(const TfwStr *hdr, const TfwHdrDef array[])
{
	const TfwHdrDef *def;
	size_t size = TFW_HTTP_HDR_RAW - TFW_HTTP_HDR_REGULAR;
	/* TODO: return error if @hdr can't be applied to response or client. */
	def = (TfwHdrDef *)__tfw_http_msg_find_hdr(hdr, array, size,
						   sizeof(TfwHdrDef));

	return def ? def->id : TFW_HTTP_HDR_RAW;
}

/**
 * Get header id in response header table for header @hdr.
 */
unsigned int
tfw_http_msg_resp_spec_hid(const TfwStr *hdr)
{
	static const TfwHdrDef resp_hdrs[] = {
		TfwStrDefV("connection:",	TFW_HTTP_HDR_CONNECTION),
		TfwStrDefV("content-length:",	TFW_HTTP_HDR_CONTENT_LENGTH),
		TfwStrDefV("content-type:",	TFW_HTTP_HDR_CONTENT_TYPE),
		TfwStrDefV("etag:",		TFW_HTTP_HDR_ETAG),
		TfwStrDefV("host:",		TFW_HTTP_HDR_HOST),
		TfwStrDefV("keep-alive:",	TFW_HTTP_HDR_KEEP_ALIVE),
		TfwStrDefV("referer:",		TFW_HTTP_HDR_REFERER),
		TfwStrDefV("server:",		TFW_HTTP_HDR_SERVER),
		TfwStrDefV("set-cookie:",	TFW_HTTP_HDR_SET_COOKIE),
		TfwStrDefV("transfer-encoding:",TFW_HTTP_HDR_TRANSFER_ENCODING),
		TfwStrDefV("x-forwarded-for:",	TFW_HTTP_HDR_X_FORWARDED_FOR),
	};

	BUILD_BUG_ON(ARRAY_SIZE(resp_hdrs) !=
		     TFW_HTTP_HDR_RAW - TFW_HTTP_HDR_REGULAR);

	return __tfw_http_msg_spec_hid(hdr, resp_hdrs);
}

/**
 * Get header id in request header table for header @hdr.
 */
unsigned int
tfw_http_msg_req_spec_hid(const TfwStr *hdr)
{
	static const TfwHdrDef req_hdrs[] = {
		TfwStrDefV("connection:",	TFW_HTTP_HDR_CONNECTION),
		TfwStrDefV("content-length:",	TFW_HTTP_HDR_CONTENT_LENGTH),
		TfwStrDefV("content-type:",	TFW_HTTP_HDR_CONTENT_TYPE),
		TfwStrDefV("cookie:",		TFW_HTTP_HDR_COOKIE),
		TfwStrDefV("host:",		TFW_HTTP_HDR_HOST),
		TfwStrDefV("if-none-match:",	TFW_HTTP_HDR_IF_NONE_MATCH),
		TfwStrDefV("keep-alive:",	TFW_HTTP_HDR_KEEP_ALIVE),
		TfwStrDefV("referer:",		TFW_HTTP_HDR_REFERER),
		TfwStrDefV("transfer-encoding:",TFW_HTTP_HDR_TRANSFER_ENCODING),
		TfwStrDefV("user-agent:",	TFW_HTTP_HDR_USER_AGENT),
		TfwStrDefV("x-forwarded-for:",	TFW_HTTP_HDR_X_FORWARDED_FOR),
	};

	BUILD_BUG_ON(ARRAY_SIZE(req_hdrs) !=
		     TFW_HTTP_HDR_RAW - TFW_HTTP_HDR_REGULAR);

	return __tfw_http_msg_spec_hid(hdr, req_hdrs);
}

/**
 * Fills @val with second part of special HTTP/1.1 header containing the
 * header value.
 *
 * TODO: with the current HTTP-parser implementation (parsing header name,
 * colon, LWS and value into different chunks) this procedure can be
 * simplified to avoid the usage of predefined header arrays.
 */
void
__http_msg_hdr_val(TfwStr *hdr, unsigned id, TfwStr *val, bool client)
{
	static const unsigned char hdr_lens[2][TFW_HTTP_HDR_RAW] = {
		(unsigned char []) {
			[TFW_HTTP_HDR_HOST]		= SLEN("Host:"),
			[TFW_HTTP_HDR_CONTENT_LENGTH]	= SLEN("Content-Length:"),
			[TFW_HTTP_HDR_CONTENT_TYPE]	= SLEN("Content-Type:"),
			[TFW_HTTP_HDR_CONNECTION]	= SLEN("Connection:"),
			[TFW_HTTP_HDR_X_FORWARDED_FOR]	= SLEN("X-Forwarded-For:"),
			[TFW_HTTP_HDR_KEEP_ALIVE]	= SLEN("Keep-Alive:"),
			[TFW_HTTP_HDR_TRANSFER_ENCODING]= SLEN("Transfer-Encoding:"),
			[TFW_HTTP_HDR_SERVER]		= SLEN("Server:"),
			[TFW_HTTP_HDR_SET_COOKIE]	= SLEN("Set-Cookie:"),
			[TFW_HTTP_HDR_ETAG]		= SLEN("ETag:"),
			[TFW_HTTP_HDR_REFERER]		= SLEN("Referer:"),
		},
		(unsigned char []) {
			[TFW_HTTP_HDR_HOST]		= SLEN("Host:"),
			[TFW_HTTP_HDR_CONTENT_LENGTH]	= SLEN("Content-Length:"),
			[TFW_HTTP_HDR_CONTENT_TYPE]	= SLEN("Content-Type:"),
			[TFW_HTTP_HDR_CONNECTION]	= SLEN("Connection:"),
			[TFW_HTTP_HDR_X_FORWARDED_FOR]	= SLEN("X-Forwarded-For:"),
			[TFW_HTTP_HDR_KEEP_ALIVE]	= SLEN("Keep-Alive:"),
			[TFW_HTTP_HDR_TRANSFER_ENCODING]= SLEN("Transfer-Encoding:"),
			[TFW_HTTP_HDR_USER_AGENT]	= SLEN("User-Agent:"),
			[TFW_HTTP_HDR_COOKIE]		= SLEN("Cookie:"),
			[TFW_HTTP_HDR_IF_NONE_MATCH]	= SLEN("If-None-Match:"),
			[TFW_HTTP_HDR_REFERER]		= SLEN("Referer:"),
		},
	};
	TfwStr *c, *end;
	int nlen;

	/* Empty and plain strings don't have header value part. */
	if (unlikely(TFW_STR_PLAIN(hdr))) {
		TFW_STR_INIT(val);
		return;
	}
	BUG_ON(TFW_STR_DUP(hdr));
	BUG_ON(id >= TFW_HTTP_HDR_RAW);

	nlen = hdr_lens[client][id];
	/*
	 * Only Host header is allowed to be empty.
	 * If header string is plain, it is always empty header.
	 * Not empty headers are compound strings.
	 */
	BUG_ON(id == TFW_HTTP_HDR_HOST ? nlen > hdr->len : nlen >= hdr->len);

	*val = *hdr;

	/* Field value, if it exist, lies in the separate chunk.
	 * So we skip several first chunks, containing field name,
	 * to get the field value. If we have field with empty value,
	 * we get an empty string with val->len = 0 and val->data from the
	 * last name's chunk, but it is unimportant.
	 */
	for (c = hdr->chunks, end = hdr->chunks + hdr->nchunks;
	     c < end; ++c)
	{
		BUG_ON(!c->len);

		if (nlen > 0) {
			nlen -= c->len;
			val->len -= c->len;
		}
		else if (unlikely((c->data)[0] == ' '
				  || (c->data)[0] == '\t'))
		{
			/*
			 * RFC 7230: skip OWS before header field.
			 * In most cases OWS is on the same chunk with
			 * the header name.
			 * Header field-value always begins at new chunk.
			 */
			val->len -= c->len;
		}
		else {
			val->chunks = c;
			return;
		}
		BUG_ON(val->nchunks < 1);
		val->nchunks--;
	}

	/* Empty header value part. */
	TFW_STR_INIT(val);
}
EXPORT_SYMBOL(__http_msg_hdr_val);

void
__h2_msg_hdr_val(TfwStr *hdr, TfwStr *out_val)
{
	TfwStr *c, *end;

	if (unlikely(TFW_STR_PLAIN(hdr))) {
		TFW_STR_INIT(out_val);
		return;
	}

	BUG_ON(TFW_STR_DUP(hdr));

	*out_val = *hdr;

	TFW_STR_FOR_EACH_CHUNK(c, hdr, end) {
		if (c->flags & TFW_STR_HDR_VALUE) {
			out_val->chunks = c;
			return;
		}
		out_val->len -= c->len;
		out_val->nchunks--;
	}

	/* Empty header value part. */
	TFW_STR_INIT(out_val);
}
EXPORT_SYMBOL(__h2_msg_hdr_val);

/**
 * Slow check of generic (raw) header for singularity.
 * Some of the header should be special and moved to tfw_http_hdr_t enum,
 * so linear search is Ok here.
 * @return true for headers which must never have duplicates.
 */
static inline bool
__hdr_is_singular(const TfwStr *hdr)
{
	static const TfwStr hdr_singular[] = {
		TFW_STR_STRING("authorization:"),
		TFW_STR_STRING("from:"),
		TFW_STR_STRING("if-unmodified-since:"),
		TFW_STR_STRING("location:"),
		TFW_STR_STRING("max-forwards:"),
		TFW_STR_STRING("proxy-authorization:"),
		TFW_STR_STRING("referer:"),
	};

	return tfw_http_msg_find_hdr(hdr, hdr_singular);
}

/**
 * Lookup for the header @hdr in already collected headers table @ht,
 * i.e. check whether the header is duplicate.
 * The lookup is performed until ':', so header name only is enough in @hdr.
 * @return the header id.
 */
unsigned int
tfw_http_msg_hdr_lookup(TfwHttpMsg *hm, const TfwStr *hdr)
{
	unsigned int id;
	TfwHttpHdrTbl *ht = hm->h_tbl;

	for (id = TFW_HTTP_HDR_RAW; id < ht->off; ++id) {
		TfwStr *h = &ht->tbl[id];
		/* There is no sense to compare against all duplicates. */
		if (h->flags & TFW_STR_DUPLICATE)
			h = TFW_STR_CHUNK(h, 0);
		if (!tfw_stricmpspn(hdr, h, ':'))
			break;
	}

	return id;
}

/**
 * Certain header fields are strictly singular and may not be repeated in
 * an HTTP message. Duplicate of a singular header fields is a bug worth
 * blocking the whole HTTP message.
 *
 * TODO: with the current HTTP-parser implementation (parsing header name,
 * colon, LWS and value into different chunks) we can avoid slow string
 * matcher, which is used in @tfw_http_msg_hdr_lookup(), and can compare
 * strings just by chunks (including searching the stop character) for both
 * HTTP/2 and HTTP/1.1 formatted headers (see @__hdr_name_cmp() below).
 * Thus, @__h1_hdr_lookup() and @tfw_http_msg_hdr_lookup() procedures should
 * be unified to @__hdr_name_cmp() and @__http_hdr_lookup() in order to
 * substitute current mess of multiple partially duplicated procedures with
 * one simple interface.
 */
static inline unsigned int
__h1_hdr_lookup(TfwHttpMsg *hm, const TfwStr *hdr)
{
	unsigned int id = tfw_http_msg_hdr_lookup(hm, hdr);

	if ((id < hm->h_tbl->off) && __hdr_is_singular(hdr))
		__set_bit(TFW_HTTP_B_FIELD_DUPENTRY, hm->flags);

	return id;
}

/**
 * Special procedure comparing the name or HPACK static index of @cmp_hdr (can
 * be in HTTP/2 or HTTP/1.1 format) against the header @hdr which also can be
 * in HTTP/2 or HTTP/1.1 format.
 */
int
__hdr_name_cmp(const TfwStr *hdr, const TfwStr *cmp_hdr)
{
	long n;
	int i1, i2, off1, off2;
	const TfwStr *c1, *c2;

	BUG_ON(hdr->flags & TFW_STR_DUPLICATE);
	BUG_ON(!cmp_hdr->len);

	if (cmp_hdr->hpack_idx && cmp_hdr->hpack_idx == hdr->hpack_idx)
		return 0;

	if (unlikely(!hdr->len))
		return 1;

	i1 = i2 = 0;
	off1 = off2 = 0;
	n = min(hdr->len, cmp_hdr->len);
	c1 = TFW_STR_CHUNK(hdr, 0);
	c2 = TFW_STR_CHUNK(cmp_hdr, 0);
	while (n) {
		int cn = min(c1->len - off1, c2->len - off2);

		if (tfw_cstricmp(c1->data + off1, c2->data + off2, cn))
			return 1;

		n -= cn;
		if (cn == c1->len - off1) {
			off1 = 0;
			++i1;
			c1 = TFW_STR_CHUNK(hdr, i1);
		} else {
			off1 += cn;
		}
		if (cn == c2->len - off2) {
			off2 = 0;
			++i2;
			c2 = TFW_STR_CHUNK(cmp_hdr, i2);
		} else {
			off2 += cn;
		}

		BUG_ON(n && (!c1 || !c2));

		/*
		 * Regardless of the header format (HTTP/2 or HTTP/1.1), the end
		 * of the name must match the end of the chunk, and the following
		 * chunk must contain value with appropriate flag (or it must
		 * contain just a single colon in case of HTTP/1.1-header).
		 */
		if (!off2) {
			const TfwStr *prev_c1;
			/*
			 * If @c2 or @c1 is NULL, then only name is contained in
			 * the @cmp_hdr or @hdr respectively.
			 */
			if (c2
			    && !(c2->flags & TFW_STR_HDR_VALUE)
			    && *c2->data != ':')
				continue;

			prev_c1 = TFW_STR_CHUNK(hdr, i1 - 1);

			if (!off1
			    && !(prev_c1->flags & TFW_STR_HDR_VALUE)
			    && (!c1
				|| c1->flags & TFW_STR_HDR_VALUE
				|| *c1->data == ':'))
				return 0;

			return 1;
		}
	}

	return 1;
}

/**
 * As @__hdr_lookup(), but intended for search during HTTP/1.1=>HTTP/2
 * and HTTP/2=>HTTP/1.1 transformations, comparing the specified name
 * headers in HTTP/2 or HTTP/1.1 format.
 */
int
__http_hdr_lookup(TfwHttpMsg *hm, const TfwStr *hdr)
{
	unsigned int id;
	TfwHttpHdrTbl *ht = hm->h_tbl;

	for (id = TFW_HTTP_HDR_RAW; id < ht->off; ++id) {
		TfwStr *h = &ht->tbl[id];
		/*
		 * We are looking only for the header's name matching,
		 * thus, there is no sense to compare against all duplicates.
		 */
		if (h->flags & TFW_STR_DUPLICATE)
			h = TFW_STR_CHUNK(h, 0);
		if (!__hdr_name_cmp(h, hdr))
			break;
	}

	return id;
}

/**
 * Open currently parsed header.
 */
void
tfw_http_msg_hdr_open(TfwHttpMsg *hm, unsigned char *hdr_start)
{
	TfwStr *hdr = &hm->stream->parser.hdr;

	BUG_ON(!TFW_STR_EMPTY(hdr));

	hdr->data = hdr_start;
	hdr->skb = ss_skb_peek_tail(&hm->msg.skb_head);

	BUG_ON(!hdr->skb);

	T_DBG3("open header at %p (char=[%c]), skb=%p\n",
	       hdr_start, *hdr_start, hdr->skb);
}

/**
 * Store fully parsed, probably compound, header (i.e. close it) to
 * HTTP message headers list.
 */
int
tfw_http_msg_hdr_close(TfwHttpMsg *hm)
{
	TfwStr *hdr, *h;
	TfwHttpHdrTbl *ht = hm->h_tbl;
	TfwHttpParser *parser = &hm->stream->parser;
	unsigned int id = parser->_hdr_tag;

	BUG_ON(parser->hdr.flags & TFW_STR_DUPLICATE);
	BUG_ON(id > TFW_HTTP_HDR_RAW);

	/* Close just parsed header. */
	parser->hdr.flags |= TFW_STR_COMPLETE;

	/* Quick path for special headers. */
	if (likely(id < TFW_HTTP_HDR_RAW)) {
		hdr = h = &ht->tbl[id];
		if (TFW_STR_EMPTY(hdr))
			/* Just store the special header in empty slot. */
			goto done;
		/*
		 * Process duplicate header.
		 *
		 * RFC 7230 3.2.2: all duplicates of special singular
		 * headers must be blocked as early as possible,
		 * just when parser reads them.
		 */
		if (id < TFW_HTTP_HDR_NONSINGULAR) {
			if (WARN_ON_ONCE(!TFW_MSG_H2(hm)
					 || id != TFW_HTTP_HDR_COOKIE))
				return TFW_BLOCK;
		} else if (id != TFW_HTTP_HDR_X_FORWARDED_FOR) {
			/*
			 * RFC 7230 3.2.2: duplicate of non-singular special
			 * header - leave the decision to classification layer.
			 */
			__set_bit(TFW_HTTP_B_FIELD_DUPENTRY, hm->flags);
		}

		goto duplicate;
	}

	/*
	 * A new raw header is to be stored, but it can be a duplicate of some
	 * existing header and we must find appropriate index for it.
	 * Both the headers, the new one and existing one, can already be
	 * compound.
	 */
	id = __http_hdr_lookup(hm, &parser->hdr);

	/* Allocate some more room if not enough to store the header. */
	if (unlikely(id == ht->size)) {
		if (tfw_http_msg_grow_hdr_tbl(hm))
			return TFW_BLOCK;

		ht = hm->h_tbl;
	}

	hdr = h = &ht->tbl[id];

	if (TFW_STR_EMPTY(hdr))
		/* Add the new header. */
		goto done;

duplicate:
	h = tfw_str_add_duplicate(hm->pool, hdr);
	if (unlikely(!h)) {
		T_WARN("Cannot close header %p id=%d\n", &parser->hdr, id);
		return TFW_BLOCK;
	}

done:
	/*
	 * During response HTTP/1.1=>HTTP/2 transformation we need only regular
	 * headers to be transformed, and status-line must not be present in the
	 * resulting HTTP/2 response at all; thus, we do not need status-line in
	 * the indirection map.
	 */
	if (TFW_RESP_TO_H2(hm)
	    && id > TFW_HTTP_STATUS_LINE
	    && tfw_h2_hdr_map((TfwHttpResp *)hm, hdr, id))
		return TFW_BLOCK;

	*h = parser->hdr;

	TFW_STR_INIT(&parser->hdr);
	T_DBG3("store header w/ ptr=%p len=%lu eolen=%u flags=%x id=%d\n",
	       h->data, h->len, h->eolen, h->flags, id);

	/* Move the offset forward if current header is fully read. */
	if (id == ht->off)
		ht->off++;

	return TFW_PASS;
}

/**
 * Fixup the new data chunk starting at @data with length @len to @str.
 *
 * If @str is an empty string, then @len may not be zero. Please use
 * other means for making TfwStr{} strings with such special properties.
 *
 * If @str doesn't have the length set yet, then @len is more like
 * an offset from @data which is the current position in the string.
 * The actual length is set relative to the start of @str.
 *
 * @len might be 0 if the field was fully read, but we have realized
 * that just now by facing CRLF at the start of the current data chunk.
 */
int
__tfw_http_msg_add_str_data(TfwHttpMsg *hm, TfwPool *pool, TfwStr *str, void *data,
			    size_t len, struct sk_buff *skb)
{
	if (WARN_ON_ONCE(str->flags & (TFW_STR_DUPLICATE | TFW_STR_COMPLETE)))
		return -EINVAL;

	T_DBG3("store field chunk len=%lu data=%p(%c) field=<%#x,%lu,%p>\n",
	       len, data, isprint(*(char *)data) ? *(char *)data : '.',
	       str->flags, str->len, str->data);

	if (TFW_STR_EMPTY(str)) {
		if (!str->data)
			__tfw_http_msg_set_str_data(str, data, skb);
		str->len = data + len - (void *)str->data;
		BUG_ON(!str->len);
	}
	else if (likely(len)) {
		TfwStr *sn = tfw_str_add_compound(pool, str);
		if (!sn) {
			T_WARN("Cannot grow HTTP data string\n");
			return -ENOMEM;
		}
		__tfw_http_msg_set_str_data(sn, data, skb);
		tfw_str_updlen(str, data + len);
	}

	return 0;
}

int
tfw_http_msg_grow_hdr_tbl(TfwHttpMsg *hm)
{
	TfwHttpHdrTbl *ht = hm->h_tbl;
	size_t order = ht->size / TFW_HTTP_HDR_NUM, new_order = order << 1;

	ht = tfw_pool_realloc(hm->pool, ht, TFW_HHTBL_SZ(order),
			      TFW_HHTBL_SZ(new_order));
	if (!ht)
		return -ENOMEM;
	ht->size = __HHTBL_SZ(new_order);
	ht->off = hm->h_tbl->off;
	bzero_fast(ht->tbl + __HHTBL_SZ(order),
		   __HHTBL_SZ(order) * sizeof(TfwStr));
	hm->h_tbl = ht;

	T_DBG3("grow http headers table to %d items\n", ht->size);

	return 0;
}

/**
 * Add new header @hdr to the message @hm just before CRLF.
 */
static int
__hdr_add(TfwHttpMsg *hm, const TfwStr *hdr, unsigned int hid)
{
	int r;
	TfwStr it = {};
	TfwStr *h = TFW_STR_CHUNK(&hm->crlf, 0);

	r = ss_skb_get_room(hm->msg.skb_head, hm->crlf.skb, h->data,
			    tfw_str_total_len(hdr), &it);
	if (r)
		return r;

	tfw_str_fixup_eol(&it, tfw_str_eolen(hdr));
	if (tfw_strcpy(&it, hdr))
		return TFW_BLOCK;

	/*
	 * Initialize the header table item by the iterator chunks.
	 * While the data references in the item are valid, some conventions
	 * (e.g. header name and value are placed in different chunks) aren't
	 * satisfied. So don't consider the header for normal HTTP processing.
	 */
	hm->h_tbl->tbl[hid] = it;

	return 0;
}

/**
 * Expand @orig_hdr by appending or replacing with the @hdr.
 * (CRLF is not accounted in TfwStr representation of HTTP headers).
 *
 * Expand the first duplicate header, do not produce more duplicates.
 */
static int
__hdr_expand(TfwHttpMsg *hm, TfwStr *orig_hdr, const TfwStr *hdr, bool append)
{
	int r;
	TfwStr *h, it = {};

	if (TFW_STR_DUP(orig_hdr))
		orig_hdr = __TFW_STR_CH(orig_hdr, 0);
	BUG_ON(!append && (hdr->len < orig_hdr->len));

	h = TFW_STR_LAST(orig_hdr);
	r = ss_skb_get_room(hm->msg.skb_head, h->skb, h->data + h->len,
			    append ? hdr->len : hdr->len - orig_hdr->len, &it);
	if (r)
		return r;

	if (tfw_strcat(hm->pool, orig_hdr, &it)) {
		T_WARN("Cannot concatenate hdr %.*s with %.*s\n",
		       PR_TFW_STR(orig_hdr), PR_TFW_STR(hdr));
		return TFW_BLOCK;
	}

	return tfw_strcpy(append ? &it : orig_hdr, hdr) ? TFW_BLOCK : 0;
}

/**
 * Delete header with identifier @hid from skb data and header table.
 */
static int
__hdr_del(TfwHttpMsg *hm, unsigned int hid)
{
	TfwHttpHdrTbl *ht = hm->h_tbl;
	TfwStr *dup, *end, *hdr = &ht->tbl[hid];

	/* Delete the underlying data. */
	TFW_STR_FOR_EACH_DUP(dup, hdr, end) {
		if (ss_skb_cutoff_data(hm->msg.skb_head, dup, 0,
				       tfw_str_eolen(dup)))
			return TFW_BLOCK;
	};

	/* Delete the header from header table. */
	if (hid < TFW_HTTP_HDR_RAW) {
		TFW_STR_INIT(&ht->tbl[hid]);
	} else {
		if (hid < ht->off - 1)
			memmove(&ht->tbl[hid], &ht->tbl[hid + 1],
				(ht->off - hid - 1) * sizeof(TfwStr));
		--ht->off;
	}

	return 0;
}

/**
 * Substitute header value.
 *
 * The original header may have LF or CRLF as it's EOL and such bytes are
 * not a part of a header field string in Tempesta (at the moment). While
 * substitution, we may want to follow the EOL pattern of the original. So,
 * if the substitute string without the EOL fits into original header, then
 * the fast path can be used. Otherwise, original header is expanded to fit
 * substitute.
 */
static int
__hdr_sub(TfwHttpMsg *hm, const TfwStr *hdr, unsigned int hid)
{
	TfwHttpHdrTbl *ht = hm->h_tbl;
	TfwStr *dst, *tmp, *end, *orig_hdr = &ht->tbl[hid];

	TFW_STR_FOR_EACH_DUP(dst, orig_hdr, end) {
		if (dst->len < hdr->len)
			continue;
		/*
		 * Adjust @dst to have no more than @hdr.len bytes and rewrite
		 * the header in-place. Do not call @ss_skb_cutoff_data if no
		 * adjustment is needed.
		 */
		if (dst->len != hdr->len
		    && ss_skb_cutoff_data(hm->msg.skb_head, dst, hdr->len, 0))
			return TFW_BLOCK;
		if (tfw_strcpy(dst, hdr))
			return TFW_BLOCK;
		goto cleanup;
	}

	if (__hdr_expand(hm, orig_hdr, hdr, false))
		return TFW_BLOCK;
	dst = TFW_STR_DUP(orig_hdr) ? __TFW_STR_CH(orig_hdr, 0) : orig_hdr;

cleanup:
	TFW_STR_FOR_EACH_DUP(tmp, orig_hdr, end) {
		if (tmp != dst
		    && ss_skb_cutoff_data(hm->msg.skb_head, tmp, 0,
					  tfw_str_eolen(tmp)))
			return TFW_BLOCK;
	}

	*orig_hdr = *dst;
	return TFW_PASS;
}

/**
 * Transform HTTP message @hm header with identifier @hid.
 * @hdr must be compound string and contain two or three parts:
 * header name, colon and header value. If @hdr value is empty,
 * then the header will be deleted from @hm.
 * If @hm already has the header it will be replaced by the new header
 * unless @append.
 * If @append is true, then @val will be concatenated to current
 * header with @hid and @name, otherwise a new header will be created
 * if the message has no the header.
 *
 * Note: The substitute string @hdr should have CRLF as EOL. The original
 * string @orig_hdr may have a single LF as EOL. We may want to follow
 * the EOL pattern of the original. For that, the EOL of @hdr needs
 * to be made the same as in the original header field string.
 *
 * Note: In case of response transformation from HTTP/1.1 to HTTP/2, for
 * optimization purposes, we use special add/replace procedures to adjust
 * headers and create HTTP/2 representation at once; for headers deletion
 * procedure there is no sense to use special HTTP/2 handling (the header
 * must not exist in the resulting response); in case of headers appending
 * we at first create the usual HTTP/1.1 representation of the final header
 * and then transform it into HTTP/2 form at the common stage of response
 * HTTP/2 transformation - we have no other choice, since we need a full
 * header for going through the HTTP/2 transformation (i.e. search in the
 * HPACK encoder dynamic index).
 */
int
tfw_http_msg_hdr_xfrm_str(TfwHttpMsg *hm, const TfwStr *hdr, unsigned int hid,
			  bool append)
{
	TfwHttpHdrTbl *ht = hm->h_tbl;
	TfwStr *orig_hdr = NULL;
	const TfwStr *s_val = TFW_STR_CHUNK(hdr, 2);

	if (unlikely(!ht)) {
		T_WARN("Try to adjust lightweight response.");
		return -EINVAL;
	}

	/* Firstly, get original message header to transform. */
	if (hid < TFW_HTTP_HDR_RAW) {
		orig_hdr = &ht->tbl[hid];
		if (TFW_STR_EMPTY(orig_hdr) && !s_val)
			/* Not found, nothing to delete. */
			return 0;
	} else {
		hid = __h1_hdr_lookup(hm, hdr);
		if (hid == ht->off && !s_val)
			/* Not found, nothing to delete. */
			return 0;
		if (hid == ht->size) {
			if (tfw_http_msg_grow_hdr_tbl(hm))
				return -ENOMEM;
			ht = hm->h_tbl;
		}
		if (hid == ht->off)
			++ht->off;
		else
			orig_hdr = &ht->tbl[hid];
	}

	if (unlikely(append && hid < TFW_HTTP_HDR_NONSINGULAR)) {
		T_WARN("Appending to nonsingular header %d\n", hid);
		return -ENOENT;
	}

	if (!orig_hdr || TFW_STR_EMPTY(orig_hdr)) {
		if (unlikely(!s_val))
			return 0;
		return __hdr_add(hm, hdr, hid);
	}

	if (!s_val)
		return __hdr_del(hm, hid);

	if (append) {
		TfwStr hdr_app = {
			.chunks = (TfwStr []){
				{ .data = ", ",		.len = 2 },
				{ .data = s_val->data,	.len = s_val->len }
			},
			.len = s_val->len + 2,
			.nchunks = 2
		};
		return __hdr_expand(hm, orig_hdr, &hdr_app, true);
	}

	return __hdr_sub(hm, hdr, hid);
}

/**
 * Same as @tfw_http_msg_hdr_xfrm_str() but use c-strings as argument.
 */
int
tfw_http_msg_hdr_xfrm(TfwHttpMsg *hm, char *name, size_t n_len,
		      char *val, size_t v_len, unsigned int hid, bool append)
{
	TfwStr new_hdr = {
		.chunks = (TfwStr []){
			{ .data = name,		.len = n_len },
			{ .data = S_DLM,	.len = SLEN(S_DLM) },
			{ .data = val,		.len = v_len },
		},
		.len = n_len + SLEN(S_DLM) + v_len,
		.eolen = 2,
		.nchunks = (val ? 3 : 2)
	};

	BUG_ON(!val && v_len);

	return tfw_http_msg_hdr_xfrm_str(hm, &new_hdr, hid, append);
}

/**
 * Delete @str (any parsed part of HTTP message) from skb data and
 * init @str.
 */
int
tfw_http_msg_del_str(TfwHttpMsg *hm, TfwStr *str)
{
	int r;

	BUG_ON(TFW_STR_DUP(str));

	if ((r = ss_skb_cutoff_data(hm->msg.skb_head, str, 0, 0)))
		return r;

	TFW_STR_INIT(str);

	return 0;
}

/**
 * Remove hop-by-hop headers in the message
 *
 * Connection header should not be removed, tfw_http_set_hdr_connection()
 * optimize removal of the header.
 */
int
tfw_http_msg_del_hbh_hdrs(TfwHttpMsg *hm)
{
	TfwHttpHdrTbl *ht = hm->h_tbl;
	unsigned int hid = ht->off;
	int r = 0;

	do {
		hid--;
		if (hid == TFW_HTTP_HDR_CONNECTION)
			continue;
		if (ht->tbl[hid].flags & TFW_STR_HBH_HDR)
			if ((r = __hdr_del(hm, hid)))
				return r;
	} while (hid);

	return 0;
}

/**
 * Modify message body, add string @data to the end of the body (if @append) or
 * to its beginning.
 */
static int
tfw_http_msg_body_xfrm(TfwHttpMsg *hm, const TfwStr *data, bool append,
		       bool after_trailer)
{
	int r;
	char *st;
	TfwMsgIter it = {.skb_head = hm->msg.skb_head, /* .frag not used. */
			 .skb = hm->body.skb};

	if (!append) {
		/* Insert string just at front of the body. */
		st = TFW_STR_CHUNK(&hm->body, 0)->data;
	}
	else if (likely(!test_bit(TFW_HTTP_B_CHUNKED_TRAILER, hm->flags)
			|| after_trailer))
	{
		/*
		 * Trailing CRLF after chunked body (chunked trailed) was cut
		 * off, restore it back at very end of the body.
		 */
		struct skb_shared_info *shi;
		it.skb = ss_skb_peek_tail(&hm->msg.skb_head);
		shi = skb_shinfo(it.skb);
		if (shi->nr_frags) {
			skb_frag_t *f = &shi->frags[shi->nr_frags - 1];
			st = skb_frag_address(f) + skb_frag_size(f);
		}
		else {
			st = it.skb->data + skb_headlen(it.skb);
		}
	}
	else {
		st = TFW_STR_CURR(&hm->body)->data + TFW_STR_CURR(&hm->body)->len;
		if ((r = tfw_http_iter_set_at(&it, st)))
			return r;
	}

	/* The modifications are done just befor push message into network,
	 * don't bother ourselves with hm stracture maintaining.
	 */
	return tfw_http_msg_insert(&it, &st, data);
}

/**
 * The http1 message (response) is about to be forwarded. If it lacks of framing
 * information add it. The message is fully assembled, so try to use as little
 * modifications as possible.
 */
int
tfw_http_msg_frame_h1_msg(TfwHttpMsg *hm)
{
	int r = 0;
	const DEFINE_TFW_STR(chunked_body_end, "\r\n0\r\n\r\n");
	const DEFINE_TFW_STR(zero_body_end, "0\r\n\r\n");
	const DEFINE_TFW_STR(crlf, "\r\n");
	TfwStr body_end = chunked_body_end;

	/*
	 * If chunked flag is set then either message was in chunked encoding
	 * or it was terminated by connection close. If 'Transfer-Encoding'
	 * header is marked as hop-by-hop, it doesn't require modification,
	 * otherwize need to append chunked as final coding.
	 */
	if (!test_bit(TFW_HTTP_B_CHUNKED, hm->flags))
		return 0;
	if (!(hm->h_tbl->tbl[TFW_HTTP_HDR_TRANSFER_ENCODING].flags
	      & TFW_STR_HBH_HDR))
	{
		r = TFW_HTTP_MSG_HDR_XFRM(hm, "transfer-encoding", "chunked",
					  TFW_HTTP_HDR_TRANSFER_ENCODING, 1);
		if (r)
			return r;
	}

	if (hm->body.len) {
		char data[TFW_ULTOA_BUF_SIZ + 2] = {0};
		TfwStr sz = {.data = data};

		sz.len = tfw_ultohex(hm->body.len, sz.data, TFW_ULTOA_BUF_SIZ);
		if (!sz.len)
			return -EINVAL;
		*(short *)(sz.data + sz.len) = 0x0a0d; /* CRLF, '\r\n' */
		sz.len += 2;

		if ((r = tfw_http_msg_body_xfrm(hm, &sz, false, false)))
			return r;
	}
	else {
		hm->body.data = hm->crlf.data + hm->crlf.len;
		body_end = zero_body_end;
	}

	if (unlikely(test_bit(TFW_HTTP_B_CHUNKED_TRAILER, hm->flags)))
		body_end.len -= 2;
	if ((r = tfw_http_msg_body_xfrm(hm, &body_end, true, false)))
		return r;
	if (unlikely(test_bit(TFW_HTTP_B_CHUNKED_TRAILER, hm->flags))) {
		if ((r = tfw_http_msg_body_xfrm(hm, &crlf, true, true)))
			return r;
	}

	return 0;
}

int
tfw_http_msg_del_parsed_cuts(TfwHttpMsg *hm, bool parsing_done)
{
	int r;
	TfwStr cut, *c, *end, *hdr;

	cut = hm->stream->parser.cut;
	if (!hm->stream->parser.pool || TFW_STR_EMPTY(&cut))
		return 0;

	if ((r = tfw_http_msg_del_str(hm, &hm->stream->parser.cut)))
		return r;
	else
		hm->msg.len -= cut.len;
	if (cut.nchunks)
		tfw_pool_free(hm->stream->parser.pool, cut.data,
			      cut.nchunks * sizeof(TfwStr));
	/*
	 * Message is fully parsed, remove all other unwanted data: 'chunked'
	 * encoding token from Transfer-Encoding header. We remove it only if
	 * it's a last coding.
	 */
	if (!parsing_done || !test_bit(TFW_HTTP_B_CHUNKED, hm->flags))
		return 0;

	/*
	 * The whole header can be removed. Don't remove it, only mark as
	 * hop-by-hop header: such headers are ignored while saved into cache
	 * and never forwarded to h2 clients. Just avoid extra fragmentation
	 * now.
	 */
	hdr = &hm->h_tbl->tbl[TFW_HTTP_HDR_TRANSFER_ENCODING];
	if (!test_bit(TFW_HTTP_B_TE_EXTRA, hm->flags)) {
		hdr->flags |= TFW_STR_HBH_HDR;
		return 0;
	}
	/*
	 * Multiple transfer encodings: remove only final 'chunked'. Although
	 * RFC 7540 encorage us to remove the header we can't: client won't
	 * be able to deduce paylod coding, e.g. gzip.
	 */
	if (TFW_STR_DUP(hdr)) {
		hdr = hdr->chunks + hdr->nchunks - 1;
	}

	cut = *hdr;
	end = cut.chunks + cut.nchunks;
	for (c = cut.chunks; c != end; ++c)
		if (!(c->flags & TFW_STR_NAME)) {
			++cut.chunks;
			--cut.nchunks;
			cut.len -= c->len;
		}
	hdr->nchunks -= cut.nchunks;
	hdr->len -= cut.len;

	return tfw_http_msg_del_str(hm, &cut);
}

/**
 * Add a header, probably duplicated, without any checking of current headers.
 * In case of response transformation from HTTP/1.1 to HTTP/2, for optimization
 * purposes, we use special handling for headers adding (see note for
 * @tfw_http_msg_hdr_xfrm_str() for details).
 */
int
tfw_http_msg_hdr_add(TfwHttpMsg *hm, const TfwStr *hdr)
{
	unsigned int hid;
	TfwHttpHdrTbl *ht;

	ht = hm->h_tbl;
	hid = ht->off;
	if (hid == ht->size) {
		if (tfw_http_msg_grow_hdr_tbl(hm))
			return -ENOMEM;
		ht = hm->h_tbl;
	}
	++ht->off;

	return __hdr_add(hm, hdr, hid);
}

/**
 * Set up @hm with empty SKB space of size @data_len for data writing.
 * Set up the iterator @it to support consecutive writes.
 *
 * This function is intended to work together with tfw_msg_write()
 * or tfw_http_msg_add_data() which use the @it iterator.
 *
 * @hm must be allocated dynamically (NOT statically) as it may have
 * to sit in a queue long after the caller has finished. It's assumed
 * that @hm is properly initialized.
 *
 * It's essential to understand, that "properly initialized" for @hm
 * may mean different things depending on the intended use. Currently
 * this function is called to send a response from cache, or to send
 * an error response. An error response is not parsed or adjusted, so
 * a shorter/faster version of message allocation and initialization
 * may be used. (See __tfw_http_msg_alloc(full=False)).
 */
int
tfw_http_msg_setup(TfwHttpMsg *hm, TfwMsgIter *it, size_t data_len,
		   unsigned int tx_flags)
{
	int r;

	if ((r = tfw_msg_iter_setup(it, &hm->msg.skb_head, data_len, tx_flags)))
		return r;
	T_DBG2("Set up HTTP message %pK with %lu bytes data\n", hm, data_len);

	return 0;
}
EXPORT_SYMBOL(tfw_http_msg_setup);

/**
 * Fill up an HTTP message by iterator @it with data from string @data.
 * Properly maintain @hm header @field, so that @hm can be used in regular
 * transformations. However, the header name and the value are not split into
 * different chunks, so advanced headers matching is not available for @hm.
 */
int
tfw_http_msg_add_data(TfwMsgIter *it, TfwHttpMsg *hm, TfwStr *field,
		      const TfwStr *data)
{
	const TfwStr *c, *end;

	BUG_ON(TFW_STR_DUP(data));
	if (WARN_ON_ONCE(it->frag >= skb_shinfo(it->skb)->nr_frags))
		return -E2BIG;

	TFW_STR_FOR_EACH_CHUNK(c, data, end) {
		char *p;
		unsigned int c_off = 0, c_size, f_room, n_copy;
this_chunk:
		c_size = c->len - c_off;
		if (it->frag >= 0) {
			unsigned int f_size;
			skb_frag_t *frag = &skb_shinfo(it->skb)->frags[it->frag];

			f_size = skb_frag_size(frag);
			f_room = PAGE_SIZE - frag->page_offset - f_size;
			p = (char *)skb_frag_address(frag) + f_size;
			n_copy = min(c_size, f_room);
			skb_frag_size_add(frag, n_copy);
			ss_skb_adjust_data_len(it->skb, n_copy);
		} else {
			f_room = skb_tailroom(it->skb);
			n_copy = min(c_size, f_room);
			p = skb_put(it->skb, n_copy);
		}

		memcpy_fast(p, c->data + c_off, n_copy);
		if (field && n_copy
		    && __tfw_http_msg_add_str_data(hm, hm->pool, field, p,
						   n_copy, it->skb))
		{
			return -ENOMEM;
		}

		/*
		 * The chunk occupied all the spare space in the SKB fragment,
		 * switch to the next fragment.
		 */
		if (c_size >= f_room) {
			if (WARN_ON_ONCE(tfw_msg_iter_next_data_frag(it)
					 && ((c_size != f_room)
					     || (c + 1 < end))))
			{
				return -E2BIG;
			}
			/*
			 * Not all data from the chunk has been copied,
			 * stay in the current chunk and copy the rest to the
			 * next fragment.
			 */
			if (c_size != f_room) {
				c_off += n_copy;
				goto this_chunk;
			}
		}
	}

	return 0;
}

void
tfw_http_msg_pair(TfwHttpResp *resp, TfwHttpReq *req)
{
	if (unlikely(resp->pair || req->pair))
		T_WARN("Response-Request pairing is broken!\n");

	resp->req = req;
	req->resp = resp;
}

static void
tfw_http_msg_unpair(TfwHttpMsg *msg)
{
	if (!msg->pair)
		return;

	msg->pair->pair = NULL;
	msg->pair = NULL;
}

void
tfw_http_msg_free(TfwHttpMsg *m)
{
	T_DBG3("Free msg=%p\n", m);
	if (!m)
		return;

	tfw_http_msg_unpair(m);
	ss_skb_queue_purge(&m->msg.skb_head);

	if (m->destructor)
		m->destructor(m);

	if (TFW_MSG_H2(m))
		tfw_pool_destroy(((TfwHttpReq *)m)->pit.pool);

	tfw_pool_destroy(m->pool);
}
EXPORT_SYMBOL(tfw_http_msg_free);

/**
 * Allocate a new HTTP message.
 * @full indicates how complex a message object is needed. When @full
 * is true, the message is set up and initialized with full support
 * for parsing and subsequent adjustment.
 */
TfwHttpMsg *
__tfw_http_msg_alloc(int type, bool full)
{
	TfwHttpMsg *hm = (type & Conn_Clnt)
			 ? (TfwHttpMsg *)tfw_pool_new(TfwHttpReq,
						      TFW_POOL_ZERO)
			 : (TfwHttpMsg *)tfw_pool_new(TfwHttpResp,
						      TFW_POOL_ZERO);
	if (!hm) {
		T_WARN("Insufficient memory to create %s message\n",
		       ((type & Conn_Clnt) ? "request" : "response"));
		return NULL;
	}

	if (full) {
		hm->h_tbl = (TfwHttpHdrTbl *)tfw_pool_alloc(hm->pool,
							    TFW_HHTBL_SZ(1));
		if (unlikely(!hm->h_tbl)) {
			T_WARN("Insufficient memory to create header table"
			       " for %s\n",
			       ((type & Conn_Clnt) ? "request" : "response"));
			tfw_pool_destroy(hm->pool);
			return NULL;
		}
		hm->h_tbl->size = __HHTBL_SZ(1);
		hm->h_tbl->off = TFW_HTTP_HDR_RAW;
		bzero_fast(hm->h_tbl->tbl, __HHTBL_SZ(1) * sizeof(TfwStr));
	}

	hm->msg.skb_head = NULL;

	if (type & Conn_Clnt) {
		INIT_LIST_HEAD(&hm->msg.seq_list);
		INIT_LIST_HEAD(&((TfwHttpReq *)hm)->fwd_list);
		INIT_LIST_HEAD(&((TfwHttpReq *)hm)->nip_list);
		hm->destructor = tfw_http_req_destruct;
	}

	return hm;
}

int
tfw_http_msg_expand_data(TfwMsgIter *it, struct sk_buff **skb_head,
			 const TfwStr *src, unsigned int *start_off)
{
	const TfwStr *c, *end;

	TFW_STR_FOR_EACH_CHUNK(c, src, end) {
		char *p;
		unsigned long off = 0, cur_len, f_room, min_len;
this_chunk:
		if (!it->skb) {
			if (!(it->skb = ss_skb_alloc(SKB_MAX_HEADER)))
				return -ENOMEM;
			ss_skb_queue_tail(skb_head, it->skb);
			it->frag = -1;
			if (!it->skb_head) {
				it->skb_head = *skb_head;

				if (start_off && *start_off) {
					skb_put(it->skb_head, *start_off);
					*start_off = 0;
				}
			}

			T_DBG3("message expanded by new skb [%p]\n", it->skb);
		}

		cur_len = c->len - off;
		if (it->frag >= 0) {
			unsigned int f_size;
			skb_frag_t *frag = &skb_shinfo(it->skb)->frags[it->frag];

			f_size = skb_frag_size(frag);
			f_room = PAGE_SIZE - frag->page_offset - f_size;
			p = (char *)skb_frag_address(frag) + f_size;
			min_len = min(cur_len, f_room);
			skb_frag_size_add(frag, min_len);
			ss_skb_adjust_data_len(it->skb, min_len);
		} else {
			f_room = skb_tailroom(it->skb);
			min_len = min(cur_len, f_room);
			p = skb_put(it->skb, min_len);
		}

		memcpy_fast(p, c->data + off, min_len);

		if (cur_len >= f_room) {
			/*
			 * If the amount of skb frags is exhausted, allocate new
			 * skb on next iteration (if it will be).
			 */
			if (MAX_SKB_FRAGS <= it->frag + 1) {
				it->skb = NULL;
				it->frag = -1;
			}
			else if (cur_len != f_room || c + 1 < end) {
				struct page *page = alloc_page(GFP_ATOMIC);
				if (!page)
					return -ENOMEM;
				++it->frag;
				skb_fill_page_desc(it->skb, it->frag, page,
						   0, 0);
				T_DBG3("message expanded by new frag %u,"
				       " page=[%p], skb=[%p]\n",
				       skb_shinfo(it->skb)->nr_frags,
				       page_address(page), it->skb);
			}

			if (cur_len != f_room) {
				off += min_len;
				goto this_chunk;
			}
		}
	}

	return 0;
}

static int
tfw_h2_msg_rewrite_data_common(TfwHttpTransIter *mit, const TfwStr *str,
			       const char *stop,
			       void cpy(void *dest, const void *src, size_t n))
{
	const TfwStr *c, *end;
	TfwMsgIter *it = &mit->iter;
	TfwNextHdrOp *next = &mit->next;

	BUG_ON(!stop);
	BUG_ON(TFW_STR_DUP(str));

	TFW_STR_FOR_EACH_CHUNK(c, str, end) {
		const char *addr, *next_ptr;
		long offset, stop_offset;
		unsigned int c_off = 0, f_size, c_size, f_room, n_copy;
this_chunk:
		c_size = c->len - c_off;
		if (it->frag >= 0) {
			skb_frag_t *frag = &skb_shinfo(it->skb)->frags[it->frag];

			f_size = skb_frag_size(frag);
			addr = skb_frag_address(frag);
		} else {
			f_size = skb_headlen(it->skb);
			addr = it->skb->data;
		}

		offset = mit->curr_ptr - addr;
		if (WARN_ON_ONCE(offset < 0 || offset >= f_size))
			return -EINVAL;

		f_room = f_size - offset;
		n_copy = min(c_size, f_room);
		next_ptr = mit->curr_ptr + n_copy;

		/*
		 * If the stop mark is met, we should verify that all the data
		 * will be copied from @str; if not, save offsets for not copied
		 * data from current @str (for subsequent copying after more
		 * space allocation) and exit with corresponding error code.
		 */
		stop_offset = stop - addr;
		if (stop_offset >= 0 && stop_offset < f_size
		    && (next_ptr > stop
			|| (next_ptr == stop
			    && (c_size > f_room || c + 1 < end))))
		{
			WARN_ON_ONCE(next->chunk || next->off);
			next->chunk = TFW_STR_PLAIN(str) ? 0 : c - str->chunks;
			next->off = c_off;

			T_WARN("Unable to transform HTTP/1.1 data into HTTP/2"
			       " format: free space exhausted (accumulated"
			       " length: %lu\n", mit->acc_len);

			return -E2BIG;
		}
		cpy(mit->curr_ptr, c->data + c_off, n_copy);

		T_DBG3("%s: acc_len=%lu, n_copy=%u, mit->curr_ptr='%.*s',"
		       " ptr_diff=%ld\n", __func__, mit->acc_len, n_copy,
		       n_copy, mit->curr_ptr, stop - mit->curr_ptr);

		mit->curr_ptr += n_copy;
		mit->acc_len += n_copy;

		/*
		 * The fragment is exhausted. Move to the next fragment (or skb)
		 * and reset the @mit->curr_ptr pointer.
		 */
		if (c_size >= f_room) {
			if (skb_shinfo(it->skb)->nr_frags > it->frag + 1) {
				skb_frag_t *frag;

				++it->frag;
				frag = &skb_shinfo(it->skb)->frags[it->frag];
				mit->curr_ptr = skb_frag_address(frag);
			}
			else {
				if (WARN_ON_ONCE(it->skb_head == it->skb->next &&
						 (c_size != f_room
						  || c + 1 < end)))
					return -EINVAL;

				tfw_h2_msg_transform_setup(mit, it->skb->next,
							   false);
			}

			if (c_size != f_room) {
				c_off += n_copy;
				goto this_chunk;
			}
		}
	}

	return 0;
}

int
tfw_h2_msg_rewrite_data(TfwHttpTransIter *mit, const TfwStr *str,
			const char *stop)
{
	return tfw_h2_msg_rewrite_data_common(mit, str, stop, memcpy_fast);
}

int
tfw_h2_msg_rewrite_data_lc(TfwHttpTransIter *mit, const TfwStr *str,
			   const char *stop)
{
	return tfw_h2_msg_rewrite_data_common(mit, str, stop, tfw_cstrtolower);
}

/**
 * Insert data from string @data to message at offset defined by message
 * iterator @it and @off. This function doesn't maintain message structure.
 * After insertion message iterator and @data will point at the start of
 * inserted data fragment.
 */
int
tfw_http_msg_insert(TfwMsgIter *it, char **off, const TfwStr *data)
{
	int r;
	TfwStr dst = {};

	if ((r = ss_skb_get_room_w_frag(it->skb_head, it->skb, *off, data->len,
					&dst, &it->frag)))
	{
		return r;
	}

	*off = dst.data;
	it->skb = dst.skb;

	return tfw_strcpy(&dst, data);
}
