/**
 *		Tempesta FW
 *
 * HTTP message manipulation helpers for the protocol processing.
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
#include <linux/ctype.h>

#if DBG_HTTP_PARSER == 0
#undef DEBUG
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
	const TfwStr tmp_hdr = {
		.chunks = (TfwStr []){
			{ .data = (void *)name,	.len = n_len },
			{ .data = S_DLM,	.len = SLEN(S_DLM) },
			{ .data = (void *)val,	.len = v_len },
		},
		.len = n_len + SLEN(S_DLM) + v_len,
		.eolen = 2,
		.nchunks = (val ? 3 : 2)
	};

	return tfw_strdup(pool, &tmp_hdr);
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
	/* TODO: return error if @hdr can't be applied to response or client. */
	def = (TfwHdrDef *)__tfw_http_msg_find_hdr(hdr, array, TFW_HTTP_HDR_RAW,
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
		TfwStrDefV("cookie:",		TFW_HTTP_HDR_COOKIE),
		TfwStrDefV("etag:",		TFW_HTTP_HDR_ETAG),
		TfwStrDefV("host:",		TFW_HTTP_HDR_HOST),
		TfwStrDefV("keep-alive:",	TFW_HTTP_HDR_KEEP_ALIVE),
		TfwStrDefV("referer:",		TFW_HTTP_HDR_REFERER),
		TfwStrDefV("server:",		TFW_HTTP_HDR_SERVER),
		TfwStrDefV("transfer-encoding:",TFW_HTTP_HDR_TRANSFER_ENCODING),
		TfwStrDefV("x-forwarded-for:",	TFW_HTTP_HDR_X_FORWARDED_FOR),
	};

	BUILD_BUG_ON(ARRAY_SIZE(resp_hdrs) != TFW_HTTP_HDR_RAW);

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

	BUILD_BUG_ON(ARRAY_SIZE(req_hdrs) != TFW_HTTP_HDR_RAW);

	return __tfw_http_msg_spec_hid(hdr, req_hdrs);
}

/**
 * Fills @val with second part of special HTTP header containing the header
 * value.
 */
void
__http_msg_hdr_val(TfwStr *hdr, unsigned id, TfwStr *val, bool client)
{
	static const size_t hdr_lens[] = {
		[TFW_HTTP_HDR_HOST]	= SLEN("Host:"),
		[TFW_HTTP_HDR_CONTENT_LENGTH] = SLEN("Content-Length:"),
		[TFW_HTTP_HDR_CONTENT_TYPE] = SLEN("Content-Type:"),
		[TFW_HTTP_HDR_CONNECTION] = SLEN("Connection:"),
		[TFW_HTTP_HDR_X_FORWARDED_FOR] = SLEN("X-Forwarded-For:"),
		[TFW_HTTP_HDR_KEEP_ALIVE] = SLEN("Keep-Alive:"),
		[TFW_HTTP_HDR_TRANSFER_ENCODING] = SLEN("Transfer-Encoding:"),
		[TFW_HTTP_HDR_SERVER]	= SLEN("Server:"),
		[TFW_HTTP_HDR_COOKIE]	= SLEN("Cookie:"),
		[TFW_HTTP_HDR_ETAG]	= SLEN("ETag:"),
		[TFW_HTTP_HDR_REFERER]	= SLEN("Referer:"),
	};

	TfwStr *c, *end;
	int nlen;

	BUILD_BUG_ON(ARRAY_SIZE(hdr_lens) != TFW_HTTP_HDR_RAW);
	/* Empty and plain strings don't have header value part. */
	if (unlikely(TFW_STR_PLAIN(hdr))) {
		TFW_STR_INIT(val);
		return;
	}
	BUG_ON(TFW_STR_DUP(hdr));
	BUG_ON(id >= TFW_HTTP_HDR_RAW);

	if (unlikely(id == TFW_HTTP_HDR_SERVER && client))
		nlen = SLEN("User-Agent:");
	else if (unlikely(id == TFW_HTTP_HDR_ETAG && client))
		nlen = SLEN("If-None-Match:");
	else
		nlen = hdr_lens[id];

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
 */
static inline unsigned int
__hdr_lookup(TfwHttpMsg *hm, const TfwStr *hdr)
{
	unsigned int id = tfw_http_msg_hdr_lookup(hm, hdr);

	if ((id < hm->h_tbl->off) && __hdr_is_singular(hdr))
		__set_bit(TFW_HTTP_B_FIELD_DUPENTRY, hm->flags);

	return id;
}

/**
 * Open currently parsed header.
 */
void
tfw_http_msg_hdr_open(TfwHttpMsg *hm, unsigned char *hdr_start)
{
	TfwStr *hdr = &hm->conn->parser.hdr;

	BUG_ON(!TFW_STR_EMPTY(hdr));

	hdr->data = hdr_start;
	hdr->skb = ss_skb_peek_tail(&hm->msg.skb_head);

	BUG_ON(!hdr->skb);

	TFW_DBG3("open header at %p (char=[%c]), skb=%p\n",
		 hdr_start, *hdr_start, hdr->skb);
}

/**
 * Store fully parsed, probably compound, header (i.e. close it) to
 * HTTP message headers list.
 */
int
tfw_http_msg_hdr_close(TfwHttpMsg *hm, unsigned int id)
{
	TfwStr *h;
	TfwHttpHdrTbl *ht = hm->h_tbl;
	TfwHttpParser *parser = &hm->conn->parser;

	BUG_ON(parser->hdr.flags & TFW_STR_DUPLICATE);
	BUG_ON(id > TFW_HTTP_HDR_RAW);

	/* Close just parsed header. */
	parser->hdr.flags |= TFW_STR_COMPLETE;

	/* Quick path for special headers. */
	if (likely(id < TFW_HTTP_HDR_RAW)) {
		h = &ht->tbl[id];
		if (TFW_STR_EMPTY(h))
			/* Just store the special header in empty slot. */
			goto done;

		/*
		 * Process duplicate header.
		 *
		 * RFC 7230 3.2.2: all duplicates of special singular
		 * headers must be blocked as early as possible,
		 * just when parser reads them.
		 */
		BUG_ON(id < TFW_HTTP_HDR_NONSINGULAR);
		/*
		 * RFC 7230 3.2.2: duplicate of non-singular special
		 * header - leave the decision to classification layer.
		 */
		__set_bit(TFW_HTTP_B_FIELD_DUPENTRY, hm->flags);
		goto duplicate;
	}

	/*
	 * A new raw header is to be stored, but it can be a duplicate of some
	 * existing header and we must find appropriate index for it.
	 * Both the headers, the new one and existing one, can already be
	 * compound.
	 */
	id = __hdr_lookup(hm, &parser->hdr);

	/* Allocate some more room if not enough to store the header. */
	if (unlikely(id == ht->size)) {
		if (tfw_http_msg_grow_hdr_tbl(hm))
			return TFW_BLOCK;

		ht = hm->h_tbl;
	}

	h = &ht->tbl[id];

	if (TFW_STR_EMPTY(h))
		/* Add the new header. */
		goto done;

duplicate:
	h = tfw_str_add_duplicate(hm->pool, h);
	if (unlikely(!h)) {
		TFW_WARN("Cannot close header %p id=%d\n", &parser->hdr, id);
		return TFW_BLOCK;
	}

done:
	*h = parser->hdr;

	TFW_STR_INIT(&parser->hdr);
	TFW_DBG3("store header w/ ptr=%p len=%lu eolen=%u flags=%x id=%d\n",
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
__tfw_http_msg_add_str_data(TfwHttpMsg *hm, TfwStr *str, void *data,
			    size_t len, struct sk_buff *skb)
{
	BUG_ON(str->flags & (TFW_STR_DUPLICATE | TFW_STR_COMPLETE));

	TFW_DBG3("store field chunk len=%lu data=%p(%c) field=<%#x,%lu,%p>\n",
		 len, data, isprint(*(char *)data) ? *(char *)data : '.',
		 str->flags, str->len, str->data);

	if (TFW_STR_EMPTY(str)) {
		if (!str->data)
			__tfw_http_msg_set_str_data(str, data, skb);
		str->len = data + len - (void *)str->data;
		BUG_ON(!str->len);
	}
	else if (likely(len)) {
		TfwStr *sn = tfw_str_add_compound(hm->pool, str);
		if (!sn) {
			TFW_WARN("Cannot grow HTTP data string\n");
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

	TFW_DBG3("grow http headers table to %d items\n", ht->size);

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
		TFW_WARN("Cannot concatenate hdr %.*s with %.*s\n",
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
 */
int
tfw_http_msg_hdr_xfrm_str(TfwHttpMsg *hm, const TfwStr *hdr, unsigned int hid,
			  bool append)
{
	TfwHttpHdrTbl *ht = hm->h_tbl;
	TfwStr *orig_hdr = NULL;
	const TfwStr *s_val = TFW_STR_CHUNK(hdr, 2);

	if (unlikely(!ht)) {
		TFW_WARN("Try to adjust lightweight response.");
		return -EINVAL;
	}

	/* Firstly, get original message header to transform. */
	if (hid < TFW_HTTP_HDR_RAW) {
		orig_hdr = &ht->tbl[hid];
		if (TFW_STR_EMPTY(orig_hdr) && !s_val)
			/* Not found, nothing to delete. */
			return 0;
	} else {
		hid = __hdr_lookup(hm, hdr);
		if (hid == ht->off && !s_val)
			/* Not found, nothing to delete. */
			return 0;
		if (hid == ht->size)
			if (tfw_http_msg_grow_hdr_tbl(hm))
				return -ENOMEM;
		if (hid == ht->off)
			++ht->off;
		else
			orig_hdr = &ht->tbl[hid];
	}

	if (unlikely(append && hid < TFW_HTTP_HDR_NONSINGULAR)) {
		TFW_WARN("Appending to nonsingular header %d\n", hid);
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
 * Add a header, probably duplicated, without any checking of current headers.
 */
int
tfw_http_msg_hdr_add(TfwHttpMsg *hm, const TfwStr *hdr)
{
	unsigned int hid;
	TfwHttpHdrTbl *ht = hm->h_tbl;

	hid = ht->off;
	if (hid == ht->size)
		if (tfw_http_msg_grow_hdr_tbl(hm))
			return -ENOMEM;
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
tfw_http_msg_setup(TfwHttpMsg *hm, TfwMsgIter *it, size_t data_len)
{
	int r;

	if ((r = tfw_msg_iter_setup(it, &hm->msg.skb_head, data_len)))
		return r;
	TFW_DBG2("Set up HTTP message %pK with %lu bytes data\n", hm, data_len);

	return 0;
}
EXPORT_SYMBOL(tfw_http_msg_setup);

static int
__http_msg_add_data_frag(TfwMsgIter *it, TfwHttpMsg *hm, TfwStr *field,
			 const TfwStr *data, unsigned int off)
{
	char *p;
	skb_frag_t *frag = &skb_shinfo(it->skb)->frags[it->frag];
	unsigned int f_size, d_size, f_room, n_copy;

next_frag:
	if (!frag)
		return -E2BIG;

	d_size = data->len - off;
	f_size = skb_frag_size(frag);
	f_room = PAGE_SIZE - frag->page_offset - f_size;
	n_copy = min(d_size, f_room);
	if (!n_copy)
		return 0;

	p = (char *)skb_frag_address(frag) + f_size;
	memcpy_fast(p, data->data + off, n_copy);
	skb_frag_size_add(frag, n_copy);
	ss_skb_adjust_data_len(it->skb, n_copy);

	if (__tfw_http_msg_add_str_data(hm, field, p, n_copy, it->skb))
		return -ENOMEM;

	if (d_size > f_room) {
		frag = ss_skb_frag_next(&it->skb, it->skb_head, &it->frag);
		off += n_copy;
		goto next_frag;
	}

	return 0;
}

/**
 * Similar to tfw_msg_write(), but properly maintain @hm header
 * fields, so that @hm can be used in regular transformations. However,
 * the header name and the value are not split into different chunks,
 * so advanced headers matching is not available for @hm.
 */
int
tfw_http_msg_add_data(TfwMsgIter *it, TfwHttpMsg *hm, TfwStr *field,
		      const TfwStr *data)
{
	char *p;
	unsigned int n_copy;

	WARN_ON_ONCE(TFW_STR_DUP(data));
	WARN_ON_ONCE(!TFW_STR_PLAIN(data));

	n_copy = min(data->len, (unsigned long)skb_tailroom(it->skb));
	if (!n_copy)
		return 0;

	if (it->frag >= 0)
		goto add_frag;

	p = skb_put(it->skb, n_copy);
	memcpy_fast(p, data->data, n_copy);

	if (__tfw_http_msg_add_str_data(hm, field, p, n_copy, it->skb))
		return -ENOMEM;

	if (data->len == n_copy) {
		if (!skb_tailroom(it->skb))
			it->frag = 0;
		return 0;
	}

add_frag:
	it->frag = 0;
	return __http_msg_add_data_frag(it, hm, field, data, n_copy);
}

void
tfw_http_msg_pair(TfwHttpResp *resp, TfwHttpReq *req)
{
	if (unlikely(resp->pair || req->pair))
		TFW_WARN("Response-Request pairing is broken!\n");

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
	TFW_DBG3("Free msg=%p\n", m);
	if (!m)
		return;

	tfw_http_msg_unpair(m);
	ss_skb_queue_purge(&m->msg.skb_head);
	if (!test_bit(TFW_HTTP_B_STREAM_PART, m->flags))
		tfw_http_msg_free((TfwHttpMsg *)m->stream);

	if (m->destructor)
		m->destructor(m);
	tfw_pool_destroy(m->pool);
}
EXPORT_SYMBOL(tfw_http_msg_free);

int
tfw_http_msg_alloc_h_tbl(TfwHttpMsg *hm, int type)
{
	hm->h_tbl = (TfwHttpHdrTbl *)tfw_pool_alloc(hm->pool, TFW_HHTBL_SZ(1));
	if (unlikely(!hm->h_tbl)) {
		TFW_WARN("Insufficient memory to create header table for %s\n",
			 ((type & Conn_Clnt) ? "request" : "response"));
		return -ENOMEM;
	}
	hm->h_tbl->size = __HHTBL_SZ(1);
	hm->h_tbl->off = TFW_HTTP_HDR_RAW;
	bzero_fast(hm->h_tbl->tbl, __HHTBL_SZ(1) * sizeof(TfwStr));

	return 0;
}

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
		? (TfwHttpMsg *)tfw_pool_new(TfwHttpReq, TFW_POOL_ZERO)
		: (TfwHttpMsg *)tfw_pool_new(TfwHttpResp, TFW_POOL_ZERO);
	if (!hm) {
		TFW_WARN("Insufficient memory to create %s message\n",
			 ((type & Conn_Clnt) ? "request" : "response"));
		return NULL;
	}

	if (full && unlikely(tfw_http_msg_alloc_h_tbl(hm, type))) {
		tfw_pool_destroy(hm->pool);
		return NULL;
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

TfwHttpMsg *
tfw_http_msg_alloc_stream_part(TfwHttpMsg *hm_head)
{
	TfwHttpStream *stream;
	int type = TFW_CONN_TYPE(hm_head->conn);

	if (WARN_ON_ONCE(hm_head->stream ||
			 test_bit(TFW_HTTP_B_STREAM_PART, hm_head->flags)))
	{
		return NULL;
	}

	stream = (TfwHttpStream *)tfw_pool_new(TfwHttpStream, TFW_POOL_ZERO);
	if (!stream) {
		TFW_WARN("Insufficient memory to create streamed %s message\n",
			 ((type & Conn_Clnt) ? "request" : "response"));
		return NULL;
	}

	/* Allocate space for trailer headers */
	if (test_bit(TFW_HTTP_B_CHUNKED, hm_head->flags)
	    && unlikely(tfw_http_msg_alloc_h_tbl((TfwHttpMsg *)stream, type)))
	{
		tfw_pool_destroy(stream->pool);
		return NULL;
	}

	__set_bit(TFW_HTTP_B_STREAM_PART, stream->flags);

	spin_lock_init(&stream->stream_lock);
	tfw_http_copy_flags(stream->flags, hm_head->flags);
	/* hm_head is responsible for get/put origin connection. */
	stream->conn = hm_head->conn;
	/* Show the parser that headers was fully parsed. */
	stream->crlf.flags |= TFW_STR_COMPLETE;

	hm_head->stream = stream;
	stream->head    = hm_head;

	return (TfwHttpMsg *)stream;
}

/**
 * Message part was sent out or skipped, clean up the message to normally
 * process the streamed part on next message chunk.
 */
void
tfw_http_msg_collapse_streamed(TfwHttpStream *stream)
{
	stream->off += stream->msg.len;
	stream->msg.len = 0;
	tfw_str_free(stream->pool, &stream->body);
	ss_skb_queue_purge(&stream->msg.skb_head);
}
