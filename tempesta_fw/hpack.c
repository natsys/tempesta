/**
 *		Tempesta FW
 *
 * Copyright (C) 2019-2020 Tempesta Technologies, Inc.
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
#undef DEBUG
#if DBG_HPACK > 0
#define DEBUG DBG_HPACK
#endif

#include "lib/str.h"
#include "pool.h"
#include "str.h"
#include "http_msg.h"
#include "hpack.h"

#include "hpack_tbl.h"

#define HP_HDR_NAME(name)						\
	(&(TfwStr){							\
		.chunks = &(TfwStr){					\
			.data = name,					\
			.len = SLEN(name),				\
		},							\
		.len = SLEN(name),					\
		.nchunks = 1						\
	})

#define HP_HDR_FULL(name, value)					\
	(&(TfwStr){							\
		.chunks = (TfwStr []){					\
			{ .data = name,	.len = SLEN(name) },		\
			{ .data = value, .len = SLEN(value),		\
			  .flags = TFW_STR_HDR_VALUE }			\
		},							\
		.len = SLEN(name) + SLEN(value),			\
		.nchunks = 2						\
	})

#define HP_ENTRY(name, h_tag, hdr_expr)					\
	((TfwHPackEntry){						\
		.hdr = hdr_expr,					\
		.name_len = SLEN(name),					\
		.name_num = 1,						\
		.tag = h_tag						\
})

#define HP_ENTRY_NAME(name, h_tag)					\
	HP_ENTRY(name, h_tag, HP_HDR_NAME(name))

#define HP_ENTRY_FULL(name, value, h_tag)				\
	HP_ENTRY(name, h_tag, HP_HDR_FULL(name, value))

static const TfwHPackEntry static_table[] ____cacheline_aligned = {
	HP_ENTRY_NAME(":authority",		TFW_TAG_HDR_H2_AUTHORITY),
	HP_ENTRY_FULL(":method", "GET",		TFW_TAG_HDR_H2_METHOD),
	HP_ENTRY_FULL(":method", "POST",	TFW_TAG_HDR_H2_METHOD),
	HP_ENTRY_FULL(":path", "/",		TFW_TAG_HDR_H2_PATH),
	HP_ENTRY_FULL(":path", "/index.html",	TFW_TAG_HDR_H2_PATH),
	HP_ENTRY_FULL(":scheme", "http",	TFW_TAG_HDR_H2_SCHEME),
	HP_ENTRY_FULL(":scheme", "https",	TFW_TAG_HDR_H2_SCHEME),
	HP_ENTRY_FULL(":status", "200",		TFW_TAG_HDR_H2_STATUS),
	HP_ENTRY_FULL(":status", "204",		TFW_TAG_HDR_H2_STATUS),
	HP_ENTRY_FULL(":status", "206",		TFW_TAG_HDR_H2_STATUS),
	HP_ENTRY_FULL(":status", "304",		TFW_TAG_HDR_H2_STATUS),
	HP_ENTRY_FULL(":status", "400",		TFW_TAG_HDR_H2_STATUS),
	HP_ENTRY_FULL(":status", "404",		TFW_TAG_HDR_H2_STATUS),
	HP_ENTRY_FULL(":status", "500",		TFW_TAG_HDR_H2_STATUS),
	HP_ENTRY_NAME("accept-charset",		TFW_TAG_HDR_RAW),
	HP_ENTRY_FULL("accept-encoding", "gzip, deflate", TFW_TAG_HDR_RAW),
	HP_ENTRY_NAME("accept-language",	TFW_TAG_HDR_RAW),
	HP_ENTRY_NAME("accept-ranges",		TFW_TAG_HDR_RAW),
	HP_ENTRY_NAME("accept",			TFW_TAG_HDR_ACCEPT),
	HP_ENTRY_NAME("access-control-allow-origin", TFW_TAG_HDR_RAW),
	HP_ENTRY_NAME("age",			TFW_TAG_HDR_RAW),
	HP_ENTRY_NAME("allow",			TFW_TAG_HDR_RAW),
	HP_ENTRY_NAME("authorization",		TFW_TAG_HDR_AUTHORIZATION),
	HP_ENTRY_NAME("cache-control",		TFW_TAG_HDR_CACHE_CONTROL),
	HP_ENTRY_NAME("content-disposition",	TFW_TAG_HDR_RAW),
	HP_ENTRY_NAME("content-encoding",	TFW_TAG_HDR_RAW),
	HP_ENTRY_NAME("content-language",	TFW_TAG_HDR_RAW),
	HP_ENTRY_NAME("content-length",		TFW_TAG_HDR_CONTENT_LENGTH),
	HP_ENTRY_NAME("content-location",	TFW_TAG_HDR_RAW),
	HP_ENTRY_NAME("content-range",		TFW_TAG_HDR_RAW),
	HP_ENTRY_NAME("content-type",		TFW_TAG_HDR_CONTENT_TYPE),
	HP_ENTRY_NAME("cookie",			TFW_TAG_HDR_COOKIE),
	HP_ENTRY_NAME("date",			TFW_TAG_HDR_RAW),
	HP_ENTRY_NAME("etag",			TFW_TAG_HDR_ETAG),
	HP_ENTRY_NAME("expect",			TFW_TAG_HDR_RAW),
	HP_ENTRY_NAME("expires",		TFW_TAG_HDR_RAW),
	HP_ENTRY_NAME("from",			TFW_TAG_HDR_RAW),
	HP_ENTRY_NAME("host",			TFW_TAG_HDR_HOST),
	HP_ENTRY_NAME("if-match",		TFW_TAG_HDR_RAW),
	HP_ENTRY_NAME("if-modified-since",	TFW_TAG_HDR_IF_MODIFIED_SINCE),
	HP_ENTRY_NAME("if-none-match",		TFW_TAG_HDR_IF_NONE_MATCH),
	HP_ENTRY_NAME("if-range",		TFW_TAG_HDR_RAW),
	HP_ENTRY_NAME("if-unmodified-since",	TFW_TAG_HDR_RAW),
	HP_ENTRY_NAME("last-modified",		TFW_TAG_HDR_RAW),
	HP_ENTRY_NAME("link",			TFW_TAG_HDR_RAW),
	HP_ENTRY_NAME("location",		TFW_TAG_HDR_RAW),
	HP_ENTRY_NAME("max-forwards",		TFW_TAG_HDR_RAW),
	HP_ENTRY_NAME("proxy-authenticate",	TFW_TAG_HDR_RAW),
	HP_ENTRY_NAME("proxy-authorization",	TFW_TAG_HDR_RAW),
	HP_ENTRY_NAME("range",			TFW_TAG_HDR_RAW),
	HP_ENTRY_NAME("referer",		TFW_TAG_HDR_REFERER),
	HP_ENTRY_NAME("refresh",		TFW_TAG_HDR_RAW),
	HP_ENTRY_NAME("retry-after",		TFW_TAG_HDR_RAW),
	HP_ENTRY_NAME("server",			TFW_TAG_HDR_SERVER),
	HP_ENTRY_NAME("set-cookie",		TFW_TAG_HDR_RAW),
	HP_ENTRY_NAME("strict-transport-security", TFW_TAG_HDR_RAW),
	HP_ENTRY_NAME("transfer-encoding",	TFW_TAG_HDR_TRANSFER_ENCODING),
	HP_ENTRY_NAME("user-agent",		TFW_TAG_HDR_USER_AGENT),
	HP_ENTRY_NAME("vary",			TFW_TAG_HDR_RAW),
	HP_ENTRY_NAME("via",			TFW_TAG_HDR_RAW),
	HP_ENTRY_NAME("www-authenticate",	TFW_TAG_HDR_RAW)
};

#define HPACK_STATIC_ENTRIES (sizeof(static_table) / sizeof(static_table[0]))

/* Limit for the HPACK variable-length integer. */
#define HPACK_LIMIT			(1 << 20)

/*
 * Estimated overhead associated with an encoder/decoder index entry (see
 * RFC 7541 section 4.1 for details).
 */
#define HPACK_ENTRY_OVERHEAD		32

/**
 * ------------------------------------------------------------------------
 *	HPACK Decoder functionality
 * ------------------------------------------------------------------------
 */

/* States HPACK decoder message processing. */
enum {
	HPACK_STATE_READY		= 0,
	HPACK_STATE_INDEX,
	HPACK_STATE_NAME,
	HPACK_STATE_NAME_LENGTH,
	HPACK_STATE_NAME_TEXT,
	HPACK_STATE_INDEXED_NAME_TEXT,
	HPACK_STATE_VALUE,
	HPACK_STATE_VALUE_LENGTH,
	HPACK_STATE_VALUE_TEXT,
	HPACK_STATE_ALL_INDEXED,
	HPACK_STATE_WINDOW,
	_HPACK_STATE_NUM
};

#define HPACK_STATE_MASK		0x0F

/* Index should be added into decoder dynamic table. */
#define HPACK_FLAGS_ADD			0x010
/* Index without literal value. */
#define HPACK_FLAGS_NO_VALUE		0x020
/* Transit header field. */
#define HPACK_FLAGS_TRANSIT		0x040
/* Huffman encoding used for field name. */
#define HPACK_FLAGS_HUFFMAN_NAME	0x080
/* Huffman encoding used for field value. */
#define HPACK_FLAGS_HUFFMAN_VALUE	0x100

#define NEXT_STATE(new)						\
do {								\
	state &= ~HPACK_STATE_MASK;				\
	state |= (new);						\
} while (0)

/*
 * Flexible integer decoding as specified in the HPACK RFC-7541. If the
 * variable-length integer greater than defined limit, this is the malformed
 * request and we should drop the parsing process.
 */
#define GET_FLEXIBLE_lambda(x, new_state, lambda)		\
do {								\
	unsigned int __m = 0;					\
	unsigned int __c;					\
	do {							\
		if (src >= last) {				\
			hp->shift = __m;			\
			NEXT_STATE(new_state);			\
			lambda;					\
			goto out;				\
		}						\
		__c = *src++;					\
		x += (__c & 127) << __m;			\
		__m += 7;					\
		if ((x) > HPACK_LIMIT) {			\
			r = T_DROP;				\
			goto out;				\
		}						\
	} while (__c > 127);					\
} while (0)

#define GET_FLEXIBLE(x, new_state)				\
	GET_FLEXIBLE_lambda(x, new_state, {})

/* Continue decoding after interruption due to absence of the next fragment.
 * If the variable-length integer greater than defined limit, this is the
 * malformed request and we should drop the parsing process.
 */
#define GET_CONTINUE_lambda(x, lambda)				\
do {								\
	unsigned int __m = hp->shift;				\
	unsigned int __c = *src++;				\
	WARN_ON_ONCE(!x);					\
	x += (__c & 127) << __m;				\
	__m += 7;						\
	if ((x) > HPACK_LIMIT) {				\
		r = T_DROP;					\
		goto out;					\
	}							\
	while (__c > 127) {					\
		if (src >= last) {				\
			hp->shift = __m;			\
			lambda;					\
			goto out;				\
		}						\
		__c = *src++;					\
		x = (__c & 127) << __m | x;			\
		__m += 7;					\
		if ((x) > HPACK_LIMIT) {			\
			r = T_DROP;				\
			goto out;				\
		}						\
	}							\
	lambda;							\
} while (0)

#define GET_CONTINUE(x)						\
	GET_CONTINUE_lambda(x, {})

#define SET_NEXT()						\
do {								\
	hp->curr += 8;						\
	hp->hctx = hp->hctx << 8 | *src++;			\
	--hp->length;						\
	T_DBG3("%s: set next, hp->curr=%d, hp->hctx=%hx,"	\
	       " hp->length=%lu, n=%lu, to_parse=%lu\n",	\
	       __func__, hp->curr, hp->hctx, hp->length, n,	\
	       last - src);					\
} while (0)

#define	BUFFER_HDR_INIT(length, it)				\
do {								\
	(it)->hdr.data = (it)->pos;				\
	(it)->hdr.len = length;					\
	(it)->next = &(it)->hdr;				\
} while (0)

#define	BUFFER_NAME_OPEN(length)				\
do {								\
	WARN_ON_ONCE(!TFW_STR_EMPTY(&it->hdr));			\
	if (state & HPACK_FLAGS_HUFFMAN_NAME) {			\
		BUFFER_GET(length, it);				\
		if (!it->pos) {					\
			r = T_DROP;				\
			goto out;				\
		}						\
		BUFFER_HDR_INIT(length, it);			\
	}							\
} while (0)

#define	BUFFER_VAL_OPEN(length)					\
do {								\
	WARN_ON_ONCE(TFW_STR_EMPTY(it->parsed_hdr));		\
	it->nm_len = it->parsed_hdr->len;			\
	it->nm_num = it->parsed_hdr->nchunks			\
		? it->parsed_hdr->nchunks			\
		: 1;						\
	if (state & HPACK_FLAGS_HUFFMAN_VALUE) {		\
		BUFFER_GET(length, it);				\
		if (!it->pos) {					\
			r = T_DROP;				\
			goto out;				\
		}						\
		if (!TFW_STR_EMPTY(&it->hdr))			\
			it->next = tfw_hpack_exp_hdr(req->pool,	\
						     length, it); \
		else						\
			BUFFER_HDR_INIT(length, it);		\
	}							\
} while (0)

static inline int
__hpack_process_hdr_name(TfwHttpReq *req)
{
	const TfwStr *c, *end;
	TfwMsgParseIter *it = &req->pit;
	const TfwStr *hdr = &it->hdr, *next = it->next;
	int ret = T_BAD;

	WARN_ON_ONCE(next != hdr);
	TFW_STR_FOR_EACH_CHUNK(c, next, end) {
		bool last = c + 1 == end;

		WARN_ON_ONCE(ret == T_OK);
		ret = tfw_h2_parse_req_hdr(c->data, c->len, req, last, false);
		if (unlikely(ret < T_POSTPONE))
			return ret;
	}
	return ret ? T_DROP : T_OK;
}

static inline int
__hpack_process_hdr_value(TfwHttpReq *req)
{
	const TfwStr *chunk, *end;
	TfwMsgParseIter *it = &req->pit;
	const TfwStr *hdr = &it->hdr, *next = it->next;
	int ret = T_BAD;

	BUG_ON(TFW_STR_DUP(hdr));
	if (TFW_STR_PLAIN(hdr)) {
		WARN_ON_ONCE(hdr != next);
		chunk = hdr;
		end = hdr + 1;
	} else {
		/*
		 * In case of compound @hdr the @next can point either to the
		 * @hdr itself (if only header's value has been Huffman-decoded,
		 * i.e. in case of indexed or raw header's name), or to some
		 * chunk inside the @hdr (if both, the name and the value, has
		 * been Huffman-decoded).
		 */
		chunk = (hdr != next) ? next : next->chunks;
		end = hdr->chunks + hdr->nchunks;
	}

	while (chunk < end) {
		bool last = chunk + 1 == end;

		WARN_ON_ONCE(ret == T_OK);
		ret = tfw_h2_parse_req_hdr(chunk->data, chunk->len,
					   req, last, true);
		if (unlikely(ret < T_POSTPONE))
			return ret;
		++chunk;
	}
	return ret ? T_DROP : T_OK;
}

#define	HPACK_DECODE_PROCESS_STRING(field, len)			\
do {								\
	T_DBG3("%s: decoding, len=%lu, n=%lu, tail=%lu\n",	\
	       __func__, len, n, last - src);			\
	r = tfw_huffman_decode(hp, req, src, len);		\
	src += len;						\
	if (r)							\
		goto out;					\
	WARN_ON_ONCE(hp->length);				\
	hp->hctx = 0;						\
	tfw_huffman_init(hp);					\
	if ((r = __hpack_process_hdr_##field(req)))		\
		goto out;					\
	T_DBG3("%s: processed decoded, tail=%lu\n", __func__,	\
	       last - src);					\
} while (0)

#define HPACK_PROCESS_STRING(len, value_stage)			\
do {								\
	hp->length -= len;					\
	r = tfw_h2_parse_req_hdr(src, len, req, !hp->length,	\
				 value_stage);			\
	src += len;						\
	T_DBG3("%s: processed plain, len=%lu, n=%lu, tail=%lu,"	\
	       " hp->length=%lu\n", __func__, len, n,		\
	       last - src, hp->length);				\
	if (r)							\
		goto  out;					\
	WARN_ON_ONCE(hp->length);				\
} while (0)

static unsigned long act_hp_str_n;

void
write_int(unsigned long index, unsigned short max, unsigned short mask,
	  TfwHPackInt *__restrict res_idx)
{
	unsigned int size = 1;
	unsigned char *dst = res_idx->buf;

	if (likely(index < max)) {
		index |= mask;
	}
	else {
		++size;
		*dst++ = max | mask;
		index -= max;
		while (index > 0x7F) {
			++size;
			*dst++ = (index & 0x7F) | 0x80;
			index >>= 7;
		}
	}
	*dst = index;
	res_idx->sz = size;
}

static inline TfwStr *
tfw_hpack_exp_hdr(TfwPool *__restrict pool, unsigned long len,
		  TfwMsgParseIter *__restrict it)
{
	TfwStr *new;

	if (!(new = tfw_str_add_compound(pool, &it->hdr)))
		return NULL;

	new->data = it->pos;
	new->len = len;
	it->hdr.len += len;

	return new;
}

static inline int
tfw_hpack_huffman_write(char sym, TfwHttpReq *__restrict req)
{
	bool np;
	TfwMsgParseIter *it = &req->pit;

	if (it->rspace) {
		--it->rspace;
		*it->pos++ = sym;
		return 0;
	}

	if (!(it->pos = __tfw_pool_alloc(it->pool, 1, false, &np)))
		return -ENOMEM;

	*it->pos = sym;

	T_DBG3("%s: it->rspace=%lu, sym=%c, np=%d\n", __func__,
	       it->rspace, sym, np);

	if (!np) {
		TfwStr *hdr = &it->hdr;
		TfwStr *last = TFW_STR_LAST(hdr);

		T_DBG3("%s: add to hdr, hdr->len=%lu, last->len=%lu,"
		       " last->data=%.*s\n", __func__, hdr->len, last->len,
		       (int)last->len, last->data);

		++hdr->len;
		if (!TFW_STR_PLAIN(hdr))
			++last->len;
		return 0;
	}

	return tfw_hpack_exp_hdr(req->pool, 1, it) ? 0 : -ENOMEM;
}

static int
huffman_decode_tail(TfwHPack *__restrict hp, TfwHttpReq *__restrict req,
		    unsigned int offset)
{
	char sym;
	unsigned int i;

	for (;;) {
		int shift;

		if (hp->curr == -HT_NBITS) {
			if (likely(offset == 0))
				return T_OK;
			else
				return T_DROP;
		}

		i = (hp->hctx << -hp->curr) & HT_NMASK;
		shift = ht_decode[offset + i].shift;
		T_DBG3("%s: hp->curr=%d, hp->hctx=%hx, hp->length=%lu,"
		       " i=%u, shift=%d, offset=%u\n", __func__,
		       hp->curr, hp->hctx, hp->length, i, shift, offset);
		if (likely(shift > 0)) {
			if (shift <= hp->curr + HT_NBITS) {
				sym = (char)ht_decode[offset + i].offset;
				if (tfw_hpack_huffman_write(sym, req))
					return T_DROP;

				hp->curr -= shift;
				offset = 0;
			} else {
				break;
			}
		}
		else if (shift < 0) {
			/*
			 * Last full prefix processed here, to allow EOS
			 * padding detection.
			 */
			if (likely(offset == 0)) {
				if ((i ^ (HT_EOS_HIGH >> 1)) <
				    (1U << -hp->curr)) {
					return T_OK;
				}
			}
			/*
			 * The first condition here equivalent to the
			 * '-shift <= hp->curr + HT_NBITS', but working
			 * faster.
			 */
			if (shift >= -HT_NBITS - hp->curr
			    && ht_decode[offset + i].offset == 0)
			{
				T_DBG3("%s: unexpected EOS detected\n",
				       __func__);
				return T_DROP;
			}

			return T_DROP;
		}
		else {
			/* @shift must not be zero. */
			WARN_ON_ONCE(1);
			return T_DROP;
		}
	}
	if (likely(offset == 0)) {
		if ((i ^ (HT_EOS_HIGH >> 1)) < (1U << -hp->curr)) {
			return T_OK;
		}
	}
	return T_DROP;
}

static int
huffman_decode_tail_s(TfwHPack *__restrict hp, TfwHttpReq *__restrict req,
		      unsigned int offset)
{
	char sym;
	int shift;
	unsigned int i;

	if (hp->curr == -HT_MBITS)
		return T_DROP;

	i = (hp->hctx << -hp->curr) & HT_MMASK;
	shift = ht_decode[offset + i].shift;

	T_DBG3("%s: hp->curr=%d, hp->hctx=%hx, hp->length=%lu, i=%u,"
	       " shift=%d, offset=%u\n", __func__, hp->curr, hp->hctx,
	       hp->length, i, shift, offset);

	if (likely(shift > 0)) {
		if (likely(shift <= hp->curr + HT_NBITS)) {
			sym = (char)ht_decode[offset + i].offset;
			if (tfw_hpack_huffman_write(sym, req))
				return T_DROP;
			hp->curr -= shift;
			return huffman_decode_tail(hp, req, 0);
		}
	}
	else {
		/*
		 * @shift for short tables must be greater
		 * than zero.
		 */
		WARN_ON_ONCE(1);
	}

	return T_DROP;
}

static int
tfw_huffman_decode(TfwHPack *__restrict hp, TfwHttpReq *__restrict req,
		   const unsigned char *__restrict src, unsigned long n)
{
	unsigned int offset;
	const unsigned char *last = src + n;

	WARN_ON_ONCE(n > hp->length);
	if (unlikely(!n))
		return T_OK;

	SET_NEXT();
	for (;;) {
		offset = 0;
		for (;;) {
			int shift;
			unsigned int i;

			if (hp->curr <= 0) {
				if (likely(src < last)) {
					SET_NEXT();
				} else if (hp->length) {
					return T_POSTPONE;
				} else {
					/*
					 * Last full prefix also processed here
					 * (see hp->curr <= 0 above).
					 */
					return huffman_decode_tail(hp, req,
								   offset);
				}
			}
			i = (hp->hctx >> hp->curr) & HT_NMASK;
			shift = ht_decode[offset + i].shift;
			offset = ht_decode[offset + i].offset;
			T_DBG3("%s: shift, hp->curr=%d, hp->hctx=%hx,"
			       " hp->length=%lu, n=%lu, to_parse=%lu, i=%u,"
			       " shift=%d, offset=%u, offset=%c\n", __func__,
			       hp->curr, hp->hctx, hp->length, n, last - src,
			       i, shift, offset, (char)offset);
			if (likely(shift > 0)) {
				if (tfw_hpack_huffman_write((char)offset, req))
					return T_DROP;
				hp->curr -= shift;
				offset = 0;
			}
			else if (shift < 0) {
				hp->curr += shift;
				if (offset >= HT_SMALL) {
					break;
				}
				if (unlikely(offset == 0)) {
					goto end;
				}
			}
			else {
				/* @shift must not be zero. */
				WARN_ON_ONCE(1);
				goto end;
			}
		}
		hp->curr += HT_NBITS - HT_MBITS;
		/*
		 * With various optimization options, the anonymous block here
		 * leads to the generation of more efficient code.
		 */
		{
			int shift;
			unsigned int i;

			if (hp->curr < 0) {
				if (likely(src < last)) {
					SET_NEXT();
				} else if (hp->length) {
					return T_POSTPONE;
				} else {
					return huffman_decode_tail_s(hp, req,
								     offset);
				}
			}
			i = (hp->hctx >> hp->curr) & HT_MMASK;
			shift = ht_decode[offset + i].shift;
			offset = ht_decode[offset + i].offset;
			T_DBG3("%s: short shift, hp->curr=%d, hp->hctx=%hx,"
			       " hp->length=%lu, n=%lu, to_parse=%lu, i=%u,"
			       " shift=%d, offset=%u, offset=%c\n", __func__,
			       hp->curr, hp->hctx, hp->length, n, last - src,
			       i, shift, offset, (char)offset);
			if (likely(shift > 0)) {
				if (tfw_hpack_huffman_write((char)offset, req))
					return T_DROP;
				hp->curr -= shift;
			}
			else {
				/*
				 * @shift for short tables must be greater
				 * than zero.
				 */
				WARN_ON_ONCE(1);
				break;
			}
		}
	}
end:
	return T_DROP;
}

static int
tfw_hpack_set_entry(TfwPool *__restrict h_pool, TfwMsgParseIter *__restrict it,
		    TfwHPackEntry *__restrict entry, bool *__restrict np)
{
	char *data;
	TfwStr *d, *d_hdr;
	const TfwStr *s, *end, *s_hdr = it->parsed_hdr;
	unsigned long size = sizeof(TfwHPackEntry);

	if (WARN_ON_ONCE(TFW_STR_PLAIN(s_hdr) || TFW_STR_DUP(s_hdr)))
		return -EINVAL;

	size += (s_hdr->nchunks + 1) * sizeof(TfwStr) + s_hdr->len;
	T_DBG3("%s: size=%lu, s_hdr->nchunks=%u, s_hdr->len=%lu\n", __func__,
	       size, s_hdr->nchunks, s_hdr->len);
	if (!(d_hdr = __tfw_pool_alloc(h_pool, size, true, np)))
		return -ENOMEM;

	*d_hdr = *s_hdr;
	d_hdr->chunks = d_hdr + 1;
	data = (char *)(TFW_STR_LAST(d_hdr) + 1);

	d = d_hdr->chunks;
	TFW_STR_FOR_EACH_CHUNK(s, s_hdr, end) {
		*d = *s;
		d->data = data;
		memcpy_fast(data, s->data, s->len);
		T_DBG3("%s: copy cycle, d->len=%lu, d->data='%.*s',"
		       " d->flags=%hu\n", __func__, d->len, (int)d->len,
		       d->data, d->flags);
		data += s->len;
		++d;
	}

	T_DBG3("%s: entry created, d_hdr->nchunks=%u, d_hdr->len=%lu,"
	       " d_hdr->flags=%hu, it->nm_len=%lu, it->nm_num=%u, it->tag=%u\n",
	       __func__, d_hdr->nchunks, d_hdr->len, d_hdr->flags, it->nm_len,
	       it->nm_num, it->tag);

	entry->hdr = d_hdr;
	entry->name_len = it->nm_len;
	entry->name_num = it->nm_num;
	entry->tag = it->tag;
	entry->last = false;

	return 0;
}

/*
 * The procedure for adding new header into the HPACK decoder table.
 * Note, that our decoder dynamic table must satisfy several main requirements:
 *	1. Provide fast direct access to entries by index;
 *	2. Be able to increase, since the real size of our table is always
 *	   greater than it's standardized pseudo-size (RFC 7541 section 4.1);
 * 	3. Store the records with variable size (headers strings and their
 *	   @TfwStr descriptors).
 * To meet this specification, the current decoder dynamic table is using two
 * pools (see @pool and @h_pool members in @TfwHPackDTbl structure description):
 * the first one is intended for storage of constant length entries (because we
 * need a quick access by index for the entries of decoder table) and it is
 * always a single resizable chunk in the memory, relocatable between different
 * pages in the pool (in case of storage growth); the purpose of the second pool
 * is to store records with variable size (the headers strings and their @TfwStr
 * descriptors) - this storage area cannot be relocated during growth due to
 * internal pointers of @TfwStr, but can be shared between different pages of
 * the pool; in general scheme the first module refers to the second one.
 */
static int
tfw_hpack_add_index(TfwHPackDTbl *__restrict tbl,
		    TfwMsgParseIter *__restrict it)
{
	int r;
	bool new_page;
	unsigned int delta;
	unsigned int window, size, new_size;
	unsigned long hdr_len = it->parsed_hdr->len;
	unsigned int count = tbl->n;
	unsigned int curr = tbl->curr;
	unsigned int length = tbl->length;
	TfwHPackEntry *entry, *prev_entry, *entries = tbl->entries;

	/* Check for integer overflow occurred during @delta calculation. */
	if ((delta = HPACK_ENTRY_OVERHEAD + hdr_len) < hdr_len)	{
		T_WARN("HPACK decoder: very big header (hdr_len = %lu). The"
		       " entry cannot be added into dynamic table\n", hdr_len);
		return -EINVAL;
	}

	size = tbl->size;
	new_size = size + delta;
	window = tbl->window;

	T_DBG3("%s: max table size: %u, current size: %u, new size: %u, delta:"
	       " %u\n", __func__, window, size, new_size, delta);
	/*
	 * The last condition 'new_size < delta' was added to handle an
	 * integer overflow, which can occur during summation of the actual
	 * window size with delta.
	 */
	if (new_size > window || unlikely(new_size < delta)) {
		if (delta <= window) {
			TfwHPackEntry *cp;
			unsigned int early = curr;

			if (curr >= count) {
				early -= count;
			} else {
				early += length - count;
			}

			window -= delta;
			T_DBG3("%s: curr: %u, early entry: %u (%u entries),"
			       "maximum allowed decreased size: %u\n",  __func__,
			       curr, early, count, window);

			cp = entries + early;
			do {
				size -= HPACK_ENTRY_OVERHEAD + cp->hdr->len;
				T_DBG3("%s: dropped index: %u\n", __func__,
				       early);
				if (cp->last)
					tfw_pool_clean(tbl->h_pool, cp->hdr);
				early++;
				cp++;
				count--;
				if (unlikely(early == length)) {
					early = 0;
					cp = entries;
				}
			} while (size > window);

			new_size = size + delta;
		} else {
			/*
			 * This branch handles rare case where delta itself is
			 * greater than the current window size. Clean of the
			 * entire table and exit in this case.
			 */
			T_DBG3("%s: cleaning of the entire table...",  __func__);
			if (count) {
				TfwHPackEntry *cp;

				if (curr >= count) {
					curr -= count;
				} else {
					curr += length - count;
				}

				cp = entries + curr;
				do {
					T_DBG3("%s: drop index: %u\n", __func__,
					       curr);
					if (cp->last)
						tfw_pool_clean(tbl->h_pool,
							       cp->hdr);
					curr++;
					cp++;
					if (unlikely(curr == length)) {
						curr = 0;
						cp = entries;
					}
				} while (--count);
				tbl->n = 0;
				tbl->curr = 0;
				tbl->size = 0;
			}
			return 0;
		}
	} else if (unlikely(count == length)) {
		TfwHPackEntry *previous = entries;
		TfwPool *pool = tbl->pool;
		unsigned long block, new_block, wrap, tail;

		T_DBG3("%s: reallocation index structures...", __func__);
		if (length) {
			block = length * sizeof(TfwHPackEntry);
			new_block = block << 1;
			entries = tfw_pool_realloc_no_copy(pool, entries,
							   block, new_block);
			if (unlikely(!entries))
				return -ENOMEM;

			length <<= 1;
			wrap = curr * sizeof(TfwHPackEntry);
			tail = block - wrap;
			if (!curr && entries == previous) {
				curr = count;
			}
			else if (entries == previous) {
				memcpy_fast(entries + new_block - tail,
					    entries + wrap, tail);
			}
			else {
				if (tail)
					memcpy_fast(entries, previous + wrap,
						    tail);
				if (wrap)
					memcpy_fast(entries + tail, previous,
						    wrap);

				tfw_pool_clean(pool, NULL);
				curr = count;
			}
		} else {
			length = 32;
			new_block = length * sizeof(TfwHPackEntry);
			entries = tfw_pool_alloc(pool, new_block);
			if (unlikely(!entries))
				return -ENOMEM;
		}
		T_DBG3("%s: table extended, length=%u, curr=%u\n", __func__,
		       length, curr);

		tbl->length = length;
		tbl->entries = entries;
	}

	entry = entries + curr;
	if ((r = tfw_hpack_set_entry(tbl->h_pool, it, entry, &new_page)))
		return r;
	/*
	 * If the new entry is placed into the new page, and previous entry
	 * exists, then mark it as last entry in previous page (in order to
	 * free unused pages during entries eviction stage).
	 */
	if (count && new_page) {
		prev_entry = curr ? (entry - 1) : (entries + length - 1);
		prev_entry->last = true;
	}

	curr++;
	if (unlikely(curr == length))
		curr = 0;
	tbl->curr = curr;
	tbl->n = count + 1;
	tbl->size = new_size;

	T_DBG3("%s: item added, tbl->curr=%u, tbl->n=%u, tbl->length=%u\n",
	       __func__, tbl->curr, tbl->n, tbl->length);

	return 0;
}

static const TfwHPackEntry *
tfw_hpack_find_index(TfwHPackDTbl *__restrict tbl, unsigned long index)
{
	const TfwHPackEntry *entry = NULL;

	WARN_ON_ONCE(tbl->n > tbl->length);

	if (index <= HPACK_STATIC_ENTRIES) {
		entry = static_table + index - 1;
		WARN_ON_ONCE(entry->name_num != 1);
	}
	else if ((index -= HPACK_STATIC_ENTRIES) <= tbl->n) {
		unsigned int curr = tbl->curr;

		if (index <= curr) {
			curr -= index;
		} else {
			curr += tbl->length - index;
		}
		T_DBG3("%s: tbl->length=%u, tbl->curr=%u, curr=%u, index=%lu\n",
		      __func__, tbl->length, tbl->curr, curr, index);

		entry = tbl->entries + curr;
		WARN_ON_ONCE(!entry->name_num);
	}

	WARN_ON_ONCE(entry && (!entry->hdr || !entry->hdr->nchunks));

	return entry;
}

static int
tfw_hpack_set_length(TfwHPack *__restrict hp, unsigned long new_size)
{
	TfwHPackDTbl *tbl = &hp->dec_tbl;
	unsigned int size = tbl->size;

	if (new_size > hp->max_window)
		return -EINVAL;

	if (size > new_size) {
		unsigned int count = tbl->n;
		unsigned int early = tbl->curr;
		const unsigned int length = tbl->length;
		TfwHPackEntry *const entries = tbl->entries;
		TfwHPackEntry *cp;

		if (early >= count) {
			early -= count;
		} else {
			early += length - count;
		}
		T_DBG3("%s: tbl->curr=%u, early=%u, count=%u, length=%u,"
		       " new_size=%lu\n", __func__, tbl->curr, early, count,
		       length, new_size);
		cp = entries + early;
		do {
			unsigned long hdr_len = cp->hdr->len;

			WARN_ON_ONCE(!hdr_len);
			size -= HPACK_ENTRY_OVERHEAD + hdr_len;

			T_DBG3("%s: drop index, early=%u, count=%u,"
			       " length=%u\n", __func__, early, count, length);
			if (cp->last)
				tfw_pool_clean(tbl->h_pool, cp->hdr);
			early++;
			cp++;
			count--;
			if (unlikely(early == length)) {
				early = 0;
				cp = entries;
			}
		} while (size > new_size);

		tbl->n = count;
		tbl->size = size;
	}

	tbl->window = new_size;

	return 0;
}

static inline void
tfw_huffman_init(TfwHPack *__restrict hp)
{
	hp->curr = -HT_NBITS;
}

int
tfw_hpack_init(TfwHPack *__restrict hp, unsigned int htbl_sz)
{
	bool np;
	TfwHPackETbl *et = &hp->enc_tbl;
	TfwHPackDTbl *dt = &hp->dec_tbl;

	BUILD_BUG_ON(sizeof(TfwHPackNode) > HPACK_ENTRY_OVERHEAD
		     || HPACK_ENC_TABLE_MAX_SIZE > SHRT_MAX);

	tfw_huffman_init(hp);

	dt->window = hp->max_window = htbl_sz;
	if (!(dt->pool = __tfw_pool_new(0)))
		return -ENOMEM;
	if (!(dt->h_pool = __tfw_pool_new(0)))
		goto err_dt;

	et->window = htbl_sz;
	spin_lock_init(&et->lock);
	et->rb_size = HPACK_ENC_TABLE_MAX_SIZE;
	if (!(et->pool = __tfw_pool_new(HPACK_ENC_TABLE_MAX_SIZE)))
		goto err_et;
	et->rbuf = __tfw_pool_alloc(et->pool, HPACK_ENC_TABLE_MAX_SIZE,
				    true, &np);
	BUG_ON(np || !et->rbuf);

	return 0;

err_et:
	tfw_pool_destroy(dt->h_pool);
err_dt:
	tfw_pool_destroy(dt->pool);

	return -ENOMEM;
}

void
tfw_hpack_clean(TfwHPack *__restrict hp)
{
	tfw_pool_destroy(hp->enc_tbl.pool);
	tfw_pool_destroy(hp->dec_tbl.h_pool);
	tfw_pool_destroy(hp->dec_tbl.pool);
	WARN_ON_ONCE(act_hp_str_n);
}

/*
 * HPACK reinitialization procedure: resetting the non-permanent part
 * of HPACK context and HTTP/2 message iterator before next HPACK
 * processing stage. Note, in result of reinitialization, the @state
 * field of HPACK context will be set to HPACK_STATE_READY (since its
 * value is zero).
 */
static inline void
tfw_hpack_reinit(TfwHPack *__restrict hp, TfwMsgParseIter *__restrict it)
{
	WARN_ON_ONCE(!TFW_STR_EMPTY(it->parsed_hdr));
	bzero_fast(it->__off,
		   sizeof(*it) - offsetof(TfwMsgParseIter, __off));
	bzero_fast(hp->__off,
		   sizeof(*hp) - offsetof(TfwHPack, __off));
}

static int
tfw_hpack_hdr_name_set(TfwHPack *__restrict hp, TfwHttpReq *__restrict req,
		       const TfwHPackEntry *__restrict entry)
{
	char *data;
	unsigned int num = entry->name_num;
	unsigned long sz = entry->name_len;
	const TfwStr *s, *end, *s_hdr = entry->hdr;
	TfwMsgParseIter *it = &req->pit;
	TfwStr *d, *d_hdr = it->parsed_hdr;

	WARN_ON_ONCE(!TFW_STR_EMPTY(d_hdr));
	if (WARN_ON_ONCE(!num || num > s_hdr->nchunks))
		return -EINVAL;

	if (!(data = tfw_pool_alloc_not_align(it->pool, sz)))
		return T_BAD;

	d_hdr->len = sz;
	d_hdr->nchunks = num;
	d_hdr->flags = s_hdr->flags;
	if (!(d_hdr->chunks = tfw_pool_alloc(req->pool, num * sizeof(TfwStr))))
		return T_BAD;

	/*
	 * Since headers in static table cannot be changed, we need to copy only
	 * descriptors (i.e. only high-level and the name descriptors), because
	 * they will grow during further processing.
	 */
	d = d_hdr->chunks;
	if (hp->index <= HPACK_STATIC_ENTRIES) {
		*d = *s_hdr->chunks;
		goto done;
	}

	for (s = s_hdr->chunks, end = s_hdr->chunks + num; s < end; ++s) {
		*d = *s;
		d->data = data;
		memcpy_fast(data, s->data, s->len);
		data += s->len;
		++d;
	}

done:
	it->tag = entry->tag;

	return T_OK;
}

static int
tfw_hpack_hdr_set(TfwHPack *__restrict hp, TfwHttpReq *__restrict req,
		  const TfwHPackEntry *__restrict entry)
{
	char *data;
	unsigned long d_size;
	TfwMsgParseIter *it = &req->pit;
	const TfwStr *s, *end, *s_hdr = entry->hdr;
	TfwHttpParser *parser = &req->stream->parser;
	TfwStr *d, *d_hdr = &parser->hdr;

	WARN_ON_ONCE(TFW_STR_PLAIN(s_hdr));
	WARN_ON_ONCE(!TFW_STR_EMPTY(d_hdr));

	/*
	 * The header in static table should not be supplanted and full header
	 * descriptor (with name and value) should not grow during subsequent
	 * processing. Thus, we can avoid the descriptor deep copying from the
	 * table and take only its high-level part.
	 */
	if (hp->index <= HPACK_STATIC_ENTRIES) {
		WARN_ON_ONCE(s_hdr->nchunks > 2);
		if (s_hdr->nchunks != 2)
			return T_DROP;
		*d_hdr = *s_hdr;
		goto done;
	}

	/*
	 * We must do a full copy of dynamically indexed headers (in-depth
	 * descriptor and data), since next header can supplant the processed
	 * header or change it by adding a new header into dynamic table, and
	 * any type of reference for header (index or high-level/full
	 * descriptor) will become invalid. Note, that for static table this
	 * problem does not exist, since statically indexed headers cannot be
	 * supplanted or changed - therefore, for subsequent work we keep
	 * (without full copying) only references for statically indexed
	 * headers (also, see comment above).
	 */
	if (!(data = tfw_pool_alloc_not_align(it->pool, s_hdr->len)))
		return T_BAD;

	d_size = s_hdr->nchunks * sizeof(TfwStr);
	if (!(d_hdr->chunks = tfw_pool_alloc(req->pool, d_size)))
		return T_BAD;

	d_hdr->len = s_hdr->len;
	d_hdr->flags = s_hdr->flags;
	d_hdr->nchunks = s_hdr->nchunks;

	d = d_hdr->chunks;
	TFW_STR_FOR_EACH_CHUNK(s, s_hdr, end) {
		*d = *s;
		d->data = data;
		memcpy_fast(data, s->data, s->len);
		data += s->len;
		++d;
	}

done:
	switch (entry->tag) {
	case TFW_TAG_HDR_H2_METHOD:
		if (hp->index == 2) {
			req->method = TFW_HTTP_METH_GET;
		} else if (hp->index == 3) {
			req->method = TFW_HTTP_METH_POST;
		} else {
			WARN_ON_ONCE(1);
			return T_DROP;
		}
		parser->_hdr_tag = TFW_HTTP_HDR_H2_METHOD;
		break;
	case TFW_TAG_HDR_H2_SCHEME:
		parser->_hdr_tag = TFW_HTTP_HDR_H2_SCHEME;
		break;
	case TFW_TAG_HDR_H2_AUTHORITY:
		parser->_hdr_tag = TFW_HTTP_HDR_H2_AUTHORITY;
		break;
	case TFW_TAG_HDR_H2_PATH:
		parser->_hdr_tag = TFW_HTTP_HDR_H2_PATH;
		break;
	case TFW_TAG_HDR_ACCEPT:
		parser->_hdr_tag = TFW_HTTP_HDR_RAW;
		break;
	case TFW_TAG_HDR_AUTHORIZATION:
		parser->_hdr_tag = TFW_HTTP_HDR_RAW;
		break;
	case TFW_TAG_HDR_CACHE_CONTROL:
		parser->_hdr_tag = TFW_HTTP_HDR_RAW;
		break;
	case TFW_TAG_HDR_CONTENT_LENGTH:
		parser->_hdr_tag = TFW_HTTP_HDR_CONTENT_LENGTH;
		break;
	case TFW_TAG_HDR_CONTENT_TYPE:
		parser->_hdr_tag = TFW_HTTP_HDR_CONTENT_TYPE;
		break;
	case TFW_TAG_HDR_COOKIE:
		parser->_hdr_tag = TFW_HTTP_HDR_COOKIE;
		break;
	case TFW_TAG_HDR_HOST:
		parser->_hdr_tag = TFW_HTTP_HDR_HOST;
		break;
	case TFW_TAG_HDR_IF_MODIFIED_SINCE:
		parser->_hdr_tag = TFW_HTTP_HDR_RAW;
		break;
	case TFW_TAG_HDR_IF_NONE_MATCH:
		parser->_hdr_tag = TFW_HTTP_HDR_IF_NONE_MATCH;
		break;
	case TFW_TAG_HDR_PRAGMA:
		parser->_hdr_tag = TFW_HTTP_HDR_RAW;
		break;
	case TFW_TAG_HDR_REFERER:
		parser->_hdr_tag = TFW_HTTP_HDR_REFERER;
		break;
	case TFW_TAG_HDR_X_FORWARDED_FOR:
		parser->_hdr_tag = TFW_HTTP_HDR_X_FORWARDED_FOR;
		break;
	case TFW_TAG_HDR_USER_AGENT:
		parser->_hdr_tag = TFW_HTTP_HDR_USER_AGENT;
		break;
	case TFW_TAG_HDR_RAW:
		parser->_hdr_tag = TFW_HTTP_HDR_RAW;
		break;
	default:
		WARN_ON_ONCE(1);
		return T_DROP;
	}

	return T_OK;
}

/*
 * HPACK decoder FSM for HTTP/2 message processing.
 */
int
tfw_hpack_decode(TfwHPack *__restrict hp, unsigned char *__restrict src,
		 unsigned long n,  TfwHttpReq *__restrict req,
		 unsigned int *__restrict parsed)
{
	unsigned int state;
	int r = T_POSTPONE;
	TfwMsgParseIter *it = &req->pit;
	const unsigned char *last = src + n;

	BUILD_BUG_ON(HPACK_STATE_MASK < _HPACK_STATE_NUM - 1);
	BUG_ON(!it->parsed_hdr);
	WARN_ON_ONCE(!n);
	*parsed += n;
	do {
		state = hp->state;

		T_DBG3("%s: header processing, n=%lu, to_parse=%lu, state=%d\n",
		       __func__, n, last - src, state);

		switch (state & HPACK_STATE_MASK) {
		case HPACK_STATE_READY:
		{
			unsigned char c = *src++;

			if (c & 0x80) {
				T_DBG3("%s: reference by index...\n", __func__);

				state |= HPACK_FLAGS_NO_VALUE;
				hp->index = c & 0x7F;
				if (hp->index == 0x7F) {
					GET_FLEXIBLE(hp->index,
						     HPACK_STATE_INDEX);
				}
				else if (unlikely(hp->index == 0)) {
					r = T_DROP;
					goto out;
				}

				T_DBG3("%s: decoded index: %lu\n", __func__,
				       hp->index);

				NEXT_STATE(HPACK_STATE_ALL_INDEXED);

				goto get_all_indexed;

			} else if (c & 0x40) {
				T_DBG3("%s: reference with addition...\n",
				       __func__);
				state |= HPACK_FLAGS_ADD;
				hp->index = c & 0x3F;
				if (hp->index == 0x3F) {
index:
					GET_FLEXIBLE(hp->index, HPACK_STATE_INDEX);
					T_DBG3("%s: decoded index: %lu\n",
					       __func__, hp->index);
					NEXT_STATE(HPACK_STATE_INDEXED_NAME_TEXT);
					goto get_indexed_name;
				}

			} else if (c & 0x20) {
				T_DBG3("%s: new window size...\n", __func__);

				hp->index = c & 0x1F;
				if (hp->index == 0x1F)
					GET_FLEXIBLE(hp->index,
						     HPACK_STATE_WINDOW);

				T_DBG3("%s: decoded window: %lu\n", __func__,
				       hp->index);

				NEXT_STATE(HPACK_STATE_WINDOW);

				goto set_window;

			} else {
				T_DBG3("%s: reference with value...\n",
				       __func__);

				if (c & 0xE0) {
					T_DBG3("%s: the code of the header's"
					       " binary representation is not"
					       " in prefix form\n", __func__);
					r = T_DROP;
					goto out;
				}

				if (c & 0x10) {
					T_DBG3("%s: transit header...\n",
					      __func__);
					state |= HPACK_FLAGS_TRANSIT;
				}

				hp->index = c & 0x0F;
				if (hp->index == 0x0F) {
					NEXT_STATE(HPACK_STATE_INDEX);
					goto index;
				}
			}

			NEXT_STATE(hp->index
				   ? HPACK_STATE_INDEXED_NAME_TEXT
				   : HPACK_STATE_NAME);

			if (src >= last)
				goto out;

			if (hp->index) {
				T_DBG3("%s: decoded index: %lu\n", __func__,
				       hp->index);
				goto get_indexed_name;
			}

			/* Fall through. */
		}
		case HPACK_STATE_NAME:
		{
			unsigned char c = *src++;

			T_DBG3("%s: decode header name length...\n", __func__);
			WARN_ON_ONCE(hp->length);
			hp->length = c & 0x7F;
			if (c & 0x80) {
				T_DBG3("%s: Huffman encoding used for name...\n",
				       __func__);
				state |= HPACK_FLAGS_HUFFMAN_NAME;
			}
			if (unlikely(hp->length == 0x7F)) {
				GET_FLEXIBLE(hp->length, HPACK_STATE_NAME_LENGTH);
			}
			else if (unlikely(hp->length == 0)) {
				r = T_DROP;
				goto out;
			}

			T_DBG3("%s: name length: %lu\n", __func__, hp->length);

			NEXT_STATE(HPACK_STATE_NAME_TEXT);

			BUFFER_NAME_OPEN(hp->length);

			if (unlikely(src >= last))
				goto out;

			/* Fall through. */
		}
		case HPACK_STATE_NAME_TEXT:
		{
			unsigned long m_len;
get_name_text:
			T_DBG3("%s: decode header name...\n", __func__);
			m_len = min((unsigned long)(last - src), hp->length);
			if (state & HPACK_FLAGS_HUFFMAN_NAME)
				HPACK_DECODE_PROCESS_STRING(name, m_len);
			else
				HPACK_PROCESS_STRING(m_len, false);

			NEXT_STATE(HPACK_STATE_VALUE);

			if (unlikely(src >= last))
				goto out;

			goto get_value;
		}
		case HPACK_STATE_INDEXED_NAME_TEXT:
		{
			const TfwHPackEntry *entry;
get_indexed_name:
			T_DBG3("%s: decode indexed (%lu) header name...\n",
			       __func__, hp->index);
			WARN_ON_ONCE(!hp->index);
			entry = tfw_hpack_find_index(&hp->dec_tbl, hp->index);
			if (!entry || tfw_hpack_hdr_name_set(hp, req, entry)) {
				r = T_DROP;
				goto out;
			}

			NEXT_STATE(HPACK_STATE_VALUE);

			/* Fall through. */
		}
		case HPACK_STATE_VALUE:
		{
			unsigned char c;
get_value:
			T_DBG3("%s: decode header value length...\n", __func__);
			c = *src++;
			WARN_ON_ONCE(hp->length);
			hp->length = c & 0x7F;
			if (c & 0x80) {
				T_DBG3("%s: Huffman encoding used for value\n",
				       __func__);
				state |= HPACK_FLAGS_HUFFMAN_VALUE;
			}
			if (unlikely(hp->length == 0x7F))
				GET_FLEXIBLE(hp->length,
					     HPACK_STATE_VALUE_LENGTH);

			T_DBG3("%s: value length: %lu\n", __func__, hp->length);

			NEXT_STATE(HPACK_STATE_VALUE_TEXT);

			BUFFER_VAL_OPEN(hp->length);

			if (unlikely(src >= last))
				goto out;

			/* Fall through. */
		}
		case HPACK_STATE_VALUE_TEXT:
		{
			unsigned long m_len;
get_value_text:
			WARN_ON_ONCE(state & HPACK_FLAGS_NO_VALUE);
			if (!hp->length) {
				T_DBG3("%s: zero-length value\n", __func__);
				r = T_DROP;
				goto out;
			}

			T_DBG3("%s: decode header value...\n", __func__);
			m_len = min((unsigned long)(last - src), hp->length);
			if (state & HPACK_FLAGS_HUFFMAN_VALUE)
				HPACK_DECODE_PROCESS_STRING(value, m_len);
			else
				HPACK_PROCESS_STRING(m_len, true);

			if (state & HPACK_FLAGS_ADD
			    && tfw_hpack_add_index(&hp->dec_tbl, it))
			{
				r = T_DROP;
				goto out;
			}

			it->hdrs_len += it->parsed_hdr->len;
			++it->hdrs_cnt;

			/*
			 * Finish parsed header and reinitialize parsing
			 * context. Note, @parser->hdr and @parser->_hdr_tag
			 * must be determined during headers' field processing
			 * above.
			 */
			if (tfw_http_msg_hdr_close((TfwHttpMsg *)req)) {
				r = T_DROP;
				goto out;
			}

			break;
		}
		case HPACK_STATE_ALL_INDEXED:
		{
			const TfwHPackEntry *entry;
get_all_indexed:
			T_DBG3("%s: get entire header by index: %lu\n", __func__,
			       hp->index);

			WARN_ON_ONCE(!(state & HPACK_FLAGS_NO_VALUE));
			WARN_ON_ONCE(!hp->index);

			entry = tfw_hpack_find_index(&hp->dec_tbl, hp->index);
			if (!entry) {
				r = T_DROP;
				goto out;
			}

			if (tfw_hpack_hdr_set(hp, req, entry)) {
				r = T_DROP;
				goto out;
			}

			it->hdrs_len += it->parsed_hdr->len;
			++it->hdrs_cnt;

			/*
			 * Finish parsed header and reinitialize parsing
			 * context. Note, in case of indexed header @parser->hdr
			 * and @parser->_hdr_tag must be determined from the
			 * decoder static/dynamic tables above.
			 */
			if (tfw_http_msg_hdr_close((TfwHttpMsg *)req)) {
				r = T_DROP;
				goto out;
			}

			break;
		}
		case HPACK_STATE_INDEX:
			GET_CONTINUE(hp->index);
			T_DBG3("%s: index finally decoded: %lu\n", __func__,
			       hp->index);
			if (state & HPACK_FLAGS_NO_VALUE) {
				NEXT_STATE(HPACK_STATE_ALL_INDEXED);
				goto get_all_indexed;
			}

			NEXT_STATE(HPACK_STATE_INDEXED_NAME_TEXT);

			if (unlikely(src >= last))
				goto out;

			goto get_indexed_name;

		case HPACK_STATE_WINDOW:
			GET_CONTINUE(hp->index);
			T_DBG3("%s: new window size finally decoded: %lu\n",
			       __func__, hp->index);
set_window:
			if (tfw_hpack_set_length(hp, hp->index)) {
				r = T_DROP;
				goto out;
			}
			T_DBG3("%s: window size has been changed\n", __func__);
			break;

		case HPACK_STATE_NAME_LENGTH:
			GET_CONTINUE(hp->length);
			T_DBG3("%s: name length finally decoded: %lu\n",
			       __func__, hp->length);

			NEXT_STATE(HPACK_STATE_NAME_TEXT);

			BUFFER_NAME_OPEN(hp->length);

			if (unlikely(src >= last))
				goto out;

			goto get_name_text;

		case HPACK_STATE_VALUE_LENGTH:
			GET_CONTINUE(hp->length);
			T_DBG3("%s: value length finally decoded: %lu\n",
			       __func__, hp->length);

			NEXT_STATE(HPACK_STATE_VALUE_TEXT);

			BUFFER_VAL_OPEN(hp->length);

			if (unlikely(src >= last))
				goto out;

			goto get_value_text;

		default:
			WARN_ON_ONCE(1);
			r = T_DROP;
			goto out;
		}

		T_DBG3("%s: new header added\n", __func__);

		tfw_hpack_reinit(hp, it);

	} while (src < last);

	return T_OK;
out:
	WARN_ON_ONCE(src > last);
	*parsed -= last - src;
	hp->state = state;
	return r;
}

/*
 * Modified version of HPACK decoder FSM - for cache entries processing,
 * HTTP/2-headers decoding (either into HTTP/2 or HTTP/1.1 format) and skb
 * expanding at once; only static indexing is allowed, no service HPACK codes,
 * no Huffman decoding and no parsing; only a limited subset of HPACK decoder
 * FSM states is used.
 */
int
tfw_hpack_cache_decode_expand(TfwHPack *__restrict hp,
			      TfwHttpResp *__restrict resp,
			      unsigned char *__restrict src, unsigned long n,
			      TfwDecodeCacheIter *__restrict dc_iter)
{
	unsigned char c;
	unsigned int state;
	int r = T_OK;
	TfwStr exp_str = {};
	TfwHttpTransIter *mit = &resp->mit;
	TfwMsgIter *it = &mit->iter;
	bool h2_mode = TFW_MSG_H2(resp->req);
	const unsigned char *prev, *last = src + n;
	struct sk_buff **skb_head = &resp->msg.skb_head;

#define GET_NEXT_DATA(cond)						\
do {									\
	if (unlikely(cond))						\
		goto out;						\
} while (0)

#define FIXUP_DATA(str, data, len)					\
	if (__tfw_http_msg_add_str_data((TfwHttpMsg *)resp, resp->pool, \
					str, data, len, NULL))		\
	{								\
		r = T_DROP;						\
		goto out;						\
	}

#define FIXUP_H2_DATA(str, data, len)					\
do {									\
	if (h2_mode)							\
		FIXUP_DATA(str, data, len);				\
} while (0)

#define EXPAND_STR_DATA(str)						\
do {									\
	if (tfw_http_msg_expand_data(it, skb_head, str, NULL)) {	\
		r = T_DROP;						\
		goto out;						\
	}								\
	dc_iter->acc_len += (str)->len;					\
} while (0)

#define EXPAND_DATA(ptr, length)					\
do {									\
	exp_str.data = ptr;						\
	exp_str.len = length;						\
	EXPAND_STR_DATA(&exp_str);					\
} while (0)

#define EXPAND_H2_DATA(data, len)					\
do {									\
	if (h2_mode)							\
		EXPAND_DATA(data, len);					\
} while (0)

	WARN_ON_ONCE(!n);

	state = hp->state;

	T_DBG3("%s: header processing, n=%lu, to_parse=%lu, state=%d\n",
	       __func__, n, last - src, state);

	switch (state & HPACK_STATE_MASK) {
	case HPACK_STATE_READY:
		prev = src;
		c = *src++;

		/*
		 * We use only static indexing during headers storing
		 * into the cache, thus `without indexing` code must be
		 * always set in the first index byte (RFC 7541 section
		 * 6.2.2) of cached response; besides, since response
		 * regular headers have no full indexes in HPACK static
		 * table, only header's name is allowed to be indexed.
		 */
		if (WARN_ON_ONCE(c & 0xF0)) {
			r = T_DROP;
			goto out;
		}

		T_DBG3("%s: reference with value...\n", __func__);

		hp->index = c & 0x0F;
		if (hp->index == 0x0F) {
			GET_FLEXIBLE_lambda(hp->index,
				HPACK_STATE_INDEX, {
				FIXUP_H2_DATA(&dc_iter->h2_data, src,
					      src - prev);
			});
		}

		T_DBG3("%s: name index: %lu\n", __func__, hp->index);

		FIXUP_H2_DATA(&dc_iter->h2_data, src, src - prev);

		NEXT_STATE(hp->index
			   ? HPACK_STATE_INDEXED_NAME_TEXT
			   : HPACK_STATE_NAME);

		GET_NEXT_DATA(src >= last);

		if (hp->index)
			goto get_indexed_name;

		/* Fall through. */

	case HPACK_STATE_NAME:
		prev = src;
		c = *src++;

		T_DBG3("%s: decode header name length...\n", __func__);
		WARN_ON_ONCE(hp->length);
		WARN_ON_ONCE(c & 0x80);

		hp->length = c & 0x7F;
		if (unlikely(hp->length == 0x7F)) {
			GET_FLEXIBLE_lambda(hp->length,
				HPACK_STATE_NAME_LENGTH, {
				FIXUP_H2_DATA(&dc_iter->h2_data, src,
					      src - prev);
			});
		}
		else if (unlikely(hp->length == 0)) {
			r = T_DROP;
			goto out;
		}

		T_DBG3("%s: name length: %lu\n", __func__, hp->length);

		FIXUP_H2_DATA(&dc_iter->h2_data, src, src - prev);

		NEXT_STATE(HPACK_STATE_NAME_TEXT);

		GET_NEXT_DATA(src >= last);

		goto get_name_text;

	case HPACK_STATE_INDEXED_NAME_TEXT:
	{
		const TfwHPackEntry *entry;
get_indexed_name:
		T_DBG3("%s: decode indexed (%lu) header name...\n",
		       __func__, hp->index);
		if (WARN_ON_ONCE(!hp->index
				 || hp->index > HPACK_STATIC_ENTRIES))
		{
			r = T_DROP;
			goto out;
		}

		entry = static_table + hp->index - 1;
		if (WARN_ON_ONCE(entry->name_num != 1)) {
			r = T_DROP;
			goto out;
		}

		dc_iter->hdr_data.len = entry->name_len;
		dc_iter->hdr_data.data = __TFW_STR_CH(entry->hdr, 0)->data;

		goto check_name_text;

	}
	case HPACK_STATE_NAME_TEXT:
	{
		int i;
		TfwHdrMods *h_mods;
		unsigned long m_len;
get_name_text:
		m_len = min((unsigned long)(last - src), hp->length);

		T_DBG3("%s: decoding header name, m_len=%lu\n", __func__, m_len);

		FIXUP_DATA(&dc_iter->hdr_data, src, m_len);

		hp->length -= m_len;
		src += m_len;

		GET_NEXT_DATA(hp->length);
check_name_text:
		i = 0;
		h_mods = dc_iter->h_mods;
		WARN_ON_ONCE(dc_iter->desc);
		if (h_mods) {
			for (; i < h_mods->sz; ++i) {
				TfwHdrModsDesc *d = &h_mods->hdrs[i];

				if (!__hdr_name_cmp(&dc_iter->hdr_data, d->hdr))
				{
					dc_iter->desc = d;
					break;
				}
			}
		}

		if (dc_iter->desc) {
			/* All duplicate headers must be skipped by caller. */
			WARN_ON_ONCE(test_bit(i, mit->found));
			__set_bit(i, mit->found);
			/*
			 * Header modifications format: 0 chunk - header name,
			 * optional 1st chunk - header value. If the value is
			 * empty, then the header is about to be removed,
			 * don't write it.
			 */
			if (!TFW_STR_CHUNK(dc_iter->desc->hdr, 1)) {
				dc_iter->skip = true;
				goto out;
			}

		}

		if (h2_mode)
			EXPAND_STR_DATA(&dc_iter->h2_data);

		EXPAND_STR_DATA(&dc_iter->hdr_data);
		TFW_STR_INIT(&dc_iter->hdr_data);

		if (!h2_mode)
			EXPAND_DATA(S_DLM, SLEN(S_DLM));

		T_DBG3("%s: name copied, n=%lu, tail=%lu, hp->length=%lu\n",
		       __func__, n, last - src, hp->length);

		NEXT_STATE(HPACK_STATE_VALUE);

		GET_NEXT_DATA(src >= last);

		/* Fall through. */
	}
	case HPACK_STATE_VALUE:
		T_DBG3("%s: decode header value length...\n", __func__);

		prev = src;
		c = *src++;
		WARN_ON_ONCE(hp->length);
		WARN_ON_ONCE(c & 0x80);

		hp->length = c & 0x7F;
		if (unlikely(hp->length == 0x7F))
			GET_FLEXIBLE_lambda(hp->length,
				HPACK_STATE_VALUE_LENGTH, {
				if (!dc_iter->desc)
					EXPAND_H2_DATA(src, src - prev);
			});

		T_DBG3("%s: value length: %lu\n", __func__, hp->length);

		if (!dc_iter->desc)
			EXPAND_H2_DATA(src, src - prev);

		NEXT_STATE(HPACK_STATE_VALUE_TEXT);

		GET_NEXT_DATA(src >= last);

		/* Fall through. */

	case HPACK_STATE_VALUE_TEXT:
	{
		unsigned long m_len;
get_value_text:
		T_DBG3("%s: decode header value...\n", __func__);
		m_len = min((unsigned long)(last - src), hp->length);

		if (dc_iter->desc && dc_iter->desc->append && h2_mode) {
			/*
			 * If the header value must be appended, we need to
			 * collect the value for HTTP/2-header, since it should
			 * be re-encoded in this case.
			 */
			FIXUP_DATA(&dc_iter->hdr_data, src, m_len);
		}
		else if (!dc_iter->desc || dc_iter->desc->append) {
			EXPAND_DATA(src, m_len);
		}

		hp->length -= m_len;
		src += m_len;

		GET_NEXT_DATA(hp->length);

		if (dc_iter->desc) {
			TfwStr *val, *h = dc_iter->desc->hdr;
			/*
			 * Header value is stored in chunk 1, see
			 * tfw_cfgop_mod_hdr_add().
			 */
			TfwStr n_val = {
				.chunks = (TfwStr []){
					{ .data = ", ", .len = 2 },
					{ .data = __TFW_STR_CH(h, 1)->data,
					  .len = __TFW_STR_CH(h, 1)->len }
				},
				.len = __TFW_STR_CH(h, 1)->len + 2,
				.nchunks = 2
			};

			dc_iter->skip = true;

			if (h2_mode) {
				TfwHPackInt vlen;

				if (dc_iter->desc->append) {
					val = &dc_iter->hdr_data;
					if (tfw_strcat(resp->pool, val, &n_val))
					{
						r = T_DROP;
						goto out;
					}
				}
				else {
					val = __TFW_STR_CH(&n_val, 1);
				}

				write_int(val->len, 0x7F, 0, &vlen);

				EXPAND_DATA(vlen.buf, vlen.sz);
				EXPAND_STR_DATA(val);

				break;
			}

			val = dc_iter->desc->append
				? &n_val
				: __TFW_STR_CH(&n_val, 1);

			EXPAND_STR_DATA(val);
		}

		if (!h2_mode)
			EXPAND_DATA(S_CRLF, SLEN(S_CRLF));

		break;
	}
	case HPACK_STATE_INDEX:
		prev = src;
		GET_CONTINUE_lambda(hp->index, {
			FIXUP_H2_DATA(&dc_iter->h2_data, src, src - prev);
		});
		T_DBG3("%s: index finally decoded: %lu\n", __func__, hp->index);

		NEXT_STATE(HPACK_STATE_INDEXED_NAME_TEXT);

		GET_NEXT_DATA(src >= last);

		goto get_indexed_name;

	case HPACK_STATE_NAME_LENGTH:
		prev = src;
		GET_CONTINUE_lambda(hp->length, {
			FIXUP_H2_DATA(&dc_iter->h2_data, src, src - prev);
		});
		T_DBG3("%s: name length finally decoded: %lu\n", __func__,
		       hp->length);

		NEXT_STATE(HPACK_STATE_NAME_TEXT);

		GET_NEXT_DATA(src >= last);

		goto get_name_text;

	case HPACK_STATE_VALUE_LENGTH:
		prev = src;
		GET_CONTINUE_lambda(hp->length, {
			if (!dc_iter->desc)
				EXPAND_H2_DATA(src, src - prev);
		});
		T_DBG3("%s: value length finally decoded: %lu\n", __func__,
		       hp->length);

		NEXT_STATE(HPACK_STATE_VALUE_TEXT);

		GET_NEXT_DATA(src >= last);

		goto get_value_text;

	default:
		WARN_ON_ONCE(1);
		r = T_DROP;
		goto out;
	}

	T_DBG3("%s: new header added\n", __func__);

	WARN_ON_ONCE(src != last);

	return T_OK;
out:
	WARN_ON_ONCE(src > last);
	hp->state = state;
	return r;

#undef GET_NEXT_DATA
#undef FIXUP_DATA
#undef FIXUP_H2_DATA
#undef EXPAND_STR_DATA
#undef EXPAND_DATA
#undef EXPAND_H2_DATA
}

/**
 * ------------------------------------------------------------------------
 *	HPACK Encoder functionality
 * ------------------------------------------------------------------------
 *
 * The encoder dynamic index table has two-layer architecture: the ring buffer
 * as the base layer and the red-black tree on top of it. The entry in the table
 * is represented by the @TfwHPackNode structure, which contains the fields
 * necessary for red-black tree logic: @parent, @left, @right, @color, which are
 * offsets (in bytes in the ring buffer) for parent, left child, and right child
 * of the current node correspondingly, and the current node's color flag. The
 * structure also contains the @rindex field - for representation of the node
 * index in the table, the @hdr_len field which is length of the header stored
 * in the entry, and the @hdr field which is the pointer to the header
 * name/value string itself (stored in the ring buffer - right after the entry
 * structure). The table itself is represented by the @TfwHPackETbl structure
 * which encapsulates the descriptor logic for both - the ring buffer and the
 * red-black tree layers. This structure includes @rbuf field which is the
 * pointer to the ring buffer beginning, @first field - the pointer to the first
 * (i.e. the oldest) entry in the ring buffer, @last field - the pointer to the
 * last (i.e. the newest) entry in the ring buffer, and @root field which is the
 * pointer to the root entry of red-black tree.
 *
 * For instance, if the encoder table has 3 headers stored in it - e.g.
 * 'accept-encoding', 'accept-range' and 'referer', which had been added exactly
 * in the given order - they should have the following layout in the ring buffer
 * (representing corresponding red-black tree balanced structure):
 *
 * r:15:c:31:-1:-1:accept-encoding|r:12:c:-1:0:59:accept-range|r:7:c:31:-1:-1:referer|_ _
 * ^                               ^                           ^
 * |                               |                           |
 * first                         root                        last
 * ^
 * |
 * rbuf
 *
 * In this situation, if we evict the oldest node, that will be the node under
 * the @first pointer, with 'accept-encoding' header, and the @first pointer
 * will be shifted to the next node in ring buffer. As a result, we will get the
 * following picture (after appropriate red-black tree re-balancing):
 *
 * _ _(31 bytes)_ _|r:12:c:-1:-1:59:accept-range|r:7:c:31:-1:-1:referer|_ _
 * ^                ^                            ^
 * |                |                            |
 * rbuf           first                        last
 *                  ^
 *                  |
 *                root
 *
 * Then, we can add the 'accept' header into the table and the final picture
 * will have the following view:
 *
 * _ _(31 bytes)_ _|r:12:c:-1:82:59:accept-range|r:7:c:31:-1:-1:referer|r:6:c:31:-1:-1:accept|_ _
 * ^                ^                                                   ^
 * |                |                                                   |
 * rbuf           first                                               last
 *                  ^
 *                  |
 *                root
 *
 * Since the 'accept' is the last header added into the table, the node with it
 * has been stored at the end of the used place in ring buffer, and the @last
 * pointer has been moved to this node. In the same time, since the 'accept'
 * header is less (as char values) then the 'accept-range' header (which is the
 * root node), it is placed into left branch of red-black tree, thus, the @left
 * field of root node has been assigned the 82 value, as offset in bytes of last
 * added node with 'accept' header.
 *
 * Notation used in the above example:
 * 'r'	- @rindex field (occupy 8 bytes);
 *	  next is the @hdr_len field (occupy 15 bits), which contains the length
 *	  of header;
 * 'c'	- @color field (occupy 1 bit);
 * next three fields are @parent, @left, @right (each occupy 2 bytes), which
 *	  contain offsets of corresponding parent/child nodes ('-1' means empty
 *	  parent/child nodes: leaf nodes and parent for root node);
 * next is the header itself (each char occupy 1 byte); note that headers should
 *	  also have values, but for simplicity and clarity, the values in this
 *	  example are omitted);
 * ':' and '|' do not occupy any space in ring buffer, and are intended only for
 *	  the purposes of visual separation of fields and entries respectively;
 * '_ '	- unused space of ring buffer.
 */
typedef struct {
	TfwHPackNode *parent;
	short *poff;
} TfwHPackNodeIter;

typedef enum {
	HPACK_IDX_ST_FOUND		= 0,
	HPACK_IDX_ST_NM_FOUND,
	HPACK_IDX_ST_NOT_FOUND,
	_HPACK_IDX_ST_NUM
} TfwHPackETblRes;

#define HPACK_IDX_ST_MASK		0x0F
#define HPACK_IDX_FLAG_ADD		0x010

#define HPACK_IDX_RES(res)						\
	((res) & HPACK_IDX_ST_MASK)

#define HPACK_MAX_ENC_EVICTION		5

#define HPACK_RB_IS_BLACK(node)		((int)(node)->color)
#define HPACK_RB_IS_RED(node)		(!HPACK_RB_IS_BLACK(node))

#define HPACK_RB_SET_BLACK(node)					\
do {									\
	(node)->color = 1;						\
} while (0)

#define HPACK_RB_SET_RED(node)						\
do {									\
	(node)->color = 0;						\
} while (0)

#define HPACK_RB_COPY_COLOR(d_node, s_node)				\
do {									\
	(d_node)->color = (s_node)->color;				\
} while (0)

#define HPACK_NODE_EMPTY(off)		((off) < 0)

#define HPACK_NODE(tbl, off)						\
	((TfwHPackNode *)((tbl)->rbuf + (off)))

#define HPACK_NODE_COND(tbl, off)					\
	(!HPACK_NODE_EMPTY(off) ? HPACK_NODE(tbl, off) : NULL)

#define HPACK_NODE_OFF(tbl, node)					\
	((char *)(node) - (tbl)->rbuf)

#define HPACK_NODE_COND_OFF(tbl, node)					\
	((node) ? HPACK_NODE_OFF(tbl, node) : -1)

#define HPACK_ALIGN(sz)	(((sz) + 7) & ~7UL)

#define HPACK_NODE_SIZE(node)						\
	HPACK_ALIGN(sizeof(TfwHPackNode) + ((TfwHPackNode *)node)->hdr_len)

#define HPACK_NODE_NEXT(node)						\
	((TfwHPackNode *)((char *)(node) + HPACK_NODE_SIZE(node)))

typedef enum {
	HPACK_HDR_NAME_SEARCH		= 0,
	HPACK_HDR_NAME_FOUND,
	HPACK_HDR_VALUE_FOUND
} TfwHPackCmpStates;

#define HP_SH(p)			(*(unsigned short *)(p))
#define HP_CHAR(p)			(*(unsigned char *)(p))

#define SH_LC(p)			(HP_SH(p) | 0x2020)
#define CHAR_LC(p)			(HP_CHAR(p) | 0x20)

#define INT_LE(p)							\
	((p)[0] << 24 | (p)[1] << 16 | (p)[2] << 8 | (p)[3])
#define SH_LE(p)							\
	((p)[0] << 8 | (p)[1])

#define INT_LE_LC(p)			(INT_LE(p) | 0x20202020)
#define SH_LE_LC(p)			(SH_LE(p) | 0x2020)

/*
 * Processing header's OWS during comparison with values stored in encoder
 * dynamic index. Note that in switch '-1' branch for @idx - all characters
 * in processed part of @data are the OWS (or ':' in case of header's name
 * processing), thus mismatching is dummy and we can continue the comparison
 * procedure.
 */
#define HPACK_HDR_OWS_PROCESS(part_len, ret)				\
({									\
	bool found = false;						\
	short idx = (part_len) - 1;					\
									\
	BUG_ON(len < (part_len));					\
	if (state != HPACK_HDR_NAME_SEARCH				\
	    && (state != HPACK_HDR_VALUE_FOUND				\
		|| chunk != TFW_STR_LAST(hdr)				\
		|| len != (part_len)))					\
		return ret;						\
									\
	for (; (data[idx] == ' ' || data[idx] == '\t') && idx >= 0;	\
	     --idx);							\
	if (state == HPACK_HDR_NAME_SEARCH				\
	    && idx >= 0							\
	    && data[idx] == ':')					\
	{								\
		found = true;						\
		--idx;							\
	}								\
	if (idx == (part_len) - 1)					\
		return ret;						\
	T_DBG3("%s: ows, state=%d, part_len=%d, ret=%d, idx=%u,"	\
	       " pos='%.*s', data='%.*s'\n", __func__, state, part_len,	\
	       ret, idx, idx + 1, pos, idx + 1, data);			\
	switch (idx) {							\
	case 1:								\
		/* Fall through. */					\
	case 2:								\
		if (state == HPACK_HDR_NAME_SEARCH) {			\
			if (SH_LC(pos) != SH_LC(data))			\
				return ret;				\
		} else if (HP_SH(pos) != HP_SH(data)) {			\
			return ret;					\
		}							\
		if (idx == 1)						\
			break;						\
		/* Fall through. */					\
	case 0:								\
		if (state == HPACK_HDR_NAME_SEARCH) {			\
			if (CHAR_LC(pos + idx) == CHAR_LC(data + idx))	\
				break;					\
		}							\
		else if (HP_CHAR(pos + idx) == HP_CHAR(data + idx)) {	\
			break;						\
		}							\
		return ret;						\
	case -1:							\
		break;							\
	default:							\
		BUG();							\
	}								\
	if (found)							\
		state = HPACK_HDR_NAME_FOUND;				\
	idx;								\
})

#define HPACK_NODE_GET_INDEX(tbl, node)					\
({									\
	unsigned long idx = 0;						\
	if (node) {							\
		idx = ~((node)->rindex - (tbl)->idx_acc) + 1;		\
		WARN_ON_ONCE(idx >= HPACK_ENC_TABLE_MAX_SIZE);		\
		idx += HPACK_STATIC_ENTRIES + 1;			\
	}								\
	idx;								\
})

static int
tfw_hpack_node_compare(const TfwStr *__restrict hdr,
		       const TfwHPackNode *__restrict node,
		       const TfwHPackNode **__restrict nm_node)
{
	short i;
	const TfwStr *chunk, *end;
	unsigned long hlen = hdr->len;
	unsigned short node_hlen = node->hdr_len;
	const char *pos = node->hdr;
	TfwHPackCmpStates state = HPACK_HDR_NAME_SEARCH;

#define HDR_PART_SHIFT(t_part, s_part)					\
do {									\
	pos += t_part;							\
	node_hlen -= t_part;						\
	data += s_part;							\
	len -= s_part;							\
} while (0)

#define HDR_PART_COMPARE(part_len, ret)					\
do {									\
	i = HPACK_HDR_OWS_PROCESS(part_len, ret);			\
	T_DBG3("%s: ows processing, part_len=%u, state=%d, *nm_node=[%p]," \
	       " node->hdr_len=%hu, node_hlen=%hu, pos='%.*s', len=%hu," \
	       " data='%.*s'\n", __func__, part_len, state, *nm_node,	\
	       node->hdr_len, node_hlen, node_hlen, pos, len,		\
	       len, data);						\
	HDR_PART_SHIFT(i + 1, part_len);				\
	if (state == HPACK_HDR_NAME_FOUND) {				\
		if (!*nm_node)						\
			*nm_node = node;				\
		hlen -=	chunk->len - min_len;				\
		goto chunk_end;						\
	}								\
} while (0)

#define SHIFT(n)							\
	HDR_PART_SHIFT(n, n)

	TFW_STR_FOR_EACH_CHUNK(chunk, hdr, end) {
		unsigned short min_len, len;
		const char *data = chunk->data;

		if (!chunk->len)
			continue;

		T_DBG3("%s: state=%d, hlen=%lu, node_hlen=%hu, pos='%.*s',"
		       " chunk->len=%lu, chunk->data='%.*s'\n", __func__, state,
		       hlen, node_hlen, node_hlen, pos, chunk->len,
		       (int)chunk->len, data);

		if (state == HPACK_HDR_NAME_FOUND) {
			if (unlikely(data[0] == ' ' || data[0] == '\t')) {
				hlen -= chunk->len;
				continue;
			}
			state = HPACK_HDR_VALUE_FOUND;
		}

		len = min_len = min((unsigned long)node_hlen, chunk->len);
		hlen -= min_len;
		while (len >= 4) {
			if (state == HPACK_HDR_NAME_SEARCH) {
				if (INT_LE_LC(pos) > INT_LE_LC(data))
					HDR_PART_COMPARE(4, -1);
				else if (INT_LE_LC(pos) < INT_LE_LC(data))
					HDR_PART_COMPARE(4, 1);
				else
					SHIFT(4);
			}
			else {
				if (INT_LE(pos) > INT_LE(data))
					HDR_PART_COMPARE(4, -1);
				else if (INT_LE(pos) < INT_LE(data))
					HDR_PART_COMPARE(4, 1);
				else
					SHIFT(4);
			}
		}
		while (len >= 2) {
			if (state == HPACK_HDR_NAME_SEARCH) {
				if (SH_LE_LC(pos) > SH_LE_LC(data))
					HDR_PART_COMPARE(2, -1);
				else if (SH_LE_LC(pos) < SH_LE_LC(data))
					HDR_PART_COMPARE(2, 1);
				else
					SHIFT(2);
			}
			else {
				if (SH_LE(pos) > SH_LE(data))
					HDR_PART_COMPARE(2, -1);
				else if (SH_LE(pos) < SH_LE(data))
					HDR_PART_COMPARE(2, 1);
				else
					SHIFT(2);
			}
		}
		if (len) {
			if (state == HPACK_HDR_NAME_SEARCH) {
				if (CHAR_LC(pos) > CHAR_LC(data))
					HDR_PART_COMPARE(1, -1);
				else if (CHAR_LC(pos) < CHAR_LC(data))
					HDR_PART_COMPARE(1, 1);
				else
					SHIFT(1);
			}
			else {
				if (HP_CHAR(pos) > HP_CHAR(data))
					HDR_PART_COMPARE(1, -1);
				else if (HP_CHAR(pos) < HP_CHAR(data))
					HDR_PART_COMPARE(1, 1);
				else
					SHIFT(1);
			}
		}
chunk_end:
		if (!node_hlen) {
			unsigned long k = min_len;
			/*
			 * If we have matched @node_hlen characters of header,
			 * and the remained characters are OWS, then the entire
			 * header should be considered matched.
			 */
			WARN_ON_ONCE(state != HPACK_HDR_VALUE_FOUND);
			for (;;) {
				for (; k < chunk->len; ++k) {
					if (data[k] != ' ' && data[k] != '\t')
						return 1;
				}

				if (++chunk >= end)
					return 0;

				data = chunk->data;
				k = 0;
			}
		}
	}
	WARN_ON_ONCE(hlen);

	return node_hlen ? -1 : 0;

#undef HDR_PART_SHIFT
#undef HDR_PART_COMPARE
#undef SHIFT
}

/*
 * Copy the header part (i.e. name/value) into @out_buf from @h_field.
 * Return pointer on the next position of @out_buf, after the copied data.
 * Note that the size of prepared @out_buf must be not less than the
 * length of the @h_field.
 */
static char *
tfw_hpack_write(const TfwStr *h_field, char *out_buf)
{
	const TfwStr *c, *end;

	T_DBG3("%s: enter, h_field->len=%lu,\n", __func__, h_field->len);

	if (WARN_ON_ONCE(TFW_STR_EMPTY(h_field)))
		return out_buf;

	TFW_STR_FOR_EACH_CHUNK(c, h_field, end) {
		if (!c->len)
			continue;

		T_DBG3("%s: c->len=%lu, c->data='%.*s'\n", __func__, c->len,
		       (int)c->len, c->data);

		memcpy_fast(out_buf, c->data, c->len);
		out_buf += c->len;
	}

	return out_buf;
}

/*
 * Left rotation of red-black tree.
 */
static void
tfw_hpack_rbtree_left_rt(TfwHPackETbl *__restrict tbl,
			 TfwHPackNode *__restrict old_apex)
{
	TfwHPackNode *child, *parent;
	TfwHPackNode *new_apex = HPACK_NODE_COND(tbl, old_apex->right);

	BUG_ON(!new_apex);
	old_apex->right = new_apex->left;

	child = HPACK_NODE_COND(tbl, new_apex->left);
	if (child)
		child->parent = HPACK_NODE_OFF(tbl, old_apex);

	new_apex->parent = old_apex->parent;
	parent = HPACK_NODE_COND(tbl, old_apex->parent);
	if (!parent)
	{
		tbl->root = new_apex;
	}
	else if (!HPACK_NODE_EMPTY(parent->left)
		 && old_apex == HPACK_NODE(tbl, parent->left))
	{
		parent->left = HPACK_NODE_OFF(tbl, new_apex);
	}
	else
	{
		parent->right = HPACK_NODE_OFF(tbl, new_apex);
	}

	new_apex->left = HPACK_NODE_OFF(tbl, old_apex);
	old_apex->parent = HPACK_NODE_OFF(tbl, new_apex);
}

/*
 * Right rotation of red-black tree.
 */
static void
tfw_hpack_rbtree_right_rt(TfwHPackETbl *__restrict tbl,
			  TfwHPackNode *__restrict old_apex)
{
	TfwHPackNode *child, *parent;
	TfwHPackNode *new_apex = HPACK_NODE_COND(tbl, old_apex->left);

	BUG_ON(!new_apex);
	old_apex->left = new_apex->right;

	child = HPACK_NODE_COND(tbl, new_apex->right);
	if (child)
		child->parent = HPACK_NODE_OFF(tbl, old_apex);

	new_apex->parent = old_apex->parent;
	parent = HPACK_NODE_COND(tbl, old_apex->parent);
	if (!parent)
	{
		tbl->root = new_apex;
	}
	else if (!HPACK_NODE_EMPTY(parent->left)
		 && old_apex == HPACK_NODE(tbl, parent->left))
	{
		parent->left = HPACK_NODE_OFF(tbl, new_apex);
	}
	else
	{
		parent->right = HPACK_NODE_OFF(tbl, new_apex);
	}

	new_apex->right = HPACK_NODE_OFF(tbl, old_apex);
	old_apex->parent = HPACK_NODE_OFF(tbl, new_apex);
}

/*
 * Procedure for red-black tree rebalancing after the new node insertion.
 */
static void
tfw_hpack_rbtree_ins_rebalance(TfwHPackETbl *__restrict tbl,
			       TfwHPackNode *__restrict new)
{
	TfwHPackNode *parent = HPACK_NODE_COND(tbl, new->parent);

	while (parent && HPACK_RB_IS_RED(parent)) {
		TfwHPackNode *gparent = HPACK_NODE_COND(tbl, parent->parent);
		TfwHPackNode *gp_left_child, *uncle;

		BUG_ON(!gparent);
		gp_left_child = HPACK_NODE_COND(tbl, gparent->left);
		if (parent == gp_left_child) {
			uncle = HPACK_NODE_COND(tbl, gparent->right);
			if (uncle && HPACK_RB_IS_RED(uncle)) {
				HPACK_RB_SET_BLACK(parent);
				HPACK_RB_SET_BLACK(uncle);
				HPACK_RB_SET_RED(gparent);
				parent = HPACK_NODE_COND(tbl, gparent->parent);
				new = gparent;
			}
			else {
				if (!HPACK_NODE_EMPTY(parent->right)
				    && new == HPACK_NODE(tbl, parent->right))
				{
					tfw_hpack_rbtree_left_rt(tbl, parent);
					parent = new;
					/*
					 * Don't need `new = HPACK_NODE_COND(tbl, parent->left);`.
					 * This is the last iteration, because the parent will turn
					 * black below
					 */
				}
				HPACK_RB_SET_BLACK(parent);
				HPACK_RB_SET_RED(gparent);
				tfw_hpack_rbtree_right_rt(tbl, gparent);
			}
		}
		else {
			uncle = gp_left_child;
			if (uncle && HPACK_RB_IS_RED(uncle)) {
				HPACK_RB_SET_BLACK(parent);
				HPACK_RB_SET_BLACK(uncle);
				HPACK_RB_SET_RED(gparent);
				parent = HPACK_NODE_COND(tbl, gparent->parent);
				new = gparent;
			}
			else {
				if (!HPACK_NODE_EMPTY(parent->left)
				    && new == HPACK_NODE(tbl, parent->left))
				{
					tfw_hpack_rbtree_right_rt(tbl, parent);
					parent = new;
					/*
					 * Don't need `new = HPACK_NODE_COND(tbl, parent->right);`.
					 * This is the last iteration, because the parent will turn
					 * black below
					 */
				}
				HPACK_RB_SET_BLACK(parent);
				HPACK_RB_SET_RED(gparent);
				tfw_hpack_rbtree_left_rt(tbl, gparent);
			}
		}
	}

	HPACK_RB_SET_BLACK(tbl->root);
}

/*
 * Procedure for red-black tree rebalancing after the node deletion.
 */
static void
tfw_hpack_rbtree_del_rebalance(TfwHPackETbl *__restrict tbl,
			       TfwHPackNode *__restrict nchild,
			       TfwHPackNode *__restrict parent)
{
	BUG_ON(!tbl->root);

	while (!nchild || (nchild != tbl->root && HPACK_RB_IS_BLACK(nchild))) {
		TfwHPackNode *brother, *l_neph, *r_neph;

		if (nchild == HPACK_NODE_COND(tbl, parent->left)) {
			BUG_ON(HPACK_NODE_EMPTY(parent->right));
			brother = HPACK_NODE(tbl, parent->right);
			if (HPACK_RB_IS_RED(brother)) {
				HPACK_RB_SET_BLACK(brother);
				HPACK_RB_SET_RED(parent);
				tfw_hpack_rbtree_left_rt(tbl, parent);
				/*
				 * In case 1 @brother->left and @brother->right
				 * also cannot be empty leafs (otherwise the 5th
				 * property of red-black tree will be broken,
				 * since the @brother itself is red in case 1),
				 * so after left rotation we can use new @brother
				 * as non-empty node.
				 */
				brother = HPACK_NODE_COND(tbl, parent->right);
				BUG_ON(!brother);
			}

			l_neph = HPACK_NODE_COND(tbl, brother->left);
			r_neph = HPACK_NODE_COND(tbl, brother->right);
			if ((!l_neph || HPACK_RB_IS_BLACK(l_neph))
			    && (!r_neph || HPACK_RB_IS_BLACK(r_neph)))
			{
				HPACK_RB_SET_RED(brother);
				nchild = parent;
				parent = HPACK_NODE_COND(tbl, nchild->parent);
			}
			else
			{
				if  (!r_neph || HPACK_RB_IS_BLACK(r_neph)) {
					HPACK_RB_SET_BLACK(l_neph);
					HPACK_RB_SET_RED(brother);
					tfw_hpack_rbtree_right_rt(tbl, brother);
					r_neph = brother;
					brother = HPACK_NODE_COND(tbl,
								  parent->right);
				}
				HPACK_RB_COPY_COLOR(brother, parent);
				HPACK_RB_SET_BLACK(parent);
				HPACK_RB_SET_BLACK(r_neph);
				tfw_hpack_rbtree_left_rt(tbl, parent);
				nchild = tbl->root;
			}
		}
		else {
			BUG_ON(HPACK_NODE_EMPTY(parent->left));
			brother = HPACK_NODE(tbl, parent->left);

			if (HPACK_RB_IS_RED(brother)) {
				HPACK_RB_SET_BLACK(brother);
				HPACK_RB_SET_RED(parent);
				tfw_hpack_rbtree_right_rt(tbl, parent);
				brother = HPACK_NODE_COND(tbl, parent->left);
				BUG_ON(!brother);
			}

			l_neph = HPACK_NODE_COND(tbl, brother->left);
			r_neph = HPACK_NODE_COND(tbl, brother->right);
			if ((!l_neph || HPACK_RB_IS_BLACK(l_neph))
			    && (!r_neph || HPACK_RB_IS_BLACK(r_neph)))
			{
				HPACK_RB_SET_RED(brother);
				nchild = parent;
				parent = HPACK_NODE_COND(tbl, nchild->parent);
			}
			else
			{
				if  (!l_neph || HPACK_RB_IS_BLACK(l_neph)) {
					HPACK_RB_SET_BLACK(r_neph);
					HPACK_RB_SET_RED(brother);
					tfw_hpack_rbtree_left_rt(tbl, brother);
					l_neph = brother;
					brother = HPACK_NODE_COND(tbl,
								  parent->left);
				}
				HPACK_RB_COPY_COLOR(brother, parent);
				HPACK_RB_SET_BLACK(parent);
				HPACK_RB_SET_BLACK(l_neph);
				tfw_hpack_rbtree_right_rt(tbl, parent);
				nchild = tbl->root;
			}
		}
	}

	HPACK_RB_SET_BLACK(nchild);
}

static inline TfwHPackNode *
tfw_hpack_rbtree_min(TfwHPackETbl *__restrict tbl,
		     TfwHPackNode *__restrict node)
{
	BUG_ON(!node);

	while (!HPACK_NODE_EMPTY(node->left)) {
		node = HPACK_NODE(tbl, node->left);
	}

	return node;
}

/*
 * Procedure for branches replacement in red-black tree.
 */
static inline void
tfw_hpack_rbtree_replace(TfwHPackETbl *__restrict tbl,
			 TfwHPackNode *__restrict old,
			 TfwHPackNode *__restrict new)
{
	TfwHPackNode *parent = HPACK_NODE_COND(tbl, old->parent);

	BUG_ON(!old);
	if (!parent)
	{
		WARN_ON_ONCE(tbl->root != old);
		tbl->root = new;
	}
	else if (!HPACK_NODE_EMPTY(parent->left)
		 && old == HPACK_NODE(tbl, parent->left))
	{
		parent->left = HPACK_NODE_COND_OFF(tbl, new);
	}
	else
	{
		WARN_ON_ONCE(HPACK_NODE_EMPTY(parent->right)
			     || old != HPACK_NODE(tbl, parent->right));
		parent->right = HPACK_NODE_COND_OFF(tbl, new);
	}

	if (new)
		new->parent = HPACK_NODE_COND_OFF(tbl, parent);
}

/*
 * Add @new node into the red-black tree in appropriate place passed from the caller
 * (and ultimately - from the @tfw_hpack_rbtree_find() unsuccessful call) in @it
 * argument.
 */
static void
tfw_hpack_rbtree_add(TfwHPackETbl *__restrict tbl, TfwHPackNode *__restrict new,
		     TfwHPackNodeIter *__restrict it)
{
	TfwHPackNode *parent = it->parent;
	short *poff = it->poff;

	new->parent = HPACK_NODE_COND_OFF(tbl, parent);
	if (!parent) {
		BUG_ON(tbl->root);
		tbl->root = new;
	}
	else {
		*poff = HPACK_NODE_OFF(tbl, new);
	}

	new->right = new->left = -1;
	HPACK_RB_SET_RED(new);

	tfw_hpack_rbtree_ins_rebalance(tbl, new);
}

/*
 * Find node which matches the required header @hdr in the red-black tree and
 * pass it to the caller in @out_node variable. If only header name is found,
 * the corresponding node is also passed upstairs, and appropriate  value is
 * returned to the caller. Note, that in case of unsuccessful search, the last
 * processed node with appropriate leaf is passed to caller in @out_place
 * variable and can be used for adding new node in correct place without
 * additional tree search (see comment for @tfw_hpack_rbtree_add() above).
 */
static TfwHPackETblRes
tfw_hpack_rbtree_find(TfwHPackETbl *__restrict tbl,
		      const TfwStr *__restrict hdr,
		      const TfwHPackNode **__restrict out_node,
		      TfwHPackNodeIter *__restrict out_place)
{
	int res;
	TfwHPackNode *parent = NULL;
	TfwHPackNode *node = tbl->root;
	const TfwHPackNode *nm_node = NULL;

	while (node) {
		parent = node;
		res = tfw_hpack_node_compare(hdr, node, &nm_node);

		if (res < 0)
			node = HPACK_NODE_COND(tbl, node->left);
		else if (res > 0)
			node = HPACK_NODE_COND(tbl, node->right);
		else {
			*out_node = node;
			return HPACK_IDX_ST_FOUND;
		}
	}

	out_place->parent = parent;

	if (!parent)
		out_place->poff = NULL;
	else if (res < 0)
		out_place->poff = &parent->left;
	else
		out_place->poff = &parent->right;

	/*
	 * If the node for the whole header @hdr is not found, but instead the
	 * node with header name is found, the pointer to that node must be
	 * assigned to the @nm_node. In this case the node with header name
	 * should be returned to the caller with special return value
	 * HPACK_IDX_ST_NM_FOUND indicating that only the name of header
	 * has been found, not the entire header.
	 */
	if (nm_node) {
		*out_node = nm_node;
		return HPACK_IDX_ST_NM_FOUND;
	}

	return HPACK_IDX_ST_NOT_FOUND;
}

/*
 * Remove specified node from the read-black tree.
 */
static void
tfw_hpack_rbtree_erase(TfwHPackETbl *__restrict tbl,
		       TfwHPackNode *__restrict node)
{
	TfwHPackNode *nchild, *sv = node;
	TfwHPackNode *parent = HPACK_NODE_COND(tbl, node->parent);
	bool sv_black = HPACK_RB_IS_BLACK(sv);

	if (HPACK_NODE_EMPTY(node->left)) {
		nchild = HPACK_NODE_COND(tbl, node->right);
		tfw_hpack_rbtree_replace(tbl, node, nchild);
	}
	else if (HPACK_NODE_EMPTY(node->right)) {
		nchild = HPACK_NODE_COND(tbl, node->left);
		tfw_hpack_rbtree_replace(tbl, node, nchild);
	}
	else {
		TfwHPackNode *n_left;

		sv = tfw_hpack_rbtree_min(tbl, HPACK_NODE(tbl, node->right));
		sv_black = HPACK_RB_IS_BLACK(sv);

		nchild = HPACK_NODE_COND(tbl, sv->right);

		if (node != HPACK_NODE(tbl, sv->parent)) {
			TfwHPackNode *n_right;

			parent = HPACK_NODE(tbl, sv->parent);
			tfw_hpack_rbtree_replace(tbl, sv, nchild);

			n_right = HPACK_NODE(tbl, node->right);
			n_right->parent = HPACK_NODE_OFF(tbl, sv);
			sv->right = node->right;
		}
		else {
			parent = sv;
		}

		tfw_hpack_rbtree_replace(tbl, node, sv);

		n_left = HPACK_NODE(tbl, node->left);
		n_left->parent = HPACK_NODE_OFF(tbl, sv);
		sv->left = node->left;

		HPACK_RB_COPY_COLOR(sv, node);
	}

	/*
	 * It makes sense to perform re-balancing only if the relocated/deleted
	 * node is BLACK and if tree is not empty (i.e. the deleted node is not
	 * the last).
	 */
	if (sv_black && tbl->root)
		tfw_hpack_rbtree_del_rebalance(tbl, nchild, parent);
}

static inline void
tfw_hpack_rbuf_iter(TfwHPackETbl *__restrict tbl,
		    TfwHPackETblIter *__restrict iter)
{
	iter->first = tbl->first;
	iter->last = tbl->last;
	iter->rb_len = tbl->rb_len;
	iter->rb_size = tbl->rb_size;
	iter->size = tbl->size;
}

static int
tfw_hpack_rbuf_calc(TfwHPackETbl *__restrict tbl, unsigned short new_size,
		    TfwHPackNode *__restrict del_list[],
		    TfwHPackETblIter *__restrict it)
{
	int i = 0;
	char *first = (char *)it->first;
	char *last = (char *)it->last;
	char *rbuf = tbl->rbuf;
	unsigned short size = it->size;
	unsigned short rb_len = it->rb_len;
	unsigned short last_len = HPACK_NODE_SIZE(last);

	WARN_ON_ONCE(!first || !last);
	do {
		unsigned short f_len, fhdr_len;

		if (i >= HPACK_MAX_ENC_EVICTION)
			return -E2BIG;

		if (last == first) {
			it->first = it->last = NULL;
			it->rb_len = it->size = 0;
			WARN_ON_ONCE(it->rb_size != HPACK_ENC_TABLE_MAX_SIZE);
			T_DBG3("%s: table is empty (rbuf=[%p])\n", __func__,
			       rbuf);
			return 0;
		}

		f_len = HPACK_NODE_SIZE(first);
		fhdr_len = ((TfwHPackNode *)first)->hdr_len;

		T_DBG3("%s: rb_len=%hu, size=%hu, new_size=%hu, rbuf=[%p],"
		       " first=[%p], last=[%p], f_len=%hu, fhdr_len=%hu,"
		       " last_len=%hu\n", __func__, rb_len, size, new_size,
		       rbuf, first, last, f_len, fhdr_len, last_len);

		if (del_list)
			del_list[i++] = (TfwHPackNode *)first;
		else
			tfw_hpack_rbtree_erase(tbl, (TfwHPackNode *)first);

		if (last < first && rb_len - f_len == last - rbuf + last_len) {
			it->rb_size = HPACK_ENC_TABLE_MAX_SIZE;
			first = rbuf;
		}
		else {
			first = (char *)HPACK_NODE_NEXT(first);
		}

		size -= HPACK_ENTRY_OVERHEAD + fhdr_len;
		rb_len -= f_len;

	} while (size > new_size);

	it->size = size;
	it->rb_len = rb_len;
	it->first = (TfwHPackNode *)first;

	return 0;
}

static inline void
tfw_hpack_rbuf_commit(TfwHPackETbl *__restrict tbl,
		      TfwStr *__restrict hdr,
		      TfwHPackNode *__restrict del_list[],
		      TfwHPackNodeIter *__restrict place,
		      TfwHPackETblIter *__restrict iter)
{
	int i;
	bool was_del = false;
	const TfwHPackNode *node = NULL;
	TfwHPackETblRes res = HPACK_IDX_ST_NOT_FOUND;

	for (i = 0; i < HPACK_MAX_ENC_EVICTION; ++i) {
		TfwHPackNode *del_node = del_list[i];

		if (!del_node)
			break;
		tfw_hpack_rbtree_erase(tbl, del_node);
		was_del = true;
	}

	/*
	 * If there was a deletion, the place may turn out to be invalid as a result
	 * of reducing the procedure for deleting a node with two children to
	 * deleting a node with less than two children.
	 */
	if (was_del) {
		res = tfw_hpack_rbtree_find(tbl, hdr, &node, place);
		WARN_ON_ONCE(res == HPACK_IDX_ST_FOUND);
	}

	tfw_hpack_rbtree_add(tbl, iter->last, place);

	tbl->first = iter->first;
	tbl->last = iter->last;
	tbl->rb_len = iter->rb_len;
	tbl->rb_size = iter->rb_size;
	tbl->size = iter->size;
}

/*
 * Add new header into the encoder dynamic index. If new size of index table
 * will be greater than current maximum allowed table size, the excess old
 * headers will be evicted from the index table.
 */
static int
tfw_hpack_add_node(TfwHPackETbl *__restrict tbl, TfwStr *__restrict hdr,
		   TfwHPackNodeIter *__restrict place, TfwH2TransOp op)
{
	char *ptr;
	unsigned long node_size, hdr_len;
	unsigned short new_size, node_len;
	unsigned short cur_size = tbl->size, window = tbl->window;
	TfwHPackNode *del_list[HPACK_MAX_ENC_EVICTION] = {};
	TfwStr s_nm = {}, s_val = {};
	TfwHPackETblIter it = {};

	hdr_len = tfw_http_hdr_split(hdr, &s_nm, &s_val,
				     op == TFW_H2_TRANS_INPLACE);

	WARN_ON_ONCE(cur_size > window || window > HPACK_ENC_TABLE_MAX_SIZE);
	if ((node_size = hdr_len + HPACK_ENTRY_OVERHEAD) > window) {
		T_DBG3("%s: header is too big (node_size = %lu, window = %hu)"
		       " and cannot be added into index\n", __func__, node_size,
		       window);
		return -E2BIG;
	}

	/*
	 * Overflow cannot occur in @new_size, since it has unsigned short
	 * integer type, and @cur_size as well as @node_size must be not greater
	 * than SHRT_MAX.
	 */
	new_size = cur_size + node_size;
	WARN_ON_ONCE(new_size < node_size);
	T_DBG3("%s: window=%hu, size=%hu, new_size=%hu, node_size=%lu\n",
	       __func__, window, cur_size, new_size, node_size);

	/*
	 * Taking into account the ring buffer structure there may be cases when
	 * we will have enough space in @window pseudo-size for new entry, but
	 * not enough space in ring buffer itself. These situations can arise
	 * when the same entry should be placed in the end and in the beginning
	 * area of ring buffer (wrapped), but since the entry cannot be splitted,
	 * it will not fit neither at the end of buffer, nor at the start. Even
	 * if the entry fits at the beginning of the ring buffer, the size of
	 * the buffer will be reduced by the size of unused end space, and the
	 * situation with too large entry can arise in future (until the buffer
	 * will be wrapped and end space delta will be discarded). Thus, due to
	 * necessity of keeping the index tables on both sides of HTTP/2
	 * connection in synchronized state during adding new entry, we need at
	 * first calculate the changes for ring buffer in @it and then commit
	 * them; in this way, if new entry will not fit into the buffer, we can
	 * safely discard all changes keeping tables on server and client sides
	 * in consistent state.
	 */
	tfw_hpack_rbuf_iter(tbl, &it);

	if (new_size > window
	    && tfw_hpack_rbuf_calc(tbl, window - node_size, del_list, &it))
		return -E2BIG;

	node_len = HPACK_ALIGN(sizeof(TfwHPackNode) + hdr_len);

	if (it.rb_size < it.rb_len + node_len) {
		WARN_ON_ONCE(it.rb_size == HPACK_ENC_TABLE_MAX_SIZE);
		return -E2BIG;
	}
	else if (!it.first) {
		it.first = it.last = (TfwHPackNode *)tbl->rbuf;
		T_DBG3("%s: reset, rbuf=[%p] rb_len=%hu, rb_size=%hu, size=%hu,"
		       " node_len=%hu\n",  __func__, tbl->rbuf, it.rb_len,
		       it.rb_size, it.size, node_len);
		goto commit;
	}
	else if (it.first <= it.last) {
		unsigned short last_len = HPACK_NODE_SIZE(it.last);
		unsigned short end_space = HPACK_ENC_TABLE_MAX_SIZE;
		/*
		 * In this case @rb_size must always be reset before
		 * (in @tfw_hpack_rbuf_calc()).
		 */
		WARN_ON_ONCE(it.rb_size != HPACK_ENC_TABLE_MAX_SIZE);
		end_space -= ((char *)it.last - tbl->rbuf) + last_len;
		if (end_space < node_len) {
			T_DBG3("%s: wrap, rbuf=[%p], first=[%p], last=[%p],"
			       " rb_len=%hu, rb_size=%hu, size=%hu,"
			       " end_space=%hu, node_len=%hu\n", __func__,
			       tbl->rbuf, it.first, it.last, it.rb_len,
			       it.rb_size, it.size, end_space, node_len);

			if (it.rb_size - end_space < it.rb_len + node_len)
				return -E2BIG;

			it.rb_size -= end_space;
			it.last = (TfwHPackNode *)tbl->rbuf;

			goto commit;
		}
	}

	it.last = HPACK_NODE_NEXT(it.last);

	T_DBG3("%s: next node, rbuf=[%p], first=[%p], last=[%p], rb_len=%hu,"
	       " rb_size=%hu, size=%hu, node_len=%hu\n", __func__, tbl->rbuf,
	       it.first, it.last, it.rb_len, it.rb_size, it.size, node_len);

commit:
	it.size += node_size;
	it.rb_len += node_len;
	it.last->hdr_len = hdr_len;
	it.last->rindex = ++tbl->idx_acc;

	ptr = tfw_hpack_write(&s_nm, it.last->hdr);
	tfw_hpack_write(&s_val, ptr);

	tfw_hpack_rbuf_commit(tbl, hdr, del_list, place, &it);

	WARN_ON_ONCE(tbl->rb_len > tbl->size);

	return 0;
}

/*
 * HPACK encoder index determination procedure. Operates with connection-wide
 * encoder dynamic table with potentially concurrent access from different
 * threads, so lock is used to protect the find/add/erase operations inside
 * this procedure.
 */
static TfwHPackETblRes
tfw_hpack_encoder_index(TfwHPackETbl *__restrict tbl,
			TfwStr *__restrict hdr,
			unsigned short *__restrict out_index,
			unsigned long *__restrict flags,
			TfwH2TransOp op)
{
	TfwHPackNodeIter place = {};
	const TfwHPackNode *node = NULL;
	TfwHPackETblRes res = HPACK_IDX_ST_NOT_FOUND;

	BUILD_BUG_ON(HPACK_IDX_ST_MASK < _HPACK_IDX_ST_NUM - 1);
	if (WARN_ON_ONCE(!hdr))
		return -EINVAL;

	spin_lock(&tbl->lock);

	if (!test_bit(TFW_HTTP_B_H2_TRANS_ENTERED, flags)
	    && atomic64_read(&tbl->guard) < 0)
		goto out;

	res = tfw_hpack_rbtree_find(tbl, hdr, &node, &place);

	WARN_ON_ONCE(!node && res != HPACK_IDX_ST_NOT_FOUND);

	*out_index = HPACK_NODE_GET_INDEX(tbl, node);

	/*
	 * Encoder dynamic index can be in three states: initial state (@guard
	 * is zero), read state (@guard is 1 or greater), and write state
	 * (@guard is -1); in read state any thread can search in index, but
	 * nobody can add or evict entries in index; if index in the write state
	 * only one thread (current writer) can add/evict entries in index and
	 * nobody can search in index; index can be switched to write state
	 * only from initial state (in general case) or from read state (if
	 * current reader is the sole read owner of the index).
	 */
	if (!test_bit(TFW_HTTP_B_H2_TRANS_ENTERED, flags)) {
		if(res != HPACK_IDX_ST_FOUND
		   && !atomic64_read(&tbl->guard)
		   && !tfw_hpack_add_node(tbl, hdr, &place, op))
		{
			res |= HPACK_IDX_FLAG_ADD;
			atomic64_set(&tbl->guard, -1);
			__set_bit(TFW_HTTP_B_H2_TRANS_ENTERED, flags);
		}
		else if (res != HPACK_IDX_ST_NOT_FOUND)
		{
			atomic64_inc(&tbl->guard);
			__set_bit(TFW_HTTP_B_H2_TRANS_ENTERED, flags);
		}
	}
	else {
		/*
		 * If value of guard is 1, we are the sole owner of the encoder
		 * dynamic index with read rights, thus we can write to it.
		 * Note, that @guard cannot be zero here, since we are already
		 * owning encoder index with read or write rights (i.e. the flag
		 * @TFW_HTTP_B_H2_TRANS_ENTERED is set for the corrently
		 * processed message), thus we have already set the @guard
		 * equal to 1 (or greater) or to -1 before.
		 */
		WARN_ON_ONCE(!atomic64_read(&tbl->guard));
		if (res != HPACK_IDX_ST_FOUND
		    && atomic64_read(&tbl->guard) <= 1
		    && !tfw_hpack_add_node(tbl, hdr, &place, op))
		{
			res |= HPACK_IDX_FLAG_ADD;
			atomic64_set(&tbl->guard, -1);
		}
	}

out:
	spin_unlock(&tbl->lock);

	return res;
}

void
tfw_hpack_enc_release(TfwHPack *__restrict hp, unsigned long *flags)
{
	TfwHPackETbl *tbl = &hp->enc_tbl;

	if (!test_bit(TFW_HTTP_B_H2_TRANS_ENTERED, flags))
		return;

	if (atomic64_read(&tbl->guard) < 0) {
		atomic64_set(&tbl->guard, 0);
	}
	else {
		WARN_ON_ONCE(!atomic64_read(&tbl->guard));
		atomic64_dec(&tbl->guard);
	}

	__clear_bit(TFW_HTTP_B_H2_TRANS_ENTERED, flags);
}

static unsigned long
tfw_huffman_encode_string_len(TfwStr *str)
{
	TfwStr *c, *end;
	unsigned long n = 0;

	BUG_ON(TFW_STR_DUP(str));

	TFW_STR_FOR_EACH_CHUNK(c, str, end) {
		unsigned long i;

		for (i = 0; i < c->len; i++) {
			n += ht_length[(unsigned char)c->data[i]];
		}
	}

	return (n + 7) >> 3;
}

static int
tfw_huffman_encode_copy(TfwStr *__restrict src, TfwStr *__restrict dst_str)
{
	TfwStr *c, *end;
	int off = 0;
	u64 last_word = 0;
	u64 *dst = (u64 *)dst_str->data;
	const char *dst_end = dst_str->data + dst_str->len;

#define JOIN_BITS(a, len, b) (((a) << (len)) | (b))
#define write_bytes(n)							\
do {									\
	unsigned int __n = n;						\
	do {								\
		if (unlikely(dst_end - (char *)dst == 0))		\
			return -EINVAL;					\
		*(char *)dst++ = (char)last_word;			\
		last_word >>= 8;					\
	} while (--__n);						\
} while (0)

	BUG_ON(!TFW_STR_PLAIN(dst_str));

	TFW_STR_FOR_EACH_CHUNK(c, src, end) {
		unsigned long i;

		for (i = 0; i < c->len; i++) {
			const unsigned int s = c->data[i];
			const unsigned int d = 64 - off;
			const unsigned int e = ht_encode[s];
			const unsigned int l = ht_length[s];

			off += l;
			if (l <= d) {
				last_word = JOIN_BITS(last_word, l, e);
			} else {
				off -= 64;
				last_word = JOIN_BITS(last_word, d, e >> off);
				if (dst_end - (char *)dst >= sizeof(u64)) {
					last_word = cpu_to_be64(last_word);
					*dst = last_word;
					dst++;
				} else {
					write_bytes(sizeof(u64));
				}
				last_word = e;
			}
		}
	}

	if (off) {
		unsigned int tail = off & 7;

		if (tail) {
			unsigned int d = 8 - tail;

			last_word = JOIN_BITS(last_word, d, HT_EOS_HIGH >> tail);
			off += d;
		}
		last_word <<= 64 - off;
		last_word = cpu_to_be64(last_word);
		if (off == 64) {
			if (dst_end - (char *)dst >= sizeof(u64)) {
				*dst = last_word;
				dst++;
			} else {
				write_bytes(sizeof(u64));
			}
			goto done;
		}
		if (off > 31) {
			if (dst_end - (char *)dst >= sizeof(u32)) {
				*(u32 *)dst = (u32)last_word;
				dst = (u64 *)((u32 *)dst + 1);
			} else {
				write_bytes(sizeof(u32));
			}
			last_word >>= 32;
			off -= 32;
		}
		if (off > 15) {
			if (dst_end - (char *)dst >= sizeof(u16)) {
				*(u16 *)dst = (u16)last_word;
				dst = (u64 *)((u16 *)dst + 1);
			} else {
				write_bytes(sizeof(u16));
			}
			last_word >>= 16;
			off -= 16;
		}
		if (off) {
			if (unlikely(dst_end - (char *)dst == 0))
				return -EINVAL;
			*(u8 *)dst = (u8)last_word;
		}
	}

#undef JOIN_BITS
#undef write_bytes

done:
	return 0;
}

static TfwStr *
tfw_huffman_encode_string(TfwStr *str, TfwPool *pool)
{
	unsigned long enc_len = tfw_huffman_encode_string_len(str);
	TfwStr *encoded;
	int r;

	if (!enc_len)
		return ERR_PTR(-EINVAL);
	encoded = tfw_pool_alloc(pool, sizeof(TfwStr) + enc_len);
	if (!encoded)
		return ERR_PTR(-ENOMEM);

	TFW_STR_INIT(encoded);
	encoded->data = (char *)(encoded + 1);
	encoded->len = enc_len;

	r = tfw_huffman_encode_copy(str, encoded);

	return r ? ERR_PTR(r) : encoded;
}

static int
tfw_hpack_str_add_raw(TfwHttpTransIter *mit, TfwStr *str, bool in_huffman)
{
	int r = 0;
	TfwHPackInt len;
	TfwStr len_str = { 0 };
	unsigned short mask = in_huffman ? 0x80 : 0x0;

	write_int(str->len, 0x7F, mask, &len);
	len_str.data = len.buf;
	len_str.len = len.sz;

	r = tfw_h2_msg_rewrite_data(mit, &len_str, mit->bnd);
	if (unlikely(r))
		return r;

	return tfw_h2_msg_rewrite_data(mit, str, mit->bnd);
}

static int
tfw_hpack_str_expand_raw(TfwHttpTransIter *mit, TfwMsgIter *it,
			 struct sk_buff **skb_head, TfwStr *str,
			 bool in_huffman)
{
	int r;
	TfwHPackInt len;
	TfwStr len_str = { 0 };
	unsigned short mask = in_huffman ? 0x80 : 0x0;

	write_int(str->len, 0x7F, mask, &len);
	len_str.data = len.buf;
	len_str.len = len.sz;

	r = tfw_http_msg_expand_data(it, skb_head, &len_str, NULL);
	if (unlikely(r))
		return r;
	mit->acc_len += len_str.len;

	r = tfw_http_msg_expand_data(it, skb_head, str, NULL);
	if (unlikely(r))
		return r;
	mit->acc_len += str->len;

	return 0;
}

/*
 * Family of functions to add new or append of h2 response. Huffman encoding
 * is never used due to performance considerations:
 * - We must write first the size of the string, it has variable size, and
 *   string encoded with Huffman codes may be shorter or longer than original
 *   string. The size will be known only after the string is completely encoded.
 * - We can't encode @str in-place in @str: due to variable-sized coding, we
 *   can't overwrite symbol-by symbol in place. But this is also not possible
 *   due to @str origin, some strings are predefined strings from const memory
 *   region, others are shared for all messages to the same vhost.
 * - For skb management we need to have exact data size before using API.
 *
 * Since these reasons we can't encode @str on the fly or encode it while
 * writing to skb, so allocate a new string and copy @str encoded value there.
 * It heavily affect performance, since we have two allocations and two copy
 * operations here. We decided to keep the code, but our core use cases shows
 * no performance improvement opportunities. According to RFC we are free to
 * choose encoding (static/dynamic/Huffman) when modifying already existent
 * headers (e.g. in cases of HTTP/1.1=>HTTP/2 or HTTP/2=>HTTP/2 response proxy),
 * thus avoiding Huffman encodings is completely RFC-compliant behaviour.
 */
static inline int
tfw_hpack_str_add(TfwHttpTransIter *mit, TfwStr *str, TfwPool *pool)
{
	bool in_huffman = false;

	if (0) {
		str = tfw_huffman_encode_string(str, pool);

		if (IS_ERR(str))
			return PTR_ERR(str);
		in_huffman = true;
	}

	return tfw_hpack_str_add_raw(mit, str, in_huffman);
}

static inline int
tfw_hpack_str_expand(TfwHttpTransIter *mit, TfwMsgIter *it,
		     struct sk_buff **skb_head, TfwStr *str,
		     TfwPool *pool)
{
	bool in_huffman = false;

	if (0) {
		str = tfw_huffman_encode_string(str, pool);

		if (IS_ERR(str))
			return PTR_ERR(str);
		in_huffman = true;
	}

	return tfw_hpack_str_expand_raw(mit, it, skb_head, str, in_huffman);
}

/*
 * Add header @hdr in HTTP/2 HPACK format with metadata @idx into the
 * response @resp.
 */
static int
tfw_hpack_hdr_add(TfwHttpResp *__restrict resp, TfwStr *__restrict hdr,
		  TfwHPackInt *__restrict idx, bool name_indexed)
{
	int r;
	TfwStr *c, *end;
	TfwHttpTransIter *mit = &resp->mit;
	TfwStr s_val;
	const TfwStr s_idx = {
		.data = idx->buf,
		.len = idx->sz,
	};

	T_DBG3("%s: s_idx->len=%lu, s_idx->data='%.*s'\n",
	       __func__, s_idx.len, (int)s_idx.len, s_idx.data);

	r = tfw_h2_msg_rewrite_data(mit, &s_idx, mit->bnd);
	if (unlikely(r))
		return r;

	if (!hdr)
		return 0;

	if (WARN_ON_ONCE(TFW_STR_PLAIN(hdr)))
		return -EINVAL;

	if (unlikely(!name_indexed)) {
		r = tfw_hpack_str_add(mit, TFW_STR_CHUNK(hdr, 0), resp->pool);
		if (unlikely(r))
			return r;
	}

	/*
	 * During headers addition into the message the source @hdr must have
	 * the following chunk structure (without the OWS):
	 *
	 *	{ name [S_DLM] value1 [value2 [value3 ...]] }.
	 *
	 */
	c = TFW_STR_CHUNK(hdr, 1);
	if (WARN_ON_ONCE(!c))
		return -EINVAL;

	if (c->len == SLEN(S_DLM) && *(short *)c->data == *(short *)S_DLM) {
		c = TFW_STR_CHUNK(hdr, 2);
		if (WARN_ON_ONCE(!c))
			return -EINVAL;
	}

	end = hdr->chunks + hdr->nchunks;
	tfw_str_collect_cmp(c, end, &s_val, NULL);

	return tfw_hpack_str_add(mit,&s_val, resp->pool);
}

/*
 * Expand the response @resp with the new @hdr in HTTP/2 HPACK format, via
 * extending of skb/frags chain.
 */
static int
tfw_hpack_hdr_expand(TfwHttpResp *__restrict resp, TfwStr *__restrict hdr,
		     TfwHPackInt *__restrict idx, bool name_indexed)
{
	int ret;
	TfwStr *c, *end;
	TfwHttpTransIter *mit = &resp->mit;
	TfwMsgIter *iter = &mit->iter;
	struct sk_buff **skb_head = &resp->msg.skb_head;
	TfwStr s_val;
	TfwStr idx_str = {
		.data = idx->buf,
		.len = idx->sz,
	};

	ret = tfw_http_msg_expand_data(iter, skb_head, &idx_str,
				       &mit->start_off);
	if (unlikely(ret))
		return ret;

	mit->acc_len += idx_str.len;

	T_DBG3("%s: idx, acc_len=%lu, idx_str.len=%lu, idx_str.data='%.*s'\n",
	       __func__, mit->acc_len, idx_str.len, (int)idx_str.len,
	       idx_str.data);

	if (!hdr)
		return 0;

	if (unlikely(!name_indexed)) {
		ret = tfw_hpack_str_expand(mit, iter, skb_head,
					   TFW_STR_CHUNK(hdr, 0), NULL);
		if (unlikely(ret))
			return ret;
	}

	/*
	 * During expanding the message the source @hdr must have the following
	 * chunk structure (without the OWS):
	 *
	 *	{ name [S_DLM] value1 [value2 [value3 ...]] }.
	 *
	 * Besides, we can get here the source header which contains only the
	 * name (e.g. due to creation of headers separately by parts on the
	 * upper HTTP level, during internal responses generation) - this is the
	 * valid case for expanding procedure and we should return control
	 * upstairs in this case - in order the header creation to be continued.
	 *
	 */
	if (!(c = TFW_STR_CHUNK(hdr, 1)))
		return 0;

	if (c->len == SLEN(S_DLM) && *(short *)c->data == *(short *)S_DLM) {
		c = TFW_STR_CHUNK(hdr, 2);
		if (WARN_ON_ONCE(!c))
			return -EINVAL;
	}

	end = hdr->chunks + hdr->nchunks;
	tfw_str_collect_cmp(c, end, &s_val, NULL);

	return tfw_hpack_str_expand(mit, iter, skb_head, &s_val, NULL);
}

/*
 * Transform the HTTP/1.1 header @hdr in-place into HTTP/2 HPACK format in the
 * response @resp.
 */
static int
tfw_hpack_hdr_inplace(TfwHttpResp *__restrict resp, TfwStr *__restrict hdr,
		      TfwHPackInt *__restrict idx, bool name_indexed,
		      bool indexed)
{
	int r;
	const char *bnd;
	TfwHPackInt vlen;
	TfwHttpTransIter *mit = &resp->mit;
	TfwStr s_name = {}, s_val = {}, s_vlen = {};
	const TfwStr s_idx = {
		.data = idx->buf,
		.len = idx->sz,
	};

	T_DBG3("%s: s_idx->len=%lu, s_idx->data='%.*s'\n",
	       __func__, s_idx.len, (int)s_idx.len, s_idx.data);

	if (!hdr || WARN_ON_ONCE(TFW_STR_PLAIN(hdr) || TFW_STR_DUP(hdr)))
		return -EINVAL;

	tfw_http_hdr_split(hdr, &s_name, &s_val, true);

	if (unlikely(!name_indexed)) {
		TfwHPackInt nlen;
		TfwStr s_nlen = {};

		bnd = __TFW_STR_CH(&s_name, 0)->data;

		r = tfw_h2_msg_rewrite_data(mit, &s_idx, bnd);
		if (unlikely(r))
			return r;

		write_int(s_name.len, 0x7F, 0, &nlen);
		s_nlen.data = nlen.buf;
		s_nlen.len = nlen.sz;

		r = tfw_h2_msg_rewrite_data(mit, &s_nlen, bnd);
		if (unlikely(r))
			return r;

		bnd = __TFW_STR_CH(&s_val, 0)->data;

		r = tfw_h2_msg_rewrite_data_lc(mit, &s_name, bnd);
		if (unlikely(r))
			return r;
	} else {
		bnd = indexed
			? mit->bnd
			: __TFW_STR_CH(&s_val, 0)->data;

		r = tfw_h2_msg_rewrite_data(mit, &s_idx, bnd);
		if (unlikely(r))
			return r;

		if (indexed)
			return 0;
	}

	write_int(s_val.len, 0x7F, 0, &vlen);
	s_vlen.data = vlen.buf;
	s_vlen.len = vlen.sz;

	r = tfw_h2_msg_rewrite_data(mit, &s_vlen, bnd);
	if (unlikely(r))
		return r;

	r = tfw_h2_msg_rewrite_data(mit, &s_val, mit->bnd);
	if (unlikely(r))
		return r;

	return 0;
}

/*
 * Perform encoding of the header @hdr into the HTTP/2 HPACK format. The four
 * operation types can be executed here: addition, substitution, in-place
 * transformation and expansion. In cases of addition, substitution and in-place
 * operations the new headers overwrites the old data in the existing skb(s).
 * In the expansion case new headers are added along with new skb(s) creation
 * into the internally generated message.
 */
int
tfw_hpack_encode(TfwHttpResp *__restrict resp, TfwStr *__restrict hdr,
		 TfwH2TransOp op, bool dyn_indexing)
{
	TfwHPackInt idx;
	bool st_full_index;
	unsigned short st_index, index = 0;
	TfwH2Ctx *ctx = tfw_h2_context(resp->req->conn);
	TfwHPackETbl *tbl = &ctx->hpack.enc_tbl;
	int r = HPACK_IDX_ST_NOT_FOUND;

	if (WARN_ON_ONCE(!hdr || TFW_STR_EMPTY(hdr)))
		return -EINVAL;

	st_index = hdr->hpack_idx;
	st_full_index = hdr->flags & TFW_STR_FULL_INDEX;

	T_DBG3("%s: op=%d, st_index=%hu, st_full_index=%d\n", __func__, op,
	       st_index, st_full_index);

	if (!st_full_index && dyn_indexing) {
		r = tfw_hpack_encoder_index(tbl, hdr, &index, resp->flags, op);
		if (r < 0)
			return r;
	}

	if (st_full_index || HPACK_IDX_RES(r) == HPACK_IDX_ST_FOUND) {
		/*
		 * The full index (whether static or dynamic) always takes
		 * precedence over partial index (when only the header name is
		 * indexed).
		 */
		if (!index)
			index = st_index;

		WARN_ON_ONCE(!index);

		write_int(index, 0x7F, 0x80, &idx);
		switch (op) {
		case TFW_H2_TRANS_SUB:
		case TFW_H2_TRANS_ADD:
			return tfw_hpack_hdr_add(resp, NULL, &idx, true);
		case TFW_H2_TRANS_EXPAND:
			return tfw_hpack_hdr_expand(resp, NULL, &idx, true);
		case TFW_H2_TRANS_INPLACE:
			return tfw_hpack_hdr_inplace(resp, hdr, &idx, true,
						     true);
		default:
			BUG();
		}
	}

	if (st_index || HPACK_IDX_RES(r) == HPACK_IDX_ST_NM_FOUND) {
		/*
		 * If we have only partial indexes (static and/or dynamic), the
		 * static index, if it had been found, always takes precedence
		 * over dynamic one.
		 */
		if (st_index)
			index = st_index;

		WARN_ON_ONCE(!index);

		if (r & HPACK_IDX_FLAG_ADD)
			write_int(index, 0x3F, 0x40, &idx);
		else
			write_int(index, 0xF, 0, &idx);

		switch (op) {
		case TFW_H2_TRANS_SUB:
		case TFW_H2_TRANS_ADD:
			return tfw_hpack_hdr_add(resp, hdr, &idx, true);
		case TFW_H2_TRANS_EXPAND:
			return tfw_hpack_hdr_expand(resp, hdr, &idx, true);
		case TFW_H2_TRANS_INPLACE:
			return tfw_hpack_hdr_inplace(resp, hdr, &idx, true,
						     false);
		default:
			BUG();
		}
	}

	WARN_ON_ONCE(index || st_index);

	idx.sz = 1;
	idx.buf[0] = (r & HPACK_IDX_FLAG_ADD) ? 0x40 : 0;

	switch (op) {
	case TFW_H2_TRANS_SUB:
	case TFW_H2_TRANS_ADD:
		return tfw_hpack_hdr_add(resp, hdr, &idx, false);
	case TFW_H2_TRANS_EXPAND:
		return tfw_hpack_hdr_expand(resp, hdr, &idx, false);
	case TFW_H2_TRANS_INPLACE:
		return tfw_hpack_hdr_inplace(resp, hdr, &idx, false,
					     false);
	default:
		BUG();
	}
}

void
tfw_hpack_set_rbuf_size(TfwHPackETbl *__restrict tbl, unsigned short new_size)
{
	if (WARN_ON_ONCE(new_size > HPACK_ENC_TABLE_MAX_SIZE))
		return;

	spin_lock(&tbl->lock);

	T_DBG3("%s: tbl->rb_len=%hu, tbl->size=%hu, tbl->window=%hu,"
	       " new_size=%hu\n", __func__, tbl->rb_len, tbl->size,
	       tbl->window, new_size);

	if (tbl->window > new_size) {
		if (tbl->size > new_size)
			tfw_hpack_rbuf_calc(tbl, new_size, NULL,
					    (TfwHPackETblIter *)tbl);
		WARN_ON_ONCE(tbl->rb_len > tbl->size);

		tbl->window = new_size;
	}

	spin_unlock(&tbl->lock);
}
