/**
 *		Tempesta FW
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015 Tempesta Technologies, Inc.
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
#include <linux/bug.h>
#include <linux/kernel.h>
#include <linux/ctype.h>

#include "lib.h"
#include "str.h"

void
tfw_str_del_chunk(TfwStr *str, int id)
{
	unsigned int cn = TFW_STR_CHUNKN(str);

	if (unlikely(TFW_STR_PLAIN(str)))
		return;
	BUG_ON(TFW_STR_DUP(str));
	BUG_ON(id >= cn);

	if (TFW_STR_CHUNKN(str) == 2) {
		/* Just fall back to plain string. */
		*str = *((TfwStr *)str->ptr + (id ^ 1));
		return;
	}

	str->len -= TFW_STR_CHUNK(str, id)->len;
	TFW_STR_CHUNKN_SUB(str, 1);
	/* Move all chunks after @id. */
	memmove((TfwStr *)str->ptr + id, (TfwStr *)str->ptr + id + 1,
		(cn - id - 1) * sizeof(TfwStr));
}

/**
 * Grow @str for @n new chunks.
 * New branches of the string tree are created on 2nd level only,
 * i.e. there is no possibility to grow number of chunks of duplicate string.
 * Pass pointer to one of the duplicates to do so.
 * @return pointer to the first of newly added chunk.
 *
 * TODO do we need exponential growing?
 */
static TfwStr *
__str_grow_tree(TfwPool *pool, TfwStr *str, unsigned int flag, int n)
{
	if (str->flags & flag) {
		unsigned int l = TFW_STR_CHUNKN(str) * sizeof(TfwStr);
		void *p = tfw_pool_realloc(pool, str->ptr, l,
					   l + n * sizeof(TfwStr));
		if (!p)
			return NULL;
		str->ptr = p;
		TFW_STR_CHUNKN_ADD(str, n);
	}
	else {
		TfwStr *a = tfw_pool_alloc(pool, (n + 1) * sizeof(TfwStr));
		if (!a)
			return NULL;
		a[0] = *str;
		str->ptr = a;
		__TFW_STR_CHUNKN_SET(str, n + 1);
	}

	str = (TfwStr *)str->ptr + TFW_STR_CHUNKN(str) - n;
	memset(str, 0, sizeof(TfwStr) * n);

	return str;
}

/**
 * Add compound piece to @str and return pointer to the piece.
 */
TfwStr *
tfw_str_add_compound(TfwPool *pool, TfwStr *str)
{
	/* Need to specify exact string duplicate to grow. */
	BUG_ON(TFW_STR_DUP(str));

	return __str_grow_tree(pool, str, __TFW_STR_COMPOUND, 1);
}
DEBUG_EXPORT_SYMBOL(tfw_str_add_compound);

/**
 * Add place for a new duplicate to string tree @str, a string wich is probably
 * alredy a set of duplicate compound strings).
 */
TfwStr *
tfw_str_add_duplicate(TfwPool *pool, TfwStr *str)
{
	TfwStr *dup_str = __str_grow_tree(pool, str, TFW_STR_DUPLICATE, 1);

	/* Length for set of duplicate strings has no sense. */
	str->len = 0;
	str->flags |= TFW_STR_DUPLICATE;

	return dup_str;
}
DEBUG_EXPORT_SYMBOL(tfw_str_add_duplicate);

int
tfw_strcpy(TfwStr *dst, const TfwStr *src)
{
	int n1, n2, o1 = 0, o2 = 0, chunks = 0;
	int mode = (TFW_STR_PLAIN(src) << 1) | TFW_STR_PLAIN(dst);
	TfwStr *c1, *c2, *sptr1, *sptr2;

	BUG_ON(TFW_STR_DUP(dst));
	BUG_ON(TFW_STR_DUP(src));

	if (unlikely(src->len > dst->len))
		return -E2BIG;

	switch (mode) {
	case 0: /* The both are plain. */
		memcpy(dst->ptr, src->ptr, dst->len);
		break;
	case 1: /* @src is compound, @dst is plain. */
		sptr1 = (TfwStr *)src->ptr;
		n1 = TFW_STR_CHUNKN(src);
		for (c1 = sptr1; c1 < sptr1 + n1; ++c1) {
			memcpy((char *)dst->ptr + o2, c1->ptr, c1->len);
			o2 += c1->len;
		}
		BUG_ON(o2 != src->len);
		return 0;
	case 2: /* @src is plain, @dst is compound. */
		sptr2 = (TfwStr *)dst->ptr;
		n2 = TFW_STR_CHUNKN(dst);
		for (c2 = sptr2; c2 < sptr2 + n2; ++c2) {
			memcpy(c2->ptr, (char *)src->ptr + o1, c2->len);
			o1 += c2->len;
			++chunks;
		}
		BUG_ON(o1 != dst->len);
		return 0;
	case 3: /* The both are compound. */
		n1 = TFW_STR_CHUNKN(src);
		n2 = TFW_STR_CHUNKN(dst);
		c1 = sptr1 = (TfwStr *)src->ptr;
		c2 = (TfwStr *)dst->ptr;
		while (1) {
			int _n = min(c1->len - o1, c2->len - o2);
			memcpy((char *)c2->ptr + o2, (char *)c1->ptr + o1, _n);
			if (c1 == sptr1 + n1 - 1 && _n == c1->len - o1) {
				/* Adjust @dst last chunk length. */
				c2->len = o2 + _n;
				break;
			}
			if (c1->len - o1 == c2->len - o2) {
				++c1;
				++c2;
				++chunks;
				o1 = o2 = 0;
			}
			else if (_n == c1->len - o1) {
				++c1;
				o1 = 0;
				o2 += _n;
			}
			else {
				++c2;
				++chunks;
				o2 = 0;
				o1 += _n;
			}
		}
	}

	/* Set resulting number of chunks, forget about others. */
	__TFW_STR_CHUNKN_SET(dst, chunks);
	dst->len = src->len;

	return 0;
}
EXPORT_SYMBOL(tfw_strcpy);

int
tfw_strcat(TfwPool *pool, TfwStr *dst, TfwStr *src)
{
	int n = TFW_STR_CHUNKN(src);
	TfwStr *to, *c;

	BUG_ON(TFW_STR_DUP(dst));
	BUG_ON(TFW_STR_DUP(src));

	to = __str_grow_tree(pool, dst, __TFW_STR_COMPOUND, n ? : 1);
	if (!to)
		return -ENOMEM;

	n = 0;
	TFW_STR_FOR_EACH_CHUNK(c, src, {
		n += c->len;
		to->ptr = c->ptr;
		to->len = c->len;
		to->skb = c->skb;
		++to;
	});
	dst->len += n;

	return 0;
}
EXPORT_SYMBOL(tfw_strcat);

/**
 * Core routine for tfw_stricmpspn() working on flat C strings.
 * TODO too slow, rewrite on AVX2.
 */
static int
__cstricmpspn(const char *s1, const char *s2, int n, int stop)
{
	unsigned char c1, c2;

	while (n) {
		c1 = tolower(*s1++);
		c2 = tolower(*s2++);
		if (c1 != c2)
			return c1 < c2 ? -1 : 1;
		if (!c1 || c1 == stop)
			break;
		n--;
	}

	return 0;
}

/**
 * Like strcasecmp(3) for TfwStr, but stops matching when faces @stop.
 * Do not use it for duplicate strings, rather call it for each duplicate
 * substring separately.
 */
int
tfw_stricmpspn(const TfwStr *s1, const TfwStr *s2, int stop)
{
	int i1, i2, off1, off2, n;
	const TfwStr *c1, *c2;

	BUG_ON((s1->flags | s2->flags) & TFW_STR_DUPLICATE);

	if (!stop || !s1->len || !s2->len) {
		n = (int)s1->len - (int)s2->len;
		if (n)
			return n;
	}

	i1 = i2 = 0;
	off1 = off2 = 0;
	n = min(s1->len, s2->len);
	c1 = TFW_STR_CHUNK(s1, 0);
	c2 = TFW_STR_CHUNK(s2, 0);
	while (n) {
		int cn = min(c1->len - off1, c2->len - off2);
		int r = stop
			? __cstricmpspn((char *)c1->ptr + off1,
					(char *)c2->ptr + off2, cn, stop)
			: strnicmp((char *)c1->ptr + off1,
				   (char *)c2->ptr + off2, cn);
		if (r)
			return r;
		n -= cn;
		if (cn == c1->len - off1) {
			off1 = 0;
			++i1;
			c1 = TFW_STR_CHUNK(s1, i1);
		} else {
			off1 += cn;
		}
		if (cn == c2->len - off2) {
			off2 = 0;
			++i2;
			c2 = TFW_STR_CHUNK(s2, i2);
		} else {
			off2 += cn;
		}
		BUG_ON(n && (!c1 || !c2));
	}

	return 0;
}
EXPORT_SYMBOL(tfw_stricmpspn);

/**
 * Generic function for comparing TfwStr and C strings.
 *
 * @str may be either plain or compound.
 *
 * @cstr_len is used for performance purposes.
 * The length may be pre-computed by the caller and saved between calls.
 *
 * @cstr is not required to be terminated.
 *
 * @flags allow to specify the following options:
 *  - TFW_STR_EQ_PREFIX
 *      The @cstr is a prefix, only first @cstr_len chars are compared, and the
 *      rest of @str is ignored.
 *  - TFW_STR_EQ_CASEI
 *      Use case-insensitive comparison function.
 */
bool
tfw_str_eq_cstr(const TfwStr *str, const char *cstr, int cstr_len,
                tfw_str_eq_flags_t flags)
{
	unsigned int len;
	const TfwStr *chunk;
	typeof(&strncmp) cmp = (flags & TFW_STR_EQ_CASEI) ? strnicmp : strncmp;

	TFW_STR_FOR_EACH_CHUNK(chunk, str, {
		len = min(cstr_len, (int)chunk->len);

		if (cmp(cstr, chunk->ptr, len))
			return false;

		if (chunk->len > cstr_len)
			return (flags & TFW_STR_EQ_PREFIX);

		cstr += len;
		cstr_len -= len;
	});

	return !cstr_len;
}
EXPORT_SYMBOL(tfw_str_eq_cstr);

/**
 * DEPRECATED - used only to compare headers which must be special.
 * RFC 7230 now prohibits spaces between header name and ':', so there is no
 * reason to process the field.
 * Moreover, due to unnecessary complexity the function uses plain C FSM,
 * whil optimized vector processing should be used.
 *
 * Generic function for comparing TfwStr and a key-value pair of C strings.
 *
 * The key-value pair has the following form:
 *   (@key)[:space:]*(@sep)[:space:]*(@val)
 *
 * For example, if:
 *   @key = "Connection"
 *   @sep = ':'
 *   @val = "keep-alive"
 * Then all the following TfwStr values will match it:
 *   "Connection:keep-alive"
 *   "Connection: keep-alive"
 *   "Connection   :   keep-alive"
 *   "Connection \r\n : \t keep-alive"
 *
 * Note: Space characters are tested using isspace(), so chars like \r\n\t
 * are treated as space.
 *
 * @key should not contain spaces (although current implementation allows it).
 * @sep is a single character, no repetitions allowed (e.g "==").
 * @val must not start with a space (because all spaces are eaten after @sep).
 * @str may consist of any number of chunks, there is no limitation
 *     on how @key/@sep/@val are spread across the chunks.
 *
 * @flags allows to specify additional options for comparison:
 *  - TFW_STR_EQ_CASEI
 *    Use case-insensitive comparison for @key and @val.
 *    The @sep is always case-sensitive.
 *
 *  - TFW_STR_EQ_PREFIX
 *    Treat @val as a prefix.
 *    For example, if @val = "text", then it will match to:
 *      "Content-Type: text"
 *      "Content-Type: text/html"
 *      "Content-Type: text/html; charset=UTF-8"
 *    The flag affects only @val (the @key comparison is always case-insensitive
 *    and @sep is always case-sensitive).
 */
bool
tfw_str_eq_kv(const TfwStr *str, const char *key, int key_len, char sep,
	      const char *val, int val_len, tfw_str_eq_flags_t flags)
{
	const char *key_end = key + key_len;
	const char *val_end = val + val_len;
	const TfwStr *chunk;
	const char *c;
	const char *cend;
	short cnum;

/* Try to move to the next chunk (if current chunk is finished).
 * Execute @ok_code on sucess or @err_code if there is no next chunk. */
#define _TRY_NEXT_CHUNK(ok_code, err_code)		\
	if (unlikely(c == cend))	{		\
		++cnum;					\
		chunk = TFW_STR_CHUNK(str, cnum); 	\
		if (chunk) {				\
			c = chunk->ptr;			\
			cend = chunk->ptr + chunk->len; \
			ok_code;			\
		} else {				\
			err_code;			\
			BUG();				\
		}					\
	}

	/* Initialize  the state - get the first chunk. */
	cnum = 0;
	chunk = TFW_STR_CHUNK(str, 0);
	if (!chunk)
		return false;
	c = chunk->ptr;
	cend = chunk->ptr + chunk->len;

	/* A tiny FSM here. Instead of a traditional for+switch construction
	 * it uses a series of small loops to improve branch prediction and
	 * locality of the code (and thus L1i hit).
	 */

state_key:
	while (key != key_end && c != cend) {
		if (tolower(*key++) != tolower(*c++))
			return false;
	}
	_TRY_NEXT_CHUNK(goto state_key, return false);

state_sp1:
	if (!isspace(sep)) {
		while (c != cend && isspace(*c))
			++c;
		_TRY_NEXT_CHUNK(goto state_sp1, return false);
	}

/* state_sep: */
	if (*c++ != sep)
		return false;

state_sp2:
	while (c != cend && isspace(*c))
		++c;
	_TRY_NEXT_CHUNK(goto state_sp2, return (val == val_end));

state_val:
	if (flags & TFW_STR_EQ_CASEI) {
		while (val != val_end && c != cend) {
			if (tolower(*val++) != tolower(*c++))
				return false;
		}
	} else {
		while (val != val_end && c != cend) {
			if (*val++ != *c++)
				return false;
		}
	}

	/* @val is not finished - request the next chunk. */
	if (val != val_end) {
		_TRY_NEXT_CHUNK(goto state_val, return false);
	}

	/* The chunk is not finished - then @val must be a prefix. */
	if (c != cend) {
		return (flags & TFW_STR_EQ_PREFIX);
	}

	/* Both @val and the current chunk are finished - full match. */
	return true;
}
EXPORT_SYMBOL(tfw_str_eq_kv);

/**
 * DEPRECATED: The function intentionaly brokes zero-copy string design.
 *
 * Join all chunks of @str to a single plain C string.
 *
 * The function copies all chunks of the @str to the @out_buf.
 * If the buffer has not enough space to fit all chunks, then the output string
 * is cropped (at most @buf_size - 1 bytes is written). The output string is
 * always terminated with '\0'.
 *
 * Returns length of the output string.
 *
 */
size_t
tfw_str_to_cstr(const TfwStr *str, char *out_buf, int buf_size)
{
	const TfwStr *chunk;
	char *pos = out_buf;
	int len;

	BUG_ON(!out_buf || (buf_size <= 0));

	--buf_size; /* Reserve one byte for '\0'. */

	TFW_STR_FOR_EACH_CHUNK(chunk, str, {
		len = min(buf_size, (int)chunk->len);
		strncpy(pos, chunk->ptr, len);
		pos += len;
		buf_size -= len;

		if (unlikely(!buf_size))
			break;
	});

	*pos = '\0';

	return (pos - out_buf);
}
EXPORT_SYMBOL(tfw_str_to_cstr);
