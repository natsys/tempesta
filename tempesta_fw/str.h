/**
 *		Tempesta FW
 *
 * String handling.
 * There are few design concepts and properties which make our strings special:
 *
 * 1. the string is designed for zero-copy operations, i.e. it handles pointer
 *    only to actual data stored somewhere else, typically in skb;
 *
 * 2. the string handles possibly chunked data, e.g. split among different
 *    skbs. In this case COMPOUND flag is used;
 *
 * 3. it is HTTP specific in that sense that the string aggregates duplicate
 *    headers, where duplicate is not necessary exact string matching
 *    (e.g. LWS should not be considered). Duplicate values are handled using
 *    DUPLICATE flag;
 *
 * 4. (2) and (3) lead to tree-like data structure if some of duplicate
 *    strings are also compound. This makes string processing logic more
 *    complex, but handles plain strings as well as compound and avoids
 *    additional dynamic memory allocations;
 *
 * 5. This is the basic structure for data transformation logic (including TL),
 *    so we must keep skb pointers to be able to rewrite underlying packets.
 *
 * String can either contain plain data, in which case `ptr` field is used as
 * a pointer to a continuous region, or multiple chunks of data, in which case
 * `ptr` points to an array of plain TfwStr's. In other words, a single
 * indirection is expected. If string have more than one chunk, it's called
 * a "compound" string. `len` field of a compound string contains total length
 * of all chunks combined. Same field for a plain string is just length of
 * a data in the region pointed to by `ptr`.
 *
 * Another possibility is a so called duplicate string. A duplicate string is
 * a bunch of strings that describe HTTP fields with the same name.
 * For example, an HTTP server can return multiple Set-Cookie fields;
 * all of those will end up in a duplicate string. Such strings use `ptr`
 * field as an array of TfwStr's, each of which can be a compound string.
 * A duplicate string can not itself consist of duplicate strings.
 *
 * `flags` field is used for both discerning the types of strings and keeping
 * the number of elements in `ptr` array, if there are any. Lower 8 bits of
 * the field are reserved for flags. Remaining bits are used to store
 * the number of chunks in a compound string. Zero means a plain string.

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
#ifndef __TFW_STR_H__
#define __TFW_STR_H__

#include <linux/bug.h>
#include <linux/ctype.h>
#include <linux/skbuff.h>
#include <linux/string.h>

#include "pool.h"

/*
 * ------------------------------------------------------------------------
 *	SIMD C strings
 *
 * BEWARE(!) using the functions in context different from softirq (any HTTP
 * processing). Softirq context is explicitly protected by kernel_fpu_begin()
 * and kernel_fpu_end(), so you must do the same if you need the functions in
 * some other context. Keep in mind that TfwStr uses the functions as well.
 *
 * The functions are optimistic for the data of length 64 and more bytes,
 * i.e. comparing or matching long strings you assume that the strings are
 * matched (in case of tfw_match_*) or the same (in case of tfw_stricmp).
 * 64 and 128 byte subroutines of the functions load and process 2 and 4
 * 32-byre registers in parallel utilizing the memory bus and avoiding
 * conditional branches. However, they may load unnecessary data is the first
 * 32 bytes contain non-matching data.
 * ------------------------------------------------------------------------
 */
void tfw_str_init_const(void);
size_t tfw_match_uri(const char *s, size_t len);
size_t tfw_match_token(const char *s, size_t len);
size_t tfw_match_qetoken(const char *s, size_t len);
size_t tfw_match_nctl(const char *s, size_t len);
size_t tfw_match_ctext_vchar(const char *s, size_t len);
size_t tfw_match_xff(const char *s, size_t len);
size_t tfw_match_cookie(const char *s, size_t len);

void tfw_init_custom_uri(const unsigned char *a);
void tfw_init_custom_token(const unsigned char *a);
void tfw_init_custom_qetoken(const unsigned char *a);
void tfw_init_custom_nctl(const unsigned char *a);
void tfw_init_custom_ctext_vchar(const unsigned char *a);
void tfw_init_custom_xff(const unsigned char *a);
void tfw_init_custom_cookie(const unsigned char *a);

#ifdef AVX2
void __tfw_strtolower_avx2(unsigned char *dest, const unsigned char *src,
			    size_t len);
int __tfw_stricmp_avx2(const char *s1, const char *s2, size_t len);
int __tfw_stricmp_avx2_2lc(const char *s1, const char *s2, size_t len);

static inline void
tfw_cstrtolower(void *dest, const void *src, size_t len)
{
	__tfw_strtolower_avx2((unsigned char *)dest, (const unsigned char *)src,
			      len);
}

/**
 * @return 0 if the strings match and non-zero otherwise.
 */
static inline int
tfw_cstricmp(const char *s1, const char *s2, size_t len)
{
	return __tfw_stricmp_avx2(s1, s2, len);
}

/**
 * Like GLIBC's strcasecmp(3), but:
 * 1. requires @len <= min(strlen(s1), strlen(s2));
 * 2. returns 0 if the strings match and 1 otherwise;
 * 3. required @s2 is always in lower case.
 */
static inline int
tfw_cstricmp_2lc(const char *s1, const char *s2, size_t len)
{
	return __tfw_stricmp_avx2_2lc(s1, s2, len);
}
#else /* AVX2 */

static inline void
tfw_cstrtolower(void *dest, const void *src, size_t len)
{
	int i;
	unsigned char *d = dest;
	const unsigned char *s = src;

	for (i = 0; i < len; ++i)
		d[i] = tolower(s[i]);
}

static inline int
tfw_cstricmp(const char *s1, const char *s2, size_t len)
{
	return strncasecmp(s1, s2, len);
}

static inline int
tfw_cstricmp_2lc(const char *s1, const char *s2, size_t len)
{
	return strncasecmp(s1, s2, len);
}
#endif

/* Buffer size to hold all possible values of unsigned long */
#define TFW_ULTOA_BUF_SIZ 20
size_t tfw_ultoa(unsigned long ai, char *buf, unsigned int len);

/*
 * ------------------------------------------------------------------------
 *	Tempesta chunked strings
 *
 * The strings use SIMD instructions, so use them carefully to not to call
 * casually from sleepable context, e.g. on configuration phase.
 * ------------------------------------------------------------------------
 */
#define __TFW_STR_CN_MAX	UINT_MAX
/*
 * Str consists from compound or plain strings.
 * Duplicate strings are also always compound on root level.
 */
#define TFW_STR_DUPLICATE	0x01
/* The string is complete and will not grow. */
#define TFW_STR_COMPLETE	0x02
/* Some name starts at the string chunk. */
#define TFW_STR_NAME		0x04
/* Some value starts at the string chunk. */
#define TFW_STR_VALUE		0x08
/* The string represents hop-by-hop header, not end-to-end one */
#define TFW_STR_HBH_HDR		0x10
/* Weak identifier was set for Etag value. */
#define TFW_STR_ETAG_WEAK	0x20

/*
 * @ptr		- pointer to string data or array of nested strings;
 * @skb		- socket buffer containing the string data;
 * @len		- total length of compound or plain string (HTTP message body
 *		  size can be extreme large, so we need 64 bits to handle it);
 * @eolen	- the length of string's line endings, if present (as for now,
 *		  it should be 0 if the string has no EOL at all, 1 for LF and
 *		  2 for CRLF);
 * @nchunks  	- number of chunks of compound string;
 * @flags	- flags;
 */
typedef struct tfwstr_t {
	union {
		char *data;
		struct tfwstr_t *chunks;
	};
	struct sk_buff	*skb;
	unsigned long	len;
	unsigned int	nchunks;
	unsigned short	flags;
	unsigned char	eolen;
} TfwStr;

#define TFW_STR_STRING(val)		((TfwStr){.data = (val), NULL,	\
						  sizeof(val) - 1, 0, 0, 0})
#define DEFINE_TFW_STR(name, val)	TfwStr name = TFW_STR_STRING(val)
#define TFW_STR_FROM_CSTR(s)		((TfwStr){.data = (char*)(s),	\
						  NULL, strlen(s), 0, 0, 0})

/* Use this with "%.*s" in printing calls. */
#define PR_TFW_STR(s)		(int)min(20UL, (s)->len), (s)->data

#define TFW_STR_INIT(s)		memset((s), 0, sizeof(TfwStr))

#define TFW_STR_EMPTY(s)	(!((s)->nchunks | (s)->len))
#define TFW_STR_PLAIN(s)	(!((s)->nchunks))
#define TFW_STR_DUP(s)		((s)->flags & TFW_STR_DUPLICATE)

/* Get @c'th chunk of @s. */
#define __TFW_STR_CH(s, c)	((s)->chunks + (c))
#define TFW_STR_CHUNK(s, c)	(!TFW_STR_PLAIN(s)			\
				 ? ((c) >= (s)->nchunks			\
				    ? NULL				\
				    : __TFW_STR_CH((s), (c)))		\
				 : (!(c) ? s : NULL))
/*
 * Get last/current chunk of @s.
 * The most left leaf is taken as the current chunk for duplicate strings tree.
 */
#define TFW_STR_CURR(s)							\
({									\
	typeof(s) _tmp = TFW_STR_DUP(s)					\
		       ? (s)->chunks + (s)->nchunks - 1			\
		       : (s);						\
	!TFW_STR_PLAIN(_tmp)						\
		? _tmp->chunks + _tmp->nchunks - 1			\
		: (_tmp);						\
 })
#define TFW_STR_LAST(s)		TFW_STR_CURR(s)

/* Iterate over all chunks (or just a single chunk if the string is plain). */
#define TFW_STR_FOR_EACH_CHUNK_INIT(c, s, end)				\
	/* Iterate over chunks, not duplicates. */			\
	BUG_ON(TFW_STR_DUP(s));						\
	if (TFW_STR_PLAIN(s)) {						\
		(c) = (s);						\
		end = (s) + 1;						\
	} else {							\
		(c) = (s)->chunks;					\
		end = (s)->chunks + (s)->nchunks;			\
	}

#define TFW_STR_FOR_EACH_CHUNK(c, s, end)				\
	TFW_STR_FOR_EACH_CHUNK_INIT(c, (s), end);				\
	for ( ; (c) < end; ++(c))

/* The same as above, but for duplicate strings. */
#define TFW_STR_FOR_EACH_DUP(d, s, end)					\
	if (TFW_STR_DUP(s)) {						\
		(end) = (s)->chunks + (s)->nchunks;			\
		(d) = (s)->chunks;					\
	} else {							\
		(d) = (s);						\
		(end) = (s) + 1;					\
	}								\
	for ( ; (d) < (end); ++(d))

/**
 * Update length of the string which points to new data ending at @curr_p.
 */
static inline void
tfw_str_updlen(TfwStr *s, const char *curr_p)
{
	unsigned int n;

	if (!TFW_STR_PLAIN(s)) {
		TfwStr *chunk = s->chunks + (s)->nchunks - 1;

		BUG_ON(chunk->len);
		BUG_ON(!chunk->data || curr_p <= chunk->data);

		n = curr_p - chunk->data;
		chunk->len = n;
	} else {
		n = curr_p - s->data;
	}
	s->len += n;
}

/**
 * Returns EOL length
 */
static inline int
tfw_str_eolen(const TfwStr *s)
{
	return s->eolen;
}

/**
 * Updates EOL length value
 */
static inline void
tfw_str_set_eolen(TfwStr *s, unsigned int eolen)
{
	BUG_ON(eolen > 2); /* LF and CRLF is the only valid EOL markers */
	s->eolen = (unsigned char)eolen;
}

/**
 * Returns total string length, including EOL
 */
static inline unsigned long
tfw_str_total_len(const TfwStr *s)
{
	return s->len + s->eolen;
}

/**
 * Reduce @str length by @eolen bytes and fill the EOL.
 */
static inline void
tfw_str_fixup_eol(TfwStr *str, int eolen)
{
	BUG_ON(eolen > 2); /* eolen = 0 is a legit value */
	BUG_ON(!TFW_STR_PLAIN(str));

	str->len -= (str->eolen = eolen);
	if (eolen == 1)
		*(str->data + str->len) = 0x0a; /* LF, '\n' */
	else if (eolen == 2)
		*(short *)(str->data + str->len) = 0x0a0d; /* CRLF, '\r\n' */
}

void tfw_str_del_chunk(TfwStr *str, int id);
void tfw_str_collect_cmp(TfwStr *chunk, TfwStr *end, TfwStr *out,
			 const char *stop);
TfwStr *tfw_str_add_compound(TfwPool *pool, TfwStr *str);
TfwStr *tfw_str_add_duplicate(TfwPool *pool, TfwStr *str);

typedef enum {
	TFW_STR_EQ_DEFAULT = 0x0,
	TFW_STR_EQ_PREFIX  = 0x1,
	TFW_STR_EQ_CASEI   = 0x2,
	TFW_STR_EQ_PREFIX_CASEI = (TFW_STR_EQ_PREFIX | TFW_STR_EQ_CASEI),
} tfw_str_eq_flags_t;

void tfw_str_free(TfwPool *pool, TfwStr *str);
int tfw_strcpy(TfwStr *dst, const TfwStr *src);
TfwStr *tfw_strdup(TfwPool *pool, const TfwStr *src);
int tfw_strcpy_desc(TfwStr *dst, TfwStr *src);
int tfw_strcat(TfwPool *pool, TfwStr *dst, TfwStr *src);

int __tfw_strcmp(const TfwStr *s1, const TfwStr *s2, int cs);
#define tfw_stricmp(s1, s2)		__tfw_strcmp((s1), (s2), 0)
#define tfw_strcmp(s1, s2)		__tfw_strcmp((s1), (s2), 1)
int __tfw_strcmpspn(const TfwStr *s1, const TfwStr *s2, int stop, int cs);
#define tfw_stricmpspn(s1, s2, stop)	__tfw_strcmpspn((s1), (s2), (stop), 0)
#define tfw_strcmpspn(s1, s2, stop)	__tfw_strcmpspn((s1), (s2), (stop), 1)

bool tfw_str_eq_cstr(const TfwStr *str, const char *cstr, int cstr_len,
		     tfw_str_eq_flags_t flags);
bool tfw_str_eq_cstr_pos(const TfwStr *str, const char *pos, const char *cstr,
			 int cstr_len, tfw_str_eq_flags_t flags);
bool tfw_str_eq_cstr_off(const TfwStr *str, ssize_t offset, const char *cstr,
			 int cstr_len, tfw_str_eq_flags_t flags);

size_t tfw_str_to_cstr(const TfwStr *str, char *out_buf, int buf_size);

TfwStr tfw_str_next_str_val(const TfwStr *str);
u32 tfw_str_crc32_calc(const TfwStr *str);

#ifdef DEBUG
void tfw_str_dprint(const TfwStr *str, const char *msg);
#else
#define tfw_str_dprint(str, msg)
#endif

#endif /* __TFW_STR_H__ */
