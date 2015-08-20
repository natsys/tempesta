/**
 *		Tempesta FW
 *
 * HTTP processing.
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
#include <linux/highmem.h>
#include <linux/skbuff.h>
#include <linux/string.h>

#include "cache.h"
#include "classifier.h"
#include "client.h"
#include "gfsm.h"
#include "hash.h"
#include "http.h"
#include "http_msg.h"
#include "http_sticky.h"
#include "log.h"
#include "sched.h"

#include "sync_socket.h"

/*
 * Build Tempesta message from pieces of data.
 *
 * The functions tfw_http_msg_setup() and tfw_http_msg_add_data()
 * are designed to work together. The objective is to avoid error
 * processing when putting stream data in SKBs piece by piece.
 *
 * Errors may be returned by memory allocation functions,
 * so that job is done in tfw_http_msg_setup(). Given the total
 * HTTP message length, it allocates an appropriate number of SKBs
 * and page fragments to hold the payload, and sets them up in
 * Tempesta message.
 *
 * SKBs are created complely headerless. The linear part of SKBs
 * is set apart for headers, and stream data is placed in paged
 * fragments. Lower layers will take care of prepending all
 * required headers.
 *
 * tfw_http_msg_add_data() adds a piece of data to the message,
 * forming data stream piece by piece. All memory for data
 * has been allocated and set up by tfw_http_msg_setup(),
 * so any errors that we may get are considered critical.
 *
 * State is kept between calls to these functions to facilitate
 * quick access to current SKB and page fragment. State is passed
 * and updated on each call to these functions.
 */
typedef struct tfw_msg_add_state {
	struct sk_buff	*skb;
	unsigned int	fragnum;
} tfw_mastate_t;

void
tfw_http_msg_add_data(void *handle, TfwMsg *msg, char *data, size_t len)
{
	skb_frag_t *frag;
	tfw_mastate_t *state = (tfw_mastate_t *)handle;
	struct sk_buff *skb = state->skb;
	unsigned int i_frag = state->fragnum;
	size_t copy_size, page_offset, data_offset = 0;

	BUG_ON(skb == NULL);
	BUG_ON(i_frag >= MAX_SKB_FRAGS);

	while (len) {
		if (i_frag >= MAX_SKB_FRAGS) {
			skb = ss_skb_next(&msg->skb_list, skb);
			state->skb = skb;
			state->fragnum = 0;
			i_frag = 0;
			BUG_ON(skb == NULL);
		}
		for (; len && (i_frag < MAX_SKB_FRAGS); i_frag++) {
			frag = &skb_shinfo(skb)->frags[i_frag];
			page_offset = skb_frag_size(frag);
			copy_size = min(len, PAGE_SIZE - page_offset);
			memcpy(page_address(frag->page.p) + page_offset,
			       data + data_offset, copy_size);
			skb_frag_size_add(frag, copy_size);
			data_offset += copy_size;
			len -= copy_size;
		}
		/*
		 * The above for() loop runs at least once,
		 * which means that i_frags is always incremented.
		 */
		state->fragnum = i_frag - 1;
	}
	/* In the end, data_offset equals the initial len value */
	skb->len += data_offset;
	skb->data_len += data_offset;
}

void *
tfw_http_msg_setup(TfwHttpMsg *hm, size_t len)
{
	struct page *page;
	struct sk_buff *skb;
	tfw_mastate_t *state;
	int i_frag, i_skb, nr_skb_frags;
	int nr_frags = DIV_ROUND_UP(len, PAGE_SIZE);
	int nr_skbs = DIV_ROUND_UP(nr_frags, MAX_SKB_FRAGS);

	/*
	 * TODO: Make sure to create SKBs with payload size <= MSS
	 */
	if ((state = tfw_pool_alloc(hm->pool, sizeof(*state))) == NULL) {
		return NULL;
	}
	for (i_skb = 0; i_skb < nr_skbs; i_skb++) {
		if ((skb = alloc_skb(MAX_TCP_HEADER, GFP_ATOMIC)) == NULL) {
			return NULL;
		}
		skb_reserve(skb, MAX_TCP_HEADER);
		ss_skb_queue_tail(&hm->msg.skb_list, skb);

		nr_skb_frags = min_t(size_t, nr_frags, MAX_SKB_FRAGS);
		for (i_frag = 0; i_frag < nr_skb_frags; i_frag++) {
			if ((page = alloc_page(GFP_ATOMIC)) == NULL) {
				return NULL;
			}
			__skb_fill_page_desc(skb, i_frag, page, 0, 0);
			skb->truesize += PAGE_SIZE;
			skb_shinfo(skb)->nr_frags++;
		}
		nr_frags -= nr_skb_frags;
	}
	/* Set up initial state */
	state->skb = ss_skb_peek(&hm->msg.skb_list);
	state->fragnum = 0;

	return state;
}

#define S_CRLF			"\r\n"
#define S_CRLFCRLF		"\r\n\r\n"
#define S_HTTP			"http://"

#define S_302			"HTTP/1.1 302 Found"
#define S_404			"HTTP/1.1 404 Not Found"
#define S_500			"HTTP/1.1 500 Internal Server Error"
#define S_502			"HTTP/1.1 502 Bad Gateway"

#define S_F_HOST		"Host: "
#define S_F_DATE		"Date: "
#define S_F_CONTENT_LENGTH	"Content-Length: "
#define S_F_LOCATION		"Location: "
#define S_F_CONNECTION		"Connection: "
#define S_F_SET_COOKIE		"Set-Cookie: "

#define S_V_DATE		"Sun, 06 Nov 1994 08:49:37 GMT"
#define S_V_CONTENT_LENGTH	"9999"

#define SLEN(s)			(sizeof(s) - 1)

/*
 * Prepare current date in the format required for HTTP "Date:"
 * header field. See RFC 2616 section 3.3.
 */
size_t
tfw_http_prep_date(char *buf)
{
	struct tm tm;
	struct timespec ts;
	char *ptr = buf;

	static char *wday[] __read_mostly =
		{ "Sun, ", "Mon, ", "Tue, ",
		  "Wed, ", "Thu, ", "Fri, ", "Sat, " };
	static char *month[] __read_mostly =
		{ " Jan ", " Feb ", " Mar ", " Apr ", " May ", " Jun ",
		  " Jul ", " Aug ", " Sep ", " Oct ", " Nov ", " Dec " };

#define PRINT_2DIGIT(p, n)			\
	*p++ = (n <= 9) ? '0' : '0' + n / 10;	\
	*p++ = '0' + n % 10;

	getnstimeofday(&ts);
	time_to_tm(ts.tv_sec, 0, &tm);

	memcpy(ptr, wday[tm.tm_wday], 5);
	ptr += 5;
	PRINT_2DIGIT(ptr, tm.tm_mday);
	memcpy(ptr, month[tm.tm_mon], 5);
	ptr += 5;
	PRINT_2DIGIT(ptr, (tm.tm_year + 1900) / 100);
	PRINT_2DIGIT(ptr, (tm.tm_year + 1900) % 100);
	*ptr++ = ' ';
	PRINT_2DIGIT(ptr, tm.tm_hour);
	*ptr++ = ':';
	PRINT_2DIGIT(ptr, tm.tm_min);
	*ptr++ = ':';
	PRINT_2DIGIT(ptr, tm.tm_sec);
	memcpy(ptr, " GMT", 4);
	ptr += 4;
#undef PRINT_2DIGIT

	return ptr - buf;
}

/*
 * Convert a C string to a printable hex string.
 *
 * Each character makes two hex digits, thus the size of the
 * output buffer must be twice of the length of input string.
 */
size_t
tfw_http_prep_hexstring(char *buf, u_char *value, size_t len)
{
	char *ptr = buf;

	while (len--) {
		*ptr++ = hex_asc_hi(*value);
		*ptr++ = hex_asc_lo(*value++);
	}
	return (ptr - buf);
}

/*
 * Prepare an HTTP 302 response to the client. The response redirects
 * the client to the same URI as the original request, but it includes
 * 'Set-Cookie:' header field that sets Tempesta sticky cookie.
 */
#define S_302_PART_01		S_302 S_CRLF S_F_DATE
/* Insert current date */
#define S_302_PART_02		S_CRLF S_F_CONTENT_LENGTH "0" S_CRLF	\
				S_F_LOCATION S_HTTP
/* Insert full location URI */
#define S_302_PART_03		S_CRLF S_F_SET_COOKIE
/* Insert cookie name and value */
#define S_302_PART_04		S_CRLFCRLF

#define S_302_FIXLEN							\
	SLEN(S_302_PART_01) + SLEN(S_V_DATE) + SLEN(S_302_PART_02)	\
	+ SLEN(S_302_PART_03) + SLEN(S_302_PART_04)

TfwHttpMsg *
tfw_http_prep_302(TfwHttpMsg *hm, TfwStr *cookie)
{
	void *handle;
	TfwStr *chunk;
	TfwMsg *msg;
	TfwHttpMsg *resp;
	TfwHttpReq *req = (TfwHttpReq *)hm;
	size_t len, data_len = S_302_FIXLEN;
	u_char buf[SLEN(S_F_HOST) + 256];

	if (!(hm->flags & TFW_HTTP_STICKY_SET)) {
		return NULL;
	}
	if ((resp = tfw_http_msg_alloc(Conn_Srv)) == NULL) {
		return NULL;
	}
	msg = (TfwMsg *)resp;
	resp->conn = hm->conn;

	/* Add variable part of data length to get the total */
	data_len += req->host.len
		    ? req->host.len
		    : hm->h_tbl->tbl[TFW_HTTP_HDR_HOST].field.len;
	data_len += req->uri_path.len + cookie->len;

	if ((handle = tfw_http_msg_setup(resp, data_len)) == NULL) {
		tfw_http_msg_free(resp);
		return NULL;
	}

	tfw_http_msg_add_data(handle, msg, S_302_PART_01, SLEN(S_302_PART_01));
	len = tfw_http_prep_date(buf);
	tfw_http_msg_add_data(handle, msg, buf, len);
	tfw_http_msg_add_data(handle, msg, S_302_PART_02, SLEN(S_302_PART_02));
	if (req->host.len) {
		TFW_STR_FOR_EACH_CHUNK(chunk, &req->host,
				       tfw_http_msg_add_data(handle, msg,
							     chunk->ptr,
							     chunk->len));
	} else {
		TfwStr *hdr = &hm->h_tbl->tbl[TFW_HTTP_HDR_HOST].field;
		if (TFW_STR_PLAIN(hdr)) {
			tfw_http_msg_add_data(handle, msg, hdr->ptr, hdr->len);
		} else  {
			/*
			 * Per RFC 1035, 2181, max length of FQDN is 255.
			 * What if it is UTF-8 encoded?
			 */
			/*
			 * TODO Linearize TfwStr{}. Should be eliminated
			 * when better TfwStr{} functions are implemented.
			 */
			tfw_str_to_cstr(hdr, buf, hdr->len);
			tfw_http_msg_add_data(handle, msg, buf, hdr->len);
		}
	}
	TFW_STR_FOR_EACH_CHUNK(chunk, &req->uri_path,
			       tfw_http_msg_add_data(handle, msg, chunk->ptr,
						     chunk->len));
	tfw_http_msg_add_data(handle, msg, S_302_PART_03, SLEN(S_302_PART_03));
	TFW_STR_FOR_EACH_CHUNK(chunk, cookie,
			       tfw_http_msg_add_data(handle, msg, chunk->ptr,
						     chunk->len));
	tfw_http_msg_add_data(handle, msg, S_302_PART_04, SLEN(S_302_PART_04));

	return resp;
}

/*
 * Prepare an HTTP 404 response to the client. It tells the client that
 * Tempesta is unable to find the requested data.
 */
#define S_404_PART_01		S_404 S_CRLF S_F_DATE
/* Insert current date */
#define S_404_PART_02		S_CRLF S_F_CONTENT_LENGTH "0" S_CRLFCRLF

#define S_404_FIXLEN							\
	SLEN(S_404_PART_01) + SLEN(S_V_DATE) + SLEN(S_404_PART_02)

TfwHttpMsg *
tfw_http_prep_404(TfwHttpMsg *hm)
{
	void *handle;
	TfwMsg *msg;
	TfwHttpMsg *resp;
	u_char buf[SLEN(S_V_DATE)];
	size_t len, data_len = S_404_FIXLEN;

	if ((resp = tfw_http_msg_alloc(Conn_Srv)) == NULL) {
		return NULL;
	}
	msg = (TfwMsg *)resp;
	resp->conn = hm->conn;

	if ((handle = tfw_http_msg_setup(resp, data_len)) == NULL) {
		tfw_http_msg_free(resp);
		return NULL;
	}

	tfw_http_msg_add_data(handle, msg, S_404_PART_01, SLEN(S_404_PART_01));
	len = tfw_http_prep_date(buf);
	tfw_http_msg_add_data(handle, msg, buf, len);
	tfw_http_msg_add_data(handle, msg, S_404_PART_02, SLEN(S_404_PART_02));

	return resp;
}

/*
 * Prepare an HTTP 500 response to the client. It tells the client that
 * there was an internal error while forwarding the request to a server.
 */
#define S_500_PART_01		S_500 S_CRLF S_F_DATE
/* Insert current date */
#define S_500_PART_02		S_CRLF S_F_CONTENT_LENGTH "0" S_CRLFCRLF

#define S_500_FIXLEN							\
	SLEN(S_500_PART_01) + SLEN(S_V_DATE) + SLEN(S_500_PART_02)

TfwHttpMsg *
tfw_http_prep_500(TfwHttpMsg *hm)
{
	void *handle;
	TfwMsg *msg;
	TfwHttpMsg *resp;
	u_char buf[SLEN(S_V_DATE)];
	size_t len, data_len = S_500_FIXLEN;

	if ((resp = tfw_http_msg_alloc(Conn_Srv)) == NULL) {
		return NULL;
	}
	msg = (TfwMsg *)resp;
	resp->conn = hm->conn;

	if ((handle = tfw_http_msg_setup(resp, data_len)) == NULL) {
		tfw_http_msg_free(resp);
		return NULL;
	}

	tfw_http_msg_add_data(handle, msg, S_500_PART_01, SLEN(S_500_PART_01));
	len = tfw_http_prep_date(buf);
	tfw_http_msg_add_data(handle, msg, buf, len);
	tfw_http_msg_add_data(handle, msg, S_500_PART_02, SLEN(S_500_PART_02));

	return resp;
}

/*
 * Prepare an HTTP 502 response to the client. It tells the client that
 * Tempesta is unable to forward the request to the designated server.
 */
#define S_502_PART_01		S_502 S_CRLF S_F_DATE
/* Insert current date */
#define S_502_PART_02		S_CRLF S_F_CONTENT_LENGTH "0" S_CRLFCRLF

#define S_502_FIXLEN							\
	SLEN(S_502_PART_01) + SLEN(S_V_DATE) + SLEN(S_502_PART_02)

TfwHttpMsg *
tfw_http_prep_502(TfwHttpMsg *hm)
{
	void *handle;
	TfwMsg *msg;
	TfwHttpMsg *resp;
	u_char buf[SLEN(S_V_DATE)];
	size_t len, data_len = S_502_FIXLEN;

	if ((resp = tfw_http_msg_alloc(Conn_Srv)) == NULL) {
		return NULL;
	}
	msg = (TfwMsg *)resp;
	resp->conn = hm->conn;

	if ((handle = tfw_http_msg_setup(resp, data_len)) == NULL) {
		tfw_http_msg_free(resp);
		return NULL;
	}

	tfw_http_msg_add_data(handle, msg, S_502_PART_01, SLEN(S_502_PART_01));
	len = tfw_http_prep_date(buf);
	tfw_http_msg_add_data(handle, msg, buf, len);
	tfw_http_msg_add_data(handle, msg, S_502_PART_02, SLEN(S_502_PART_02));

	return resp;
}

static int
tfw_http_send_404(TfwHttpMsg *hm)
{
	TfwHttpMsg *resp;
	TfwConnection *conn = hm->conn;

	if ((resp = tfw_http_prep_404(hm)) == NULL) {
		return -1;
	}
	TFW_DBG("Send HTTP 404 response to the client\n");
	tfw_connection_send(conn, (TfwMsg *)resp);
	tfw_http_msg_free(resp);

	return 0;
}

static int
tfw_http_send_500(TfwHttpMsg *hm)
{
	TfwHttpMsg *resp;
	TfwConnection *conn = hm->conn;

	if ((resp = tfw_http_prep_500(hm)) == NULL) {
		return -1;
	}
	TFW_DBG("Send HTTP 500 response to the client\n");
	tfw_connection_send(conn, (TfwMsg *)resp);
	tfw_http_msg_free(resp);

	return 0;
}

TfwMsg *
tfw_http_conn_msg_alloc(TfwConnection *conn)
{
	TfwHttpMsg *hm = tfw_http_msg_alloc(TFW_CONN_TYPE(conn));
	if (unlikely(!hm))
		return NULL;

	hm->conn = conn;
	tfw_gfsm_state_init(&hm->msg.state, conn, TFW_HTTP_FSM_INIT);

	return (TfwMsg *)hm;
}

/**
 * TODO Initialize allocated Client structure by HTTP specific callbacks and FSM.
 */
static int
tfw_http_conn_init(TfwConnection *conn)
{
	return 0;
}

static void
tfw_http_conn_destruct(TfwConnection *conn)
{
	TfwMsg *msg, *tmp;

	tfw_http_msg_free((TfwHttpMsg *)conn->msg);

	list_for_each_entry_safe(msg, tmp, &conn->msg_queue, msg_list)
		tfw_http_msg_free((TfwHttpMsg *)msg);
	INIT_LIST_HEAD(&conn->msg_queue);
}

/**
 * Create a sibling for @msg message.
 * Siblings in HTTP are usually pipelined requests
 * that can share the same SKBs.
 */
static TfwHttpMsg *
tfw_http_msg_create_sibling(TfwHttpMsg *hm, struct sk_buff **skb,
			    unsigned int split_offset, int type)
{
	TfwHttpMsg *shm;
	struct sk_buff *nskb;

	shm = tfw_http_msg_alloc(type);
	if (!shm)
		return NULL;

	/*
	 * The sibling message is set up with a clone of current
	 * SKB (the last SKB in skb_list) as the starting SKB.
	 */
	nskb = ss_skb_split(*skb, split_offset);
	if (!nskb) {
		tfw_http_msg_free(shm);
		return NULL;
	}
	ss_skb_queue_tail(&shm->msg.skb_list, nskb);
	*skb = nskb;

	/* The sibling message belongs to the same connection. */
	shm->conn = hm->conn;

	return shm;
}

/**
 * Set for all new just parsed headers pointers to last skb
 * (to which they belong).
 *
 * If some header name or value are splitted among number of skb's, then
 * hdr->skb points to the first skb and all other skbs are dereferenced
 * through skb->next. TODO The parser cares to set correct lengths for name
 * and value field which consists from few skb's.
 */
static void
tfw_http_establish_skb_hdrs(TfwHttpMsg *hm)
{
	int i;

	if (unlikely(!hm->h_tbl || !hm->h_tbl->size))
		return;

	for (i = 0; i < hm->h_tbl->size; ++i) {
		TfwHttpHdr *hdr = hm->h_tbl->tbl + i;
		if (hdr->skb)
			continue;
		if (!hdr->field.ptr)
			break;
		hdr->skb = hm->msg.skb_list.last;
	}
}

/**
 * Sometimes kernel gives bit more memory for skb than was requested
 * - use the extra memory if enough to place @n bytes or allocate
 * new linear data.
 * 
 * @return new pointer to @split.
 *
 * The main part of the function is borrowed from Linux pskb_expand_head().
 */
static void *
tfw_skb_get_room(struct sk_buff *skb, unsigned char *split, size_t n)
{
	int i;
	u8 *data;
	int size = skb_end_offset(skb) + n;
	long off = split - skb->head;
	gfp_t gfp_mask = GFP_ATOMIC;

	/* Quick path: we have some room. */
	if (skb->tail + n <= skb->end) {
		memmove(skb->head + off + n, skb->head + off,
			skb_tail_pointer(skb) - split);
		skb_put(skb, n);
		return split;
	}

	/* Ohh, we must copy... */
	if (skb_shared(skb))
		BUG();

	/*
	 * Probably we'll need more space to adjust other headers,
	 * so request more data.
	 */
	size = SKB_DATA_ALIGN(skb_end_offset(skb) + n * 4);

	if (skb_pfmemalloc(skb))
		gfp_mask |= __GFP_MEMALLOC;
	data = kmalloc(size + SKB_DATA_ALIGN(sizeof(struct skb_shared_info)),
		       gfp_mask);
	if (!data)
		goto nodata;
	size = SKB_WITH_OVERHEAD(ksize(data));

	/*
	 * Copy data before @split and after @split + @n to leave room
	 * to insert data.
	 */
	memcpy(data, skb->head, off);
	memcpy(data + off + n, skb->head + off, skb_tail_pointer(skb) - split);
	split = data + off;

	memcpy((struct skb_shared_info *)(data + size),
	       skb_shinfo(skb),
	       offsetof(struct skb_shared_info, frags[skb_shinfo(skb)->nr_frags]));

	if (skb_cloned(skb)) {
		if (skb_orphan_frags(skb, gfp_mask))
			goto nofrags;
		for (i = 0; i < skb_shinfo(skb)->nr_frags; i++)
			skb_frag_ref(skb, i);

		if (skb_has_frag_list(skb)) {
			struct sk_buff *list;
			skb_walk_frags(skb, list)
				skb_get(list);
		}

		/* skb_release_data() */
		if (!skb->cloned
		    || !atomic_sub_return(skb->nohdr
			    		  ? (1 << SKB_DATAREF_SHIFT) + 1
					  : 1,
					  &skb_shinfo(skb)->dataref))
		{
			if (skb_shinfo(skb)->nr_frags)
				for (i = 0; i < skb_shinfo(skb)->nr_frags; i++)
					skb_frag_unref(skb, i);

			if (skb_shinfo(skb)->tx_flags & SKBTX_DEV_ZEROCOPY) {
				struct ubuf_info *uarg;

				uarg = skb_shinfo(skb)->destructor_arg;
				if (uarg->callback)
					uarg->callback(uarg, true);
			}

			if (skb_has_frag_list(skb)) {
				kfree_skb_list(skb_shinfo(skb)->frag_list);
				skb_shinfo(skb)->frag_list = NULL;
			}

			if (skb->head_frag)
				put_page(virt_to_head_page(skb->head));
			else
				kfree(skb->head);
		}
	} else {
		if (skb->head_frag)
			put_page(virt_to_head_page(skb->head));
		else
			kfree(skb->head);
	}
	off = data - skb->head;

	skb->head	= data;
	skb->head_frag	= 0;
	skb->data	+= off;
#ifdef NET_SKBUFF_DATA_USES_OFFSET
	skb->end	= size;
	off		= 0;
#else
	skb->end	= skb->head + size;
#endif
	skb->tail	+= off + n;
	skb->len	+= n;
	/* skb_headers_offset_update(skb, off) */
	skb->transport_header += off;
	skb->network_header   += off;
	if (skb_mac_header_was_set(skb))
		skb->mac_header += off;
	skb->inner_transport_header += off;
	skb->inner_network_header += off;
	skb->inner_mac_header += off;
	skb->cloned	= 0;
	skb->hdr_len	= 0;
	skb->nohdr	= 0;
	atomic_set(&skb_shinfo(skb)->dataref, 1);
	return split;

nofrags:
	kfree(data);
nodata:
	return NULL;
}

/**
 * Add @new_hdr as a last header just before the message body.
 *
 * FIXME RFC 7230 3.2.2 prohibits generating headers with the same field name.
 */
static int
__hdr_add(const char *new_hdr, size_t nh_len, struct sk_buff *skb,
	  unsigned char *crlf)
{
	int i, dlen;
	struct sk_buff *frag_i;
	unsigned char *vaddr;

next_skb:
	dlen = skb_headlen(skb);
	vaddr = skb->data;

	/* Process linear data. */
	if (crlf >= vaddr && crlf < vaddr + dlen) {
		void *split = tfw_skb_get_room(skb, crlf, nh_len);
		if (!split)
			return TFW_BLOCK;
		memcpy(split, new_hdr, nh_len);
		return TFW_PASS;
	}

	/* Process paged data. */
	for (i = 0; i < skb_shinfo(skb)->nr_frags; ++i) {
		const skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		vaddr = skb_frag_address(frag);
		dlen = skb_frag_size(frag);

		/* TODO do we need to process this? */
	}

	/* Process packet fragments. */
	skb_walk_frags(skb, frag_i) {
		int r = __hdr_add(new_hdr, nh_len, frag_i, crlf);
		if (r == TFW_PASS)
			return r;
	}

	skb = skb->next;
	if (skb)
		goto next_skb;

	/* It seems not all data was received. */
	return TFW_BLOCK;
}

#define TFW_HTTP_HDR_ADD(hm, str)	__hdr_add(str "\r\n", sizeof(str) + 1, \
						  hm->msg.skb_list.first, \
						  hm->crlf)

/**
 * FIXME update for duplicate strings.
 */
static int
__hdr_delete(TfwStr *hdr, struct sk_buff *skb)
{
	int i, dlen, c = 0, r = TFW_PASS;
	struct sk_buff *frag_i;
	TfwStr *h = TFW_STR_CHUNK(hdr, 0);
	unsigned char *vaddr;

	if (hdr->flags & TFW_STR_DUPLICATE) {
		TFW_WARN("Duplicate headers deletion is not supported\n");
		return TFW_BLOCK;
	}

#define PROCESS_DATA(code)						\
do {									\
	unsigned char *p = h->ptr;					\
	if (p >= vaddr && p < vaddr + dlen) {				\
		if (p + h->len < vaddr + dlen) {			\
			/* The header is linear. */			\
			BUG_ON(!TFW_STR_PLAIN(hdr));			\
			memmove(p, p + h->len, dlen - (p - vaddr) - h->len); \
			skb_trim(skb, skb->len - h->len);		\
			code;						\
			return TFW_PASS;				\
		} else {						\
			/* Header can't exceed data chunks boundary. */	\
			BUG_ON(p + h->len - vaddr - dlen);		\
			skb_trim(skb, skb->len - h->len);		\
			code;						\
			if (TFW_STR_PLAIN(hdr))			\
				return TFW_PASS;			\
			/* Compound header: process next chunk. */	\
			++c;						\
			h = TFW_STR_CHUNK(hdr, c);			\
			if (!h)						\
				return TFW_PASS;			\
		}							\
	}								\
} while (0)

next_skb:
	dlen = skb_headlen(skb);
	vaddr = skb->head;

	/* Process linear data. */
	PROCESS_DATA({});

	/* Process paged data. */
	for (i = 0; i < skb_shinfo(skb)->nr_frags; ++i) {
		skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		vaddr = skb_frag_address(frag);
		vaddr += frag->page_offset;
		dlen = skb_frag_size(frag);

		PROCESS_DATA({
				skb->data_len -= h->len;
				skb_frag_size_set(frag, dlen - h->len);
			});
	}

	/* Process packet fragments. */
	skb_walk_frags(skb, frag_i) {
		TfwStr hdr2 = { .flags = hdr->flags };
		if (!TFW_STR_PLAIN(hdr)) {
			hdr2.len = hdr->len - c;
			hdr2.ptr = h;
		} else {
			hdr2.len = h->len;
			hdr2.ptr = h->ptr;
		}
		r = __hdr_delete(&hdr2, frag_i);
		if (r == TFW_PASS)
			return r;
	}

	skb = skb->next;
	if (skb)
		goto next_skb;

	/* It seems not all data was received. */
	return TFW_BLOCK;
#undef PROCESS_DATA
}

/**
 * Substitute @hdr by @new_bdr.
 *
 * FIXME support duplicate @hdr.
 */
static int
__hdr_sub(TfwStr *hdr, const char *new_hdr, size_t nh_len, struct sk_buff *skb)
{
	int c, i, r, dlen, tot_hlen = 0;
	struct sk_buff *frag_i;
	TfwStr *h;
	unsigned char *vaddr, *p;

	if (hdr->flags & TFW_STR_DUPLICATE) {
		TFW_WARN("Duplicate headers substitution is not supported\n");
		return TFW_BLOCK;
	}

	for (h = TFW_STR_CHUNK(hdr, 0), c = 0; h; h = TFW_STR_CHUNK(hdr, ++c))
		tot_hlen += h->len;
	c = 0;
	h = TFW_STR_CHUNK(hdr, c);

next_skb:
	dlen = skb_headlen(skb);
	vaddr = skb->data;

	/* Process linear data. */
	p = h->ptr;
	if (p >= vaddr && p < vaddr + dlen) {
		int delta = nh_len - tot_hlen;
		if (tot_hlen < nh_len) {
			/* Make up for deficient room in skb linear data. */
			p = tfw_skb_get_room(skb, p, delta);
			if (!p)
				return TFW_BLOCK;
		}
		if (p + h->len < vaddr + dlen) {
			/* The header is linear. */
			BUG_ON(!TFW_STR_PLAIN(hdr));
			memcpy(p, new_hdr, nh_len);
			if (h->len > nh_len) {
				/* Set SPs at the end of header. */
				memset(p + nh_len - 2, ' ',
				       h->len - nh_len);
				memcpy(p + h->len - 2, "\r\n", 2);
			}
			return TFW_PASS;
		} else {
			int n = min((size_t)h->len, nh_len);
			/* Header can't exceed data chunks boundary. */
			BUG_ON(p + h->len - vaddr - dlen);

			/* Replace current part of the header. */
			memcpy(p, new_hdr, n);

			/* Set SPs at the end of header. */
			if (h->len > nh_len) {
				memset(p + nh_len - 2, ' ',
				       h->len - nh_len);
				memcpy(p + h->len - 2, "\r\n", 2);
				return TFW_PASS;
			}

			new_hdr += n;
			nh_len -= n;
			tot_hlen -= n;

			/* Write the extra allocated room. */
			if (tot_hlen < nh_len)
				memcpy(p + n, new_hdr, delta);

			/* Move to next header chunk if exists. */
			if (TFW_STR_PLAIN(hdr))
				return TFW_PASS;
					++c;
			h = TFW_STR_CHUNK(hdr, c);
			if (!h)	
				return TFW_PASS;
		}
	}

	/* Process paged data. */
	for (i = 0; i < skb_shinfo(skb)->nr_frags; ++i) {
		const skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		vaddr = skb_frag_address(frag);
		dlen = skb_frag_size(frag);

		/*
		 * TODO do we need to process poaged data?
		 * It's easy to rewrite the header chunks if it starts at
		 * linear data and there we allocated extra room, but it's
		 * unclear how to allocate extra room if frags array is full.
		 */
	}

	/* Process packet fragments. */
	skb_walk_frags(skb, frag_i) {
		TfwStr hdr2 = { .flags = hdr->flags };
		if (!TFW_STR_PLAIN(hdr)) {
			hdr2.len = hdr->len - c;
			hdr2.ptr = h;
		} else {
			hdr2.len = h->len;
			hdr2.ptr = h->ptr;
		}
		r = __hdr_sub(&hdr2, new_hdr, nh_len, frag_i);
		if (r == TFW_PASS)
			return r;
	}

	skb = skb->next;
	if (skb)
		goto next_skb;

	/* It seems not all data was received. */
	return TFW_BLOCK;
}

#define TFW_HTTP_HDR_SUB(hdr, str, skb)	__hdr_sub(hdr, str "\r\n",	\
						  sizeof(str) + 1, skb)

/**
 * Removes Connection header from HTTP message @msg if @conn_flg is zero,
 * and replace or set a new header value otherwise.
 *
 * Sometimes there is some extra space in skb (see ksize() in linux/mm/slab.c),
 * so in some cases we can place some additional data w/o memory allcations.
 *
 * skb's can be shared between number of HTTP messages. We don't copy skb if
 * it's shared - we modify skb's safely and shared skb is still owned by one
 * CPU.
 *
 * TODO handle generic headers adjustment.
 * The three cases are possible:
 *
 * 1. we need to delete the header - we just shift first or second
 *    (which is shorter) using skb pointers;
 *
 * 2. need to add a header - we add the header as last header shifting message
 *    body. Duplicate headers should also be processed for this case;
 *
 * 3. replace some of the headers - aggregate all current headers with the same
 *    name to one single header with comma separated fields (RFC 2616 4.2)
 *    shrinking unneccessary fields and adding the new fields at the end of
 *    the list;
 *    if the resulting header is shorter than sum of current headers, then we
 *    place SPs to avoid data movement;
 *    we need to move headers between the substituted headers with the same
 *    name and message body if the new header is longer than the sum of the
 *    cyrrent headers.
 */
static int
tfw_http_set_hdr_connection(TfwHttpMsg *hm, int conn_flg)
{
	int r = 0;
	unsigned int need_add = (hm->flags & conn_flg) ^ conn_flg;
	unsigned int need_del = (hm->flags & conn_flg)
				^ (hm->flags & __TFW_HTTP_CONN_MASK);
	TfwHttpHdr *ch = hm->h_tbl->tbl + TFW_HTTP_HDR_CONNECTION;

	/* Never call the function if no changes are required. */
	BUG_ON(!need_add && !need_del);

	if (need_add && need_del) {
		/* Substitute the header. */
		switch (need_add) {
		case TFW_HTTP_CONN_CLOSE:
			r = TFW_HTTP_HDR_SUB(&ch->field, "close", ch->skb);
			break;
		case TFW_HTTP_CONN_KA:
			r = TFW_HTTP_HDR_SUB(&ch->field, "keep-alive", ch->skb);
			break;
		default:
			BUG();
		}
	}
	else if (need_add) {
		/* There is no Connection header, add one. */
		BUG_ON(ch->field.ptr);
		switch (need_add) {
		case TFW_HTTP_CONN_CLOSE:
			r = TFW_HTTP_HDR_ADD(hm, "Connection: close");
			break;
		case TFW_HTTP_CONN_KA:
			r = TFW_HTTP_HDR_ADD(hm, "Connection: keep-alive");
			break;
		default:
			BUG();
		}
	}
	else {
		/* Just delete the header. */
		r = __hdr_delete(&ch->field, ch->skb);
	}

	return r;
}

/**
 * Get @skb's source address and port as a string, e.g. "127.0.0.1", "::1".
 *
 * Only the source IP address is printed to @out_buf, and the TCP/SCTP port
 * is not printed. That is done because:
 *  - Less output bytes means more chance for fast path in __hdr_add().
 *  - RFC7239 says the port is optional.
 *  - Most proxy servers don't put it to the field.
 *  - Usually you get a random port of an outbound connection there,
 *    so the value is likely useless.
 * If at some point we will need the port, then the fix should be trivial:
 * just get it with tcp_hdr(skb)->src (or sctp_hdr() for SPDY).
 */
static char *
tfw_fmt_skb_src_addr(const struct sk_buff *skb, char *out_buf)
{
	const struct iphdr *ih4 = ip_hdr(skb);
	const struct ipv6hdr *ih6 = ipv6_hdr(skb);

	if (ih6->version == 6)
		return tfw_addr_fmt_v6(&ih6->saddr, 0, out_buf);

	return tfw_addr_fmt_v4(ih4->saddr, 0, out_buf);
}

static int
tfw_http_add_forwarded_for(TfwHttpMsg *m)
{
#define XFF_HDR "X-Forwarded-For: "
#define XFF_LEN (sizeof(XFF_HDR) - 1)

	struct sk_buff *skb;
	char *pos;
	int r, len;
	char buf[XFF_LEN + TFW_ADDR_STR_BUF_SIZE + 2] = XFF_HDR;

	skb = m->msg.skb_list.first;
	pos = buf + XFF_LEN;
	pos = tfw_fmt_skb_src_addr(skb, pos);

	*pos++ = '\r';
	*pos++ = '\n';
	len = (pos - buf);
	r = __hdr_add(buf, len, skb, m->crlf);

	if (r)
		TFW_ERR("can't add X-Forwarded-For header to msg: %p, "
			"buf: %*s", m, len, buf);
	else
		TFW_DBG("added X-Forwarded-For header: %*s\n", len, buf);

	return r;

#undef XFF_HDR
#undef XFF_LEN
}

static int
tfw_http_append_forwarded_for(TfwHttpMsg *m)
{
	TfwHttpHdr *hdr = &m->h_tbl->tbl[TFW_HTTP_HDR_X_FORWARDED_FOR];
	struct sk_buff *skb;
	char *buf, *pos;
	int r, old_hdr_len, buf_size, new_hdr_len;

	skb = m->msg.skb_list.first;
	old_hdr_len = hdr->field.len;
	buf_size = old_hdr_len + TFW_ADDR_STR_BUF_SIZE + sizeof(", \r\n");

	buf = tfw_pool_alloc(m->pool, buf_size);
	if (!buf)
		return TFW_BLOCK;

	tfw_str_to_cstr(&hdr->field, buf, buf_size);

	pos = buf + old_hdr_len;
	*pos++ = ',';
	*pos++ = ' ';
	BUG_ON(!skb);
	pos = tfw_fmt_skb_src_addr(skb, pos);
	*pos++ = '\r';
	*pos++ = '\n';

	new_hdr_len = (pos - buf);
	r = __hdr_sub(&hdr->field, buf, new_hdr_len, skb);

	if (r)
		TFW_ERR("can't replace X-Forwarded-For with: %.*s",
			new_hdr_len, buf);
	else
		TFW_DBG("re-placed X-Forwarded-For header: %.*s",
			new_hdr_len, buf);

	return r;
}

static int
tfw_http_add_or_append_forwarded_for(TfwHttpMsg *m)
{
	if (m->h_tbl->tbl[TFW_HTTP_HDR_X_FORWARDED_FOR].field.len)
		return tfw_http_append_forwarded_for(m);

	return tfw_http_add_forwarded_for(m);
}

/**
 * Adjust the request before proxying it to real server.
 */
static int
tfw_http_adjust_req(TfwHttpReq *req)
{
	int r = 0;
	TfwHttpMsg *m = (TfwHttpMsg *)req;

	r = tfw_http_add_or_append_forwarded_for(m);
	if (r)
		return r;

	if ((m->flags & __TFW_HTTP_CONN_MASK) != TFW_HTTP_CONN_KA)
		r = tfw_http_set_hdr_connection(m, TFW_HTTP_CONN_KA);

	return r;
}

/**
 * Adjust the response before proxying it to real client.
 */
static int
tfw_http_adjust_resp(TfwHttpResp *resp)
{
	/*
	 * TODO adjust Connection header and all connection-token headers
	 * (e.g. Keep-Alive) according to our policy.
	 */
	(void)resp;

	return 0;
}

/*
 * Depending on results of processing of a request, either send the request
 * to an appropriate server, or return the cached response. If none of that
 * can be done for any reason, return HTTP 404 or 500 error to the client.
 */
static void
tfw_http_req_cache_cb(TfwHttpReq *req, TfwHttpResp *resp, void *data)
{
	int r;

	if (resp) {
		/*
		 * We have prepared response, send it as is.
		 * TODO should we adjust it somehow?
		 */
		tfw_connection_send(req->conn, (TfwMsg *)resp);
	} else {
		/* Dispatch request to an appropriate server. */
		TfwConnection *conn = tfw_sched_get_srv_conn((TfwMsg *)req);
		if (!conn) {
			TFW_ERR("Unable to find a backend server\n");
			goto send_404;
		}
		r = tfw_http_sticky_req_process((TfwHttpMsg *)req);
		if (r < 0) {
			goto send_500;
		} else if (r > 0) {
			/* Response sent, nothing to do */
			tfw_http_msg_free((TfwHttpMsg *)req);
			return;
		}
		if (tfw_http_adjust_req(req))
			goto send_500;

		/* Add request to the connection. */
		list_add_tail(&req->msg.msg_list, &conn->msg_queue);

		/* Send request to the server. */
		tfw_connection_send(conn, (TfwMsg *)req);
	}
	return;

send_404:
	tfw_http_send_404((TfwHttpMsg *)req);
	tfw_http_msg_free((TfwHttpMsg *)req);
	return;
send_500:
	tfw_http_send_500((TfwHttpMsg *)req);
	tfw_http_msg_free((TfwHttpMsg *)req);
	return;
}

/**
 * @return zero on success and negative value otherwise.
 */
static int
tfw_http_req_process(TfwConnection *conn, struct sk_buff *skb, unsigned int off)
{
	int r = TFW_BLOCK;
	unsigned int data_off = off;
	unsigned int skb_len = skb->len;

	BUG_ON(!conn->msg);
	BUG_ON(off >= skb_len);

	TFW_DBG("Received %u client data bytes on conn=%p\n",
		skb_len - off, conn);
	/*
	 * Process pipelined requests in a loop
	 * until all data in the SKB is processed.
	 */
	while (data_off < skb_len) {
		TfwHttpMsg *hmsib = NULL;
		TfwHttpMsg *hmreq = (TfwHttpMsg *)conn->msg;
		TfwHttpParser *parser = &hmreq->parser;

		/*
		 * Process/parse data in the SKB.
		 * @off points at the start of data for processing.
		 * @data_off is the current offset of data to process in
		 * the SKB. After processing @data_off points at the end
		 * of latest data chunk. However processing may have
		 * stopped in the middle of the chunk. Adjust it to point 
		 * to the right location within the chunk.
		 */
		off = data_off;
		r = ss_skb_process(skb, &data_off, tfw_http_parse_req, hmreq);
		data_off -= parser->to_go;
		hmreq->msg.len += data_off - off;

		TFW_DBG("Request parsed: len=%u parsed=%d msg_len=%lu res=%d\n",
			skb_len - off, data_off - off, hmreq->msg.len, r);

		switch (r) {
		default:
			TFW_ERR("Unrecognized HTTP request "
				"parser return code, %d\n", r);
			BUG();
		case TFW_BLOCK:
			TFW_DBG("Block invalid HTTP request\n");
			return TFW_BLOCK;
		case TFW_POSTPONE:
			tfw_http_establish_skb_hdrs(hmreq);
			r = tfw_gfsm_move(&hmreq->msg.state,
					  TFW_HTTP_FSM_REQ_CHUNK, skb, off);
			TFW_DBG("TFW_HTTP_FSM_REQ_CHUNK return code %d\n", r);
			if (r == TFW_BLOCK)
				return TFW_BLOCK;
			/*
			 * TFW_POSTPONE status means that parsing succeeded
			 * but more data is needed to complete it. Lower layers
			 * just supply data for parsing. They only want to know
			 * if processing of a message should continue or not.
			 */
			return TFW_PASS;
		case TFW_PASS:
			/*
			 * The request is fully parsed,
			 * fall through and process it.
			 */
			;
		}

		tfw_http_establish_skb_hdrs(hmreq);
		r = tfw_gfsm_move(&hmreq->msg.state,
				  TFW_HTTP_FSM_REQ_MSG, skb, off);
		TFW_DBG("TFW_HTTP_FSM_REQ_MSG return code %d\n", r);
		if (r == TFW_BLOCK)
			return TFW_BLOCK;

		if (data_off < skb_len) {
			/*
			 * Pipelined requests: create a new sibling message.
			 * @skb is replaced with pointer to a new SKB.
			 */
			hmsib = tfw_http_msg_create_sibling(hmreq, &skb,
							    data_off,
							    Conn_Clnt);
			if (hmsib == NULL) {
				/*
				 * Not enough memory. Unfortunately, there's
				 * no recourse. The caller expects that data
				 * is processed in full, and can't deal with
				 * partially processed data.
				 */
				TFW_WARN("Not enough memory "
					 "to create request sibling\n");
				return TFW_BLOCK;
			}
		}
		/*
		 * The request should either be stored or released.
		 * Otherwise we lose the reference to it and get a leak.
		 */
		tfw_cache_req_process((TfwHttpReq *)hmreq,
				      tfw_http_req_cache_cb, NULL);

		if (hmsib) {
			/*
			 * Switch connection to the new sibling message.
			 * Data processing will continue with the new SKB.
			 */
			data_off = 0;
			skb_len = skb->len;
			conn->msg = (TfwMsg *)hmsib;
		}
	}
	/*
	 * All data in the SKB has been processed, and the processing
	 * is successful. A complete HTTP message has been collected,
	 * and stored or released. Future SKBs should be put in a new
	 * message.
	 *
	 * Otherwise, the function just returns from inside the loop.
	 * conn->msg contains the reference to a message, which can
	 * be used to release it.
	 */
	conn->msg = NULL;

	return r;
}

/**
 * @return zero on success and negative value otherwise.
 */
static int
tfw_http_resp_process(TfwConnection *conn, struct sk_buff *skb,
		      unsigned int off)
{
	int r;
	unsigned int data_off = off;
	TfwHttpMsg *hmreq, *hmresp = (TfwHttpMsg *)conn->msg;

	BUG_ON(!hmresp);

	TFW_DBG("received %u server data bytes on conn=%p\n",
		skb->len - off, conn);

	r = ss_skb_process(skb, &data_off, tfw_http_parse_resp, hmresp);
	hmresp->msg.len += data_off - off;

	TFW_DBG("response parsed: len=%u parsed=%d res=%d\n",
		skb->len - off, data_off - off, r);

	switch (r) {
	default:
		TFW_ERR("Unrecognized HTTP response "
			"parser return code, %d\n", r);
		BUG();
	case TFW_BLOCK:
		/*
		 * The response has not been fully parsed.
		 * We have no choice but report a critical error.
		 * The lower layer will close the connection and release
		 * the response message, and well as all request messages
		 * that went out on this connection and are waiting for
		 * paired response messages.
		 */
		TFW_DBG("Block invalid HTTP response\n");
		return TFW_BLOCK;
	case TFW_POSTPONE:
		tfw_http_establish_skb_hdrs(hmresp);
		r = tfw_gfsm_move(&hmresp->msg.state,
				  TFW_HTTP_FSM_RESP_CHUNK, skb, off);
		TFW_DBG("TFW_HTTP_FSM_RESP_CHUNK return code %d\n", r);
		if (r == TFW_BLOCK)
			/*
			 * We don't have a complete response.
			 * We have no choice but report a critical error.
			 */
			return TFW_BLOCK;
		/*
		 * TFW_POSTPONE status means that parsing succeeded
		 * but more data is needed to complete it. Lower layers
		 * just supply data for parsing. They only want to know
		 * if processing of a message should continue or not.
		 */
		return TFW_PASS;
	case TFW_PASS:
		/*
		 * The response is fully parsed,
		 * fall through and process it.
		 */
		;
	}

	tfw_http_establish_skb_hdrs(hmresp);
	r = tfw_gfsm_move(&hmresp->msg.state,
			  TFW_HTTP_FSM_RESP_MSG, skb, off);
	TFW_DBG("TFW_HTTP_FSM_RESP_MSG return code %d\n", r);
	if (r == TFW_BLOCK)
		goto delreq;

	r = tfw_gfsm_move(&hmresp->msg.state,
			  TFW_HTTP_FSM_LOCAL_RESP_FILTER, skb, off);
	TFW_DBG("TFW_HTTP_FSM_LOCAL_RESP_FILTER return code %d\n", r);
	if (r == TFW_BLOCK)
		goto delreq;

	if (tfw_http_adjust_resp((TfwHttpResp *)hmresp))
		goto delreq;

	/*
	 * Cache adjusted and filtered responses only.
	 * We get responses in the same order as requests,
	 * so we can just pop the first request.
	 */
	if (unlikely(list_empty(&conn->msg_queue))) {
		TFW_WARN("Response w/o request\n");
		goto freeresp;
	}
	hmreq = (TfwHttpMsg *)
		list_first_entry(&conn->msg_queue, TfwMsg, msg_list);
	list_del(&hmreq->msg.msg_list);

	r = tfw_http_sticky_resp_process(hmresp, hmreq);
	if (r < 0)
		goto freereq;

	/*
	 * Send the response to client before caching it.
	 * The cache frees the response and the request.
	 * conn->msg will get NULLed in the process.
	 */
	tfw_connection_send(hmreq->conn, (TfwMsg *)hmresp);
	tfw_cache_add((TfwHttpResp *)hmresp, (TfwHttpReq *)hmreq);

	return TFW_PASS;

	/*
	 * We've got a complete response message. However an error
	 * occured on further processing. Such errors are considered
	 * rare. Remove the response and the corresponding (paired)
	 * request, and keep the connection open for data exchange.
	 */
delreq:
	if (unlikely(list_empty(&conn->msg_queue))) {
		TFW_WARN("Response w/o request\n");
		goto freeresp;
	}
	hmreq = (TfwHttpMsg *)
		list_first_entry(&conn->msg_queue, TfwMsg, msg_list);
	list_del(&hmreq->msg.msg_list);
freereq:
	tfw_http_msg_free(hmreq);
freeresp:
	/* conn->msg will get NULLed in the process. */
	tfw_http_msg_free(hmresp);

	return TFW_PASS;
}

int
tfw_http_hdr_add(TfwHttpMsg *hm, const char *data, size_t len)
{
	return __hdr_add(data, len, hm->msg.skb_list.first, hm->crlf);
}

int
tfw_http_hdr_del(TfwHttpMsg *hm, TfwStr *hdr)
{
	return __hdr_delete(hdr, hm->msg.skb_list.first);
}

int
tfw_http_hdr_sub(TfwHttpMsg *hm, TfwStr *hdr, const char *data, size_t len)
{
	return __hdr_sub(hdr, data, len, hm->msg.skb_list.first);
}

/**
 * @return status (application logic decision) of the message processing.
 */
int
tfw_http_msg_process(void *conn, struct sk_buff *skb, unsigned int off)
{
	TfwConnection *c = (TfwConnection *)conn;

	return (TFW_CONN_TYPE(c) & Conn_Clnt)
		? tfw_http_req_process(c, skb, off)
		: tfw_http_resp_process(c, skb, off);
}

/**
 * Calculate key of a HTTP request by hashing its URI and Host header.
 *
 * Requests with the same URI and Host are mapped to the same key with
 * high probability. Different keys may be calculated for the same Host and URI
 * when they consist of many chunks.
 */
unsigned long
tfw_http_req_key_calc(TfwHttpReq *req)
{
	if (req->hash)
		return req->hash;

	req->hash = tfw_hash_str(&req->h_tbl->tbl[TFW_HTTP_HDR_HOST].field)
		    ^ tfw_hash_str(&req->uri_path);

	return req->hash;
}
EXPORT_SYMBOL(tfw_http_req_key_calc);

static TfwConnHooks http_conn_hooks = {
	.conn_init	= tfw_http_conn_init,
	.conn_destruct	= tfw_http_conn_destruct,
	.conn_msg_alloc	= tfw_http_conn_msg_alloc,
};

int __init
tfw_http_init(void)
{
	int r = tfw_gfsm_register_fsm(TFW_FSM_HTTP, tfw_http_msg_process);
	if (r)
		return r;

	tfw_connection_hooks_register(&http_conn_hooks, TFW_FSM_HTTP);

	/* Must be last call - we can't unregister the hook. */
	r = tfw_gfsm_register_hook(TFW_FSM_HTTPS, TFW_GFSM_HOOK_PRIORITY_ANY,
				   TFW_HTTPS_FSM_TODO_ISSUE_81,
				   TFW_FSM_HTTP, TFW_HTTP_FSM_INIT);

	return r;
}

void
tfw_http_exit(void)
{
}
