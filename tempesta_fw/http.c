/**
 *		Tempesta FW
 *
 * Core HTTP-layer processing, including HTTP/2 and HTTP/1.1 versions.
 *
 * Notes about the design of HTTP/2 implementation.
 *
 * In order to perform internal HTTP-specific analysis (HTTP-tables,
 * HTTP-limits, Sessions module, Scheduling etc.) - for both HTTP/2 and
 * HTTP/1.1 processing - we need representation of HTTP-message content.
 * In case of HTTP/1.1 we have such representation right from the message's
 * source skb - those are ASCII strings, which don't need to be decrypted
 * and allow quick processing with SIMD instructions. However, content of
 * HTTP/2-message (i.e. headers) could be encrypted with special HPACK
 * methods (static/dynamic indexing and Huffman coding), which doesn't
 * allow to analyze the message content directly. To solve this issue for
 * HTTP/2-requests processing, current implementation of HTTP-layer creates
 * HTTP/1.1-representation of HTTP/2 headers (during HPACK-decoding and
 * HTTP/2-parsing) and places that representation into the special pool
 * @TfwHttpReq.pit.pool.
 *
 * Actually, we don't need to create separate HTTP/1.1-representation
 * for all HTTP/2 headers: some of them could be not encoded (not in Huffman
 * form - in ASCII instead) and some - could be just indexed (we can keep static
 * and dynamic indexes during internal request analysis and convert them into
 * ASCII strings in-place - on demand); thus, in current implementation we save
 * memory/processor resources and create additional HTTP/1.1-representation only
 * for Huffman encoded headers. On the final stage of request processing (in
 * @tfw_h2_adjust_req() procedure, before re-sending request to backend) the
 * obtained @TfwHttpReq.pit.pool with HTTP/1.1-representation is used for
 * request assembling in case of HTTP/2 => HTTP/1.1 transformation.
 *
 * Described above approach was chosen instead of immediate HTTP/2 => HTTP/1.1
 * transformation on HTTP/2-message decoding, because the latter one is not
 * scales for the case of HTTP/2 => HTTP/2 proxying, since during request
 * receiving/processing we do not know what backend (HTTP/2 or HTTP/1.1)
 * the request attended for. Thus, until the backend determination moment,
 * we need to leave HTTP/2-representation in the source skb.
 * Yet another choice (instead of HTTP/1.1-representation creation for HTTP/2
 * message) could be an implementation HTTP/2-specific functionality set with
 * custom flags in @TfwHttpReq.h_tbl - to perform HTTP-specific analysis right
 * over source HTTP/2-representation of the message. However, there are several
 * problems with HTTP/2-representation analysis:
 * 1. HTTP/2 still allows ASCII strings, and even the same HTTP message may
 *    contain the same header in ASCII and in static table index. Thus, even
 *    with pure HTTP/2 operation we still must care about binary headers
 *    representation and plain ASCII representation. That means that the whole
 *    headers analyzing logic (mentioned above Schedulers, HTTPTables etc.) must
 *    either encode/decode strings on the fly or keep the two representations
 *    for the headers;
 * 2. Huffman decoding is extremely slow: it operates on units less than a byte,
 *    while we use SIMD operations for ASCII processing. The bytes-crossing
 *    logic doesn't allow to efficiently encode Huffman decoding in SIMD;
 * 3. Huffman encoding, also due to byte boundary crossing, mangles string
 *    information representation, so efficient strings matching algorithms
 *    required for #496 and #732 can not be applied.
 * Thus, the points specified above (and #732) leave us only one possibility:
 * since we must process ASCII-headers along with Huffman-encoded, we have to
 * decode Huffman on HTTP-message reception.
 *
 * Regarding of internal HTTP/2-responses (error and cached) generation - dual
 * logic design is used; i.e. along with existing functionality for
 * HTTP/1.1-responses creation, separate logic implemented for HTTP/2-responses
 * generation, in order to get performance benefits of creating a message right
 * away in HTTP/2-format instead of transforming into HTTP/2 from already
 * created HTTP/1.1-message.
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
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/sort.h>
#include <linux/bsearch.h>

#include "lib/hash.h"
#include "lib/str.h"
#include "cache.h"
#include "hash.h"
#include "http_limits.h"
#include "http_tbl.h"
#include "http_parser.h"
#include "http_frame.h"
#include "client.h"
#include "http_msg.h"
#include "http_sess.h"
#include "log.h"
#include "procfs.h"
#include "server.h"
#include "tls.h"
#include "apm.h"

#include "sync_socket.h"
#include "lib/common.h"

#define S_H2_METHOD		":method"
#define S_H2_SCHEME		":scheme"
#define S_H2_AUTH		":authority"
#define S_H2_PATH		":path"
#define S_H2_STAT		":status"

#define T_WARN_ADDR_STATUS(msg, addr_ptr, print_port, status)		\
	TFW_WITH_ADDR_FMT(addr_ptr, print_port, addr_str,		\
			  T_WARN("%s, status %d: %s\n",			\
				 msg, status, addr_str))

#define RESP_BUF_LEN		128

static DEFINE_PER_CPU(char[RESP_BUF_LEN], g_buf);
int ghprio; /* GFSM hook priority. */

#define TFW_CFG_BLK_DEF		(TFW_BLK_ERR_REPLY)
unsigned short tfw_blk_flags = TFW_CFG_BLK_DEF;

/* Array of whitelist marks for request's skb. */
static struct {
	unsigned int	*mrks;
	unsigned int	sz;
} tfw_wl_marks;

#define S_CRLFCRLF		"\r\n\r\n"
#define S_HTTP			"http://"
#define S_HTTPS			"https://"

#define S_200			"HTTP/1.1 200 OK"
#define S_302			"HTTP/1.1 302 Found"
#define S_304			"HTTP/1.1 304 Not Modified"
#define S_400			"HTTP/1.1 400 Bad Request"
#define S_403			"HTTP/1.1 403 Forbidden"
#define S_404			"HTTP/1.1 404 Not Found"
#define S_412			"HTTP/1.1 412 Precondition Failed"
#define S_500			"HTTP/1.1 500 Internal Server Error"
#define S_502			"HTTP/1.1 502 Bad Gateway"
#define S_503			"HTTP/1.1 503 Service Unavailable"
#define S_504			"HTTP/1.1 504 Gateway Timeout"

#define S_XFF			"x-forwarded-for"
#define S_WARN			"warning"

#define S_F_HOST		"host: "
#define S_F_DATE		"date: "
#define S_F_CONTENT_LENGTH	"content-length: "
#define S_F_CONTENT_TYPE	"content-type: "
#define S_F_CONNECTION		"connection: "
#define S_F_ETAG		"etag: "
#define S_F_RETRY_AFTER		"retry-after: "
#define S_F_SERVER		"server: "


#define S_V_DATE		"Sun, 06 Nov 1994 08:49:37 GMT"
#define S_V_CONTENT_LENGTH	"9999"
#define S_V_CONN_CLOSE		"close"
#define S_V_CONN_KA		"keep-alive"
#define S_V_RETRY_AFTER		"10"
#define S_V_MULTIPART		"multipart/form-data; boundary="
#define S_V_WARN		"110 - Response is stale"

#define S_H_CONN_KA		S_F_CONNECTION S_V_CONN_KA S_CRLFCRLF
#define S_H_CONN_CLOSE		S_F_CONNECTION S_V_CONN_CLOSE S_CRLFCRLF

#define S_200_PART_01		S_200 S_CRLF S_F_DATE
#define S_200_PART_02		S_CRLF S_F_CONTENT_LENGTH "0" S_CRLF
#define S_400_PART_01		S_400 S_CRLF S_F_DATE
#define S_400_PART_02		S_CRLF S_F_CONTENT_LENGTH "0" S_CRLF
#define S_403_PART_01		S_403 S_CRLF S_F_DATE
#define S_403_PART_02		S_CRLF S_F_CONTENT_LENGTH "0" S_CRLF
#define S_404_PART_01		S_404 S_CRLF S_F_DATE
#define S_404_PART_02		S_CRLF S_F_CONTENT_LENGTH "0" S_CRLF
#define S_412_PART_01		S_412 S_CRLF S_F_DATE
#define S_412_PART_02		S_CRLF S_F_CONTENT_LENGTH "0" S_CRLF
#define S_500_PART_01		S_500 S_CRLF S_F_DATE
#define S_500_PART_02		S_CRLF S_F_CONTENT_LENGTH "0" S_CRLF
#define S_502_PART_01		S_502 S_CRLF S_F_DATE
#define S_502_PART_02		S_CRLF S_F_CONTENT_LENGTH "0" S_CRLF
#define S_503_PART_01		S_503 S_CRLF S_F_DATE
#define S_503_PART_02		S_CRLF S_F_CONTENT_LENGTH "0" S_CRLF \
				S_F_RETRY_AFTER S_V_RETRY_AFTER S_CRLF
#define S_504_PART_01		S_504 S_CRLF S_F_DATE
#define S_504_PART_02		S_CRLF S_F_CONTENT_LENGTH "0" S_CRLF
#define S_DEF_PART_02		S_CRLF S_F_CONTENT_LENGTH "0" S_CRLF
#define S_DEF_PART_03		S_F_SERVER TFW_NAME "/" TFW_VERSION S_CRLF

/*
 * Array with predefined response data
 */
static TfwStr http_predef_resps[RESP_NUM] = {
	[RESP_200] = {
		.chunks = (TfwStr []){
			{ .data = S_200_PART_01, .len = SLEN(S_200_PART_01) },
			{ .data = NULL, .len = SLEN(S_V_DATE) },
			{ .data = S_200_PART_02, .len = SLEN(S_200_PART_02) },
			{ .data = S_DEF_PART_03, .len = SLEN(S_DEF_PART_03) },
			{ .data = S_CRLF, .len = SLEN(S_CRLF) },
			{ .data = NULL, .len = 0 },
		},
		.len = SLEN(S_200_PART_01 S_V_DATE S_200_PART_02 S_DEF_PART_03
			    S_CRLF),
		.nchunks = 6
	},
	/* Response has invalid syntax, client shouldn't repeat it. */
	[RESP_400] = {
		.chunks = (TfwStr []){
			{ .data = S_400_PART_01, .len = SLEN(S_400_PART_01) },
			{ .data = NULL, .len = SLEN(S_V_DATE) },
			{ .data = S_400_PART_02, .len = SLEN(S_400_PART_02) },
			{ .data = S_DEF_PART_03, .len = SLEN(S_DEF_PART_03) },
			{ .data = S_CRLF, .len = SLEN(S_CRLF) },
			{ .data = NULL, .len = 0 },
		},
		.len = SLEN(S_400_PART_01 S_V_DATE S_400_PART_02 S_DEF_PART_03
			    S_CRLF),
		.nchunks = 6
	},
	/* Response is syntactically valid, but refuse to authorize it. */
	[RESP_403] = {
		.chunks = (TfwStr []){
			{ .data = S_403_PART_01, .len = SLEN(S_403_PART_01) },
			{ .data = NULL, .len = SLEN(S_V_DATE) },
			{ .data = S_403_PART_02, .len = SLEN(S_403_PART_02) },
			{ .data = S_DEF_PART_03, .len = SLEN(S_DEF_PART_03) },
			{ .data = S_CRLF, .len = SLEN(S_CRLF) },
			{ .data = NULL, .len = 0 },
		},
		.len = SLEN(S_403_PART_01 S_V_DATE S_403_PART_02 S_DEF_PART_03
			    S_CRLF),
		.nchunks = 6
	},
	/* Can't find the requested resource. */
	[RESP_404] = {
		.chunks = (TfwStr []){
			{ .data = S_404_PART_01, .len = SLEN(S_404_PART_01) },
			{ .data = NULL, .len = SLEN(S_V_DATE) },
			{ .data = S_404_PART_02, .len = SLEN(S_404_PART_02) },
			{ .data = S_DEF_PART_03, .len = SLEN(S_DEF_PART_03) },
			{ .data = S_CRLF, .len = SLEN(S_CRLF) },
			{ .data = NULL, .len = 0 },
		},
		.len = SLEN(S_404_PART_01 S_V_DATE S_404_PART_02 S_DEF_PART_03
			    S_CRLF),
		.nchunks = 6
	},
	[RESP_412] = {
		.chunks = (TfwStr []){
			{ .data = S_412_PART_01, .len = SLEN(S_412_PART_01) },
			{ .data = NULL, .len = SLEN(S_V_DATE) },
			{ .data = S_412_PART_02, .len = SLEN(S_412_PART_02) },
			{ .data = S_DEF_PART_03, .len = SLEN(S_DEF_PART_03) },
			{ .data = S_CRLF, .len = SLEN(S_CRLF) },
			{ .data = NULL, .len = 0 },
		},
		.len = SLEN(S_412_PART_01 S_V_DATE S_412_PART_02 S_DEF_PART_03
			    S_CRLF),
		.nchunks = 6
	},
	/* Internal error in TempestaFW. */
	[RESP_500] = {
		.chunks = (TfwStr []){
			{ .data = S_500_PART_01, .len = SLEN(S_500_PART_01) },
			{ .data = NULL, .len = SLEN(S_V_DATE) },
			{ .data = S_500_PART_02, .len = SLEN(S_500_PART_02) },
			{ .data = S_DEF_PART_03, .len = SLEN(S_DEF_PART_03) },
			{ .data = S_CRLF, .len = SLEN(S_CRLF) },
			{ .data = NULL, .len = 0 },
		},
		.len = SLEN(S_500_PART_01 S_V_DATE S_500_PART_02 S_DEF_PART_03
			    S_CRLF),
		.nchunks = 6
	},
	/* Error (syntax or network) while receiving request from backend. */
	[RESP_502] = {
		.chunks = (TfwStr []){
			{ .data = S_502_PART_01, .len = SLEN(S_502_PART_01) },
			{ .data = NULL, .len = SLEN(S_V_DATE) },
			{ .data = S_502_PART_02, .len = SLEN(S_502_PART_02) },
			{ .data = S_DEF_PART_03, .len = SLEN(S_DEF_PART_03) },
			{ .data = S_CRLF, .len = SLEN(S_CRLF) },
			{ .data = NULL, .len = 0 },
		},
		.len = SLEN(S_502_PART_01 S_V_DATE S_502_PART_02 S_DEF_PART_03
			    S_CRLF),
		.nchunks = 6
	},
	/*
	 * Sticky cookie or JS challenge failed, refuse to serve the client.
	 * Add Retry-After header, normal browser will repeat the request
	 * after given time, 10s by default.
	 */
	[RESP_503] = {
		.chunks = (TfwStr []){
			{ .data = S_503_PART_01, .len = SLEN(S_503_PART_01) },
			{ .data = NULL, .len = SLEN(S_V_DATE) },
			{ .data = S_503_PART_02, .len = SLEN(S_503_PART_02) },
			{ .data = S_DEF_PART_03, .len = SLEN(S_DEF_PART_03) },
			{ .data = S_CRLF, .len = SLEN(S_CRLF) },
			{ .data = NULL, .len = 0 },
		},
		.len = SLEN(S_503_PART_01 S_V_DATE S_503_PART_02 S_DEF_PART_03
			    S_CRLF),
		.nchunks = 6
	},
	/* Can't get a response in time. */
	[RESP_504] = {
		.chunks = (TfwStr []){
			{ .data = S_504_PART_01, .len = SLEN(S_504_PART_01) },
			{ .data = NULL, .len = SLEN(S_V_DATE) },
			{ .data = S_504_PART_02, .len = SLEN(S_504_PART_02) },
			{ .data = S_DEF_PART_03, .len = SLEN(S_DEF_PART_03) },
			{ .data = S_CRLF, .len = SLEN(S_CRLF) },
			{ .data = NULL, .len = 0 },
		},
		.len = SLEN(S_504_PART_01 S_V_DATE S_504_PART_02 S_DEF_PART_03
			    S_CRLF),
		.nchunks = 6
	}
};

/*
 * Chunks for various message parts in @http_predef_resps array
 * have predefined positions:
 * 1: Start line,
 * 2: Date,
 * 3: Content-Length header,
 * 4: Server header,
 * 5: CRLF,
 * 6: Message body.
 * Message body is empty by default but can be overridden by 'response_body'
 * directive.
 *
 * Some position-dependent macros specific to @http_predef_resps
 * are defined below.
 */
#define TFW_STR_START_CH(msg)	__TFW_STR_CH(msg, 0)
#define TFW_STR_DATE_CH(msg)	__TFW_STR_CH(msg, 1)
#define TFW_STR_CLEN_CH(msg)	__TFW_STR_CH(msg, 2)
#define TFW_STR_SRV_CH(msg)	__TFW_STR_CH(msg, 3)
#define TFW_STR_CRLF_CH(msg)	__TFW_STR_CH(msg, 4)
#define TFW_STR_BODY_CH(msg)	__TFW_STR_CH(msg, 5)

/*
 * Two static TfwStr structures are needed due to have the opportunity
 * to set separately one page body, e.g. for 500 answer, and another
 * page body - for the remaining 5xx answers.
 */
static TfwStr http_4xx_resp_body = {
	.chunks = (TfwStr []){
		{ .data = NULL, .len = 0 },
		{ .data = NULL, .len = 0 },
	},
	.len = 0,
};
static TfwStr http_5xx_resp_body = {
	.chunks = (TfwStr []){
		{ .data = NULL, .len = 0 },
		{ .data = NULL, .len = 0 },
	},
	.len = 0,
};

/*
 * Prepare current date in the format required for HTTP "Date:"
 * header field. See RFC 2616 section 3.3.
 */
static void
tfw_http_prep_date_from(char *buf, time_t date)
{
	struct tm tm;
	char *ptr = buf;

	static const char * const wday[] =
		{ "Sun, ", "Mon, ", "Tue, ",
		  "Wed, ", "Thu, ", "Fri, ", "Sat, " };
	static const char * const month[] =
		{ " Jan ", " Feb ", " Mar ", " Apr ", " May ", " Jun ",
		  " Jul ", " Aug ", " Sep ", " Oct ", " Nov ", " Dec " };

	/*
	 * If you see the function in perf top, then replace the naive
	 * printer by https://github.com/jeaiii/itoa.git
	 */
#define PRINT_2DIGIT(p, n)			\
	*p++ = (n <= 9) ? '0' : '0' + n / 10;	\
	*p++ = '0' + n % 10;

	time_to_tm(date, 0, &tm);

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
#undef PRINT_2DIGIT
}

static inline void
tfw_http_prep_date(char *buf)
{
	tfw_http_prep_date_from(buf, tfw_current_timestamp());
}

int
tfw_h2_prep_redirect(TfwHttpResp *resp, unsigned short status, TfwStr *rmark,
		     TfwStr *cookie, TfwStr *body)
{
	int r;
	TfwHPackInt vlen;
	unsigned int stream_id;
	unsigned long hdrs_len, loc_val_len;
	TfwHttpReq *req = resp->req;
	TfwHttpTransIter *mit = &resp->mit;
	TfwMsgIter *iter = &mit->iter;
	struct sk_buff **skb_head = &resp->msg.skb_head;
	static TfwStr h_loc = TFW_STR_STRING(S_LOCATION);
	static TfwStr proto = TFW_STR_STRING(S_HTTPS);
	static TfwStr h_sc = TFW_STR_STRING(S_SET_COOKIE);
	TfwStr host, *host_ptr = &host, s_vlen = {};

	stream_id = tfw_h2_stream_id_close(req, HTTP2_HEADERS,
					   HTTP2_F_END_STREAM);
	if (unlikely(!stream_id))
		return -ENOENT;

	/* Set HTTP/2 ':status' pseudo-header. */
	mit->start_off = FRAME_HEADER_SIZE;
	r = tfw_h2_resp_status_write(resp, status, TFW_H2_TRANS_EXPAND, false);
	if (unlikely(r))
		return r;

	/* Add 'date' header. */
	r = tfw_h2_add_hdr_date(resp, TFW_H2_TRANS_EXPAND, false);
	if (unlikely(r))
		return r;

	/* Add 'location' header (possibly, with redirection mark). */
	h_loc.hpack_idx = 46;
	r = tfw_hpack_encode(resp, &h_loc, TFW_H2_TRANS_EXPAND, false);
	if (unlikely(r))
		return r;

	if (req->host.len)
		host_ptr = &req->host;
	else
		__h2_msg_hdr_val(&req->h_tbl->tbl[TFW_HTTP_HDR_HOST], &host);

	loc_val_len = req->uri_path.len;
	loc_val_len += host_ptr->len ? host_ptr->len + proto.len : 0;
	loc_val_len += rmark->len;

	write_int(loc_val_len, 0x7F, 0, &vlen);
	s_vlen.data = vlen.buf;
	s_vlen.len = vlen.sz;

	r = tfw_http_msg_expand_data(iter, skb_head, &s_vlen, NULL);
	if (unlikely(r))
		return r;

	if (host_ptr->len) {
		r = tfw_http_msg_expand_data(iter, skb_head, &proto, NULL);
		if (unlikely(r))
			return r;

		r = tfw_http_msg_expand_data(iter, skb_head, host_ptr, NULL);
		if (unlikely(r))
			return r;
	}

	if (rmark->len) {
		r = tfw_http_msg_expand_data(iter, skb_head, rmark, NULL);
		if (unlikely(r))
			return r;
	}

	r = tfw_http_msg_expand_data(iter, skb_head, &req->uri_path, NULL);
	if (unlikely(r))
		return r;

	hdrs_len = s_vlen.len + loc_val_len;

	/* Add 'set-cookie' header. */
	h_sc.hpack_idx = 55;
	r = tfw_hpack_encode(resp, &h_sc, TFW_H2_TRANS_EXPAND, false);
	if (unlikely(r))
		return r;

	write_int(cookie->len, 0x7F, 0, &vlen);
	s_vlen.data = vlen.buf;
	s_vlen.len = vlen.sz;

	r = tfw_http_msg_expand_data(iter, skb_head, &s_vlen, NULL);
	if (unlikely(r))
		return r;

	r = tfw_http_msg_expand_data(iter, skb_head, cookie, NULL);
	if (unlikely(r))
		return r;

	hdrs_len += s_vlen.len + cookie->len;
	hdrs_len += mit->acc_len;

	return tfw_h2_frame_local_resp(resp, stream_id, hdrs_len, body);
}

#define S_REDIR_302	S_302 S_CRLF
#define S_REDIR_503	S_503 S_CRLF
#define S_REDIR_GEN	" Redirection" S_CRLF
#define S_REDIR_P_01	S_F_DATE
#define S_REDIR_P_02	S_CRLF S_F_LOCATION
#define S_REDIR_P_03	S_CRLF S_F_SET_COOKIE
#define S_REDIR_KEEP	S_CRLF S_F_CONNECTION S_V_CONN_KA S_CRLF
#define S_REDIR_CLOSE	S_CRLF S_F_CONNECTION S_V_CONN_CLOSE S_CRLF

/**
 * The response redirects the client to the same URI as the original request,
 * but it includes 'Set-Cookie:' header field that sets Tempesta sticky cookie.
 * If JS challenge is enabled, then body contained JS challenge is provided.
 * Body string contains the 'Content-Length' header, CRLF and body itself.
 */
int
tfw_h1_prep_redirect(TfwHttpResp *resp, unsigned short status, TfwStr *rmark,
		     TfwStr *cookie, TfwStr *body)
{
	TfwHttpReq *req = resp->req;
	size_t data_len;
	int ret = 0;
	TfwMsgIter it;
	static TfwStr rh_302 = {
		.data = S_REDIR_302, .len = SLEN(S_REDIR_302) };
	static TfwStr rh_503 = {
		.data = S_REDIR_503, .len = SLEN(S_REDIR_503) };
	TfwStr rh_gen = {
		.chunks = (TfwStr []){
			{ .data = S_0, .len = SLEN(S_0) },
			{ .data = (*this_cpu_ptr(&g_buf) + RESP_BUF_LEN / 2),
			  .len = 3 },
			{ .data = S_REDIR_GEN, .len = SLEN(S_REDIR_GEN) }
		},
		.len = SLEN(S_0 S_REDIR_GEN) + 3,
		.nchunks = 3
	};
	TfwStr h_common_1 = {
		.chunks = (TfwStr []){
			{ .data = S_REDIR_P_01, .len = SLEN(S_REDIR_P_01) },
			{ .data = *this_cpu_ptr(&g_buf), .len = SLEN(S_V_DATE) },
			{ .data = S_REDIR_P_02, .len = SLEN(S_REDIR_P_02) }
		},
		.len = SLEN(S_REDIR_P_01 S_V_DATE S_REDIR_P_02),
		.nchunks = 3
	};
	static TfwStr h_common_2 = {
		.data = S_REDIR_P_03, .len = SLEN(S_REDIR_P_03) };
	static TfwStr crlf = {
		.data = S_CRLF, .len = SLEN(S_CRLF) };
	static TfwStr crlf_keep = {
		.data = S_REDIR_KEEP, .len = SLEN(S_REDIR_KEEP) };
	static TfwStr crlf_close = {
		.data = S_REDIR_CLOSE, .len = SLEN(S_REDIR_CLOSE) };
	TfwStr c_len_crlf = {
		.chunks = (TfwStr []){
			{ .data = S_F_CONTENT_LENGTH,
			  .len = SLEN(S_F_CONTENT_LENGTH) },
			{ .data = (*this_cpu_ptr(&g_buf) + RESP_BUF_LEN / 2 + 3),
			  .len = 0 },
			{ .data = S_CRLFCRLF, .len = SLEN(S_CRLFCRLF) }
		},
		.len = SLEN(S_F_CONTENT_LENGTH S_CRLFCRLF),
		.nchunks = 3
	};
	static TfwStr protos[] = {
		{ .data = S_HTTP, .len = SLEN(S_HTTP) },
		{ .data = S_HTTPS, .len = SLEN(S_HTTPS) },
	};
	TfwStr *proto = &protos[TFW_CONN_PROTO(req->conn) == TFW_FSM_HTTPS];
	TfwStr host, *rh, *cookie_crlf = &crlf;

	if (status == 302) {
		rh = &rh_302;
	} else if (status == 503) {
		rh = &rh_503;
	} else {
		tfw_ultoa(status, __TFW_STR_CH(&rh_gen, 1)->data, 3);
		rh = &rh_gen;
	}
	__TFW_STR_CH(&c_len_crlf, 1)->len += tfw_ultoa(
		body ? body->len : 0, __TFW_STR_CH(&c_len_crlf, 1)->data,
		RESP_BUF_LEN / 2 - 3);
	c_len_crlf.len += __TFW_STR_CH(&c_len_crlf, 1)->len;

	if (req->host.len)
		host = req->host;
	else
		tfw_http_msg_clnthdr_val(req,
					 &req->h_tbl->tbl[TFW_HTTP_HDR_HOST],
					 TFW_HTTP_HDR_HOST, &host);

	/* Set "Connection:" header field if needed. */
	if (test_bit(TFW_HTTP_B_CONN_CLOSE, req->flags))
		cookie_crlf = &crlf_close;
	else if (test_bit(TFW_HTTP_B_CONN_KA, req->flags))
		cookie_crlf = &crlf_keep;

	/* Add variable part of data length to get the total */
	data_len = rh->len + h_common_1.len;
	data_len += host.len ? host.len + proto->len : 0;
	data_len += rmark->len;
	data_len += req->uri_path.len + h_common_2.len + cookie->len;
	data_len += cookie_crlf->len + c_len_crlf.len;
	data_len += body ? body->len : 0;

	if (tfw_http_msg_setup((TfwHttpMsg *)resp, &it, data_len, 0))
		return TFW_BLOCK;

	tfw_http_prep_date(__TFW_STR_CH(&h_common_1, 1)->data);

	ret = tfw_msg_write(&it, rh);
	ret |= tfw_msg_write(&it, &h_common_1);
	/*
	 * HTTP/1.0 may have no host part, so we create relative URI.
	 * See RFC 1945 9.3 and RFC 7231 7.1.2.
	 */
	if (host.len) {
		ret |= tfw_msg_write(&it, proto);
		ret |= tfw_msg_write(&it, &host);
	}

	if (rmark->len)
		ret |= tfw_msg_write(&it, rmark);

	ret |= tfw_msg_write(&it, &req->uri_path);
	ret |= tfw_msg_write(&it, &h_common_2);
	ret |= tfw_msg_write(&it, cookie);
	ret |= tfw_msg_write(&it, cookie_crlf);
	ret |= tfw_msg_write(&it, &c_len_crlf);
	if (body)
		ret |= tfw_msg_write(&it, body);

	return ret;
}

#define S_304_PART_01	S_304 S_CRLF
#define S_304_KEEP	S_F_CONNECTION S_V_CONN_KA S_CRLF
#define S_304_CLOSE	S_F_CONNECTION S_V_CONN_CLOSE S_CRLF

/*
 * Preparing 304 response (Not Modified) for HTTP/1.1-client.
 */
int
tfw_http_prep_304(TfwHttpReq *req, struct sk_buff **skb_head, TfwMsgIter *it)
{
	int ret = 0;
	static TfwStr rh = {
		.data = S_304_PART_01, .len = SLEN(S_304_PART_01) };
	static TfwStr crlf_keep = {
		.data = S_304_KEEP, .len = SLEN(S_304_KEEP) };
	static TfwStr crlf_close = {
		.data = S_304_CLOSE, .len = SLEN(S_304_CLOSE) };
	TfwStr *end = NULL;

	/* Set "Connection:" header field if needed. */
	if (test_bit(TFW_HTTP_B_CONN_CLOSE, req->flags))
		end = &crlf_close;
	else if (test_bit(TFW_HTTP_B_CONN_KA, req->flags))
		end = &crlf_keep;

	ret = tfw_http_msg_expand_data(it, skb_head, &rh, NULL);
	if (unlikely(ret))
		return ret;

	if (end) {
		ret = tfw_http_msg_expand_data(it, skb_head, end, NULL);
		if (unlikely(ret))
			return ret;
	}

	T_DBG("Send HTTP 304 response\n");

	return 0;
}

/*
 * Free an HTTP message.
 * Also, free the connection instance if there's no more references.
 *
 * This function should be used anytime when there's a chance that
 * a connection instance may belong to multiple messages, which is
 * almost always. If a connection is suddenly closed then it still
 * can be safely dereferenced and used in the code.
 * In rare cases we're sure that a connection instance in a message
 * doesn't have multiple users. For example, when an error response
 * is prepared and sent by Tempesta, that HTTP message does not need
 * a connection instance. The message is then immediately destroyed,
 * and a simpler tfw_http_msg_free() can be used for that.
 *
 * NOTE: @hm->conn may be NULL if @hm is the response that was served
 * from cache.
 */
void
tfw_http_conn_msg_free(TfwHttpMsg *hm)
{
	if (unlikely(!hm))
		return;

	if (hm->conn) {
		/*
		 * Check that the paired response has been destroyed before
		 * the request.
		 */
		WARN_ON_ONCE((TFW_CONN_TYPE(hm->conn) & Conn_Clnt) && hm->pair);

		/*
		 * Unlink the connection while there is at least one
		 * reference. Use atomic exchange to avoid races with
		 * new messages arriving on the connection.
		 *
		 * NOTE: currently this unlink operation is not needed
		 * for HTTP/2 mode; it is left here as is since it does
		 * nothing in HTTP/2 mode, because default general stream
		 * @conn->stream is not used and @conn->stream.msg must
		 * be always NULL during HTTP/2 processing.
		 */
		__cmpxchg((unsigned long *)&hm->conn->stream.msg,
			  (unsigned long)hm, 0UL, sizeof(long));
		tfw_connection_put(hm->conn);
	}

	tfw_http_msg_free(hm);
}

/*
 * Free request after removing it from seq_queue (or after closing the
 * corresponding stream - in case of HTTP/2 processing). This function
 * is needed in cases when response is not sent to client for some reasons.
 */
static inline void
tfw_http_conn_req_clean(TfwHttpReq *req)
{
	if (TFW_MSG_H2(req)) {
		tfw_h2_stream_id_close(req, _HTTP2_UNDEFINED, 0);
	} else {
		spin_lock_bh(&((TfwCliConn *)req->conn)->seq_qlock);
		if (likely(!list_empty(&req->msg.seq_list)))
			list_del_init(&req->msg.seq_list);
		spin_unlock_bh(&((TfwCliConn *)req->conn)->seq_qlock);
	}
	tfw_http_conn_msg_free((TfwHttpMsg *)req);
}

/*
 * Free the request and the paired response.
 */
static inline void
tfw_http_resp_pair_free(TfwHttpReq *req)
{
	tfw_http_conn_msg_free(req->pair);
	tfw_http_conn_msg_free((TfwHttpMsg *)req);
}

/*
 * Close the client connection and free unpaired request. This function
 * is needed for cases when we cannot prepare response for this request.
 * As soon as request is not linked with any response, sending to that
 * client stops starting with that request, because that creates
 * a "hole" in the chain of requests -- a request without a response.
 * Subsequent responses cannot be sent to the client until that
 * hole is closed, which at this point will never happen. To solve
 * this situation there is no choice but to close client connection.
 *
 * Note: As a consequence of closing a client connection on error of
 * preparing a response, it's possible that some already prepared
 * responses will not be sent to the client. That depends on the
 * order in which CPUs close the connection and call tfw_http_resp_fwd().
 * This is the intended behaviour. The goal is to free some memory
 * at the cost of dropping a few clients, so that Tempesta can
 * continue working.
 */
void
tfw_http_resp_build_error(TfwHttpReq *req)
{
	tfw_connection_close(req->conn, true);
	tfw_http_conn_req_clean(req);
	TFW_INC_STAT_BH(clnt.msgs_otherr);
}

static inline resp_code_t
tfw_http_enum_resp_code(int status)
{
	switch(status) {
	case 200:
		return RESP_200;
	case 400:
		return RESP_400;
	case 403:
		return RESP_403;
	case 404:
		return RESP_404;
	case 412:
		return RESP_412;
	case 500:
		return RESP_500;
	case 502:
		return RESP_502;
	case 503:
		return RESP_503;
	case 504:
		return RESP_504;
	default:
		return RESP_NUM;
	}
}

/**
 * Write HTTP/2 ':status' pseudo-header. The ':status' is only defined
 * pseudo-header for the response and all HTTP/2 responses must contain it.
 * https://httpwg.org/specs/rfc7540.html#rfc.section.8.1.2.4.
 */
int
tfw_h2_resp_status_write(TfwHttpResp *resp, unsigned short status,
			 TfwH2TransOp op, bool cache)
{
	int ret;
	unsigned short index = tfw_h2_pseudo_index(status);
	char buf[H2_STAT_VAL_LEN];
	TfwStr s_hdr = {
		.chunks = (TfwStr []){
			{ .data = S_H2_STAT,	.len = SLEN(S_H2_STAT) },
			{ .data = buf,		.len = H2_STAT_VAL_LEN }
		},
		.len = SLEN(S_H2_STAT) + H2_STAT_VAL_LEN,
		.nchunks = 2,
		.hpack_idx = index ? index : 8
	};

	WARN_ON_ONCE(op != TFW_H2_TRANS_EXPAND && op != TFW_H2_TRANS_SUB);

	/*
	 * If the status code is not in the static table, set the default
	 * static index just for the ':status' name.
	 */
	if (index) {
		s_hdr.flags |= TFW_STR_FULL_INDEX;
	}

	if (!tfw_ultoa(status, __TFW_STR_CH(&s_hdr, 1)->data, H2_STAT_VAL_LEN))
		return -E2BIG;

	if ((ret = tfw_hpack_encode(resp, &s_hdr, op, !cache)))
		return ret;

	return 0;
}

void
tfw_h2_resp_fwd(TfwHttpResp *resp)
{
	TfwHttpReq *req = resp->req;
	TfwH2Ctx *ctx = tfw_h2_context(req->conn);

	tfw_connection_get(req->conn);

	if (tfw_cli_conn_send((TfwCliConn *)req->conn, (TfwMsg *)resp)) {
		T_DBG("%s: cannot send data to client via HTTP/2\n", __func__);
		TFW_INC_STAT_BH(serv.msgs_otherr);
		tfw_connection_close(req->conn, true);
	}
	else {
		TFW_INC_STAT_BH(serv.msgs_forwarded);
	}

	tfw_connection_put(req->conn);

	tfw_hpack_enc_release(&ctx->hpack, resp->flags);

	tfw_http_resp_pair_free(req);
}

static void
tfw_h2_send_resp(TfwHttpReq *req, int status, unsigned int stream_id)
{
	TfwStr *msg;
	resp_code_t code;
	TfwHttpResp *resp;
	struct sk_buff **skb_head;
	TfwHttpTransIter *mit;
	char *date_val, *data_ptr;
	unsigned long nlen, vlen;
	TfwStr *start, *date, *clen, *srv, *body;
	TfwH2Ctx *ctx = tfw_h2_context(req->conn);
	TfwStr hdr = {
		.chunks = (TfwStr []){ {}, {} },
		.nchunks = 2
	};

	if (!stream_id) {
		stream_id = tfw_h2_stream_id_close(req, HTTP2_HEADERS,
						   HTTP2_F_END_STREAM);
		if (unlikely(!stream_id)) {
			tfw_http_conn_msg_free((TfwHttpMsg *)req);
			return;
		}
	}

	code = tfw_http_enum_resp_code(status);
	if (code == RESP_NUM) {
		T_WARN("Unexpected response error code: [%d]\n", status);
		code = RESP_500;
	}
	msg = &http_predef_resps[code];

	resp = tfw_http_msg_alloc_resp_light(req);
	if (unlikely(!resp))
		goto err;

	mit = &resp->mit;
	skb_head = &resp->msg.skb_head;
	body = TFW_STR_BODY_CH(msg);

	/* Set HTTP/2 ':status' pseudo-header. */
	mit->start_off = FRAME_HEADER_SIZE;
	if (tfw_h2_resp_status_write(resp, status, TFW_H2_TRANS_EXPAND, false))
		goto err_setup;

	/*
	 * Form and write HTTP/2 response headers excluding "\r\n", ':'
	 * separators and OWS.
	 */
	start = TFW_STR_START_CH(msg);
	date = TFW_STR_DATE_CH(msg);
	__TFW_STR_CH(&hdr, 0)->data = start->data + start->len - SLEN(S_F_DATE);
	__TFW_STR_CH(&hdr, 0)->len = nlen = SLEN(S_F_DATE) - 2;
	date_val = *this_cpu_ptr(&g_buf);
	tfw_http_prep_date(date_val);
	__TFW_STR_CH(&hdr, 1)->data = date_val;
	__TFW_STR_CH(&hdr, 1)->len = vlen = date->len;
	hdr.len = nlen + vlen;
	hdr.hpack_idx = 33;
	if (tfw_hpack_encode(resp, &hdr, TFW_H2_TRANS_EXPAND, true))
		goto err_setup;

	clen = TFW_STR_CLEN_CH(msg);
	__TFW_STR_CH(&hdr, 0)->data = data_ptr = clen->data + SLEN(S_CRLF);
	__TFW_STR_CH(&hdr, 0)->len = nlen = SLEN(S_F_CONTENT_LENGTH) - 2;
	__TFW_STR_CH(&hdr, 1)->data = data_ptr = data_ptr + nlen + 2;
	__TFW_STR_CH(&hdr, 1)->len = vlen = clen->data + clen->len
		- data_ptr - SLEN(S_CRLF);
	hdr.len = nlen + vlen;
	hdr.hpack_idx = 28;
	if (tfw_hpack_encode(resp, &hdr, TFW_H2_TRANS_EXPAND, true))
		goto err_setup;

	srv = TFW_STR_SRV_CH(msg);
	__TFW_STR_CH(&hdr, 0)->data = data_ptr = srv->data;
	__TFW_STR_CH(&hdr, 0)->len = nlen = SLEN(S_F_SERVER) - 2;
	__TFW_STR_CH(&hdr, 1)->data = data_ptr = data_ptr + nlen + 2;
	__TFW_STR_CH(&hdr, 1)->len = vlen = srv->data + srv->len
		- data_ptr - SLEN(S_CRLF);
	hdr.len = nlen + vlen;
	hdr.hpack_idx = 54;
	if (tfw_hpack_encode(resp, &hdr, TFW_H2_TRANS_EXPAND, true))
		goto err_setup;

	if (WARN_ON_ONCE(!mit->acc_len))
		goto err_setup;

	if (tfw_h2_frame_local_resp(resp, stream_id, mit->acc_len, body))
		goto err_setup;

	/* Send resulting HTTP/2 response and release HPACK encoder index. */
	tfw_h2_resp_fwd(resp);

	return;

err_setup:
	T_DBG("%s: HTTP/2 response message transformation error: conn=[%p]\n",
	      __func__, req->conn);

	tfw_hpack_enc_release(&ctx->hpack, resp->flags);

	tfw_http_msg_free((TfwHttpMsg *)resp);
err:
	tfw_http_resp_build_error(req);
}

/*
 * Perform operations common to sending an error response to a client.
 * Set current date in the header of an HTTP error response, and set
 * the "Connection:" header field if it was present in the request.
 * If memory allocation error or message setup errors occurred, then
 * client connection should be closed, because response-request
 * pairing for pipelined requests is violated.
 *
 * NOTE: This function expects the predefined order of chunks in @msg:
 * the fourth chunk must be CRLF.
 */
static void
tfw_h1_send_resp(TfwHttpReq *req, int status)
{
	TfwMsgIter it;
	resp_code_t code;
	TfwHttpResp *resp;
	TfwStr *date, *crlf, *body;
	TfwStr msg = {
		.chunks = (TfwStr []){ {}, {}, {}, {}, {}, {} },
		.len = 0,
		.nchunks = 6
	};

	code = tfw_http_enum_resp_code(status);
	if (code == RESP_NUM) {
		T_WARN("Unexpected response error code: [%d]\n", status);
		code = RESP_500;
	}

	if (tfw_strcpy_desc(&msg, &http_predef_resps[code]))
		goto err;

	crlf = TFW_STR_CRLF_CH(&msg);
	if (test_bit(TFW_HTTP_B_CONN_KA, req->flags)
	    || test_bit(TFW_HTTP_B_CONN_CLOSE, req->flags))
	{
		unsigned long crlf_len = crlf->len;
		if (test_bit(TFW_HTTP_B_CONN_CLOSE, req->flags)) {
			crlf->data = S_H_CONN_CLOSE;
			crlf->len = SLEN(S_H_CONN_CLOSE);
		} else {
			crlf->data = S_H_CONN_KA;
			crlf->len = SLEN(S_H_CONN_KA);
		}
		msg.len += crlf->len - crlf_len;
	}

	if (!(resp = tfw_http_msg_alloc_resp_light(req)))
		goto err;
	if (tfw_http_msg_setup((TfwHttpMsg *)resp, &it, msg.len, 0))
		goto err_setup;

	body = TFW_STR_BODY_CH(&msg);
	date = TFW_STR_DATE_CH(&msg);
	date->data = *this_cpu_ptr(&g_buf);
	tfw_http_prep_date(date->data);
	if (!body->data)
		msg.nchunks = 5;

	if (tfw_msg_write(&it, &msg))
		goto err_setup;

	tfw_http_resp_fwd(resp);

	return;
err_setup:
	T_DBG2("%s: Response message allocation error: conn=[%p]\n",
	       __func__, req->conn);
	tfw_http_msg_free((TfwHttpMsg *)resp);
err:
	tfw_http_resp_build_error(req);
}

/*
 * SKB data is needed for calculation of a cache key from fields of
 * a request. It's also needed when a request may need to be re-sent.
 * In all other cases it can just be passed to the network layer.
 *
 * However, at this time requests may always be re-sent in case of
 * a connection failure. There's no option to prohibit re-sending.
 * Thus, request's SKB can't be passed to the network layer until
 * certain changes are implemented. For now there's no choice but
 * make a copy of request's SKBs in SS layer.
 *
 * TODO: Making a copy of each SKB _IS BAD_. See issues #391 and #488.
 */
static inline void
tfw_http_req_init_ss_flags(TfwSrvConn *srv_conn, TfwHttpReq *req)
{
	((TfwMsg *)req)->ss_flags |= SS_F_KEEP_SKB;
}

static inline void
tfw_http_resp_init_ss_flags(TfwHttpResp *resp)
{
	if (test_bit(TFW_HTTP_B_CONN_CLOSE, resp->req->flags))
		resp->msg.ss_flags |= SS_F_CONN_CLOSE;
}

/*
 * Check if a request is non-idempotent.
 */
static inline bool
tfw_http_req_is_nip(TfwHttpReq *req)
{
	return test_bit(TFW_HTTP_B_NON_IDEMP, req->flags);
}

/*
 * Reset the flag saying that @srv_conn has non-idempotent requests.
 */
static inline void
tfw_http_conn_nip_reset(TfwSrvConn *srv_conn)
{
	if (list_empty(&srv_conn->nip_queue))
		clear_bit(TFW_CONN_B_HASNIP, &srv_conn->flags);
}

/*
 * Put @req on the list of non-idempotent requests in @srv_conn.
 * Raise the flag saying that @srv_conn has non-idempotent requests.
 */
static inline void
tfw_http_req_nip_enlist(TfwSrvConn *srv_conn, TfwHttpReq *req)
{
	BUG_ON(!list_empty(&req->nip_list));
	list_add_tail(&req->nip_list, &srv_conn->nip_queue);
	set_bit(TFW_CONN_B_HASNIP, &srv_conn->flags);
}

/*
 * Remove @req from the list of non-idempotent requests in @srv_conn.
 * If it is the last request on the list, then clear the flag saying
 * that @srv_conn has non-idempotent requests.
 *
 * Does nothing if @req is NOT on the list.
 */
static inline void
tfw_http_req_nip_delist(TfwSrvConn *srv_conn, TfwHttpReq *req)
{
	if (!list_empty(&req->nip_list)) {
		list_del_init(&req->nip_list);
		tfw_http_conn_nip_reset(srv_conn);
	}
}

/*
 * Remove idempotent requests from the list of non-idempotent requests
 * in @srv_conn. A non-idempotent request may become idempotent when
 * another request is received from a client before a response to the
 * non-idempotent request is forwarded to the client. See the comment
 * to tfw_http_req_add_seq_queue().
 */
static inline void
tfw_http_conn_nip_adjust(TfwSrvConn *srv_conn)
{
	TfwHttpReq *req, *tmp;

	list_for_each_entry_safe(req, tmp, &srv_conn->nip_queue, nip_list)
		if (!tfw_http_req_is_nip(req)) {
			BUG_ON(list_empty(&req->nip_list));
			list_del_init(&req->nip_list);
		}
	tfw_http_conn_nip_reset(srv_conn);
}

/*
 * Tell if the server connection's forwarding queue is on hold.
 * It's on hold if the request that was sent last was non-idempotent.
 */
static inline bool
tfw_http_conn_on_hold(TfwSrvConn *srv_conn)
{
	TfwHttpReq *req_sent = (TfwHttpReq *)srv_conn->msg_sent;

	BUG_ON(!(TFW_CONN_TYPE(srv_conn) & Conn_Srv));
	return (req_sent && tfw_http_req_is_nip(req_sent));
}

/*
 * Tell if the server connection's forwarding queue is drained.
 * It's drained if there're no requests in the queue after the
 * request that was sent last.
 */
static inline bool
tfw_http_conn_drained(TfwSrvConn *srv_conn)
{
	struct list_head *fwd_queue = &srv_conn->fwd_queue;
	TfwHttpReq *req_sent = (TfwHttpReq *)srv_conn->msg_sent;

	BUG_ON(!(TFW_CONN_TYPE(srv_conn) & Conn_Srv));

	if (list_empty(fwd_queue))
		return true;
	if (!req_sent)
		return false;
	if (list_is_last(&req_sent->fwd_list, fwd_queue))
		return true;
	return false;
}

/*
 * Tell if the server connection's forwarding queue has requests
 * that need to be forwarded.
 */
static inline bool
tfw_http_conn_need_fwd(TfwSrvConn *srv_conn)
{
	return (!tfw_http_conn_on_hold(srv_conn)
		&& !tfw_http_conn_drained(srv_conn));
}

/*
 * Get the request that is previous to @srv_conn->msg_sent.
 */
static inline TfwMsg *
__tfw_http_conn_msg_sent_prev(TfwSrvConn *srv_conn)
{
	TfwHttpReq *req_sent = (TfwHttpReq *)srv_conn->msg_sent;

	/*
	 * There is list_is_last() function in the Linux kernel,
	 * but there is no list_is_first(). The condition below
	 * is an implementation of list_is_first().
	 */
	return (srv_conn->fwd_queue.next == &req_sent->fwd_list) ?
		NULL : (TfwMsg *)list_prev_entry(req_sent, fwd_list);
}

/*
 * Reset server connection's @fwd_queue and move all requests
 * to @dst list.
 */
static inline void
tfw_http_fwdq_reset(TfwSrvConn *srv_conn, struct list_head *dst)
{
	list_splice_tail_init(&srv_conn->fwd_queue, dst);
	srv_conn->qsize = 0;
	srv_conn->msg_sent = NULL;
	INIT_LIST_HEAD(&srv_conn->nip_queue);
	clear_bit(TFW_CONN_B_HASNIP, &srv_conn->flags);
}

/**
 * Add @req to the server connection's forwarding queue.
 */
static inline void
tfw_http_req_enlist(TfwSrvConn *srv_conn, TfwHttpReq *req)
{
	list_add_tail(&req->fwd_list, &srv_conn->fwd_queue);
	srv_conn->qsize++;
	if (tfw_http_req_is_nip(req))
		tfw_http_req_nip_enlist(srv_conn, req);
}

/**
 * Remove @req from the server connection's forwarding queue.
 * Caller must care about @srv_conn->msg_sent on it's own to keep the
 * queue state consistent.
 */
static inline void
tfw_http_req_delist(TfwSrvConn *srv_conn, TfwHttpReq *req)
{
	tfw_http_req_nip_delist(srv_conn, req);
	list_del_init(&req->fwd_list);
	srv_conn->qsize--;
}

/*
 * Common actions in case of an error while forwarding requests.
 * Erroneous requests are removed from the forwarding queue and placed
 * in @eq. The error code and the reason for an error response are
 * saved as well.
 */
static inline void
__tfw_http_req_err(TfwHttpReq *req, struct list_head *eq,
		   unsigned short status, const char *reason)
{
	list_add_tail(&req->fwd_list, eq);
	req->httperr.status = status;
	req->httperr.reason = reason;
}

static inline void
tfw_http_req_err(TfwSrvConn *srv_conn, TfwHttpReq *req,
		 struct list_head *eq, unsigned short status,
		 const char *reason)
{
	if (srv_conn)
		tfw_http_req_delist(srv_conn, req);
	__tfw_http_req_err(req, eq, status, reason);
}

static inline void
tfw_http_nip_req_resched_err(TfwSrvConn *srv_conn, TfwHttpReq *req,
			     struct list_head *eq)
{
	tfw_http_req_err(srv_conn, req, eq, 504,
			 "request dropped: non-idempotent requests aren't"
			  " re-forwarded or re-scheduled");
}

/* Common interface for sending error responses. */
void
tfw_http_send_resp(TfwHttpReq *req, int status, const char *reason)
{
	if (!(tfw_blk_flags & TFW_BLK_ERR_NOLOG)) {
		T_WARN_ADDR_STATUS(reason, &req->conn->peer->addr,
				   TFW_WITH_PORT, status);
	}

	if (TFW_MSG_H2(req))
		tfw_h2_send_resp(req, status, 0);
	else
		tfw_h1_send_resp(req, status);
}

static bool
tfw_http_hm_suspend(TfwHttpResp *resp, TfwServer *srv)
{
	unsigned long old_flags, flags = READ_ONCE(srv->flags);

	if (!(flags & TFW_SRV_F_HMONITOR))
		return true;

	if (!tfw_apm_hm_srv_limit(resp->status, srv->apmref))
		return false;

	do {
		old_flags = cmpxchg(&srv->flags, flags,
				    flags | TFW_SRV_F_SUSPEND);
		if (likely(old_flags == flags)) {
			T_WARN_ADDR_STATUS("server has been suspended: limit "
					   "for bad responses is exceeded",
					   &srv->addr, TFW_WITH_PORT,
					   resp->status);
			break;
		}
		flags = old_flags;
	} while (flags & TFW_SRV_F_HMONITOR);

	return true;
}

static void
tfw_http_hm_control(TfwHttpResp *resp)
{
	TfwServer *srv = (TfwServer *)resp->conn->peer;

	if (tfw_http_hm_suspend(resp, srv))
		return;

	if (!tfw_srv_suspended(srv) ||
	    !tfw_apm_hm_srv_alive(resp->status, &resp->body, srv->apmref))
		return;

	tfw_srv_mark_alive(srv);
}

static inline void
tfw_http_hm_srv_update(TfwServer *srv, TfwHttpReq *req)
{
	if (test_bit(TFW_SRV_B_HMONITOR, &srv->flags))
		tfw_apm_hm_srv_rcount_update(&req->uri_path, srv->apmref);
}

static int
tfw_http_marks_cmp(const void *l, const void *r)
{
	unsigned int m1 = *(unsigned int *)l;
	unsigned int m2 = *(unsigned int *)r;

	return (m1 < m2) ? -1 : (m1 > m2);
}

static inline void
tfw_http_mark_wl_new_msg(TfwConn *conn, TfwHttpMsg *msg,
			 const struct sk_buff *skb)
{
	if (!tfw_wl_marks.mrks || !(TFW_CONN_TYPE(conn) & Conn_Clnt))
		return;

	if (bsearch(&skb->mark, tfw_wl_marks.mrks, tfw_wl_marks.sz,
		    sizeof(tfw_wl_marks.mrks[0]), tfw_http_marks_cmp))
	{
		__set_bit(TFW_HTTP_B_WHITELIST, msg->flags);
	}
}


/*
 * Forwarding of requests to a back end server is run under a lock
 * on the server connection's forwarding queue. It's performed as
 * fast as possible by moving failed requests to the error queue
 * that can be processed without the lock.
 *
 * Process requests that were not forwarded due to an error. Send
 * an error response to a client. The response will be attached to
 * the request and then sent to the client in proper seq order.
 */
static void
tfw_http_req_zap_error(struct list_head *eq)
{
	TfwHttpReq *req, *tmp;

	T_DBG2("%s: queue is %sempty\n",
	       __func__, list_empty(eq) ? "" : "NOT ");
	if (list_empty(eq))
		return;

	list_for_each_entry_safe(req, tmp, eq, fwd_list) {
		list_del_init(&req->fwd_list);
		if ((TFW_MSG_H2(req) && req->stream)
		    || (!TFW_MSG_H2(req)
			&& !test_bit(TFW_HTTP_B_REQ_DROP, req->flags)))
		{
			tfw_http_send_resp(req, req->httperr.status,
					   req->httperr.reason);
		}
		else
			tfw_http_conn_msg_free((TfwHttpMsg *)req);

		TFW_INC_STAT_BH(clnt.msgs_otherr);
	}
}

/*
 * If @req is dropped since the client was disconnected for some reason,
 * just free the request w/o connection putting.
 */
static inline bool
tfw_http_req_evict_dropped(TfwSrvConn *srv_conn, TfwHttpReq *req)
{
	/*
	 * The special case are the health monitor requests, which have
	 * not corresponding client connection and, consequently, cannot
	 * be dropped.
	 */
	if (!req->conn)
		return false;

	if (TFW_MSG_H2(req)) {
		if (req->stream)
			return false;
		T_DBG2("%s: Eviction: req=[%p] corresponding stream has been"
		       " dropped\n", __func__, req);
	} else {
		if (likely(!test_bit(TFW_HTTP_B_REQ_DROP, req->flags)))
			return false;
		T_DBG2("%s: Eviction: req=[%p] client disconnected\n", __func__,
		       req);
	}

	if (srv_conn)
		tfw_http_req_delist(srv_conn, req);

	tfw_http_conn_msg_free((TfwHttpMsg *)req);
	TFW_INC_STAT_BH(clnt.msgs_otherr);

	return true;
}

/*
 * If @req has timed out (has not been forwarded for too long), then
 * move it to the error queue @eq for sending an error response later.
 */
static inline bool
tfw_http_req_evict_timeout(TfwSrvConn *srv_conn, TfwServer *srv,
			   TfwHttpReq *req, struct list_head *eq)
{
	unsigned long jqage = jiffies - req->jrxtstamp;

	if (unlikely(time_after(jqage, srv->sg->max_jqage))) {
		T_DBG2("%s: Eviction: req=[%p] overdue=[%dms]\n",
		       __func__, req,
			 jiffies_to_msecs(jqage - srv->sg->max_jqage));
		tfw_http_req_err(srv_conn, req, eq, 504,
				 "request evicted: timed out");
		return true;
	}
	return false;
}

/*
 * If the number of re-forwarding attempts for @req is exceeded, then
 * move it to the error queue @eq for sending an error response later.
 */
static inline bool
tfw_http_req_evict_retries(TfwSrvConn *srv_conn, TfwServer *srv,
			   TfwHttpReq *req, struct list_head *eq)
{
	if (unlikely(req->retries++ >= srv->sg->max_refwd)) {
		T_DBG2("%s: Eviction: req=[%p] retries=[%d]\n",
		       __func__, req, req->retries);
		tfw_http_req_err(srv_conn, req, eq, 504,
				 "request evicted: the number"
				 " of retries exceeded");
		return true;
	}
	return false;
}

static inline bool
tfw_http_req_evict_stale_req(TfwSrvConn *srv_conn, TfwServer *srv,
			     TfwHttpReq *req, struct list_head *eq)
{
	return tfw_http_req_evict_dropped(srv_conn, req)
	       || tfw_http_req_evict_timeout(srv_conn, srv, req, eq);
}

static inline bool
tfw_http_req_evict(TfwSrvConn *srv_conn, TfwServer *srv, TfwHttpReq *req,
		   struct list_head *eq)
{
	return tfw_http_req_evict_dropped(srv_conn, req)
	       || tfw_http_req_evict_timeout(srv_conn, srv, req, eq)
	       || tfw_http_req_evict_retries(srv_conn, srv, req, eq);
}

/*
 * If forwarding of @req in @srv_conn is not successful, then move
 * it to the error queue @eq for sending an error response later.
 * If -EBADF or -EBUSY error occurred, then request should be left
 * in @fwd_queue to send it to backend later (or reschedule it to
 * other connection).
 */
static inline int
tfw_http_req_fwd_send(TfwSrvConn *srv_conn, TfwServer *srv, TfwHttpReq *req,
		      struct list_head *eq)
{
	int r;

	req->jtxtstamp = jiffies;
	tfw_http_req_init_ss_flags(srv_conn, req);

	if (!(r = tfw_connection_send((TfwConn *)srv_conn, (TfwMsg *)req)))
		return 0;

	T_DBG2("%s: Forwarding error: conn=[%p] req=[%p] error=[%d]\n",
	       __func__, srv_conn, req, r);

	if (r == -EBADF || r == -EBUSY)
		return r;

	if (test_bit(TFW_HTTP_B_HMONITOR, req->flags)) {
		tfw_http_req_delist(srv_conn, req);
		WARN_ON_ONCE(req->pair);
		tfw_http_msg_free((TfwHttpMsg *)req);
		T_WARN_ADDR("Unable to send health monitoring request to server",
			    &srv_conn->peer->addr, TFW_WITH_PORT);
	} else {
		tfw_http_req_err(srv_conn, req, eq, 500,
				 "request dropped: forwarding error");
	}

	return r;
}

/*
 * Forward one request @req to server connection @srv_conn. Return 0 if
 * request has been sent successfully, or error code otherwise.
 */
static inline int
tfw_http_req_fwd_single(TfwSrvConn *srv_conn, TfwServer *srv,
			TfwHttpReq *req, struct list_head *eq)
{
	int r;

	if (tfw_http_req_evict_stale_req(srv_conn, srv, req, eq))
		return -EINVAL;
	if ((r = tfw_http_req_fwd_send(srv_conn, srv, req, eq)))
		return r;
	srv_conn->msg_sent = (TfwMsg *)req;
	TFW_INC_STAT_BH(clnt.msgs_forwarded);
	return 0;
}

/*
 * Forward unsent requests in server connection @srv_conn. The requests
 * are forwarded until a non-idempotent request is found in the queue.
 * It's assumed that the forwarding queue in @srv_conn is locked and
 * NOT drained. Returns 0 if forwarding has been finished or error code
 * otherwise (e.g. the case of hanged connection with busy work queue).
 */
static int
tfw_http_conn_fwd_unsent(TfwSrvConn *srv_conn, struct list_head *eq)
{
	TfwHttpReq *req, *tmp;
	TfwServer *srv = (TfwServer *)srv_conn->peer;
	struct list_head *fwd_queue = &srv_conn->fwd_queue;

	T_DBG2("%s: conn=%pK\n", __func__, srv_conn);
	WARN_ON(!spin_is_locked(&srv_conn->fwd_qlock));
	BUG_ON(tfw_http_conn_drained(srv_conn));

	req = srv_conn->msg_sent
	    ? list_next_entry((TfwHttpReq *)srv_conn->msg_sent, fwd_list)
	    : list_first_entry(fwd_queue, TfwHttpReq, fwd_list);

	list_for_each_entry_safe_from(req, tmp, fwd_queue, fwd_list) {
		int ret = tfw_http_req_fwd_single(srv_conn, srv, req, eq);
		/*
		 * In case of busy work queue and absence of forwarded but
		 * unanswered request(s) in connection, the forwarding procedure
		 * is considered failed and the error is returned to the caller.
		 */
		if (ret == -EBUSY && srv_conn->msg_sent == NULL)
			return ret;
		/*
		 * If connection is broken or work queue is busy and connection
		 * has request(s) forwarded but unanswered, we can leave all
		 * requests in @fwd_queue: another attempt to send them will
		 * be made when connection will be repaired or when response(s)
		 * for unanswered request(s) will arrive from backend.
		 */
		if (ret == -EBADF || ret == -EBUSY)
			break;
		/*
		 * Connection is alive, but request has been removed from
		 * @fwd_queue due to some error.
		 */
		if (ret)
			continue;
		/* Stop forwarding if the request is non-idempotent. */
		if (tfw_http_req_is_nip(req))
			break;
		/* See if the idempotent request was non-idempotent. */
		tfw_http_req_nip_delist(srv_conn, req);
	}

	return 0;
}

/*
 * Forward the request @req to server connection @srv_conn.
 *
 * The request is added to the server connection's forwarding queue.
 * If forwarding is on hold at the moment, then the request will be
 * forwarded later. Otherwise, forward the request to the server now.
 *
 * Forwarding to a server is considered to be on hold after
 * a non-idempotent request is forwarded. The hold is removed when
 * a response is received to the holding request. The hold is also
 * removed when the holding non-idempotent request is followed by
 * another request from the same client. Effectively, that re-enables
 * pipelining. See RFC 7230 6.3.2.
 *
 * Requests must be forwarded in the same order they are put in the
 * queue, and so it must be done under the queue lock, otherwise
 * pairing of requests with responses may get broken. Take a simple
 * scenario. CPU-1 locks the queue, adds a request to it, unlocks
 * the queue. CPU-2 does the same after CPU-1 (the queue was locked).
 * After that CPU-1 and CPU-2 are fully concurrent. If CPU-2 happens
 * to proceed first with forwarding, then pairing gets broken.
 *
 * TODO: In current design @fwd_queue is locked until after a request
 * is submitted to SS for sending. It shouldn't be necessary to lock
 * @fwd_queue for that. There's the ordered @fwd_queue. Also there's
 * the ordered work queue in SS layer. Perhaps the right way of ordering
 * these actions is to use message tickets according to the ordering of
 * requests in @fwd_queue. Typically tfw_connection_send() or its pure
 * server variant must care about ticket ordering. Backoff and per-cpu
 * lock data structures could be used just like in Linux MCS locking.
 * Please see the issue #687.
 */
static int
tfw_http_req_fwd(TfwSrvConn *srv_conn, TfwHttpReq *req, struct list_head *eq,
		 bool resched)
{
	int ret = 0;

	T_DBG2("%s: srv_conn=%pK req=%pK\n", __func__, srv_conn, req);
	BUG_ON(!(TFW_CONN_TYPE(srv_conn) & Conn_Srv));

	spin_lock_bh(&srv_conn->fwd_qlock);
	tfw_http_req_enlist(srv_conn, req);
	/*
	 * If we are rescheduling request and connection is on hold or
	 * forwarding procedure is failed (the case of busy hanged
	 * connection) -  evict request from the current @fwd_queue
	 * to try reschedule it via another connection.
	 */
	if ((tfw_http_conn_on_hold(srv_conn)
	     || tfw_http_conn_fwd_unsent(srv_conn, eq))
	    && resched)
	{
		tfw_http_req_delist(srv_conn, req);
		ret = -1;
	}
	spin_unlock_bh(&srv_conn->fwd_qlock);

	return ret;
}

/*
 * Treat a possible non-idempotent request in case of a connection
 * repair (re-send or re-schedule).
 *
 * A non-idempotent request that was forwarded but not responded to
 * is not re-sent or re-scheduled by default. Configuration option
 * can be used to have that request re-sent or re-scheduled.
 *
 * As forwarding is paused after a non-idempotent request is sent,
 * there can be only one such request among forwarded requests, and
 * that's @srv_conn->msg_sent.
 *
 * Note: @srv_conn->msg_sent may change in result.
 */
static inline void
tfw_http_conn_treatnip(TfwSrvConn *srv_conn, struct list_head *eq)
{
	TfwServer *srv = (TfwServer *)srv_conn->peer;
	TfwHttpReq *req_sent = (TfwHttpReq *)srv_conn->msg_sent;

	if (tfw_http_conn_on_hold(srv_conn)
	    && !(srv->sg->flags & TFW_SRV_RETRY_NIP))
	{
		BUG_ON(list_empty(&req_sent->nip_list));
		srv_conn->msg_sent = __tfw_http_conn_msg_sent_prev(srv_conn);
		tfw_http_nip_req_resched_err(srv_conn, req_sent, eq);
	}
}

/*
 * Re-forward requests in a server connection. Requests that exceed
 * the set limits are evicted.
 *
 * Note: @srv_conn->msg_sent may change in result.
 */
static int
tfw_http_conn_resend(TfwSrvConn *srv_conn, bool first, struct list_head *eq)
{
	TfwHttpReq *req, *tmp, *req_resent = NULL;
	TfwServer *srv = (TfwServer *)srv_conn->peer;
	struct list_head *end, *fwd_queue = &srv_conn->fwd_queue;

	if (!srv_conn->msg_sent)
		return 0;

	T_DBG2("%s: conn=[%p] first=[%s]\n",
	       __func__, srv_conn, first ? "true" : "false");
	BUG_ON(!srv_conn->msg_sent);
	BUG_ON(list_empty(&((TfwHttpReq *)srv_conn->msg_sent)->fwd_list));

	req = list_first_entry(fwd_queue, TfwHttpReq, fwd_list);
	end = ((TfwHttpReq *)srv_conn->msg_sent)->fwd_list.next;

	/* Similar to list_for_each_entry_safe_from() */
	for (tmp = list_next_entry(req, fwd_list);
	     &req->fwd_list != end;
	     req = tmp, tmp = list_next_entry(tmp, fwd_list))
	{
		int err;
		if (tfw_http_req_evict(srv_conn, srv, req, eq))
			continue;
		err = tfw_http_req_fwd_send(srv_conn, srv, req, eq);
		/*
		 * If connection is broken, leave all requests in
		 * @fwd_queue in order to re-send them during next
		 * repairing attempt.
		 */
		if (err == -EBADF)
			return err;
		/*
		 * If work queue is busy during re-sending, shift
		 * @msg_sent back to last sent request; remaining
		 * requests will be processed in the following
		 * @tfw_http_conn_fwd_unsent call.
		 */
		if (err == -EBUSY) {
			srv_conn->msg_sent = (TfwMsg *)req_resent;
			return err;
		}
		/*
		 * Request has been removed from @fwd_queue due to some
		 * other error. Connection is alive, so we continue
		 * requests re-sending.
		 */
		if (err)
			continue;
		req_resent = req;
		if (unlikely(first))
			break;
	}
	/*
	 * If only one first request is needed to be re-send, change
	 * @srv_conn->msg_sent only if it must be set to NULL. That
	 * means that all requests for re-sending - had not been
	 * re-sent, but instead have been evicted or removed due to
	 * some error, and we have no requests to re-send any more.
	 */
	if (!first || !req_resent)
		srv_conn->msg_sent = (TfwMsg *)req_resent;

	return 0;
}

/*
 * Remove restrictions from a server connection.
 */
static inline void
__tfw_srv_conn_clear_restricted(TfwSrvConn *srv_conn)
{
	clear_bit(TFW_CONN_B_QFORWD, &srv_conn->flags);
	if (test_and_clear_bit(TFW_CONN_B_RESEND, &srv_conn->flags))
		TFW_DEC_STAT_BH(serv.conn_restricted);
}

/*
 * Make the connection full-functioning again if done with repair.
 */
static inline bool
tfw_srv_conn_reenable_if_done(TfwSrvConn *srv_conn)
{
	if (!list_empty(&srv_conn->fwd_queue))
		return false;
	BUG_ON(srv_conn->qsize);
	BUG_ON(srv_conn->msg_sent);
	__tfw_srv_conn_clear_restricted(srv_conn);
	return true;
}

/*
 * Handle the complete re-forwarding of requests in a server connection
 * that is being repaired, after the first request had been re-forwarded.
 * The connection is not scheduled until all requests in it are re-sent.
 */
static int
tfw_http_conn_fwd_repair(TfwSrvConn *srv_conn, struct list_head *eq)
{
	int ret = 0;
	T_DBG2("%s: conn=[%p]\n", __func__, srv_conn);
	WARN_ON(!spin_is_locked(&srv_conn->fwd_qlock));
	BUG_ON(!tfw_srv_conn_restricted(srv_conn));

	if (tfw_srv_conn_reenable_if_done(srv_conn))
		return 0;
	if (test_bit(TFW_CONN_B_QFORWD, &srv_conn->flags)) {
		if (tfw_http_conn_need_fwd(srv_conn))
			ret = tfw_http_conn_fwd_unsent(srv_conn, eq);
	} else {
		/*
		 * Resend all previously forwarded requests. After that
		 * @srv_conn->msg_sent will be either NULL or the last
		 * request that was re-sent successfully. If re-sending
		 * of non-idempotent requests is allowed, then that last
		 * request may be non-idempotent. Continue with sending
		 * requests that were never forwarded only if the last
		 * request that was re-sent was NOT non-idempotent.
		 */
		if (tfw_http_conn_resend(srv_conn, false, eq) == -EBADF)
			return 0;
		set_bit(TFW_CONN_B_QFORWD, &srv_conn->flags);
		if (tfw_http_conn_need_fwd(srv_conn))
			ret = tfw_http_conn_fwd_unsent(srv_conn, eq);
	}
	tfw_srv_conn_reenable_if_done(srv_conn);

	return ret;
}

/*
 * Snip @fwd_queue (and @nip_queue) and move its contents to @out_queue.
 *
 * This is run under a lock, so spend minimum time under the lock and
 * do it fast while maintaining consistency. First destroy @nip_queue,
 * most often it has just one entry. Then snip @fwd_queue, move it to
 * @out_queue, and zero @qsize and @msg_sent.
 */
static void
tfw_http_conn_snip_fwd_queue(TfwSrvConn *srv_conn, struct list_head *out_queue)
{
	TfwHttpReq *req, *tmp;

	list_for_each_entry_safe(req, tmp, &srv_conn->nip_queue, nip_list)
		list_del_init(&req->nip_list);
	tfw_http_conn_nip_reset(srv_conn);
	list_splice_tail_init(&srv_conn->fwd_queue, out_queue);
	srv_conn->qsize = 0;
	srv_conn->msg_sent = NULL;
}

/*
 * Find an outgoing server connection for an HTTP message.
 *
 * This function is always called in SoftIRQ context.
 */
static TfwSrvConn *
tfw_http_get_srv_conn(TfwMsg *msg)
{
	TfwHttpReq *req = (TfwHttpReq *)msg;
	TfwHttpSess *sess = req->sess;

	/* Sticky cookies are disabled or client doesn't support cookies. */
	if (!sess)
		return tfw_vhost_get_srv_conn(msg);

	return tfw_http_sess_get_srv_conn(msg);
}

/*
 * Re-schedule a request collected from a dead server connection's
 * queue to a live server connection.
 *
 * Note: the re-scheduled request is put at the tail of a new server's
 * connection queue, and NOT according to their original timestamps.
 * That's the intended behaviour. Such rescheduled requests are unlucky
 * already. They were delayed by waiting in their original server connections,
 * and then by the time spent on multiple attempts to reconnect. Now they
 * have much greater chance to be evicted when it's their turn to be
 * forwarded. The main effort is put into servicing requests that are on time.
 * Unlucky requests are just given another chance with minimal effort.
 */
static int
tfw_http_req_resched(TfwHttpReq *req, TfwServer *srv, struct list_head *eq)
{
	int ret;
	TfwSrvConn *sch_conn;

	/*
	 * Health monitoring requests must be re-scheduled to
	 * the same server (other servers may not have enabled
	 * health monitor).
	 */
	if (test_bit(TFW_HTTP_B_HMONITOR, req->flags)) {
		sch_conn = srv->sg->sched->sched_srv_conn((TfwMsg *)req, srv);
		if (!sch_conn) {
			list_del_init(&req->fwd_list);
			tfw_http_conn_msg_free((TfwHttpMsg *)req);
			T_WARN_ADDR("Unable to find connection to reschedule "
				    "health monitoring request on server",
				    &srv->addr, TFW_WITH_PORT);
			return 0;
		}
	} else if (!(sch_conn = tfw_http_get_srv_conn((TfwMsg *)req))) {
		T_DBG("Unable to find a backend server\n");
		tfw_http_send_resp(req, 502, "request dropped: unable to"
				   " find an available back end server");
		TFW_INC_STAT_BH(clnt.msgs_otherr);
		return 0;
	} else {
		tfw_http_hm_srv_update((TfwServer *)sch_conn->peer,
				       req);
	}
	ret = tfw_http_req_fwd(sch_conn, req, eq, true);
	/*
	 * Paired with tfw_srv_conn_get_if_live() via sched_srv_conn callback or
	 * tfw_http_get_srv_conn() which increments the reference counter.
	 */
	tfw_srv_conn_put(sch_conn);

	return ret;
}

/*
 * Evict timed-out and dropped requests. Reschedule all the other
 * requests from the forwarding queue with up to limit of re-send
 * attempts.
 */
static void
tfw_http_fwdq_resched(TfwSrvConn *srv_conn, struct list_head *resch_queue,
		      struct list_head *eq)
{
	TfwHttpReq *req, *tmp;
	TfwServer *srv = (TfwServer *)srv_conn->peer;

	list_for_each_entry_safe(req, tmp, resch_queue, fwd_list) {
		INIT_LIST_HEAD(&req->nip_list);
		INIT_LIST_HEAD(&req->fwd_list);
		if (tfw_http_req_evict_stale_req(NULL, srv, req, eq))
			continue;
		if (unlikely(tfw_http_req_is_nip(req)
			     && !(srv->sg->flags & TFW_SRV_RETRY_NIP)))
		{
			tfw_http_nip_req_resched_err(NULL, req, eq);
			continue;
		}
		while (!tfw_http_req_evict_retries(NULL, srv, req, eq)) {
			if (!tfw_http_req_resched(req, srv, eq))
				break;
		}
	}
}

/*
 * Forward @req into server connection @srv_conn. Timed-out and dropped
 * requests are evicted to error queue @eq for sending an error response
 * later. If forwarding procedure returns error, then it considered
 * unfinished; in this case the connection's @fwd_queue will be reset
 * and all requests from it will be rescheduled to other connections.
 */
static void
tfw_http_req_fwd_resched(TfwSrvConn *srv_conn, TfwHttpReq *req,
			 struct list_head *eq)
{
	LIST_HEAD(reschq);

	T_DBG2("%s: srv_conn=[%p], req=[%p]\n", __func__, srv_conn, req);
	BUG_ON(!(TFW_CONN_TYPE(srv_conn) & Conn_Srv));

	spin_lock_bh(&srv_conn->fwd_qlock);
	tfw_http_req_enlist(srv_conn, req);
	if (tfw_http_conn_on_hold(srv_conn)
	    || !tfw_http_conn_fwd_unsent(srv_conn, eq))
	{
		spin_unlock_bh(&srv_conn->fwd_qlock);
		return;
	}
	tfw_srv_set_busy_delay(srv_conn);
	tfw_http_fwdq_reset(srv_conn, &reschq);
	spin_unlock_bh(&srv_conn->fwd_qlock);

	tfw_http_fwdq_resched(srv_conn, &reschq, eq);
}

/**
 * Process forwarding queue of a server connection to be released.
 * Timed-out requests and requests depleted number of re-send attempts are
 * evicted.
 *
 * Note: The limit on re-forward attempts is checked against the maximum value
 * for the current server group. Later the request is placed in another
 * connection in the same group. It's essential that all servers in a group have
 * the same limit. Otherwise, it will be necessary to check requests for
 * eviction _after_ a new connection is found.
 */
static void
tfw_http_conn_shrink_fwdq(TfwSrvConn *srv_conn)
{
	LIST_HEAD(eq);
	TfwHttpReq *req, *tmp;
	TfwServer *srv = (TfwServer *)srv_conn->peer;
	struct list_head *end, *fwdq = &srv_conn->fwd_queue;

	T_DBG2("%s: conn=[%p]\n", __func__, srv_conn);

	spin_lock_bh(&srv_conn->fwd_qlock);
	if (list_empty(fwdq)) {
		spin_unlock_bh(&srv_conn->fwd_qlock);
		return;
	}

	/*
	 * Evict timed-out requests, NOT including the request that was sent
	 * last. Do it for requests that were sent before, no NIP requests are
	 * here. Don't touch unsent requests so far.
	 */
	if (srv_conn->msg_sent) {
		TfwMsg *msg_sent_prev;

		/* Similar to list_for_each_entry_safe_from() */
		req = list_first_entry(fwdq, TfwHttpReq, fwd_list);
		end = &((TfwHttpReq *)srv_conn->msg_sent)->fwd_list;
		for (tmp = list_next_entry(req, fwd_list);
		     &req->fwd_list != end;
		     req = tmp, tmp = list_next_entry(tmp, fwd_list))
		{
			tfw_http_req_evict_stale_req(srv_conn, srv, req, &eq);
		}
		/*
		 * Process the request that was forwarded last, and then
		 * reassign @srv_conn->msg_sent in case it is evicted.
		 * @req is now the same as @srv_conn->msg_sent.
		 */
		msg_sent_prev = __tfw_http_conn_msg_sent_prev(srv_conn);
		if (tfw_http_req_evict_stale_req(srv_conn, srv, req, &eq))
			srv_conn->msg_sent = msg_sent_prev;
	}

	/*
	 * Process the rest of the forwarding queue. These requests were never
	 * forwarded yet through the connection. Evict some of them by timeout.
	 */
	req = srv_conn->msg_sent
	    ? list_next_entry((TfwHttpReq *)srv_conn->msg_sent, fwd_list)
	    : list_first_entry(fwdq, TfwHttpReq, fwd_list);

	list_for_each_entry_safe_from(req, tmp, fwdq, fwd_list)
		tfw_http_req_evict_stale_req(srv_conn, srv, req, &eq);

	spin_unlock_bh(&srv_conn->fwd_qlock);

	tfw_http_req_zap_error(&eq);
}

/**
 * The same as tfw_http_conn_shrink_fwdq(), but for connections which messages
 * must be rescheduled. Non-evicted requests are rescheduled to other
 * connections or servers.
 */
static void
tfw_http_conn_shrink_fwdq_resched(TfwSrvConn *srv_conn)
{
	LIST_HEAD(eq);
	LIST_HEAD(schq);

	T_DBG2("%s: conn=[%p]\n", __func__, srv_conn);

	spin_lock_bh(&srv_conn->fwd_qlock);
	if (list_empty(&srv_conn->fwd_queue)) {
		spin_unlock_bh(&srv_conn->fwd_qlock);
		return;
	}
	tfw_http_fwdq_reset(srv_conn, &schq);
	spin_unlock_bh(&srv_conn->fwd_qlock);

	tfw_http_fwdq_resched(srv_conn, &schq, &eq);

	tfw_http_req_zap_error(&eq);
}

/*
 * Repair a connection. Makes sense only for server connections.
 *
 * Find requests in the server's connection queue that were forwarded
 * to the server. These are unanswered requests. According to RFC 7230
 * 6.3.2, "a client MUST NOT pipeline immediately after connection
 * establishment". To address that, re-send the first request to the
 * server. When a response comes, that will trigger resending of the
 * rest of those unanswered requests (tfw_http_conn_fwd_repair()).
 *
 * The connection is not scheduled until all requests in it are re-sent.
 *
 * The limit on the number of reconnect attempts is used to re-schedule
 * requests that would never be forwarded otherwise.
 *
 * No need to take a reference on the server connection here as this
 * is executed as part of establishing the connection. It definitely
 * can't go away.
 */
static void
tfw_http_conn_repair(TfwConn *conn)
{
	int err;
	TfwSrvConn *srv_conn = (TfwSrvConn *)conn;
	LIST_HEAD(reschq);
	LIST_HEAD(eq);

	T_DBG2("%s: conn=[%p]\n", __func__, srv_conn);
	BUG_ON(!(TFW_CONN_TYPE(srv_conn) & Conn_Srv));

	/* See if requests need to be rescheduled. */
	if (unlikely(!tfw_srv_conn_live(srv_conn))) {
		if (tfw_srv_conn_need_resched(srv_conn))
			tfw_http_conn_shrink_fwdq_resched(srv_conn);
		else
			tfw_http_conn_shrink_fwdq(srv_conn);
		return;
	}

	spin_lock_bh(&srv_conn->fwd_qlock);
	if (list_empty(&srv_conn->fwd_queue)) {
		spin_unlock_bh(&srv_conn->fwd_qlock);
		return;
	}

	/* Treat a non-idempotent request if any. */
	tfw_http_conn_treatnip(srv_conn, &eq);

	/* Re-send only the first unanswered request. */
	err = tfw_http_conn_resend(srv_conn, true, &eq);
	if (err == -EBADF) {
		spin_unlock_bh(&srv_conn->fwd_qlock);
		goto out;
	}
	/*
	 * If re-sending procedure successfully passed,
	 * but requests had not been re-sent, and removed
	 * instead, then send the remaining unsent requests.
	 */
	if (!err && !srv_conn->msg_sent) {
		if (!list_empty(&srv_conn->fwd_queue)) {
			set_bit(TFW_CONN_B_QFORWD, &srv_conn->flags);
			err = tfw_http_conn_fwd_unsent(srv_conn, &eq);
		}
		tfw_srv_conn_reenable_if_done(srv_conn);
	}
	/*
	 * Move out if re-sending/sending procedures are
	 * passed without errors.
	 */
	if (!err) {
		spin_unlock_bh(&srv_conn->fwd_qlock);
		goto out;
	}

	/*
	 * In case of requests re-sending error (-EBUSY) or
	 * requests forwarding error (-EBUSY and @msg_sent
	 * is NULL) the reschedule procedure is started;
	 * @msg_sent is definitely NULL here, so there are
	 * no unanswered requests and we can cut all remaining
	 * requests from @fwd_queue for rescheduling.
	 */
	WARN_ON(srv_conn->msg_sent);
	__tfw_srv_conn_clear_restricted(srv_conn);
	tfw_srv_set_busy_delay(srv_conn);
	tfw_http_fwdq_reset(srv_conn, &reschq);
	spin_unlock_bh(&srv_conn->fwd_qlock);
	tfw_http_fwdq_resched(srv_conn, &reschq, &eq);
out:
	tfw_http_req_zap_error(&eq);
}

/*
 * Destructor for a request message.
 */
void
tfw_http_req_destruct(void *msg)
{
	TfwHttpReq *req = msg;

	WARN_ON_ONCE(!list_empty(&req->msg.seq_list));
	WARN_ON_ONCE(!list_empty(&req->fwd_list));
	WARN_ON_ONCE(!list_empty(&req->nip_list));

	tfw_vhost_put(req->vhost);
	if (req->sess)
		tfw_http_sess_put(req->sess);

	if (req->peer)
		tfw_client_put(req->peer);
}

/**
 * Request messages that were forwarded to a backend server are added
 * to and kept in @fwd_queue of the connection @conn for that server.
 * If a paired request is not found, then the response must be deleted.
 *
 * If a paired client request is missing, then it seems upstream server
 * is misbehaving, so the caller has to drop the server connection.
 *
 * Correct response parsing is only possible when request properties,
 * such as method, are known. Thus resp->req pairing is mandatory. In the
 * same time req->resp pairing is not required until response is ready to
 * be forwarded to client. It's needed to avoid passing both resp and req
 * across all functions and creating indirect req<->resp pairing.
 */
static int
tfw_http_resp_pair(TfwHttpMsg *hmresp)
{
	TfwHttpReq *req;
	TfwSrvConn *srv_conn = (TfwSrvConn *)hmresp->conn;

	spin_lock(&srv_conn->fwd_qlock);
	list_for_each_entry(req, &srv_conn->fwd_queue, fwd_list) {
		if (!req->pair) {
			tfw_http_msg_pair((TfwHttpResp *)hmresp, req);
			spin_unlock(&srv_conn->fwd_qlock);

			return 0;
		}
		if (req == (TfwHttpReq *)srv_conn->msg_sent)
			break;
	}
	spin_unlock(&srv_conn->fwd_qlock);

	T_WARN("Paired request missing, HTTP Response Splitting attack?\n");
	TFW_INC_STAT_BH(serv.msgs_otherr);

	return -EINVAL;
}

/*
 * Allocate a new HTTP message structure and link it with the connection
 * instance. Increment the number of users of the instance. Initialize
 * GFSM for the message.
 */
static TfwMsg *
tfw_http_conn_msg_alloc(TfwConn *conn, TfwStream *stream)
{
	int type = TFW_CONN_TYPE(conn);
	TfwHttpMsg *hm = __tfw_http_msg_alloc(type, true);
	if (unlikely(!hm))
		return NULL;

	hm->conn = conn;
	tfw_connection_get(conn);
	hm->stream = stream;

	if (type & Conn_Clnt)
		tfw_http_init_parser_req((TfwHttpReq *)hm);
	else
		tfw_http_init_parser_resp((TfwHttpResp *)hm);

	if (TFW_CONN_H2(conn)) {
		TfwHttpReq *req = (TfwHttpReq *)hm;

		if(!(req->pit.pool = __tfw_pool_new(0)))
			goto clean;
		req->pit.parsed_hdr = &req->stream->parser.hdr;
		__set_bit(TFW_HTTP_B_H2, req->flags);
		/* Version for HTTP/1 is filled by parser. */
		req->version = TFW_HTTP_VER_20;
	}

	if (type & Conn_Clnt) {
		TFW_INC_STAT_BH(clnt.rx_messages);
	} else {
		if (unlikely(tfw_http_resp_pair(hm)))
			goto clean;

		if (TFW_MSG_H2(hm->req)) {
			size_t sz = TFW_HDR_MAP_SZ(TFW_HDR_MAP_INIT_CNT);
			TfwHttpTransIter *mit = &((TfwHttpResp *)hm)->mit;

			mit->map = tfw_pool_alloc(hm->pool, sz);
			if (unlikely(!mit->map)) {
				T_WARN("HTTP/2: unable to allocate memory for"
				       " response header map\n");
				goto clean;
			}
			mit->map->size = TFW_HDR_MAP_INIT_CNT;
			mit->map->count = 0;
		}

		TFW_INC_STAT_BH(serv.rx_messages);
	}

	return (TfwMsg *)hm;
clean:
	tfw_http_conn_msg_free(hm);

	return NULL;
}

/*
 * Connection with a peer is created.
 *
 * Called when a connection is created. Initialize the connection's
 * state machine here.
 */
static int
tfw_http_conn_init(TfwConn *conn)
{
	T_DBG2("%s: conn=[%p]\n", __func__, conn);

	if (TFW_CONN_TYPE(conn) & Conn_Srv) {
		TfwSrvConn *srv_conn = (TfwSrvConn *)conn;
		if (!list_empty(&srv_conn->fwd_queue)) {
			set_bit(TFW_CONN_B_RESEND, &srv_conn->flags);
			TFW_INC_STAT_BH(serv.conn_restricted);
		}
	}
	tfw_gfsm_state_init(&conn->state, conn, TFW_HTTP_FSM_INIT);
	return 0;
}

static int
tfw_http_conn_close(TfwConn *conn, bool sync)
{
	return ss_close(conn->sk, sync ? SS_F_SYNC : 0);
}

/*
 * Connection with a peer is released.
 *
 * This function is called when all users of a server connection are gone,
 * and the connection's resources can be released.
 *
 * If a server connection is in failover state, then the requests that were
 * sent to that server are kept in the queue until a paired response comes.
 * The responses will never come now. Keep the queue. When the connection
 * is restored the requests will be re-sent to the server.
 *
 * If a server connection is completely destroyed (on Tempesta's shutdown),
 * then all outstanding requests in @fwd_queue are dropped and released.
 * Depending on Tempesta's state, both user and kernel context threads
 * may try to do that at the same time. As @fwd_queue is moved atomically
 * to local @zap_queue, only one thread is able to proceed and release
 * the resources.
 */
static void
tfw_http_conn_release(TfwConn *conn)
{
	TfwHttpReq *req, *tmp;
	TfwSrvConn *srv_conn = (TfwSrvConn *)conn;
	LIST_HEAD(zap_queue);

	T_DBG2("%s: conn=[%p]\n", __func__, srv_conn);
	BUG_ON(!(TFW_CONN_TYPE(srv_conn) & Conn_Srv));

	if (likely(ss_active())) {
		/*
		 * Server is removed from configuration and won't be available
		 * any more, reschedule it's forward queue.
		 */
		if (unlikely(test_bit(TFW_CONN_B_DEL, &srv_conn->flags)))
			tfw_http_conn_shrink_fwdq_resched(srv_conn);
		__tfw_srv_conn_clear_restricted(srv_conn);

		return;
	}

	/*
	 * Destroy server connection's queues.
	 * Move all requests from them to @zap_queue.
	 */
	spin_lock_bh(&srv_conn->fwd_qlock);
	tfw_http_conn_snip_fwd_queue(srv_conn, &zap_queue);
	spin_unlock_bh(&srv_conn->fwd_qlock);

	/*
	 * Remove requests from @zap_queue (formerly @fwd_queue) and from
	 * @seq_queue of respective client connections, then destroy them.
	 */
	list_for_each_entry_safe(req, tmp, &zap_queue, fwd_list) {
		list_del_init(&req->fwd_list);
		if (TFW_MSG_H2(req)) {
			tfw_h2_stream_id_close(req, _HTTP2_UNDEFINED, 0);
		}
		else if (unlikely(!list_empty_careful(&req->msg.seq_list))) {
			spin_lock_bh(&((TfwCliConn *)req->conn)->seq_qlock);
			if (unlikely(!list_empty(&req->msg.seq_list)))
				list_del_init(&req->msg.seq_list);
			spin_unlock_bh(&((TfwCliConn *)req->conn)->seq_qlock);
		}
		tfw_http_conn_msg_free((TfwHttpMsg *)req);
	}
}

/*
 * Drop client connection's resources.
 *
 * Disintegrate the client connection's @seq_list. Requests without a paired
 * response have not been answered yet. They are held in the lists of server
 * connections until responses come. A paired response may be in use until
 * TFW_HTTP_B_RESP_READY flag is not set.  Don't free any of those requests.
 *
 * If a response comes or gets ready to forward after @seq_list is
 * disintegrated, then both the request and the response are dropped at the
 *  sight of an empty list.
 *
 * Locking is necessary as @seq_list is constantly probed from server
 * connection threads.
 */
static void
tfw_http_conn_cli_drop(TfwCliConn *cli_conn)
{
	TfwHttpReq *req, *tmp;
	struct list_head *seq_queue = &cli_conn->seq_queue;

	T_DBG2("%s: conn=[%p]\n", __func__, cli_conn);
	BUG_ON(!(TFW_CONN_TYPE(cli_conn) & Conn_Clnt));

	if (list_empty_careful(seq_queue))
		return;

	/*
	 * Disintegration of the list must be done under the lock.
	 * The list can't be just detached from seq_queue, and then
	 * be disintegrated without the lock. That would open a race
	 * condition with freeing of a request in tfw_http_resp_fwd().
	 */
	spin_lock(&cli_conn->seq_qlock);
	list_for_each_entry_safe(req, tmp, seq_queue, msg.seq_list) {
		/*
		 * Request must be destroyed if the response is fully processed
		 * and removed from fwd_queue. If the request is still in use
		 * immediately after REQ_DROP flag is set, the request-response
		 * pair can be destroyed in other thread.
		 */
		bool unused = req->resp
			&& test_bit(TFW_HTTP_B_RESP_READY, req->resp->flags);
		list_del_init(&req->msg.seq_list);
		smp_mb__before_atomic();
		set_bit(TFW_HTTP_B_REQ_DROP, req->flags);
		if (unused) {
			tfw_http_resp_pair_free(req);
			TFW_INC_STAT_BH(serv.msgs_otherr);
		}
	}
	spin_unlock(&cli_conn->seq_qlock);
}

/*
 * Connection with a peer is dropped.
 *
 * Release resources that are not needed anymore, and keep other
 * resources that are needed while there are users of the connection.
 */
static void tfw_http_resp_terminate(TfwHttpMsg *hm);

static void
tfw_http_conn_drop(TfwConn *conn)
{
	bool h2_mode = TFW_CONN_H2(conn);

	T_DBG2("%s: conn=[%p]\n", __func__, conn);

	if (TFW_CONN_TYPE(conn) & Conn_Clnt) {
		if (h2_mode)
			tfw_h2_conn_streams_cleanup(tfw_h2_context(conn));
		else
			tfw_http_conn_cli_drop((TfwCliConn *)conn);
	}
	else if (conn->stream.msg) { /* server connection */
		if (!tfw_http_parse_terminate((TfwHttpMsg *)conn->stream.msg))
			tfw_http_resp_terminate((TfwHttpMsg *)conn->stream.msg);
	}

	if (!h2_mode)
		tfw_http_conn_msg_free((TfwHttpMsg *)conn->stream.msg);
}

/*
 * Send a message through the connection.
 *
 * Called when the connection is used to send a message through.
 */
static int
tfw_http_conn_send(TfwConn *conn, TfwMsg *msg)
{
	return ss_send(conn->sk, &msg->skb_head, msg->ss_flags);
}

/**
 * Create a sibling for @hm message.
 * Siblings in HTTP are pipelined HTTP messages that share the same SKB.
 */
static TfwHttpMsg *
tfw_http_msg_create_sibling(TfwHttpMsg *hm, struct sk_buff *skb)
{
	TfwHttpMsg *shm;

	T_DBG2("Create sibling message: conn %p, msg: %p, skb %p\n",
	       hm->conn, hm, skb);

	/* The sibling message belongs to the same connection. */
	shm = (TfwHttpMsg *)tfw_http_conn_msg_alloc(hm->conn, hm->stream);
	if (unlikely(!shm))
		return NULL;

	/*
	 * New message created, so it should be in whitelist if
	 * previous message was (for client connections). Also
	 * we have new skb here and 'mark' propagation is needed.
	 */
	if (TFW_CONN_TYPE(hm->conn) & Conn_Clnt) {
		if (test_bit(TFW_HTTP_B_WHITELIST, hm->flags))
			__set_bit(TFW_HTTP_B_WHITELIST, shm->flags);
		skb->mark = hm->msg.skb_head->mark;
	}

	ss_skb_queue_tail(&shm->msg.skb_head, skb);

	return shm;
}

/*
 * Add 'Date:' header field to an HTTP message.
 */
static int
tfw_http_set_hdr_date(TfwHttpMsg *hm)
{
	int r;
	char *s_date = *this_cpu_ptr(&g_buf);

	tfw_http_prep_date_from(s_date, ((TfwHttpResp *)hm)->date);
	r = tfw_http_msg_hdr_xfrm(hm, "date", sizeof("date") - 1,
				  s_date, SLEN(S_V_DATE),
				  TFW_HTTP_HDR_RAW, 0);
	if (r)
		T_ERR("Unable to add Date: header to msg [%p]\n", hm);
	else
		T_DBG2("Added Date: header to msg [%p]\n", hm);
	return r;
}

/*
 * Expand HTTP response with 'Date:' header field.
 */
int
tfw_http_expand_hdr_date(TfwHttpResp *resp)
{
	int r;
	struct sk_buff **skb_head = &resp->msg.skb_head;
	TfwHttpTransIter *mit = &resp->mit;
	char *date = *this_cpu_ptr(&g_buf);
	TfwStr h_date = {
		.chunks = (TfwStr []){
			{ .data = S_F_DATE, .len = SLEN(S_F_DATE) },
			{ .data = date, .len = SLEN(S_V_DATE) },
			{ .data = S_CRLF, .len = SLEN(S_CRLF) }
		},
		.len = SLEN(S_F_DATE) + SLEN(S_V_DATE) + SLEN(S_CRLF),
		.nchunks = 3
	};

	tfw_http_prep_date_from(date, resp->date);
	r = tfw_http_msg_expand_data(&mit->iter, skb_head, &h_date, NULL);
	if (r)
		T_ERR("Unable to expand resp [%p] with 'Date:' header\n", resp);
	else
		T_DBG2("Epanded resp [%p] with 'Date:' header\n", resp);

	return r;
}

int
tfw_http_expand_hdr_clen(TfwHttpResp *resp, size_t len)
{
	int r;
	struct sk_buff **skb_head = &resp->msg.skb_head;
	TfwHttpTransIter *mit = &resp->mit;
	char *buf = *this_cpu_ptr(&g_buf);
	TfwStr h_clen = {
		.chunks = (TfwStr []){
			TFW_STR_STRING(S_F_CONTENT_LENGTH),
			{ .data = buf, .len = 0 },
			TFW_STR_STRING(S_CRLF),
		},
		.len = SLEN(S_F_CONTENT_LENGTH) + SLEN(S_CRLF),
		.nchunks = 3
	};
	TfwStr *len_str = __TFW_STR_CH(&h_clen, 1);

	if (!len)
		return 0;

	len_str->len = tfw_ultoa(len, len_str->data, TFW_ULTOA_BUF_SIZ);
	if (!len_str->len)
		return -EINVAL;
	h_clen.len += len_str->len;
	r = tfw_http_msg_expand_data(&mit->iter, skb_head, &h_clen, NULL);
	if (r)
		T_ERR("Unable to expand resp [%p] with 'content-length:' "
		      "header\n", resp);
	else
		T_DBG2("Expanded resp [%p] with 'content-length:' header\n",
		       resp);

	return r;
}

/**
 * Connection is to be closed after response for the request @req is forwarded
 * to the client. Don't process new requests from the client and update
 * message flags for proper "Connection: " header value.
 */
static inline void
tfw_http_req_set_conn_close(TfwHttpReq *req)
{
	TFW_CONN_TYPE(req->conn) |= Conn_Stop;
	set_bit(TFW_HTTP_B_CONN_CLOSE, req->flags);
}

/**
 * Expand HTTP/1.1 response with hop-by-hop headers. It is implied that this
 * procedure should be used only for cases when original hop-by-hop headers
 * is already removed from the response: e.g. creation HTTP/1.1-response from
 * the cache (see also comments for tfw_http_set_hdr_connection(),
 * tfw_http_set_hdr_keep_alive() and tfw_http_adjust_resp()).
 */
int
tfw_http_expand_hbh(TfwHttpResp *resp, unsigned short status)
{
	TfwHttpReq *req = resp->req;
	TfwHttpTransIter *mit = &resp->mit;
	struct sk_buff **skb_head = &resp->msg.skb_head;
	bool proxy_close = test_bit(TFW_HTTP_B_CONN_CLOSE, resp->flags)
		&& (status / 100 == 4);
	TfwStr h_conn = {
		.chunks = (TfwStr []){
			{ .data = S_F_CONNECTION, .len = SLEN(S_F_CONNECTION) },
			{},
			{ .data = S_CRLF, .len = SLEN(S_CRLF) }
		},
		.len = SLEN(S_F_CONNECTION) + SLEN(S_CRLF),
		.nchunks = 3
	};
	bool add_h_conn = true;

	if (unlikely(test_bit(TFW_HTTP_B_CONN_CLOSE, req->flags)
		     || proxy_close))
	{
		__TFW_STR_CH(&h_conn, 1)->data = S_V_CONN_CLOSE;
		__TFW_STR_CH(&h_conn, 1)->len = SLEN(S_V_CONN_CLOSE);
		h_conn.len += SLEN(S_V_CONN_CLOSE);
	}
	else if (test_bit(TFW_HTTP_B_CONN_KA, req->flags))
	{
		__TFW_STR_CH(&h_conn, 1)->data = S_V_CONN_KA;
		__TFW_STR_CH(&h_conn, 1)->len = SLEN(S_V_CONN_KA);
		h_conn.len += SLEN(S_V_CONN_KA);
	}
	else
	{
		/* Empty connection: header. */
		add_h_conn = false;
	}

	if (unlikely(proxy_close))
		tfw_http_req_set_conn_close(req);

	return add_h_conn
		? tfw_http_msg_expand_data(&mit->iter, skb_head, &h_conn, NULL)
		: 0;
}

/**
 * Remove Connection header from HTTP message @msg if @conn_flg is zero,
 * and replace or set a new header value otherwise.
 *
 * SKBs may be shared by several HTTP messages. A shared SKB is not copied
 * but safely modified. Thus, a shared SKB is still owned by one CPU.
 */
static int
tfw_http_set_hdr_connection(TfwHttpMsg *hm, unsigned long conn_flg)
{
	BUILD_BUG_ON(BIT_WORD(__TFW_HTTP_MSG_M_CONN) != 0);
	if (((hm->flags[0] & __TFW_HTTP_MSG_M_CONN) == conn_flg)
	    && (!TFW_STR_EMPTY(&hm->h_tbl->tbl[TFW_HTTP_HDR_CONNECTION]))
	    && !test_bit(TFW_HTTP_B_CONN_EXTRA, hm->flags))
		return 0;

	switch (conn_flg) {
	case BIT(TFW_HTTP_B_CONN_CLOSE):
		return TFW_HTTP_MSG_HDR_XFRM(hm, "Connection", "close",
					     TFW_HTTP_HDR_CONNECTION, 0);
	case BIT(TFW_HTTP_B_CONN_KA):
		return TFW_HTTP_MSG_HDR_XFRM(hm, "Connection", "keep-alive",
					     TFW_HTTP_HDR_CONNECTION, 0);
	default:
		return TFW_HTTP_MSG_HDR_DEL(hm, "Connection",
					    TFW_HTTP_HDR_CONNECTION);
	}
}

/**
 * Add/Replace/Remove Keep-Alive header field to/from HTTP message.
 */
static int
tfw_http_set_hdr_keep_alive(TfwHttpMsg *hm, unsigned long conn_flg)
{
	int r;

	BUILD_BUG_ON(BIT_WORD(__TFW_HTTP_MSG_M_CONN) != 0);
	if ((hm->flags[0] & __TFW_HTTP_MSG_M_CONN) == conn_flg)
		return 0;

	switch (conn_flg) {
	case BIT(TFW_HTTP_B_CONN_CLOSE):
		r = TFW_HTTP_MSG_HDR_DEL(hm, "Keep-Alive",
					 TFW_HTTP_HDR_KEEP_ALIVE);
		if (unlikely(r && r != -ENOENT)) {
			T_WARN("Cannot delete Keep-Alive header (%d)\n", r);
			return r;
		}
		return 0;
	case BIT(TFW_HTTP_B_CONN_KA):
		/*
		 * If present, "Keep-Alive" header informs the other side
		 * of the timeout policy for a connection. Otherwise, it's
		 * presumed that default policy is in action.
		 *
		 * TODO: Add/Replace "Keep-Alive" header when Tempesta
		 * implements connection timeout policies and the policy
		 * for the connection differs from default policy.
		 */
		return 0;
	default:
		/*
		 * "Keep-Alive" header mandates that "Connection: keep-alive"
		 * header in present in HTTP message. HTTP/1.1 connections
		 * are keep-alive by default. If we want to add "Keep-Alive"
		 * header then "Connection: keep-alive" header must be added
		 * as well. TFW_HTTP_F_CONN_KA flag will force the addition
		 * of "Connection: keep-alive" header to HTTP message.
		 */
		return 0;
	}
}

/*
 * In case if response is stale, we should pass it with a warning.
 */
int
tfw_http_expand_stale_warn(TfwHttpResp *resp)
{
	/* TODO: adjust for #865 */
	struct sk_buff **skb_head = &resp->msg.skb_head;
	TfwHttpTransIter *mit = &resp->mit;
	TfwStr wh = {
		.chunks = (TfwStr []){
			{ .data = S_WARN, .len = SLEN(S_WARN) },
			{ .data = S_DLM, .len = SLEN(S_DLM) },
			{ .data = S_V_WARN, .len = SLEN(S_V_WARN) },
			{ .data = S_CRLF, .len = SLEN(S_CRLF) }
		},
		.len = SLEN(S_WARN) + SLEN(S_DLM) + SLEN(S_V_WARN) + SLEN(S_CRLF),
		.nchunks = 4,
	};

	return tfw_http_msg_expand_data(&mit->iter, skb_head, &wh, NULL);
}

static inline int
__tfw_http_add_hdr_via(TfwHttpMsg *hm, int http_version, bool from_cache)
{
	int r = 0;
	static const char * const s_http_version[] = {
		[0 ... _TFW_HTTP_VER_COUNT] = NULL,
		[TFW_HTTP_VER_09] = "0.9 ",
		[TFW_HTTP_VER_10] = "1.0 ",
		[TFW_HTTP_VER_11] = "1.1 ",
		[TFW_HTTP_VER_20] = "2.0 ",
	};
	TfwGlobal *g_vhost = tfw_vhost_get_global();
	const TfwStr rh = {
		.chunks = (TfwStr []) {
			{ .data = S_F_VIA, .len = SLEN(S_F_VIA) },
			{ .data = (void *)s_http_version[http_version],
			  .len = 4 },
			{ .data = *this_cpu_ptr(&g_buf),
			  .len = g_vhost->hdr_via_len },
		},
		.len = SLEN(S_F_VIA) + 4 + g_vhost->hdr_via_len,
		.eolen = 2,
		.nchunks = 3
	};

	memcpy_fast(__TFW_STR_CH(&rh, 2)->data, g_vhost->hdr_via,
		    g_vhost->hdr_via_len);

	if (!from_cache) {
		r = tfw_http_msg_hdr_add(hm, &rh);
	}
	else {
		struct sk_buff **skb_head = &hm->msg.skb_head;
		TfwHttpTransIter *mit = &((TfwHttpResp *)hm)->mit;
		TfwStr crlf = { .data = S_CRLF, .len = SLEN(S_CRLF) };

		r = tfw_http_msg_expand_data(&mit->iter, skb_head, &rh, NULL);
		r |= tfw_http_msg_expand_data(&mit->iter, skb_head,
					     &crlf, NULL);
	}
	if (r)
		T_ERR("Unable to add via: header to msg [%p]\n", hm);
	else
		T_DBG2("Added via: header to msg [%p]\n", hm);

	return r;
}

int tfw_http_expand_hdr_via(TfwHttpResp *resp)
{
	return __tfw_http_add_hdr_via((TfwHttpMsg *)resp, resp->req->version,
				      true);
}

static int
tfw_http_add_hdr_via(TfwHttpMsg *hm)
{
	return __tfw_http_add_hdr_via(hm, hm->version, false);
}

static int
tfw_http_add_x_forwarded_for(TfwHttpMsg *hm)
{
	int r;
	char *p, *buf = *this_cpu_ptr(&g_buf);

	p = ss_skb_fmt_src_addr(hm->msg.skb_head, buf);

	r = tfw_http_msg_hdr_xfrm(hm, "X-Forwarded-For",
				  sizeof("X-Forwarded-For") - 1, buf, p - buf,
				  TFW_HTTP_HDR_X_FORWARDED_FOR, 0);
	if (r)
		T_ERR("can't add X-Forwarded-For header for %.*s to msg %p",
		      (int)(p - buf), buf, hm);
	else
		T_DBG2("added X-Forwarded-For header for %.*s\n",
		       (int)(p - buf), buf);
	return r;
}

/**
 * Compose Content-Type header field from scratch.
 *
 * A POST-request with multipart/form-data payload need a boundary, which is
 * supplied by a parameter in the Content-Type header field. There are strict
 * instructions on how to parse that parameter (see RFC 7231 and RFC 7230), but
 * application servers parse it in a non-standard way. For example, PHP checks
 * whenever parameter name contains substring "boundary", and thus happily takes
 * "xxboundaryxx". Such quirks are used to bypass web application firewalls.
 *
 * To make evasions harder, this function composes value of the Content-Type
 * field from the parsed data. All parameters other than "boundary" are dropped.
 */
static int
tfw_http_recreate_content_type_multipart_hdr(TfwHttpReq *req)
{
	TfwStr replacement = {
		.chunks = (TfwStr []) {
			TFW_STR_STRING("Content-Type"),
			TFW_STR_STRING(": "),
			TFW_STR_STRING("multipart/form-data; boundary="),
			req->multipart_boundary_raw,
		},
		.nchunks = 4,
	};
	TfwStr *c = replacement.chunks;

	BUG_ON(!TFW_STR_PLAIN(&req->multipart_boundary_raw));
	replacement.len = c[0].len + c[1].len + c[2].len + c[3].len;
	return tfw_http_msg_hdr_xfrm_str((TfwHttpMsg *)req, &replacement,
					 TFW_HTTP_HDR_CONTENT_TYPE, false);
}

static bool
tfw_http_should_validate_post_req(TfwHttpReq *req)
{
	if (req->location && req->location->validate_post_req)
		return true;

	if (WARN_ON_ONCE(!req->vhost))
		return false;

	if (req->vhost->loc_dflt && req->vhost->loc_dflt->validate_post_req)
		return true;

	if (req->vhost->vhost_dflt &&
	    req->vhost->vhost_dflt->loc_dflt->validate_post_req)
		return true;

	return false;
}

/**
 * Add local headers (defined by administrator in configuration file) to http/1
 * message.
 *
 * @hm		- Message to be updated;
 * @is_resp	- Message represents response, not request;
 * @from_cache	- The response is created from cache, not applied to requests.
 */
int
tfw_h1_set_loc_hdrs(TfwHttpMsg *hm, bool is_resp, bool from_cache)
{
	size_t i;
	int mod_type = is_resp ? TFW_VHOST_HDRMOD_RESP : TFW_VHOST_HDRMOD_REQ;
	TfwHttpReq *req = is_resp ? hm->req : (TfwHttpReq *)hm;
	TfwHdrMods *h_mods = tfw_vhost_get_hdr_mods(req->location, req->vhost,
						    mod_type);

	if(WARN_ON_ONCE(!is_resp && from_cache))
		return -EINVAL;
	if (!h_mods)
		return 0;

	for (i = 0; i < h_mods->sz; ++i) {
		int r;
		TfwHdrModsDesc *d = &h_mods->hdrs[i];
		/*
		 * Header is stored optimized for HTTP2: without delimiter
		 * between header and value. Add it as separate chunk as
		 * required for tfw_http_msg_hdr_xfrm_str.
		 */
		TfwStr h_mdf = {
			.chunks = (TfwStr []){
				{},
				{ .data = S_DLM, .len = SLEN(S_DLM) },
				{}
			},
			.len = SLEN(S_DLM),
			.nchunks = 2 /* header name + delimeter. */
		};

		h_mdf.chunks[0] = d->hdr->chunks[0];
		if (d->hdr->nchunks == 2) {
			h_mdf.chunks[2] = d->hdr->chunks[1];
			h_mdf.nchunks += 1;
		}
		h_mdf.len += d->hdr->len;
		h_mdf.flags = d->hdr->flags;
		h_mdf.eolen += d->hdr->eolen;

		/*
		 * A response is built from cache. Response is stored in
		 * cache optimised for h2 and it's being created
		 * header-by-header right away.
		 */
		if (from_cache) {
			TfwHttpResp *resp = (TfwHttpResp *)hm;
			struct sk_buff **skb_head = &resp->msg.skb_head;
			TfwHttpTransIter *mit = &resp->mit;
			TfwStr crlf = { .data = S_CRLF, .len = SLEN(S_CRLF) };
			/*
			 * Skip the configured header if we have already
			 * processed it during cache reading, or if the header
			 * is configured for deletion (without value chunk).
			 */
			if (test_bit(i, mit->found) || h_mdf.nchunks < 3)
				continue;
			/* h_mdf->eolen is ignored, add explicit CRLF. */
			r = tfw_http_msg_expand_data(&mit->iter, skb_head,
						     &h_mdf, NULL);
			r |= tfw_http_msg_expand_data(&mit->iter, skb_head,
						     &crlf, NULL);
		} else {
			r = tfw_http_msg_hdr_xfrm_str(hm, &h_mdf, d->hid,
						      d->append);
		}

		if (r) {
			T_ERR("can't update location-specific header in msg %p\n",
			      hm);
			return r;
		}

		T_DBG2("updated location-specific header in msg %p\n", hm);
	}

	return 0;
}

/**
 * Adjust the request before proxying it to real server.
 */
static int
tfw_h1_adjust_req(TfwHttpReq *req)
{
	int r;
	TfwHttpMsg *hm = (TfwHttpMsg *)req;

	r = tfw_http_sess_req_process(req);
	if (r)
		return r;

	r = tfw_http_add_x_forwarded_for(hm);
	if (r)
		return r;

	r = tfw_http_add_hdr_via(hm);
	if (r)
		return r;

	r = tfw_http_msg_del_hbh_hdrs(hm);
	if (r < 0)
		return r;

	r = tfw_h1_set_loc_hdrs(hm, false, false);
	if (r < 0)
		return r;

	if (req->method == TFW_HTTP_METH_POST &&
	    test_bit(TFW_HTTP_B_CT_MULTIPART, req->flags) &&
	    tfw_http_should_validate_post_req(req))
	{
		r = tfw_http_recreate_content_type_multipart_hdr(req);
		if (r)
			return r;
	}

	return tfw_http_set_hdr_connection(hm, BIT(TFW_HTTP_B_CONN_KA));
}

static inline void
__h2_hdrs_dup_decrease(TfwHttpReq *req, const TfwStr *hdr)
{
	const TfwStr *dup, *dup_end;
	TfwMsgParseIter *it = &req->pit;

	TFW_STR_FOR_EACH_DUP(dup, hdr, dup_end) {
		--it->hdrs_cnt;
		it->hdrs_len -= dup->len;
	}
}

/**
 * Apply header modification. @hdr contains exactly two chunks: header name and
 * value.
 *
 * The @hdr descriptor (top level TfwStr is copied directly into header table.
 * It looks dangerous but it's safe and we avoid extra copy operations.
 * @req holds a reference to vhost, and @hdr value is stored inside that
 * vhost/location description. On reconfiguration a new vhost instance is
 * created instead of alternating its settings in place. So @hdr will valid
 * until request itself is alive.
 *
 * Since h2 requests are always converted to http1 and all headers are
 * recreated from cratch, there is no need to fragment underlying skbs and copy
 * data there, it's enough to put safe pointers inside header table.
 */
static int
__h2_req_hdrs(TfwHttpReq *req, const TfwStr *hdr, unsigned int hid, bool append)
{
	TfwStr *orig_hdr;
	TfwHttpMsg *hm = (TfwHttpMsg *)req;
	TfwHttpHdrTbl *ht = hm->h_tbl;
	TfwMsgParseIter *it = &req->pit;
	const TfwStr *s_val = TFW_STR_CHUNK(hdr, 1);

	if (WARN_ON_ONCE(!ht))
		return -EINVAL;

	if (unlikely(append && hid < TFW_HTTP_HDR_NONSINGULAR)) {
		T_WARN("Appending to singular header %d\n", hid);
		return -ENOENT;
	}

	if (hid < TFW_HTTP_HDR_RAW) {
		orig_hdr = &ht->tbl[hid];
		/*
		 * Insert special header if empty and exit if we have nothing
		 * to insert.
		 */
		if (TFW_STR_EMPTY(orig_hdr)) {
			if (unlikely(!s_val))
				return 0;
			++it->hdrs_cnt;
			it->hdrs_len += hdr->len;
			*orig_hdr = *hdr;
			return 0;
		}
	}
	else {
		hid = __http_hdr_lookup(hm, hdr);
		if (hid == ht->off && !s_val)
			/*
			 * The raw header not found, and there is nothing
			 * to delete.
			 */
			return 0;
		if (unlikely(hid == ht->size)) {
			if (tfw_http_msg_grow_hdr_tbl(hm))
				return -ENOMEM;
			ht = hm->h_tbl;
		}
		if (hid == ht->off) {
			/*
			 * The raw header not found, but we have the new
			 * header to insert.
			 */
			++ht->off;
			++it->hdrs_cnt;
			it->hdrs_len += hdr->len;
			ht->tbl[hid] = *hdr;
			return 0;
		}
		orig_hdr = &ht->tbl[hid];
	}

	BUG_ON(TFW_STR_EMPTY(orig_hdr));
	/*
	 * The original header exists, but we have nothing to insert, thus,
	 * the original header should be evicted.
	 */
	if (!s_val) {
		__h2_hdrs_dup_decrease(req, orig_hdr);
		TFW_STR_INIT(orig_hdr);
		return 0;
	}

	if (append) {
		TfwStr h_app = {
			.chunks = (TfwStr []){
				{ .data = ", ",		.len = 2 },
				{ .data = s_val->data,	.len = s_val->len }
			},
			.len = s_val->len + 2,
			.nchunks = 2
		};
		/*
		 * Concatenate only the first duplicate header, there is no need
		 * to produce more duplicates.
		 */
		if (TFW_STR_DUP(orig_hdr))
			orig_hdr = __TFW_STR_CH(orig_hdr, 0);

		it->hdrs_len += h_app.len;
		return tfw_strcat(req->pool, orig_hdr, &h_app);
	}
	/*
	 * The remaining case is the substitution, since we have both: existing
	 * original header and the new header to insert.
	 */
	__h2_hdrs_dup_decrease(req, orig_hdr);
	++it->hdrs_cnt;
	it->hdrs_len += hdr->len;
	*orig_hdr = *hdr;

	return 0;
}

static int
tfw_h2_req_set_loc_hdrs(TfwHttpReq *req)
{
	int i;
	TfwHdrMods *h_mods = tfw_vhost_get_hdr_mods(req->location, req->vhost,
						    TFW_VHOST_HDRMOD_REQ);
	if (!h_mods)
		return 0;

	for (i = 0; i < h_mods->sz; ++i) {
		int r;
		TfwHdrModsDesc *d = &h_mods->hdrs[i];

		if ((r = __h2_req_hdrs(req, d->hdr, d->hid, d->append)))  {
			T_ERR("HTTP/2: can't update location-specific header in"
			      " the request [%p]\n", req);
			return r;
		}
	}

	return 0;
}

/**
 * Transform h2 request to http1.1 request before forward it to backend server.
 * Usually we prefer in-place header modifications avoid copying, but here
 * we have to insert a lot of information into header, like delimiters between
 * header name and value, and between headers. To avoid creating extreme number
 * of skb fragments we cut off skbs with h2 headers from the beginning of the
 * request and replace them with http1.1 headers.
 *
 * Note, that we keep original headers in h_tbl untouched, since the response
 * may want to access the request headers: the cache subsystem reads `Host`
 * header and `uri` part, also if 'Vary' header controls response
 * representation, any header listed inside 'Vary' one may be also read on
 * response processing (not implemented yet).
 */
static int
tfw_h2_adjust_req(TfwHttpReq *req)
{
	int r;
	TfwMsgParseIter *pit = &req->pit;
	ssize_t h1_hdrs_sz;
	TfwHttpHdrTbl *ht = req->h_tbl;
	bool auth = !TFW_STR_EMPTY(&ht->tbl[TFW_HTTP_HDR_H2_AUTHORITY]);
	bool host = !TFW_STR_EMPTY(&ht->tbl[TFW_HTTP_HDR_HOST]);
	size_t pseudo_num;
	TfwStr meth = {}, host_val = {}, *field, *end;
	struct sk_buff *new_head = NULL, *old_head = NULL;
	TfwMsgIter it;
	const DEFINE_TFW_STR(sp, " ");
	const DEFINE_TFW_STR(dlm, S_DLM);
	const DEFINE_TFW_STR(crlf, S_CRLF);
	const DEFINE_TFW_STR(fl_end, " " S_VERSION11 S_CRLF S_F_HOST);
	char *buf = *this_cpu_ptr(&g_buf);
	char *xff_end = ss_skb_fmt_src_addr(req->msg.skb_head, buf);
	const TfwStr h_xff = {
		.chunks = (TfwStr []){
			{ .data = S_XFF, .len = SLEN(S_XFF) },
			{ .data = S_DLM, .len = SLEN(S_DLM) },
			{ .data = buf, .len = xff_end - buf },
			{ .data = S_CRLF, .len = SLEN(S_CRLF) },
		},
		.len = SLEN(S_XFF) + SLEN(S_DLM) + xff_end - buf + SLEN(S_CRLF),
		.nchunks = 4
	};
	TfwGlobal *g_vhost = tfw_vhost_get_global();
	const TfwStr h_via = {
		.chunks = (TfwStr []) {
			{ .data = S_F_VIA, .len = SLEN(S_F_VIA) },
			{ .data = "1.1 ", .len = 4 },
			{ .data = (char *)g_vhost->hdr_via,
			  .len = g_vhost->hdr_via_len },
			{ .data = S_CRLF, .len = SLEN(S_CRLF) }
		},
		.len = SLEN(S_F_VIA) + 4 + g_vhost->hdr_via_len + SLEN(S_CRLF),
		.nchunks = 4
	};
	const TfwStr h_ct = {
		.chunks = (TfwStr []) {
			{ .data = S_F_CONTENT_TYPE S_V_MULTIPART,
			  .len = SLEN(S_F_CONTENT_TYPE S_V_MULTIPART) },
			req->multipart_boundary_raw,
			{ .data = S_CRLF, .len = SLEN(S_CRLF) }
		},
		.nchunks = 3,
		.len = SLEN(S_F_CONTENT_TYPE S_V_MULTIPART)
			+ req->multipart_boundary_raw.len + SLEN(S_CRLF)
	};
	int h_ct_replace = 0;
	TfwStr h_cl = {0};
	char cl_data[TFW_ULTOA_BUF_SIZ] = {0};
	size_t cl_len = 0;
	/*
	 * The Transfer-Encoding header field cannot be in the h2 request, because
	 * requests with Transfer-Encoding are blocked.
	 */
	bool need_cl = req->body.len &&
	               TFW_STR_EMPTY(&ht->tbl[TFW_HTTP_HDR_CONTENT_LENGTH]);

	if (need_cl) {
		cl_len = tfw_ultoa(req->body.len, cl_data, TFW_ULTOA_BUF_SIZ);
		if (!cl_len)
			return -EINVAL;
		h_cl = (TfwStr) {
			.chunks = (TfwStr []) {
				{ .data = "Content-Length", .len = 14 },
				{ .data = S_DLM, .len = SLEN(S_DLM) },
				{ .data = cl_data, .len = cl_len },
				{ .data = S_CRLF, .len = SLEN(S_CRLF) }
			},
			.len = 14 + SLEN(S_DLM) + cl_len + SLEN(S_CRLF),
			.nchunks = 4
		};
	}

	T_DBG3("%s: req [%p] to be converted to http1.1\n", __func__, req);

	/* H2 client may use either authority or host header but at least one
	 * is required for correct conversion.
	 */
	if (!auth && !host) {
		T_WARN("Cant convert h2 request to http/1.1: no authority "
		       "found\n");
		return -EINVAL;
	}

	/*
	 * First apply message modifications defined by admin in configuration
	 * file. Ideally we should do it at last stage, when h2 headers are
	 * copied into h1 buffer and apply modifications during copying. But
	 * this doesn't allow us to predict h1 headers size before memory
	 * allocation. Header modifications manual on wiki is already has a
	 * warning about performance impact, so just live it as is, a more
	 * robust algorithm will be used here if really required.
	 */
	if ((r = tfw_h2_req_set_loc_hdrs(req)))
		return r;
	/*
	 * tfw_h2_req_set_loc_hdrs() may realloc header table and user may
	 * defined headers modifications, even headers we rely on, recheck them.
	 */
	ht = req->h_tbl;
	auth = !TFW_STR_EMPTY(&ht->tbl[TFW_HTTP_HDR_H2_AUTHORITY]);
	host = !TFW_STR_EMPTY(&ht->tbl[TFW_HTTP_HDR_HOST]);
	pseudo_num = 3; /* Count authority as usual header for now. */
	/*
	 * Calculate http1.1 headers size. H2 request contains pseudo headers
	 * that are represented in different way in the http1.1 requests.
	 * pit->hdrs_cnt is aware of header duplicates. Redirection mark is
	 * ignored and not copied.
	 */
	h1_hdrs_sz = pit->hdrs_len
		+ (pit->hdrs_cnt - pseudo_num) * (SLEN(S_DLM) + SLEN(S_CRLF))
		- req->mark.len;
	/* First request line: remove pseudo headers names, all values are on
	 * the same line.
	 */
	h1_hdrs_sz += (long int)2 + SLEN(S_VERSION11) + SLEN(S_CRLF)
			- ht->tbl[TFW_HTTP_HDR_H2_SCHEME].len
			- SLEN(S_H2_METHOD)
			- SLEN(S_H2_PATH)
			+ SLEN(S_CRLF) /* After headers */;
	/* :authority pseudo header */
	if (auth) {
		/* RFC 7540:
		 * An intermediary that converts an HTTP/2 request to HTTP/1.1
		 * MUST create a Host header field if one is not present in a
		 * request by copying the value of the :authority pseudo-header
		 * field.
		 * AND
		 * Clients that generate HTTP/2 requests directly SHOULD use
		 * the :authority pseudo-header field instead of the Host
		 * header field.
		 */
		if (host) {
			h1_hdrs_sz -= ht->tbl[TFW_HTTP_HDR_HOST].len
					+ SLEN(S_DLM) + SLEN(S_CRLF);
			h1_hdrs_sz -= SLEN(S_H2_AUTH);
			/* S_F_HOST already contains S_DLM */
			h1_hdrs_sz += SLEN(S_F_HOST) - SLEN(S_DLM);
		}
		else {
			h1_hdrs_sz -= SLEN(S_H2_AUTH);
			/* S_F_HOST already contains S_DLM */
			h1_hdrs_sz += SLEN(S_F_HOST) - SLEN(S_DLM);
		}
	}

	/* 'x-forwarded-for' header must be updated. */
	if (!TFW_STR_EMPTY(&ht->tbl[TFW_HTTP_HDR_X_FORWARDED_FOR])) {
		TfwStr *xff_hdr = &ht->tbl[TFW_HTTP_HDR_X_FORWARDED_FOR];
		TfwStr *dup, *dup_end;

		TFW_STR_FOR_EACH_DUP(dup, xff_hdr, dup_end) {
			h1_hdrs_sz -= dup->len + SLEN(S_DLM) + SLEN(S_CRLF);
		}
	}
	h1_hdrs_sz += h_xff.len;
	h1_hdrs_sz += h_via.len;
	if (need_cl)
		h1_hdrs_sz += h_cl.len;

	/*
	 * Conditional substitution/additions of 'content-type' header. This is
	 * singular header, so we can avoid duplicates processing.
	 */
	if (req->method == TFW_HTTP_METH_POST &&
	    test_bit(TFW_HTTP_B_CT_MULTIPART, req->flags) &&
	    tfw_http_should_validate_post_req(req))
	{
		TfwStr *h_ct_old = &ht->tbl[TFW_HTTP_HDR_CONTENT_TYPE];

		if (WARN_ON_ONCE(!TFW_STR_PLAIN(&req->multipart_boundary_raw)
				 || TFW_STR_EMPTY(h_ct_old)))
			return -EINVAL;

		h1_hdrs_sz -= h_ct_old->len + SLEN(S_DLM) + SLEN(S_CRLF);
		h1_hdrs_sz += h_ct.len;
		h_ct_replace = 1;
	}

	if (WARN_ON_ONCE(h1_hdrs_sz < 0))
		return -EINVAL;
	if ((r = tfw_msg_iter_setup(&it, &new_head, h1_hdrs_sz, 0)))
		return r;

	/* First line. */
	__h2_msg_hdr_val(&ht->tbl[TFW_HTTP_HDR_H2_METHOD], &meth);
	r = tfw_msg_write(&it, &meth);
	r |= tfw_msg_write(&it, &sp);
	r |= tfw_msg_write(&it, &req->uri_path);
	r |= tfw_msg_write(&it, &fl_end); /* start of Host: header */
	if (auth)
		__h2_msg_hdr_val(&ht->tbl[TFW_HTTP_HDR_H2_AUTHORITY], &host_val);
	else if (host)
		__h2_msg_hdr_val(&ht->tbl[TFW_HTTP_HDR_HOST], &host_val);
	r |= tfw_msg_write(&it, &host_val);
	r |= tfw_msg_write(&it, &crlf);

	/* Skip host header: it's already written. */
	FOR_EACH_HDR_FIELD_FROM(field, end, req, TFW_HTTP_HDR_REGULAR) {
		TfwStr *dup, *dup_end;

		switch (field - ht->tbl)
		{
		case TFW_HTTP_HDR_HOST:
			continue; /* Already written. */
		case TFW_HTTP_HDR_X_FORWARDED_FOR:
			r |= tfw_msg_write(&it, &h_xff);
			continue;
		case TFW_HTTP_HDR_CONTENT_TYPE:
			if (h_ct_replace) {
				r |= tfw_msg_write(&it, &h_ct);
				continue;
			}
			break;
		default:
			break;
		}

		if (TFW_STR_EMPTY(field))
			continue;
		TFW_STR_FOR_EACH_DUP(dup, field, dup_end) {
			TfwStr *chunk, *chunk_end, hval = {};

			if (unlikely(TFW_STR_PLAIN(dup))) {
				r = -EINVAL;
				goto err;
			}

			hval.chunks = dup->chunks;
			TFW_STR_FOR_EACH_CHUNK(chunk, dup, chunk_end) {
				if (chunk->flags & TFW_STR_HDR_VALUE)
					break;
				hval.nchunks++;
				hval.len += chunk->len;
			}
			r |= tfw_msg_write(&it, &hval);
			r |= tfw_msg_write(&it, &dlm);
			hval.chunks += hval.nchunks;
			hval.nchunks = dup->nchunks - hval.nchunks;
			hval.len = dup->len - hval.len;
			r |= tfw_msg_write(&it, &hval);

			r |= tfw_msg_write(&it, &crlf);
		}
		if (unlikely(r))
			goto err;
	}

	r |= tfw_msg_write(&it, &h_via);
	if (need_cl)
		r |= tfw_msg_write(&it, &h_cl);
	/* Finally close headers. */
	r |= tfw_msg_write(&it, &crlf);

	if (unlikely(r))
		goto err;

	T_DBG3("%s: req [%p] converted to http1.1\n", __func__, req);

	old_head = req->msg.skb_head;
	req->msg.skb_head = new_head;

	/* Http chains might add a mark for the message, keep it. */
	new_head->mark = old_head->mark;

	if (!TFW_STR_EMPTY(&req->body)) {
		/*
		 * Request has a body. we have to detach it from the old
		 * skb_head and append to a new one. There might be trailing
		 * headers after the body, but we're already copied them before
		 * body. This is not a problem, but we have to drop the trailer
		 * part after the body to avoid sending the same headers twice.
		 *
		 * Body travels in a separate DATA frame thus it's always in
		 * it's own skb.
		 */
		struct sk_buff *b_skbs = old_head, *trailer;
		size_t len = 0;

		do {
			b_skbs = b_skbs->next;
			if (WARN_ON_ONCE((b_skbs == old_head)))
				goto err;
		} while (b_skbs != req->body.skb);

		ss_skb_queue_split(old_head, b_skbs);
		trailer = b_skbs;
		do {
			len += trailer->len;
			trailer = trailer->next;

		} while ((trailer != b_skbs) && (len != req->body.len));
		ss_skb_queue_append(&req->msg.skb_head, b_skbs);
		if (trailer != b_skbs) {
			ss_skb_queue_split(req->msg.skb_head, trailer);
			ss_skb_queue_append(&old_head, trailer);
		}
	}
	ss_skb_queue_purge(&old_head);

	return 0;
err:
	ss_skb_queue_purge(&new_head);
	T_DBG3("%s: req [%p] convertation to http1.1 has failed\n",
	       __func__, req);
	return r;
}

/**
 * Adjust the response before proxying it to real client.
 */
static int
tfw_http_adjust_resp(TfwHttpResp *resp)
{
	TfwHttpReq *req = resp->req;
	TfwHttpMsg *hm = (TfwHttpMsg *)resp;
	unsigned long conn_flg = 0;
	int r;

	/*
	 * If request violated backend rules, backend may respond with 4xx code
	 * and close connection to Tempesta. Don't encourage client to send
	 * more such requests and cause performance degradation, close the
	 * client connection.
	 */
	if (test_bit(TFW_HTTP_B_CONN_CLOSE, resp->flags)
	    && (resp->status / 100 == 4))
	{
		tfw_http_req_set_conn_close(req);
		conn_flg = BIT(TFW_HTTP_B_CONN_CLOSE);
	}
	else
	{
		if (unlikely(test_bit(TFW_HTTP_B_CONN_CLOSE, req->flags)))
			conn_flg = BIT(TFW_HTTP_B_CONN_CLOSE);
		else if (test_bit(TFW_HTTP_B_CONN_KA, req->flags))
			conn_flg = BIT(TFW_HTTP_B_CONN_KA);
	}

	r = tfw_http_sess_resp_process(resp, false);
	if (r < 0)
		return r;

	r = tfw_http_msg_del_hbh_hdrs(hm);
	if (r < 0)
		return r;

	r = tfw_http_set_hdr_keep_alive(hm, conn_flg);
	if (r < 0)
		return r;

	r = tfw_http_set_hdr_connection(hm, conn_flg);
	if (r < 0)
		return r;

	r = tfw_http_add_hdr_via(hm);
	if (r < 0)
		return r;

	r = tfw_h1_set_loc_hdrs(hm, true, false);
	if (r < 0)
		return r;

	if (!test_bit(TFW_HTTP_B_HDR_DATE, resp->flags)) {
		r = tfw_http_set_hdr_date(hm);
		if (r < 0)
			return r;
	}

	r = TFW_HTTP_MSG_HDR_XFRM(hm, "Server", TFW_NAME "/" TFW_VERSION,
				     TFW_HTTP_HDR_SERVER, 0);
	if (r < 0)
		return r;

	/* Frame response if framing information was lost or absent. */
	return tfw_http_msg_frame_h1_msg(hm);
}

/*
 * Forward responses in @ret_queue to the client in correct order.
 *
 * In case of error the client connection must be closed immediately.
 * Otherwise, the correct order of responses will be broken. Unsent
 * responses are taken care of by the caller.
 */
static void
__tfw_http_resp_fwd(TfwCliConn *cli_conn, struct list_head *ret_queue)
{
	TfwHttpReq *req, *tmp;

	list_for_each_entry_safe(req, tmp, ret_queue, msg.seq_list) {
		BUG_ON(!req->resp);
		tfw_http_resp_init_ss_flags(req->resp);
		if (tfw_cli_conn_send(cli_conn, (TfwMsg *)req->resp)) {
			tfw_connection_close((TfwConn *)cli_conn, true);
			return;
		}
		list_del_init(&req->msg.seq_list);
		tfw_http_resp_pair_free(req);
		TFW_INC_STAT_BH(serv.msgs_forwarded);
	}
}

/*
 * Mark @resp as ready to transmit. Then, starting with the first request
 * in @seq_queue, pick consecutive requests that have response ready to
 * transmit. Move those requests to the list of returned responses
 * @ret_queue. Sequentially send responses from @ret_queue to the client.
 */
void
tfw_http_resp_fwd(TfwHttpResp *resp)
{
	TfwHttpReq *req = resp->req;
	TfwCliConn *cli_conn = (TfwCliConn *)req->conn;
	struct list_head *seq_queue = &cli_conn->seq_queue;
	struct list_head *req_retent = NULL;
	LIST_HEAD(ret_queue);

	T_DBG2("%s: req=[%p], resp=[%p]\n", __func__, req, resp);
	WARN_ON_ONCE(req->resp != resp);

	/*
	 * If the list is empty, then it's either a bug, or the client
	 * connection had been closed. If it's a bug, then the correct
	 * order of responses to requests may be broken. The connection
	 * with the client must be closed immediately.
	 *
	 * Doing ss_close() on client connection's socket is safe
	 * as long as @req that holds a reference to the connection is
	 * not freed.
	 */
	spin_lock_bh(&cli_conn->seq_qlock);
	if (unlikely(list_empty(seq_queue))) {
		BUG_ON(!list_empty(&req->msg.seq_list));
		spin_unlock_bh(&cli_conn->seq_qlock);
		T_DBG2("%s: The client was disconnected, drop resp and req: "
		       "conn=[%p]\n",
			 __func__, cli_conn);
		tfw_connection_close(req->conn, true);
		tfw_http_resp_pair_free(req);
		TFW_INC_STAT_BH(serv.msgs_otherr);
		return;
	}
	BUG_ON(list_empty(&req->msg.seq_list));
	set_bit(TFW_HTTP_B_RESP_READY, resp->flags);
	/* Move consecutive requests with @req->resp to @ret_queue. */
	list_for_each_entry(req, seq_queue, msg.seq_list) {
		if (!req->resp
		    || !test_bit(TFW_HTTP_B_RESP_READY, req->resp->flags))
		{
			break;
		}
		req_retent = &req->msg.seq_list;
	}
	if (!req_retent) {
		spin_unlock_bh(&cli_conn->seq_qlock);
		return;
	}
	__list_cut_position(&ret_queue, seq_queue, req_retent);

	/*
	 * The function may be called concurrently on different CPUs,
	 * all going for the same client connection. In some threads
	 * a response is paired with a request, but the first response
	 * in the queue is not ready yet, so it can't be sent out. When
	 * there're responses to send, sending must be in correct order
	 * which is controlled by the lock. To avoid delays in progress
	 * of other threads during responses sending, unlock the seq_queue
	 * lock and use different lock @ret_qlock for sending.
	 *
	 * A client may close the connection at any time. A connection
	 * is destroyed when the last reference goes, so the argument
	 * to spin_unlock() may get invalid. Hold the connection until
	 * sending is done.
	 *
	 * TODO: There's a lock contention here as multiple threads/CPUs
	 * go for the same client connection's queue. Perhaps there's a
	 * better way of doing this that is more effective. Please see
	 * the TODO comment above and to the function tfw_http_popreq().
	 * Also, please see the issue #687.
	 *
	 * TODO #687: this is the only place where req_qlock is used. Instead
	 * of competing for the lock from different softirqs, just process
	 * the next available response, set a flag for current softirq
	 * processing ret_queue and make the current softirq retry from
	 * determination of req_retent.
	 */
	tfw_connection_get((TfwConn *)(cli_conn));
	spin_lock_bh(&cli_conn->ret_qlock);
	spin_unlock_bh(&cli_conn->seq_qlock);

	__tfw_http_resp_fwd(cli_conn, &ret_queue);

	spin_unlock_bh(&cli_conn->ret_qlock);
	tfw_connection_put((TfwConn *)(cli_conn));

	/* Zap request/responses that were not sent due to an error. */
	if (!list_empty(&ret_queue)) {
		TfwHttpReq *tmp;
		list_for_each_entry_safe(req, tmp, &ret_queue, msg.seq_list) {
			T_DBG2("%s: Forwarding error: conn=[%p] resp=[%p]\n",
			       __func__, cli_conn, req->resp);
			BUG_ON(!req->resp);
			list_del_init(&req->msg.seq_list);
			tfw_http_resp_pair_free(req);
			TFW_INC_STAT_BH(serv.msgs_otherr);
		}
	}
}

int
tfw_h2_hdr_map(TfwHttpResp *resp, const TfwStr *hdr, unsigned int id)
{
	TfwHdrIndex *index;
	TfwHttpHdrMap *map = resp->mit.map;

	if (id >= (1 << TFW_IDX_BITS) || hdr->nchunks > (1 << TFW_D_IDX_BITS)) {
		T_WARN("HTTP/2: too many headers (duplicates) in"
		       " HTTP/1.1-response (header id: %u, header dups: %u\n",
		       id, hdr->nchunks);
		return -EINVAL;
	}

	T_DBG3("%s: id=%u, hdr->nchunks=%u, map->size=%u, map->count=%u\n",
	       __func__, id, hdr->nchunks, map->size, map->count);

	if (unlikely(map->count == map->size)) {
		unsigned int new_size = map->size << 1;

		map = tfw_pool_realloc(resp->pool, map,
				       TFW_HDR_MAP_SZ(map->size),
				       TFW_HDR_MAP_SZ(new_size));
		if (!map) {
			T_WARN("HTTP/2: unable to reallocate memory for"
			       " response header map\n");
			return -ENOMEM;
		}

		map->size = new_size;
		resp->mit.map = map;

		BUG_ON(map->count >= map->size);
		T_DBG3("%s: expanded map, map->size=%u, map->count=%u\n",
		       __func__, map->size, map->count);
	}

	index = &map->index[map->count];
	index->idx = id;
	index->d_idx = TFW_STR_DUP(hdr) ? hdr->nchunks - 1 : 0;
	++map->count;

	return 0;
}

/*
 * Same as @tfw_http_add_hdr_via(), but intended for usage in HTTP/1.1=>HTTP/2
 * transformation.
 */
static int
tfw_h2_add_hdr_via(TfwHttpResp *resp)
{
	int r;
	TfwGlobal *g_vhost = tfw_vhost_get_global();
	TfwStr via = {
		.chunks = (TfwStr []) {
			{ .data = S_VIA, .len = SLEN(S_VIA) },
			{ .data = S_VIA_H2_PROTO, .len = SLEN(S_VIA_H2_PROTO) },
			{ .data = *this_cpu_ptr(&g_buf),
			  .len = g_vhost->hdr_via_len },
		},
		.len = SLEN(S_VIA) + SLEN(S_VIA_H2_PROTO) + g_vhost->hdr_via_len,
		.nchunks = 3
	};

	memcpy_fast(__TFW_STR_CH(&via, 2)->data, g_vhost->hdr_via,
		    g_vhost->hdr_via_len);

	via.hpack_idx = 60;

	r = tfw_hpack_encode(resp, &via, TFW_H2_TRANS_ADD, true);
	if (unlikely(r))
		T_ERR("HTTP/2: unable to add 'via' header (resp=[%p])\n", resp);
	else
		T_DBG3("%s: added 'via' header, resp=[%p]\n", __func__, resp);
	return r;
}

/*
 * Same as @tfw_http_set_hdr_date(), but intended for usage in HTTP/1.1=>HTTP/2
 * transformation.
 */
int
tfw_h2_add_hdr_date(TfwHttpResp *resp, TfwH2TransOp op, bool cache)
{
	int r;
	char *s_date = *this_cpu_ptr(&g_buf);
	TfwStr hdr = {
		.chunks = (TfwStr []){
			{ .data = "date", .len = SLEN("date") },
			{ .data = s_date, .len = SLEN(S_V_DATE) },
		},
		.len = SLEN("date") + SLEN(S_V_DATE),
		.nchunks = 2
	};

	tfw_http_prep_date_from(s_date, resp->date);

	hdr.hpack_idx = 33;

	r = tfw_hpack_encode(resp, &hdr, op, !cache);
	if (unlikely(r))
		T_ERR("HTTP/2: unable to add 'date' header to response"
			" [%p]\n", resp);
	else
		T_DBG3("%s: added 'date' header, resp=[%p]\n", __func__, resp);

	return r;
}

/*
 * In case if response is stale, we should pass it with a warning.
 */
int
tfw_h2_set_stale_warn(TfwHttpResp *resp)
{
	TfwStr wh = {
		.chunks = (TfwStr []){
			{ .data = S_WARN, .len = SLEN(S_WARN) },
			{ .data = S_V_WARN, .len = SLEN(S_V_WARN) }
		},
		.len = SLEN(S_WARN) + SLEN(S_V_WARN),
		.nchunks = 2
	};

	return tfw_hpack_encode(resp, &wh, TFW_H2_TRANS_EXPAND, false);
}

/*
 * Split header into two parts: name and value, evicting ':' and OWS. Return
 * the resulting length of both parts.
 *
 * NOTE: this function is intended for response processing only (during
 * HTTP/1.1=>HTTP/2 transformation), since the response HTTP parser
 * supports splitting the header name, colon, LWS, value and RWS into
 * different chunks.
 */
unsigned long
tfw_http_hdr_split(TfwStr *hdr, TfwStr *name_out, TfwStr *val_out, bool inplace)
{
	unsigned long hdr_tail = 0;
	TfwStr *chunk, *end, *last_chunk = NULL;
	bool name_found = false, val_found = false;

	BUG_ON(!TFW_STR_EMPTY(name_out) || !TFW_STR_EMPTY(val_out));

	if (WARN_ON_ONCE(TFW_STR_PLAIN(hdr)))
		return 0;

	if (TFW_STR_EMPTY(hdr))
		return 0;

	if (!inplace) {
		unsigned long off = 0;
		/*
		 * During headers addition (or message expansion) the source
		 * @hdr must have the following chunk structure (without the
		 * OWS):
		 *
		 *	{ name [S_DLM] value1 [value2 [value3 ...]] }.
		 *
		 */
		*name_out = *hdr->chunks;

		chunk = TFW_STR_CHUNK(hdr, 1);
		if (WARN_ON_ONCE(!chunk))
			return 0;

		if (chunk->len == SLEN(S_DLM)
		    && *(short *)chunk->data == *(short *)S_DLM)
		{
			off = SLEN(S_DLM);
			chunk = TFW_STR_CHUNK(hdr, 2);
			if (WARN_ON_ONCE(!chunk))
				return 0;
		}

		val_out->chunks = chunk;
		val_out->nchunks = hdr->chunks + hdr->nchunks - chunk;
		val_out->len = hdr->len - name_out->len - off;

		return hdr->len - off;
	}

	name_out->chunks = hdr->chunks;

	TFW_STR_FOR_EACH_CHUNK(chunk, hdr, end) {
		if (!chunk->len)
			continue;

		if (!name_found) {
			if (chunk->data[0] == ':') {
				WARN_ON_ONCE(chunk->len != 1);
				name_found = true;
			} else {
				++name_out->nchunks;
				name_out->len += chunk->len;
			}
			continue;
		}

		/*
		 * LWS is always in the separate chunks between the name and
		 * value; thus, we can skip length of the entire (LWS) chunks.
		 */
		if (!val_found) {
			if (unlikely(chunk->flags & TFW_STR_OWS))
				continue;

			val_out->chunks = chunk;
			val_found = true;
		}

		val_out->len += chunk->len;

		/* 
		 * Skip OWS after the header value (RWS) - they must be in
		 * separate chunks too.
		 */
		if (unlikely(chunk->flags & TFW_STR_OWS)) {
			hdr_tail += chunk->len;
		} else {
			last_chunk = chunk;
			hdr_tail = 0;
		}
	}

	/* The header value is empty. */
	if (unlikely(!val_found))
		return name_out->len;

	if (WARN_ON_ONCE(!last_chunk))
		return 0;

	T_DBG3("%s: hdr_tail=%lu, val_out->len=%lu, last_chunk->len=%lu,"
	       " last_chunk->data='%.*s'\n", __func__, hdr_tail, val_out->len,
	       last_chunk->len, (int)last_chunk->len, last_chunk->data);

	val_out->nchunks = last_chunk - val_out->chunks + 1;
	val_out->len -= hdr_tail;

	return name_out->len + val_out->len;
}

unsigned long
tfw_h2_hdr_size(unsigned long n_len, unsigned long v_len,
		unsigned short st_index)
{
	unsigned long size;

	if (st_index) {
		size = tfw_hpack_int_size(st_index, 0xF);
	} else {
		size = 1;
		size += tfw_hpack_int_size(n_len, 0x7F);
		size += n_len;
	}
	size += tfw_hpack_int_size(v_len, 0x7F);
	size += v_len;

	return size;
}

int
tfw_h2_resp_add_loc_hdrs(TfwHttpResp *resp, const TfwHdrMods *h_mods,
			 bool cache)
{
	unsigned int i;
	TfwHttpTransIter *mit = &resp->mit;
	TfwH2TransOp op = cache ? TFW_H2_TRANS_EXPAND : TFW_H2_TRANS_ADD;

	if (!h_mods)
		return 0;

	for (i = 0; i < h_mods->sz; ++i) {
		const TfwHdrModsDesc *desc = &h_mods->hdrs[i];
		int r;

		if (test_bit(i, mit->found) || !TFW_STR_CHUNK(desc->hdr, 1))
			continue;

		r = tfw_hpack_encode(resp, desc->hdr, op, !cache);
		if (unlikely(r))
			return r;
	}

	return 0;
}

/*
 * Get next header from the @mit->map. Procedure designed to be called from the
 * outer cycle with changing of @mit iterator (including @mit->curr index of
 * current header in the indirection map). Note, for optimization purposes, on
 * each iteration function produces the boundary pointer @mit->bnd for current
 * iteration and the operation instance @mit->next - for the next iteration
 * (including source header @mit->next.s_hdr).
 *
 * TODO #1103: This function should be treated as a foundation for #1103 issue.
 */
static int
tfw_h2_resp_next_hdr(TfwHttpResp *resp, const TfwHdrMods *h_mods)
{
	int r;
	unsigned int i;
	TfwHttpTransIter *mit = &resp->mit;
	TfwHttpHdrMap *map = mit->map;
	TfwNextHdrOp *next = &mit->next;
	TfwHttpHdrTbl *ht = resp->h_tbl;

	mit->bnd = NULL;

	for (i = mit->curr; i < map->count; ++i) {
		int k;
		TfwStr *first;
		unsigned short hid = map->index[i].idx;
		unsigned short d_num = map->index[i].d_idx;
		TfwStr *tgt = &ht->tbl[hid];
		TfwHdrModsDesc *f_desc = NULL;
		const TfwStr *val;

		if (TFW_STR_DUP(tgt))
			tgt = TFW_STR_CHUNK(tgt, d_num);

		first = TFW_STR_CHUNK(tgt, 0);

		if (WARN_ON_ONCE(!tgt
				 || TFW_STR_EMPTY(tgt)
				 || TFW_STR_DUP(tgt)))
			return -EINVAL;

		T_DBG3("%s: hid=%hu, d_num=%hu, nchunks=%u, h_mods->sz=%lu\n",
		       __func__, hid, d_num, ht->tbl[hid].nchunks,
		       h_mods ? h_mods->sz : 0);

		if (!h_mods)
			goto def;

		for (k = 0; k < h_mods->sz; ++k) {
			TfwHdrModsDesc *desc = &h_mods->hdrs[k];

			if ((hid < TFW_HTTP_HDR_RAW && hid == desc->hid)
			    || (hid >= TFW_HTTP_HDR_RAW
				&& !__hdr_name_cmp(tgt, desc->hdr)))
			{
				f_desc = desc;
				break;
			}
		}
		if (!f_desc)
			goto def;

		val = TFW_STR_CHUNK(f_desc->hdr, 2);
		/*
		 * If this is a duplicate of already processed header,
		 * leave this duplicate as is (for transformation
		 * in-place) in case of appending operation, and remove
		 * it (by skipping) in case of substitution or deletion
		 * operations.
		 */
		if (test_bit(k, mit->found)) {
			if (!val || !f_desc->append)
				continue;

			mit->bnd = first->data;
			next->s_hdr = *tgt;
			next->op = TFW_H2_TRANS_INPLACE;

			break;
		}

		__set_bit(k, mit->found);

		/*
		 * If header configured with empty value, it should be
		 * removed from the response; so, just skip such header.
		 */
		if (!val)
			continue;

		mit->bnd = first->data;

		/*
		 * If the header configured for value appending,
		 * concatenate it with the target header in skb for
		 * subsequent in-place rewriting.
		 */
		if (f_desc->append) {
			TfwStr h_app = {
				.chunks = (TfwStr []){
					{ .data = ", ", .len = 2 },
					{ .data = val->data,
					  .len = val->len }
				},
				.len = val->len + 2,
				.nchunks = 2
			};

			r = tfw_strcat(resp->pool, tgt, &h_app);
			if (unlikely(r))
				return r;

			next->s_hdr = *tgt;
			next->op = TFW_H2_TRANS_INPLACE;
			break;
		}

		next->s_hdr = *f_desc->hdr;
		next->op = TFW_H2_TRANS_SUB;
		break;

def:
		/*
		 * Remove 'Connection', 'Keep-Alive' headers and all hop-by-hop
		 * headers from the HTTP/2 response.
		 */
		if (hid == TFW_HTTP_HDR_KEEP_ALIVE
		    || hid == TFW_HTTP_HDR_CONNECTION
		    || tgt->flags & TFW_STR_HBH_HDR)
			continue;

		/*
		 * 'Server' header must be replaced; thus, remove the original
		 * header (and all its duplicates) skipping it here; the new
		 * header will be written later, during new headers' addition
		 * stage.
		 */
		if (hid == TFW_HTTP_HDR_SERVER)
			continue;

		/*
		 * In general case the header should be transformed in-place
		 * from its original HTTP/1.1-representation in skb.
		 */
		mit->bnd = first->data;
		next->s_hdr = *tgt;
		next->op = TFW_H2_TRANS_INPLACE;

		break;
	}

	mit->curr = i + 1;

	return 0;
}

#define __tfw_h2_make_frames(len, hdr_flags)				\
do {									\
	r = tfw_msg_iter_move(iter, (unsigned char **)&data,		\
			      max_sz + skew);				\
	if (r)								\
		return r;						\
	/*								\
	 * Each frame header is inserted before given data pointer,	\
	 * skip it. Exception - first move operation: @data is set right\
	 * after frame header.						\
	 */								\
	skew = sizeof(buf);						\
									\
	frame_hdr.length = min(max_sz, (len));				\
	(len) -= frame_hdr.length;					\
	frame_hdr.flags = (len) ?  0 : (hdr_flags);			\
	tfw_h2_pack_frame_header(buf, &frame_hdr);			\
									\
	r = tfw_http_msg_insert(iter, &data, &frame_hdr_str);		\
	if (unlikely(r)) 						\
		return r;						\
} while ((len));

/**
 * Split response body stored locally. Allocate a new skb and put body there
 * by fragments. Every skb fragment has size of single page and has frame
 * header at the beginning. Just like body constructed in
 * @tfw_cache_build_resp_body().
 *
 * The function is designed for @body preallocated during configuration
 * processing thus no chunked body allowed, only plain TfwStr is accepted there.
 */
static int
tfw_h2_append_predefined_body(TfwHttpResp *resp, unsigned int stream_id,
			      const TfwStr *body)
{
	TfwHttpTransIter *mit = &resp->mit;
	TfwMsgIter *it = &mit->iter;
	size_t len, max_copy = PAGE_SIZE - FRAME_HEADER_SIZE;
	TfwFrameHdr frame_hdr = {.stream_id = stream_id, .type = HTTP2_DATA};
	char *data;
	int r;

	if (!body || !body->data)
		return 0;
	if (!TFW_STR_PLAIN(body))
		return -EINVAL;
	len = body->len;

	if (!(it->skb = ss_skb_peek_tail(&it->skb_head)))
		return -EINVAL;
	it->frag = skb_shinfo(it->skb)->nr_frags - 1;

	if ((it->frag + 1 >= MAX_SKB_FRAGS)
	    || (skb_shinfo(it->skb)->tx_flags & SKBTX_SHARED_FRAG))
	{
		if  ((r = tfw_msg_iter_append_skb(it)))
			return r;
		skb_shinfo(it->skb)->tx_flags &= ~SKBTX_SHARED_FRAG;
	}

	data = body->data;
	while (len) {
		struct page *page;
		char *p;
		size_t copy = min(len, max_copy);

		len -= copy;
		frame_hdr.flags = len ? 0 : HTTP2_F_END_STREAM;
		frame_hdr.length = copy;

		if (!(page = alloc_page(GFP_ATOMIC))) {
			return -ENOMEM;
		}
		p = page_address(page);
		tfw_h2_pack_frame_header(p, &frame_hdr);
		memcpy_fast(p + FRAME_HEADER_SIZE, data, copy);
		data += copy;

		++it->frag;
		skb_fill_page_desc(it->skb, it->frag, page, 0,
				   copy + FRAME_HEADER_SIZE);
		skb_frag_ref(it->skb, it->frag);
		ss_skb_adjust_data_len(it->skb, copy + FRAME_HEADER_SIZE);

		if (it->frag + 1 == MAX_SKB_FRAGS
		    && (r = tfw_msg_iter_append_skb(it)))
		{
			return r;
		}
	}

	return 0;
}

/**
 * Split response into http/2 frames with respect to remote peer MAX_FRAME_SIZE
 * settings. Both HEADERS and DATA frames require framing or peer will reject
 * the message or entire connection.
 *
 * @resp		- response to be framed.
 * @stream_id		- HTTP/2 stream id.
 * @h_len		- total length of HTTP headers.
 * @local_response	- response is generated locally by Tempesta,
 *			  all foreign responses represents responses converted
 *			  from h1 to h2 and require some additional processing.
 * @local_body		- locally generated response has a body which not yet
 *			  added into response and even not addressed by
 *			  resp->body.
 *
 * WARNING: this function manually inserts fragments containing h2 frame headers
 * (9 bytes each), which are NOT tracked by the @resp handler and cannot be
 * addressed and modified directly. This function must be the LAST step before
 * message is pushed into network. No stream id modification, no header
 * adjustments are allowed after the call.
 *
 * The only case when message can be modified - body addition for locally
 * generated responses, which add body fragment-by-fragment with required
 * framing information.
 */
static int
tfw_h2_make_frames(TfwHttpResp *resp, unsigned int stream_id,
		   unsigned long h_len, bool local_response,
		   bool local_body)
{
	int r;
	char *data;
	unsigned long b_len = resp->body.len;
	unsigned char buf[FRAME_HEADER_SIZE];
	TfwFrameHdr frame_hdr = {.stream_id = stream_id};
	const TfwStr frame_hdr_str = { .data = buf, .len = sizeof(buf)};
	TfwHttpTransIter *mit = &resp->mit;
	TfwMsgIter *iter = &mit->iter;
	TfwH2Ctx *ctx = tfw_h2_context(resp->req->conn);
	unsigned long max_sz = ctx->rsettings.max_frame_sz;
	unsigned char fr_flags = (b_len || local_body)
			? HTTP2_F_END_HEADERS
			: HTTP2_F_END_HEADERS | HTTP2_F_END_STREAM;

	T_DBG2("%s: frame response with max frame size of %lu\n",
	       __func__, max_sz);
	/*
	 * First frame header before HEADERS block. A data enough to store
	 * the header is reserved at the beginning of the skb data.
	 */
	if (WARN_ON_ONCE(!(skb_headlen(resp->msg.skb_head))))
		return -ENOMEM;
	frame_hdr.type = HTTP2_HEADERS;
	frame_hdr.length = min(max_sz, h_len);
	frame_hdr.flags = (h_len <= max_sz) ? fr_flags : 0;
	tfw_h2_pack_frame_header(buf, &frame_hdr);
	data = resp->msg.skb_head->data;
	memcpy_fast(data, buf, sizeof(buf));

	/*
	 * In responses built locally headers fragments are added one by one
	 * when needed, while forwarded responses may have extra space after
	 * h1-> h2 transformation, since h2 messages are generally smaller
	 * than h1 ones. When this function is called, all headers just have
	 * been added and message iterator points at the end of the last header
	 * and protected from overwriting body. Use this immediately to put the
	 * first body hrame header and cut extra data after it. It's possible
	 * to do in reverse order, but we save a few fragment operations here.
	 */
	if (!local_response) {
		if (b_len) {
			frame_hdr.length = min(max_sz, b_len);
			frame_hdr.type = HTTP2_DATA;
			frame_hdr.flags = (frame_hdr.length == b_len)
					? HTTP2_F_END_STREAM : 0;
			tfw_h2_pack_frame_header(buf, &frame_hdr);

			r = tfw_h2_msg_rewrite_data(mit, &frame_hdr_str,
						    mit->bnd);
			if (unlikely(r))
				return r;
		}

		r = ss_skb_cut_extra_data(iter->skb_head, iter->skb, iter->frag,
					  mit->curr_ptr, mit->bnd);
		if (unlikely(r))
			return r;
	}

	/* Add more frame headers for HEADER block. */
	if (h_len > max_sz) {
		unsigned long skew = sizeof(buf);

		iter->skb = resp->msg.skb_head;
		iter->frag = -1; /* Already checked that skb_head is linear. */
		data = iter->skb->data;

		h_len -= max_sz;
		frame_hdr.type = HTTP2_CONTINUATION;
		__tfw_h2_make_frames(h_len, fr_flags);
	}

	if (local_response)
		return 0;

	/* Add more frame headers for DATA block. */
	if (b_len > max_sz) {
		unsigned long skew = 0;

		iter->skb = resp->body.skb;
		data = TFW_STR_CHUNK(&resp->body, 0)->data;
		if ((r = tfw_http_iter_set_at(iter, data)))
			return r;

		b_len -= max_sz;
		frame_hdr.type = HTTP2_DATA;
		__tfw_h2_make_frames(b_len, HTTP2_F_END_STREAM);
	}

	return 0;
}

/**
 * Frame forwarded response.
 */
int
tfw_h2_frame_fwd_resp(TfwHttpResp *resp, unsigned int stream_id,
		     unsigned long h_len)
{
	return tfw_h2_make_frames(resp, stream_id, h_len, false, false);
}

/**
 * Frame response generated locally.
 */
int
tfw_h2_frame_local_resp(TfwHttpResp *resp, unsigned int stream_id,
		       unsigned long h_len, const TfwStr *body)
{
	int r;

	r = tfw_h2_make_frames(resp, stream_id, h_len, true,
			       body ? body->len : false);
	if (r)
		return r;

	return tfw_h2_append_predefined_body(resp, stream_id, body);
}

static void
tfw_h1_resp_adjust_fwd(TfwHttpResp *resp)
{
	TfwHttpReq *req = resp->req;

	/*
	 * A client can disconnect at any time after the request was
	 * forwarded to backend. In this case the response will never be sent
	 * to the client. Keep the response until it's saved in the cache,
	 * so other clients can served from cache. After response is saved to
	 * cache it can be dropped.
	 */
	if (unlikely(test_bit(TFW_HTTP_B_REQ_DROP, req->flags))) {
		T_DBG2("%s: resp=[%p] dropped: client disconnected\n",
		       __func__, resp);
		tfw_http_resp_pair_free(req);
		return;
	}
	/*
	 * Typically we're at a node far from the node where @resp was
	 * received, so we do an inter-node transfer. However, this is
	 * the final place where the response will be stored. Upcoming
	 * requests will get responded to by the current node without
	 * inter-node data transfers. (see tfw_http_req_cache_cb())
	 */
	if (tfw_http_adjust_resp(resp)) {
		tfw_http_conn_msg_free((TfwHttpMsg *)resp);
		tfw_http_send_resp(req, 500,
				   "response dropped: processing error");
		TFW_INC_STAT_BH(serv.msgs_otherr);
		return;
	}
	tfw_http_resp_fwd(resp);
}

/**
 * Error happen, current request @req will be discarded. Connection should
 * be closed after response for the previous request is sent.
 *
 * Returns true, if the connection will be automatically closed with the
 * last response sent. Returns false, if there are no responses to forward
 * and manual connection close action is required.
 */
static bool
tfw_http_req_prev_conn_close(TfwHttpReq *req)
{
	TfwCliConn *cli_conn = (TfwCliConn *)req->conn;
	TfwHttpReq *last_req = NULL;
	struct list_head *prev;

	spin_lock(&cli_conn->seq_qlock);
	/*
	 * The request may be not stored in any lists. There are several reasons
	 * for this:
	 * - Error happened during request parsing. Client connection is alive.
	 * - Error happened during response processing, but the client
	 * connection is already closed, and the request is marked as dropped.
	 */
	prev = (!list_empty(&req->msg.seq_list)) ? req->msg.seq_list.prev
						 : cli_conn->seq_queue.prev;
	if (prev != &cli_conn->seq_queue) {
		last_req = list_entry(prev, TfwHttpReq, msg.seq_list);
		tfw_http_req_set_conn_close(last_req);
	}

	spin_unlock(&cli_conn->seq_qlock);

	return last_req;
}

static void
tfw_http_conn_error_log(TfwConn *conn, const char *msg)
{
	if (!(tfw_blk_flags & TFW_BLK_ERR_NOLOG))
		T_WARN_ADDR(msg, &conn->peer->addr, TFW_WITH_PORT);
}

static void
tfw_h2_error_resp(TfwHttpReq *req, int status, bool reply, bool attack,
		  bool on_req_recv_event)
{
	unsigned int stream_id;
	TfwH2Ctx *ctx = tfw_h2_context(req->conn);

	/*
	 * If stream is already unlinked and removed (due to particular stream
	 * closing from client side or the entire connection closing) we have
	 * nothing to do with that stream/request, and can go straight to the
	 * connection-specific logic.
	 */
	if (!req->stream)
		goto skip_stream;

	/*
	 * If reply should be sent and this is not the attack case - we
	 * can just send error response, leave the connection alive and
	 * drop request's corresponding stream; in this case stream either
	 * is already in locally closed state (switched in
	 * @tfw_h2_stream_id_close() during failed proxy/internal response
	 * creation) or will be switched into locally closed state in
	 * @tfw_h2_send_resp() (or in @tfw_h2_stream_id_close() if no error
	 * response is needed) below; remotely (i.e. on client side) stream
	 * will be closed - due to END_STREAM flag set in the last frame of
	 * error response; in case of attack we must close entire connection,
	 * and GOAWAY frame should be sent (RFC 7540 section 6.8) after
	 * error response.
	 */
	if (reply) {
		tfw_h2_send_resp(req, status, 0);
		if (attack)
			tfw_h2_conn_terminate_close(ctx, HTTP2_ECODE_PROTO,
						    !on_req_recv_event);
		return;
	}

	 /*
	  * If no reply is needed and this is not the attack case, the
	  * connection needn't to be closed, and we should indicate to
	  * remote peer (via RST_STREAM frame), that the stream has entered
	  * into closed state (RFC 7540 section 6.4).
	  */
	stream_id = tfw_h2_stream_id_close(req, HTTP2_RST_STREAM, 0);
	if (stream_id && !attack)
		tfw_h2_send_rst_stream(ctx, stream_id, HTTP2_ECODE_CANCEL);

skip_stream:
	if (attack) {
		if (reply)
			tfw_h2_conn_terminate_close(ctx, HTTP2_ECODE_PROTO,
						    !on_req_recv_event);
		else if (!on_req_recv_event)
			tfw_connection_close(req->conn, true);
	}

	tfw_http_conn_msg_free((TfwHttpMsg *)req);
}

static void
tfw_h1_error_resp(TfwHttpReq *req, int status, bool reply, bool attack,
		  bool on_req_recv_event)
{
	TfwCliConn *cli_conn = (TfwCliConn *)req->conn;

	/* The client connection is to be closed with the last resp sent. */
	reply &= !test_bit(TFW_HTTP_B_REQ_DROP, req->flags);
	if (reply) {
		if (on_req_recv_event) {
			WARN_ONCE(!list_empty_careful(&req->msg.seq_list),
				  "Request is already in seq_queue\n");
			tfw_stream_unlink_msg(req->stream);
			spin_lock(&cli_conn->seq_qlock);
			list_add_tail(&req->msg.seq_list, &cli_conn->seq_queue);
			spin_unlock(&cli_conn->seq_qlock);
		}
		/*
		 * If !on_req_recv_event, then the request @req may be some
		 * random request from the seq_queue, not the last one.
		 * If under attack:
		 *   Send the response and discard all the following requests.
		 * If not under attack and not on_req_recv_event:
		 *   Prepare an error response for the request, without stopping
		 *   the connection or discarding any following requests. This
		 *   isn't supposed to be an attack anyway.
		 * If not under attack and on_req_recv_event:
		 *   Can't proceed with this client connection, show the client
		 *   that an illegal request took place, send the response and
		 *   close client connection.
		 */
		if (on_req_recv_event || attack)
			tfw_http_req_set_conn_close(req);
		tfw_h1_send_resp(req, status);
	}
	/*
	 * Serve all pending requests if not under attack, close immediately
	 * otherwise.
	 */
	else {
		bool close = !on_req_recv_event;

		if (!attack)
			close &= !tfw_http_req_prev_conn_close(req);
		if (close)
			tfw_connection_close(req->conn, true);
		tfw_http_conn_req_clean(req);
	}
}

/**
 * Function define logging and response behaviour during detection of
 * malformed or malicious messages. Mark client connection in special
 * manner to delay its closing until transmission of error response
 * will be finished.
 *
 * @req			- malicious or malformed request;
 * @status		- response status code to use;
 * @msg			- message to be logged;
 * @attack		- true if the request was sent intentionally, false for
 *			  internal errors or misconfigurations;
 * @on_req_recv_event	- true if request is not fully parsed and the caller
 *			  handles the connection closing on its own.
 */
static void
tfw_http_cli_error_resp_and_log(TfwHttpReq *req, int status, const char *msg,
				bool attack, bool on_req_recv_event)
{
	bool reply;
	bool nolog;

	/*
	 * Error was happened and request should be dropped or blocked,
	 * but other modules (e.g. sticky cookie module) may have a response
	 * prepared for this request. A new error response is to be generated
	 * for the request, drop any previous response paired with the request.
	 */
	tfw_http_conn_msg_free(req->pair);

	if (attack) {
		reply = tfw_blk_flags & TFW_BLK_ATT_REPLY;
		nolog = tfw_blk_flags & TFW_BLK_ATT_NOLOG;
	}
	else {
		reply = tfw_blk_flags & TFW_BLK_ERR_REPLY;
		nolog = tfw_blk_flags & TFW_BLK_ERR_NOLOG;
	}

	if (!nolog)
		T_WARN_ADDR(msg, &req->conn->peer->addr, TFW_WITH_PORT);

	if (TFW_MSG_H2(req))
		tfw_h2_error_resp(req, status, reply, attack, on_req_recv_event);
	else
		tfw_h1_error_resp(req, status, reply, attack, on_req_recv_event);
}

/**
 * Unintentional error happen during request parsing. Stop the client connection
 * from receiving new requests. Caller must return TFW_BLOCK to the
 * ss_tcp_data_ready() function for propper connection close.
 */
static inline void
tfw_http_req_parse_drop(TfwHttpReq *req, int status, const char *msg)
{
	tfw_http_cli_error_resp_and_log(req, status, msg, false, true);
}

/**
 * Attack is detected during request parsing.
 * Caller must return TFW_BLOCK to the ss_tcp_data_ready() function for
 * propper connection close.
 */
static inline void
tfw_http_req_parse_block(TfwHttpReq *req, int status, const char *msg)
{
	tfw_http_cli_error_resp_and_log(req, status, msg, true, true);
}

/**
 * Unintentional error happen during request or response processing. Caller
 * function is not a part of ss_tcp_data_ready() function and manual connection
 * close will be performed.
 */
static inline void
tfw_http_req_drop(TfwHttpReq *req, int status, const char *msg)
{
	tfw_http_cli_error_resp_and_log(req, status, msg, false, false);
}

/**
 * Attack is detected during request or response processing. Caller function is
 * not a part of ss_tcp_data_ready() function and manual connection close
 * will be performed.
 */
static inline void
tfw_http_req_block(TfwHttpReq *req, int status, const char *msg)
{
	tfw_http_cli_error_resp_and_log(req, status, msg, true, false);
}

/*
 * TODO: RFC 7540 8.1.2
 *    However, header field names MUST be converted to lowercase prior to
 *    their encoding in HTTP/2. A request or response containing uppercase
 *    header field names MUST be treated as malformed (Section 8.1.2.6).
 *
 * Major browsers and curl ignore that RFC requirement an work well. But
 * that is definitely an RFC violation and implementation specific behaviour.
 */
static void
tfw_h2_resp_adjust_fwd(TfwHttpResp *resp)
{
	int r;
	unsigned int stream_id;
	bool hdrs_end = false;
	TfwHttpReq *req = resp->req;
	TfwH2Ctx *ctx = tfw_h2_context(req->conn);
	TfwHttpTransIter *mit = &resp->mit;
	TfwNextHdrOp *next = &mit->next;
	const TfwHdrMods *h_mods = tfw_vhost_get_hdr_mods(req->location,
							  req->vhost,
							  TFW_VHOST_HDRMOD_RESP);
	/*
	 * Get ID of corresponding stream to prepare/send HTTP/2 response, and
	 * unlink request from the stream.
	 */
	stream_id = tfw_h2_stream_id_close(req, HTTP2_HEADERS,
					   HTTP2_F_END_STREAM);
	if (unlikely(!stream_id))
		goto out;

	/*
	 * Transform HTTP/1.1 headers into HTTP/2 form, in parallel with
	 * adjusting of particular headers.
	 */
	WARN_ON_ONCE(mit->acc_len || mit->curr);

	tfw_h2_msg_transform_setup(mit, resp->msg.skb_head, true);

	r = tfw_h2_resp_next_hdr(resp, h_mods);
	if (unlikely(r))
		goto clean;

	r = tfw_h2_resp_status_write(resp, resp->status, TFW_H2_TRANS_SUB,
				     false);
	if (unlikely(r))
		goto clean;

	if (WARN_ON_ONCE(!mit->bnd))
		goto clean;

	do {
		TfwStr *last;
		TfwStr hdr = next->s_hdr;
		TfwH2TransOp op = next->op;

		r = tfw_h2_resp_next_hdr(resp, h_mods);
		if (unlikely(r))
			goto clean;

		if (!mit->bnd) {
			last = TFW_STR_LAST(&resp->crlf);
			mit->bnd = last->data + last->len;
			hdrs_end = true;
		}

		r = tfw_hpack_encode(resp, &hdr, op, true);
		if (unlikely(r))
			goto clean;

	} while (!hdrs_end);

	/*
	 * Write additional headers in HTTP/2 format in the end of the
	 * headers block, including configured headers which haven't been
	 * processed above and which have non-empty value (i.e. configured
	 * not for deletion).
	 */
	r = tfw_http_sess_resp_process(resp, false);
	if (unlikely(r))
		goto clean;

	r = tfw_h2_add_hdr_via(resp);
	if (unlikely(r))
		goto clean;

	if (!test_bit(TFW_HTTP_B_HDR_DATE, resp->flags)) {
		r = tfw_h2_add_hdr_date(resp, TFW_H2_TRANS_ADD, false);
		if (unlikely(r))
			goto clean;
	}

	r = TFW_H2_MSG_HDR_ADD(resp, "server", TFW_SERVER, 54);
	if (unlikely(r))
		goto clean;

	r = tfw_h2_resp_add_loc_hdrs(resp, h_mods, false);
	if (unlikely(r))
		goto clean;

	r = tfw_h2_frame_fwd_resp(resp, stream_id, mit->acc_len);
	if (unlikely(r))
		goto clean;

	tfw_h2_resp_fwd(resp);

	return;
clean:
	tfw_http_conn_msg_free((TfwHttpMsg *)resp);
	if (!(tfw_blk_flags & TFW_BLK_ERR_NOLOG))
		T_WARN_ADDR_STATUS("response dropped: processing error",
				   &req->conn->peer->addr,
				   TFW_WITH_PORT, 500);
	tfw_h2_send_resp(req, 500, stream_id);
	tfw_hpack_enc_release(&ctx->hpack, resp->flags);
	TFW_INC_STAT_BH(serv.msgs_otherr);

	return;
out:
	tfw_http_resp_pair_free(req);
}

/**
 * The request is serviced from cache.
 * Send the response as is and unrefer its data.
 */
static void
tfw_http_req_cache_service(TfwHttpResp *resp)
{
	TfwHttpReq *req = resp->req;

	WARN_ON_ONCE(!list_empty(&req->fwd_list));
	WARN_ON_ONCE(!list_empty(&req->nip_list));

	if (TFW_MSG_H2(req))
		tfw_h2_resp_fwd(resp);
	else
		tfw_http_resp_fwd(resp);

	TFW_INC_STAT_BH(clnt.msgs_fromcache);
}

/**
 * Depending on results of processing of a request, either send the request
 * to an appropriate server, or return the cached response. If none of that
 * can be done for any reason, return HTTP 500 or 502 error to the client.
 */
static void
tfw_http_req_cache_cb(TfwHttpMsg *msg)
{
	int r;
	TfwHttpReq *req = (TfwHttpReq *)msg;
	TfwSrvConn *srv_conn = NULL;
	LIST_HEAD(eq);

	T_DBG2("%s: req = %p, resp = %p\n", __func__, req, req->resp);

	if (req->resp) {
		tfw_http_req_cache_service(req->resp);
		return;
	}

	/*
	 * Dispatch request to an appropriate server. Schedulers should
	 * make a decision based on an unmodified request, so this must
	 * be done before any request mangling.
	 *
	 * The code below is usually called on a remote NUMA node. That's
	 * not good, but TDB lookup must be run on the node before it is
	 * executed, to avoid unnecessary work in SoftIRQ and to speed up
	 * the cache operation. At the same time, cache hits are expected
	 * to prevail over cache misses, so this is not a frequent path.
	 */
	if (!(srv_conn = tfw_http_get_srv_conn((TfwMsg *)req))) {
		T_DBG("Unable to find a backend server\n");
		goto send_502;
	}

	r = TFW_MSG_H2(req)
		? tfw_h2_adjust_req(req)
		: tfw_h1_adjust_req(req);
	if (r)
		goto send_500;

	/* Account current request in APM health monitoring statistics */
	tfw_http_hm_srv_update((TfwServer *)srv_conn->peer, req);

	/* Forward request to the server. */
	tfw_http_req_fwd_resched(srv_conn, req, &eq);
	tfw_http_req_zap_error(&eq);
	goto conn_put;

send_502:
	tfw_http_send_resp(req, 502, "request dropped: processing error");
	TFW_INC_STAT_BH(clnt.msgs_otherr);
	return;
send_500:
	tfw_http_send_resp(req, 500, "request dropped: processing error");
	TFW_INC_STAT_BH(clnt.msgs_otherr);
conn_put:
	/*
	 * Paired with tfw_srv_conn_get_if_live() via tfw_http_get_srv_conn() which
	 * increments the reference counter.
	 */
	tfw_srv_conn_put(srv_conn);
}

static void
tfw_http_req_mark_nip(TfwHttpReq *req)
{
	TfwVhost *vh_dflt;
	TfwLocation *loc, *loc_dflt;
	/* See RFC 7231 4.2.1 */
	static const unsigned int safe_methods =
		(1 << TFW_HTTP_METH_GET) | (1 << TFW_HTTP_METH_HEAD)
		| (1 << TFW_HTTP_METH_OPTIONS) | (1 << TFW_HTTP_METH_PROPFIND)
		| (1 << TFW_HTTP_METH_TRACE);

	BUILD_BUG_ON(sizeof(safe_methods) * BITS_PER_BYTE
		     < _TFW_HTTP_METH_COUNT);

	if (!req->vhost)
		return;
	/*
	 * Search in the current location of the current vhost. If there
	 * are no entries there, then search in the default location of
	 * the current vhost. If there are no entries there either, then
	 * search in the default location of the default vhost - that is,
	 * in the global policies.
	 *
	 * TODO #862: req->location must be the full set of options.
	 */
	loc = req->location;
	loc_dflt = req->vhost->loc_dflt;
	vh_dflt = req->vhost->vhost_dflt;
	if (loc && loc->nipdef_sz) {
		if (tfw_nipdef_match(loc, req->method, &req->uri_path))
			goto nip_match;
	} else if (loc_dflt && loc_dflt->nipdef_sz) {
		if (tfw_nipdef_match(loc_dflt, req->method, &req->uri_path))
			goto nip_match;
	} else if (vh_dflt && vh_dflt->loc_dflt->nipdef_sz) {
		if (tfw_nipdef_match(vh_dflt->loc_dflt, req->method,
				     &req->uri_path))
			goto nip_match;
	}

	if (safe_methods & (1 << req->method))
		return;

nip_match:
	T_DBG2("non-idempotent: method=[%d] uri=[%.*s]\n",
	       req->method, (int)TFW_STR_CHUNK(&req->uri_path, 0)->len,
		 TFW_STR_CHUNK(&req->uri_path, 0)->data);
	__set_bit(TFW_HTTP_B_NON_IDEMP, req->flags);
	return;
}

/*
 * Set the flag if @req is non-idempotent. Add the request to the list
 * of the client connection to preserve the correct order of responses.
 * If the request follows a non-idempotent request in flight, then the
 * preceding request becomes idempotent.
 */
static void
tfw_http_req_add_seq_queue(TfwHttpReq *req)
{
	TfwHttpReq *req_prev;
	TfwCliConn *cli_conn = (TfwCliConn *)req->conn;
	struct list_head *seq_queue = &cli_conn->seq_queue;

	tfw_http_req_mark_nip(req);

	spin_lock(&cli_conn->seq_qlock);
	req_prev = list_empty(seq_queue) ?
		   NULL : list_last_entry(seq_queue, TfwHttpReq, msg.seq_list);
	if (req_prev && tfw_http_req_is_nip(req_prev))
		clear_bit(TFW_HTTP_B_NON_IDEMP, req_prev->flags);
	list_add_tail(&req->msg.seq_list, seq_queue);
	spin_unlock(&cli_conn->seq_qlock);
}

static inline bool
tfw_http_check_wildcard_status(const char c, int *out)
{
	switch (c) {
	case '1':
		*out = HTTP_STATUS_1XX;
		break;
	case '2':
		*out = HTTP_STATUS_2XX;
		break;
	case '3':
		*out = HTTP_STATUS_3XX;
		break;
	case '4':
		*out = HTTP_STATUS_4XX;
		break;
	case '5':
		*out = HTTP_STATUS_5XX;
		break;
	default:
		return false;
	}
	return true;
}

static inline void
tfw_http_hm_drop_resp(TfwHttpResp *resp)
{
	TfwHttpReq *req = resp->req;

	tfw_stream_unlink_msg(resp->stream);
	tfw_http_conn_msg_free((TfwHttpMsg *)resp);
	tfw_http_msg_free((TfwHttpMsg *)req);
}

static TfwStr
tfw_http_get_ip_from_xff(TfwHttpReq *req)
{
	const TfwStr *s_xff, *c, *end;
	TfwStr s_ip;
	unsigned int nchunks;

	/*
	 * If a client works through a forward proxy, then a proxy can pass it's
	 * IP address by the first value in X-Forwarded-For
	 */
	s_xff = &req->h_tbl->tbl[TFW_HTTP_HDR_X_FORWARDED_FOR];
	/* Pick only end client address, ignore all proxies between it and us.  */
	if (TFW_STR_DUP(s_xff))
		s_xff = __TFW_STR_CH(s_xff, 0);
	s_ip = tfw_str_next_str_val(s_xff);
	nchunks = 0;
	TFW_STR_FOR_EACH_CHUNK(c, &s_ip, end) {
		if (!(c->flags & TFW_STR_VALUE))
			break;
		nchunks++;
	}
	s_ip.nchunks = nchunks;

	return s_ip;
}

static int
tfw_http_req_client_link(TfwConn *conn, TfwHttpReq *req)
{
	TfwStr s_ip, s_user_agent, *ua;
	TfwAddr addr;
	TfwClient *cli, *conn_cli;

	s_ip = tfw_http_get_ip_from_xff(req);
	if (!TFW_STR_EMPTY(&s_ip)) {
		if (tfw_addr_pton(&s_ip, &addr) != 0)
			return TFW_BLOCK;

		conn_cli = (TfwClient *)conn->peer;
		ua = &req->h_tbl->tbl[TFW_HTTP_HDR_USER_AGENT];
		tfw_http_msg_clnthdr_val(req, ua, TFW_HTTP_HDR_USER_AGENT,
					 &s_user_agent);
		cli = tfw_client_obtain(conn_cli->addr, &addr, &s_user_agent,
					NULL);
		if (cli) {
			if (cli != conn_cli)
				req->peer = cli;
			else
				tfw_client_put(cli);
		}
	}

	return 0;
}

static TfwHttpMsg *
tfw_h1_req_process(TfwStream *stream, struct sk_buff *skb)
{
	TfwHttpReq *req = (TfwHttpReq *)stream->msg;
	TfwHttpMsg *hmsib = NULL;

	/*
	 * In HTTP 1.0 the server always closes the connection
	 * after sending the response unless the client sent a
	 * a "Connection: keep-alive" request header, and the
	 * server sent a "Connection: keep-alive" response header.
	 *
	 * This behavior was added to existing HTTP 1.0 protocol.
	 * RFC 1945 section 1.3 says:
	 * "Except for experimental applications, current practice
	 * requires that the connection be established by the client
	 * prior to each request and closed by the server after
	 * sending the response."
	 *
	 * Make it work this way in Tempesta by setting the flag.
	 */
	if ((req->version == TFW_HTTP_VER_09)
	    || ((req->version == TFW_HTTP_VER_10)
		&& !test_bit(TFW_HTTP_B_CONN_KA, req->flags)))
	{
		__set_bit(TFW_HTTP_B_CONN_CLOSE, req->flags);
	}

	/*
	 * The request has been successfully parsed and processed.
	 * If the connection will be closed after the response to
	 * the request is sent to the client, then there's no need
	 * to process pipelined requests. Also, the request may be
	 * released when handled in general HTTP processing in caller
	 * function. So, reset sibling skb pointer (if it exists)
	 * to indicate for the following code that processing must be
	 * stopped, since corresponding flag may not be accessible later
	 * through @req->flags. If the connection must be closed, it
	 * also should be marked with @Conn_Stop flag - to left it alive
	 * for sending responses and, at the same time, to stop passing
	 * data for processing from the lower layer.
	 */
	if (test_bit(TFW_HTTP_B_CONN_CLOSE, req->flags)) {
		TFW_CONN_TYPE(req->conn) |= Conn_Stop;
		if (unlikely(skb)) {
			__kfree_skb(skb);
			skb = NULL;
		}
	}

	/*
	 * Pipelined requests: create a new sibling message.
	 * If pipelined message can't be created, it still possible to
	 * process current one. But @skb must be freed then, since it's
	 * not owned by any message.
	 */
	if (skb) {
		hmsib = tfw_http_msg_create_sibling((TfwHttpMsg *)req, skb);
		if (unlikely(!hmsib)) {
			TFW_INC_STAT_BH(clnt.msgs_otherr);
			__set_bit(TFW_HTTP_B_CONN_CLOSE, req->flags);
			TFW_CONN_TYPE(req->conn) |= Conn_Stop;
			tfw_http_conn_error_log(req->conn, "Can't create"
						" pipelined request");
			__kfree_skb(skb);
		}
	}

	/*
	 * Complete HTTP message has been collected and processed
	 * with success. Mark the message as complete in @stream as
	 * further handling of @stream depends on that. Future SKBs
	 * will be put in a new message.
	 * On an error the function returns from anywhere inside
	 * the loop. @stream->msg holds the reference to the message,
	 * which can be used to release it.
	 */
	tfw_stream_unlink_msg(stream);

	/*
	 * Add the request to the list of the client connection
	 * to preserve the correct order of responses to requests.
	 */
	tfw_http_req_add_seq_queue(req);

	return hmsib;
}

/**
 * @return zero on success and negative value otherwise.
 * TODO enter the function depending on current GFSM state.
 */
static int
tfw_http_req_process(TfwConn *conn, TfwStream *stream, const TfwFsmData *data)
{
	bool block;
	ss_skb_actor_t *actor;
	unsigned int parsed;
	struct sk_buff *skb = data->skb;
	TfwHttpReq *req;
	TfwHttpMsg *hmsib;
	TfwFsmData data_up;
	int r = TFW_BLOCK;

	BUG_ON(!stream->msg);

	T_DBG2("Received %u client data bytes on conn=%p msg=%p\n",
	       skb->len, conn, stream->msg);

	/*
	 * Process pipelined requests in a loop
	 * until all data in the SKB is processed.
	 */
next_msg:
	block = false;
	parsed = 0;
	hmsib = NULL;
	req = (TfwHttpReq *)stream->msg;
	actor = TFW_MSG_H2(req) ? tfw_h2_parse_req : tfw_http_parse_req;

	r = ss_skb_process(skb, actor, req, &req->chunk_cnt, &parsed);
	req->msg.len += parsed;
	TFW_ADD_STAT_BH(parsed, clnt.rx_bytes);

	T_DBG2("Request parsed: len=%u next=%pK parsed=%d msg_len=%lu"
	       " ver=%d res=%d\n",
		 skb->len, skb->next, parsed, req->msg.len, req->version, r);

	/*
	 * We have to keep @data the same to pass it as is to FSMs
	 * registered with lower priorities after us, but we must
	 * feed the new data version to FSMs registered on our states.
	 */
	data_up.skb = skb;
	data_up.req = (TfwMsg *)req;
	data_up.resp = NULL;

	switch (r) {
	default:
		T_ERR("Unrecognized HTTP request parser return code, %d\n", r);
	case TFW_BLOCK:
		T_DBG2("Block invalid HTTP request\n");
		TFW_INC_STAT_BH(clnt.msgs_parserr);
		tfw_http_req_parse_drop(req, 400, "failed to parse request");
		return TFW_BLOCK;
	case TFW_POSTPONE:
		if (WARN_ON_ONCE(parsed != data_up.skb->len)) {
			/*
			 * The parser should only return TFW_POSTPONE if it ate
			 * all available data, but that weren't enough.
			 */
			TFW_INC_STAT_BH(clnt.msgs_otherr);
			tfw_http_req_parse_block(req, 500,
				"Request parsing inconsistency");
			return TFW_BLOCK;
		}
		if (TFW_MSG_H2(req)) {
			TfwH2Ctx *ctx;

			if (tfw_h2_stream_req_complete(req->stream)) {
				if (likely(!tfw_h2_parse_req_finish(req)))
					break;
				TFW_INC_STAT_BH(clnt.msgs_otherr);
				tfw_http_req_parse_block(req, 500,
					"Request parsing inconsistency");
				return TFW_BLOCK;
			}
			ctx = tfw_h2_context(conn);
			if (ctx->hdr.flags & HTTP2_F_END_HEADERS)
				__set_bit(TFW_HTTP_B_HEADERS_PARSED, req->flags);
		}

		r = tfw_gfsm_move(&conn->state, TFW_HTTP_FSM_REQ_CHUNK, &data_up);
		T_DBG3("TFW_HTTP_FSM_REQ_CHUNK return code %d\n", r);
		if (r == TFW_BLOCK) {
			TFW_INC_STAT_BH(clnt.msgs_filtout);
			tfw_http_req_parse_block(req, 403,
				"postponed request has been filtered out");
			return TFW_BLOCK;
		}
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

		if (WARN_ON_ONCE(!test_bit(TFW_HTTP_B_CHUNKED, req->flags)
				 && (req->content_length != req->body.len)))
		{
			return TFW_BLOCK;
		}
	}

	/*
	 * The message is fully parsed, the rest of the data in the
	 * stream may represent another request or its part.
	 * If skb splitting has failed, the request can't be forwarded
	 * to backend server or request-response sequence can be broken.
	 * @skb is replaced with pointer to a new SKB.
	 */
	if (parsed < skb->len) {
		WARN_ON_ONCE(TFW_MSG_H2(req));
		skb = ss_skb_split(skb, parsed);
		if (unlikely(!skb)) {
			TFW_INC_STAT_BH(clnt.msgs_otherr);
			tfw_http_req_parse_block(req, 500,
						 "Can't split pipelined requests");
			return TFW_BLOCK;
		}
	} else {
		skb = NULL;
	}

	if ((r = tfw_http_req_client_link(conn, req)))
		return r;
	/*
	 * Assign a target virtual host for the current request before further
	 * processing.
	 *
	 * There are multiple ways to get a target vhost:
	 * - search in HTTP chains (defined in the configuration by an admin),
	 * can be slow on big configurations, since chains are tested
	 * one-by-one;
	 * - get vhost from the HTTP session information (by Sticky cookie);
	 * - get Vhost according to TLS SNI header parsing.
	 *
	 * There is a possibility, that each method will give a very different
	 * result. It absolutely depends on configuration provided by
	 * an administrator and application behaviour. Some differences are
	 * expected anyway, e.g. if tls client doesn't send an SNI identifier
	 * it will be matched to 'default' vhost while http_chains can identify
	 * target vhost. We also can't just skip http_chains and fully rely
	 * on sticky module, since http_chains also contains non-terminating
	 * rules, such as `mark` rule. Even if http_chains is the
	 * slowest method we have, we can't simply skip it.
	 */
	req->vhost = tfw_http_tbl_vhost((TfwMsg *)req, &block);
	if (unlikely(block)) {
		TFW_INC_STAT_BH(clnt.msgs_filtout);
		tfw_http_req_parse_block(req, 403,
			"request has been filtered out via http table");
		return TFW_BLOCK;
	}
	if (req->vhost)
		req->location = tfw_location_match(req->vhost, &req->uri_path);
	/*
	 * If vhost is not found the request will be dropped, but it will still
	 * go through some processing stages since some subsystems need to track
	 * all incoming requests.
	 */
	/*
	 * The time the request was received is used for age
	 * calculations in cache, and for eviction purposes.
	 */
	req->cache_ctl.timestamp = tfw_current_timestamp();
	req->jrxtstamp = jiffies;

	/*
	 * Run frang checks first before any processing happen. Can't start
	 * the checks earlier, since vhost and specific client is required
	 * for frang checks.
	 *
	 * If a request was received in a single skb, the only frang check
	 * happens here. At the first sight it seems like http tables are not
	 * protected with anti-DDoS limits and attackers may stress http tables
	 * as long as they want till they get 403 responses from us. But
	 * Tempesta closes connection every time it faces `block` action
	 * in HTTP table, this causes attackers to open a new connection
	 * for every new request. Connection rates limits usually much more
	 * strict than request rates, so this attack path is closed by usual
	 * frang configuration.
	 *
	 * TODO #1490: block the request if Frang didn't finish its job.
	 */
	r = tfw_gfsm_move(&conn->state, TFW_HTTP_FSM_REQ_MSG, &data_up);
	T_DBG3("TFW_HTTP_FSM_REQ_MSG return code %d\n", r);
	/* Don't accept any following requests from the peer. */
	if (r == TFW_BLOCK) {
		TFW_INC_STAT_BH(clnt.msgs_filtout);
		tfw_http_req_parse_block(req, 403,
			"parsed request has been filtered out");
		return TFW_BLOCK;
	}

	/*
	 * Sticky cookie module must be used before request can reach cache.
	 * Unauthorised clients mustn't be able to get any resource on
	 * protected service and stress cache subsystem. The module is also
	 * the quickest way to obtain target VHost and target backend server
	 * connection since it allows to avoid expensive tables lookups.
	 */
	switch (tfw_http_sess_obtain(req))
	{
	case TFW_HTTP_SESS_SUCCESS:
		break;

	case TFW_HTTP_SESS_REDIRECT_NEED:
		/* Response is built and stored in @req->resp. */
		break;

	case TFW_HTTP_SESS_VIOLATE:
		TFW_INC_STAT_BH(clnt.msgs_filtout);
		tfw_http_req_parse_block(req, 503,
			"request dropped: sticky cookie challenge was failed");
		return TFW_BLOCK;

	case TFW_HTTP_SESS_JS_NOT_SUPPORTED:
		/*
		 * Requested resource can't be challenged, forward all pending
		 * responses and close the connection to allow client to recover.
		 */
		TFW_INC_STAT_BH(clnt.msgs_filtout);
		tfw_http_req_parse_block(req, 503,
			"request dropped: can't send JS challenge");
		return TFW_BLOCK;

	default:
		TFW_INC_STAT_BH(clnt.msgs_otherr);
		tfw_http_req_parse_block(req, 500,
			"request dropped: internal error in Sticky module");
		return TFW_BLOCK;
	}

	/*
	 * Method override masks real request properties, non-idempotent methods
	 * can hide behind idempotent, method is used as a key in cache
	 * subsystem to store and look up cached responses. Thus hiding real
	 * method can spoil responses for other clients. Use the real method
	 * for accurate processing.
	 *
	 * We don't rewrite the method string and don't remove override header
	 * since there can be additional intermediates between TempestaFW and
	 * backend.
	 */
	if (unlikely(req->method_override))
		req->method = req->method_override;

	if (!TFW_MSG_H2(req))
		hmsib = tfw_h1_req_process(stream, skb);

	/*
	 * Response is already prepared for the client by sticky module.
	 */
	if (unlikely(req->resp)) {
		if (TFW_MSG_H2(req))
			tfw_h2_resp_fwd(req->resp);
		else
			tfw_http_resp_fwd(req->resp);
	}
	/*
	 * If no virtual host has been found for current request, there
	 * is no sense for its further processing, so we drop it, send
	 * error response to client and move on to the next request.
	 */
	else if (unlikely(!req->vhost)) {
		tfw_http_req_block(req, 403,
				   "request dropped: cannot find appropriate "
				   "virtual host");
		TFW_INC_STAT_BH(clnt.msgs_otherr);
	}
	else if (tfw_cache_process((TfwHttpMsg *)req, tfw_http_req_cache_cb)) {
		/*
		 * The request should either be stored or released.
		 * Otherwise we lose the reference to it and get a leak.
		 */
		tfw_http_send_resp(req, 500, "request dropped:"
					     " processing error");
		TFW_INC_STAT_BH(clnt.msgs_otherr);
	}
	/*
	 * According to RFC 7230 6.3.2, connection with a client
	 * must be dropped after a response is sent to that client,
	 * if the client sends "Connection: close" header field in
	 * the request (@tfw_h1_req_process() return NULL for @hmsib
	 * in this case). Subsequent requests from the client coming
	 * over the same connection are ignored.
	 *
	 * Note: This connection's @conn must not be dereferenced
	 * from this point on.
	 */
	if (hmsib) {
		/*
		 * No sibling messages should appear in processing
		 * of HTTP/2 protocol.
		 */
		WARN_ON_ONCE(TFW_MSG_H2(hmsib));
		/*
		 * Switch connection to the new sibling message.
		 * Data processing will continue with the new SKB.
		 */
		stream->msg = (TfwMsg *)hmsib;
		goto next_msg;
	}

	return r;
}

/**
 * This is the second half of tfw_http_resp_process().
 * tfw_http_resp_process() runs in SoftIRQ whereas tfw_http_resp_cache_cb()
 * runs in cache thread that is scheduled at an appropriate TDB node.
 *
 * HTTP requests are usually much smaller than HTTP responses, so it's
 * better to transfer requests to a TDB node to make any adjustments.
 * The other benefit of the scheme is that less work is done in SoftIRQ.
 */
static void
tfw_http_resp_cache_cb(TfwHttpMsg *msg)
{
	TfwHttpResp *resp = (TfwHttpResp *)msg;

	T_DBG2("%s: req = %p, resp = %p\n", __func__, resp->req, resp);

	tfw_http_sess_learn(resp);

	if (TFW_MSG_H2(resp->req))
		tfw_h2_resp_adjust_fwd(resp);
	else
		tfw_h1_resp_adjust_fwd(resp);
}

/**
 * Just received response is parsed and processed. The corresponding
 * request is the first one in the connection forwarding
 * queue, and srv_conn->msg_sent points to it or to one of the next requests.
 * @fwd_unsent is set to true if progress inside connection is possible.
 * The forwarding queue state is fully consistent after the call.
 *
 * If processing of the response is successful then it's possible to forward
 * all unsent requests.
 *
 * Upstreams don't normally send invalid responses. The processing error will
 * happen once again if the request will be re-sent or forwarded to another
 * server. Delist the request to prevent future errors. The server connection
 * is about to be closed and there is no sense in forwarding unsent requests.
 *
 * TODO: When a response is received and a paired request is found,
 * pending (unsent) requests in the connection are forwarded to the
 * server right away. In current design, @fwd_queue is locked until
 * after a request is submitted to SS for sending. It shouldn't be
 * necessary to lock @fwd_queue for that. Please see a similar TODO
 * comment to tfw_http_req_fwd(). Also, please see the issue #687.
 */
static void
tfw_http_popreq(TfwHttpMsg *hmresp, bool fwd_unsent)
{
	int err = 0;
	TfwHttpReq *req = hmresp->req;
	TfwSrvConn *srv_conn = (TfwSrvConn *)hmresp->conn;
	LIST_HEAD(reschq);
	LIST_HEAD(eq);

	spin_lock(&srv_conn->fwd_qlock);
	if ((TfwMsg *)req == srv_conn->msg_sent)
		srv_conn->msg_sent = NULL;
	tfw_http_req_delist(srv_conn, req);
	tfw_http_conn_nip_adjust(srv_conn);

	if (unlikely(!fwd_unsent)) {
		spin_unlock(&srv_conn->fwd_qlock);
		return;
	}
	/*
	 * Run special processing if the connection is in repair
	 * mode. Otherwise, forward pending requests to the server.
	 *
	 * @hmresp is holding a reference to the server connection
	 * while forwarding is done, so there's no need to take an
	 * additional reference.
	 */
	if (unlikely(tfw_srv_conn_restricted(srv_conn)))
		err = tfw_http_conn_fwd_repair(srv_conn, &eq);
	else if (tfw_http_conn_need_fwd(srv_conn))
		err = tfw_http_conn_fwd_unsent(srv_conn, &eq);
	if (!err) {
		spin_unlock(&srv_conn->fwd_qlock);
		goto out;
	}
	/*
	 * If error occurred during repairing or forwarding procedures
	 * (-EBUSY and @msg_sent is NULL) the rescheduling is started;
	 * Since @msg_sent is definitely NULL here, there must not be
	 * pending sibling responses attached to requests, so it is
	 * safe to cut all remaining requests from @fwd_queue for
	 * rescheduling.
	 */
	WARN_ON(srv_conn->msg_sent);
	__tfw_srv_conn_clear_restricted(srv_conn);
	tfw_srv_set_busy_delay(srv_conn);
	tfw_http_fwdq_reset(srv_conn, &reschq);
	spin_unlock(&srv_conn->fwd_qlock);

	tfw_http_fwdq_resched(srv_conn, &reschq, &eq);
out:
	tfw_http_req_zap_error(&eq);
}

/*
 * Post-process the response. Pass it to modules registered with GFSM
 * for further processing. Finish the request/response exchange properly
 * in case of an error.
 */
static int
tfw_http_resp_gfsm(TfwHttpMsg *hmresp, TfwFsmData *data)
{
	int r;
	TfwHttpReq *req = hmresp->req;

	BUG_ON(!hmresp->conn);

	r = tfw_gfsm_move(&hmresp->conn->state, TFW_HTTP_FSM_RESP_MSG, data);
	T_DBG3("TFW_HTTP_FSM_RESP_MSG return code %d\n", r);
	if (r == TFW_BLOCK)
		goto error;

	r = tfw_gfsm_move(&hmresp->conn->state, TFW_HTTP_FSM_LOCAL_RESP_FILTER,
			  data);
	T_DBG3("TFW_HTTP_FSM_LOCAL_RESP_FILTER return code %d\n", r);
	if (r == TFW_PASS)
		return TFW_PASS;

error:
	tfw_http_popreq(hmresp, false);
	/* The response is freed by tfw_http_req_block(). */
	tfw_http_req_block(req, 403, "response blocked: filtered out");
	TFW_INC_STAT_BH(serv.msgs_filtout);
	return r;
}

/*
 * Set up the response @hmresp with data needed down the road,
 * get the paired request, and then pass the response to cache
 * for further processing.
 */
static void
tfw_http_resp_cache(TfwHttpMsg *hmresp)
{
	TfwHttpResp *resp = (TfwHttpResp *)hmresp;
	TfwHttpReq *req = hmresp->req;
	TfwFsmData data;
	time_t timestamp = tfw_current_timestamp();

	/*
	 * The time the response was received is used in cache
	 * for age calculations, and for APM and Load Balancing.
	 */
	hmresp->cache_ctl.timestamp = timestamp;
	resp->jrxtstamp = jiffies;
	/*
	 * If 'Date:' header is missing in the response, then
	 * set the date to the time the response was received.
	 */
	if (!test_bit(TFW_HTTP_B_HDR_DATE, hmresp->flags))
		((TfwHttpResp *)hmresp)->date = timestamp;
	/*
	 * Response is fully received, delist corresponding request from
	 * fwd_queue.
	 */
	tfw_http_popreq(hmresp, true);
	/*
	 * TODO: Currently APM holds the pure roundtrip time (RTT) from
	 * the time a request is forwarded to the time a response to it
	 * is received and parsed. Perhaps it makes sense to penalize
	 * server connections which get broken too often. What would be
	 * a fast and simple algorithm for that? Keep in mind, that the
	 * value of RTT has an upper boundary in the APM.
	 */
	tfw_apm_update(((TfwServer *)resp->conn->peer)->apmref,
		       resp->jrxtstamp, resp->jrxtstamp - req->jtxtstamp);
	/*
	 * Health monitor request means that its response need not to
	 * send anywhere.
	 */
	if (test_bit(TFW_HTTP_B_HMONITOR, req->flags)) {
		tfw_http_hm_drop_resp((TfwHttpResp *)hmresp);
		return;
	}
	/*
	 * This hook isn't in tfw_http_resp_fwd() because responses from the
	 * cache shouldn't be accounted.
	 */
	data.skb = NULL;
	data.req = (TfwMsg *)req;
	data.resp = (TfwMsg *)hmresp;
	if (tfw_gfsm_move(&hmresp->conn->state, TFW_HTTP_FSM_RESP_MSG_FWD, &data)) {
		/* The response is freed by tfw_http_req_block(). */
		tfw_http_req_block(req, 403, "response blocked: filtered out");
		TFW_INC_STAT_BH(serv.msgs_filtout);
		return;
	}

	/*
	 * Complete HTTP message has been collected and processed
	 * with success. Mark the message as complete in @stream as
	 * further handling of @conn depends on that. Future SKBs
	 * will be put in a new message.
	 */
	tfw_stream_unlink_msg(hmresp->stream);
	if (tfw_cache_process(hmresp, tfw_http_resp_cache_cb))
	{
		tfw_http_conn_msg_free(hmresp);
		tfw_http_send_resp(req, 500, "response dropped:"
				   " processing error");
		TFW_INC_STAT_BH(serv.msgs_otherr);
		/* Proceed with processing of the next response. */
	}
}

/*
 * Finish a response that is terminated by closing the connection.
 *
 * Http/1 response is terminated by connection close and lacks of framing
 * information. H2 connections have their own framing happening just before
 * forwarding message to network, but h1 connections still require explicit
 * framing. Don't add framing now, @tfw_http_adjust_resp() will handle it.
 */
static void
tfw_http_resp_terminate(TfwHttpMsg *hm)
{
	TfwFsmData data;

	if (unlikely(!TFW_MSG_H2(hm->req))) {
		/*
		 * A sender MUST NOT apply chunked more than once
		 * to a message body (i.e., chunking an already
		 * chunked message is not allowed). RFC 7230 3.3.1.
		 */
		if (!test_bit(TFW_HTTP_B_CHUNKED_APPLIED, hm->flags))
			__set_bit(TFW_HTTP_B_CHUNKED, hm->flags);
		else
			set_bit(TFW_HTTP_B_CONN_CLOSE, hm->req->flags);
	}

	/*
	 * Note that in this case we don't have data to process.
	 * All data has been processed already. The response needs
	 * to go through Tempesta's post-processing, and then be
	 * sent to the client. The full skb->len is used as the
	 * offset to mark this case in the post-processing phase.
	 */
	data.skb = ss_skb_peek_tail(&hm->msg.skb_head);
	BUG_ON(!data.skb);
	data.req = NULL;
	data.resp = (TfwMsg *)hm;

	if (tfw_http_resp_gfsm(hm, &data) != TFW_PASS)
		return;
	tfw_http_resp_cache(hm);
}

/**
 * @return zero on success and negative value otherwise.
 * TODO enter the function depending on current GFSM state.
 */
static int
tfw_http_resp_process(TfwConn *conn, TfwStream *stream, const TfwFsmData *data)
{
	int r = TFW_BLOCK;
	unsigned int chunks_unused, parsed;
	struct sk_buff *skb = data->skb;
	TfwHttpReq *bad_req;
	TfwHttpMsg *hmresp, *hmsib;
	TfwFsmData data_up;
	bool conn_stop, filtout = false;

	BUG_ON(!stream->msg);
	/*
	 * #769: There is no client side TLS, so we don't read HTTP responses
	 * through TLS connection, so trail and off should be zero.
	 * However, TCP overlapping segments still may produce non-zero offset
	 * in ss_tcp_process_skb().
	 */

	T_DBG2("Received %u server data bytes on conn=%p msg=%p\n",
	       skb->len, conn, stream->msg);
	/*
	 * Process pipelined requests in a loop
	 * until all data in the SKB is processed.
	 */
next_msg:
	conn_stop = false;
	parsed = 0;
	hmsib = NULL;
	hmresp = (TfwHttpMsg *)stream->msg;

	r = ss_skb_process(skb, tfw_http_parse_resp, hmresp, &chunks_unused,
			   &parsed);
	hmresp->msg.len += parsed;
	TFW_ADD_STAT_BH(parsed, serv.rx_bytes);

	T_DBG2("Response parsed: len=%u parsed=%d msg_len=%lu ver=%d res=%d\n",
	       skb->len, parsed, hmresp->msg.len, hmresp->version, r);

	/*
	 * We have to keep @data the same to pass it as is to FSMs
	 * registered with lower priorities after us, but we must
	 * feed the new data version to FSMs registered on our states.
	 */
	data_up.skb = skb;
	data_up.req = NULL;
	data_up.resp = (TfwMsg *)hmresp;

	switch (r) {
	default:
		T_ERR("Unrecognized HTTP response parser return code, %d\n", r);
	case TFW_BLOCK:
		/*
		 * The response has not been fully parsed. There's no
		 * choice but report a critical error. The lower layer
		 * will close the connection and release the response
		 * message, and well as all request messages that went
		 * out on this connection and are waiting for paired
		 * response messages.
		 */
		T_DBG2("Block invalid HTTP response\n");
		TFW_INC_STAT_BH(serv.msgs_parserr);
		goto bad_msg;
	case TFW_POSTPONE:
		if (WARN_ON_ONCE(parsed != data_up.skb->len)) {
			/*
			 * The parser should only return TFW_POSTPONE if it ate
			 * all available data, but that weren't enough.
			 */
			TFW_INC_STAT_BH(serv.msgs_otherr);
			goto bad_msg;
		}
		r = tfw_gfsm_move(&conn->state, TFW_HTTP_FSM_RESP_CHUNK,
				  &data_up);
		T_DBG3("TFW_HTTP_FSM_RESP_CHUNK return code %d\n", r);
		if (r == TFW_BLOCK) {
			TFW_INC_STAT_BH(serv.msgs_filtout);
			filtout = true;
			goto bad_msg;
		}
		/*
		 * Cut extra data found by parser and never intended to be
		 * forwarded to client, such as chunked encoding. It can be cut
		 * off later, but just do it now while all the data sits in the
		 * last skb.
		 */
		if (tfw_http_msg_del_parsed_cuts(hmresp, false)) {
			TFW_INC_STAT_BH(serv.msgs_otherr);
			goto bad_msg;
		}
		/*
		 * TFW_POSTPONE status means that parsing succeeded
		 * but more data is needed to complete it. Lower layers
		 * just supply data for parsing. They only want to know
		 * if processing of a message should continue or not.
		 */
		return TFW_PASS;
	case TFW_PASS:
		/*
		 * The response is fully parsed, fall through and
		 * process it. If the response has broken length, then
		 * block it (the server connection will be dropped).
		 */
		if (!(test_bit(TFW_HTTP_B_CHUNKED, hmresp->flags)
		      || test_bit(TFW_HTTP_B_VOID_BODY, hmresp->flags))
		    && (hmresp->content_length != hmresp->body.len))
		{
			goto bad_msg;
		}
	}

	/*
	 * The message is fully parsed, the rest of the data in the
	 * stream may represent another response or its part.
	 * If skb splitting has failed, the response cant be forwarded
	 * to client or request-response sequence on client side can be
	 * broken and client may receive sensitive data from other
	 * clients can be also sent there.
	 * @skb is replaced with pointer to a new SKB.
	 */
	if (parsed < skb->len) {
		skb = ss_skb_split(skb, parsed);
		if (unlikely(!skb)) {
			TFW_INC_STAT_BH(serv.msgs_otherr);
			goto bad_msg;
		}
	}
	else {
		skb = NULL;
	}
	/*
	 * Cut everything from response, which we don't want to pass, e.g.
	 * chunked encoding.
	 */
	if (tfw_http_msg_del_parsed_cuts(hmresp, true)) {
		TFW_INC_STAT_BH(serv.msgs_otherr);
		goto bad_msg;
	}

	/*
	 * Verify response in context of http health monitor,
	 * and mark server as disabled/enabled.
	 *
	 * TODO (TBD) Probably we should close server connection here to
	 * make all queued request be rescheduled to other servers.
	 * Also it's a common practice to reset and reestablish
	 * connections with buggy applications. Now we stop scheduling
	 * new requests to the server and forward all, probably error
	 * responses, for queued requests to clients.
	 */
	tfw_http_hm_control((TfwHttpResp *)hmresp);

	/*
	 * Pass the response to GFSM for further processing.
	 * Drop server connection in case of serious error or security
	 * event.
	 */
	r = tfw_http_resp_gfsm(hmresp, &data_up);
	if (unlikely(r < TFW_PASS))
		return TFW_BLOCK;

	/*
	 * If @skb's data has not been processed in full, then
	 * we have pipelined responses. Create a sibling message.
	 * @skb is replaced with a pointer to a new SKB.
	 */
	if (skb) {
		hmsib = tfw_http_msg_create_sibling(hmresp, skb);
		/*
		 * In case of an error there's no recourse. The
		 * caller expects that data is processed in full,
		 * and can't deal with partially processed data.
		 */
		if (unlikely(!hmsib)) {
			TFW_INC_STAT_BH(serv.msgs_otherr);
			tfw_http_conn_error_log(conn, "Can't create pipelined"
						      " response");
			__kfree_skb(skb);
			skb = NULL;
			conn_stop = true;
		}
	}

	/*
	 * If a non critical error occurred in further GFSM processing,
	 * then the response and the paired request had been handled.
	 * Keep the server connection open for data exchange.
	 */
	if (unlikely(r != TFW_PASS)) {
		r = TFW_PASS;
		goto next_resp;
	}
	/*
	 * Pass the response to cache for further processing.
	 * In the end, the response is sent on to the client.
	 * @hmsib is not attached to the connection yet.
	 */
	tfw_http_resp_cache(hmresp);

next_resp:
	if (hmsib) {
		/*
		 * Switch the connection to the sibling message.
		 * Data processing will continue with the new SKB.
		 */
		stream->msg = (TfwMsg *)hmsib;
		goto next_msg;
	}
	else if (unlikely(conn_stop)) {
		/*
		 * Creation of sibling response has failed, close
		 * the connection to recover.
		 */
		return TFW_BLOCK;
	}

	return r;
bad_msg:
	/*
	 * Response can't be parsed or processed. This is abnormal situation,
	 * upstream server usually sends valid responses or closes the
	 * connection when it refuses to serve the request. But this exact
	 * request makes server to send invalid response. Most likely that the
	 * situation will happen once again if the request will be re-sent.
	 * Send error or drop the request.
	 */
	bad_req = hmresp->req;
	tfw_http_popreq(hmresp, false);
	/* The response is freed by tfw_http_req_block/drop(). */
	if (filtout)
		tfw_http_req_block(bad_req, 502,
				   "response blocked: filtered out");
	else
		tfw_http_req_drop(bad_req, 502,
				  "response dropped: processing error");
	return TFW_BLOCK;
}

/**
 * @return status (application logic decision) of the message processing.
 */
int
tfw_http_msg_process_generic(TfwConn *conn, TfwStream *stream, TfwFsmData *data)
{
	if (WARN_ON_ONCE(!stream))
		return -EINVAL;
	if (unlikely(!stream->msg)) {
		stream->msg = tfw_http_conn_msg_alloc(conn, stream);
		if (!stream->msg) {
			__kfree_skb(data->skb);
			return TFW_BLOCK;
		}
		tfw_http_mark_wl_new_msg(conn, (TfwHttpMsg *)stream->msg,
					 data->skb);
		T_DBG2("Link new msg %p with connection %p\n",
		       stream->msg, conn);
	}

	T_DBG2("Add skb %p to message %p\n", data->skb, stream->msg);
	ss_skb_queue_tail(&stream->msg->skb_head, data->skb);

	return (TFW_CONN_TYPE(conn) & Conn_Clnt)
		? tfw_http_req_process(conn, stream, data)
		: tfw_http_resp_process(conn, stream, data);
}

/**
 * TLS can send us list of decrypted skbs, it doesn't care about the list any
 * more. Meantime, HTTP uses it's own skb lists, so here we process the list
 * and pretend that we have each skb separately.
 *
 * We responsible for freeing all consumed skbs, including the skb which
 * returned an error code on. The rest of skbs are freed by us.
 */
int
tfw_http_msg_process(void *conn, TfwFsmData *data)
{
	int r = T_OK;
	TfwStream *stream = &((TfwConn *)conn)->stream;
	struct sk_buff *next;

	if (data->skb->prev)
		data->skb->prev->next = NULL;
	for (next = data->skb->next; data->skb;
	     data->skb = next, next = next ? next->next : NULL)
	{
		if (likely(r == T_OK || r == T_POSTPONE)) {
			data->skb->next = data->skb->prev = NULL;
			r = TFW_CONN_H2(conn)
				? tfw_h2_frame_process(conn, data)
				: tfw_http_msg_process_generic(conn, stream, data);
		} else {
			__kfree_skb(data->skb);
		}
	}

	return r;
}

/**
 * Send monitoring request to backend server to check its state (alive or
 * suspended) in the sense of HTTP accessibility.
 */
void
tfw_http_hm_srv_send(TfwServer *srv, char *data, unsigned long len)
{
	TfwMsgIter it;
	TfwHttpReq *req;
	TfwHttpMsg *hmreq;
	TfwSrvConn *srv_conn;
	TfwStr msg = {
		.data = data,
		.len = len,
	};
	LIST_HEAD(equeue);
	bool block = false;

	if (!(req = tfw_http_msg_alloc_req_light()))
		return;
	hmreq = (TfwHttpMsg *)req;
	if (tfw_http_msg_setup(hmreq, &it, msg.len, 0))
		goto cleanup;
	if (tfw_msg_write(&it, &msg))
		goto cleanup;

	__set_bit(TFW_HTTP_B_HMONITOR, req->flags);
	req->jrxtstamp = jiffies;

	/*
	 * Vhost and location store policies definitions that can be
	 * required on various stages of request-response processing.
	 * E.g. response to HM request still needs to be processed by frang,
	 * and vhost keeps the frang configuration.
	 *
	 * The request is created using lightweight function, req->uri_path
	 * is not set, thus default location is used.
	 *
	 * TBD: it's more natural to configure HM not in server group section,
	 * but in vhost: instead of table lookups target vhost could be chosen
	 * directly.
	 */
	req->vhost = tfw_http_tbl_vhost((TfwMsg *)req, &block);
	if (unlikely(!req->vhost || block)) {
		T_WARN_ADDR("Unable to assign vhost for health monitoring "
			    "request of backend server", &srv->addr,
			    TFW_WITH_PORT);
		goto cleanup;
	}
	req->location = req->vhost->loc_dflt;

	srv_conn = srv->sg->sched->sched_srv_conn((TfwMsg *)req, srv);
	if (!srv_conn) {
		T_WARN_ADDR("Unable to find connection for health monitoring "
			    "of backend server", &srv->addr, TFW_WITH_PORT);
		goto cleanup;
	}

	tfw_http_req_fwd(srv_conn, req, &equeue, false);
	tfw_http_req_zap_error(&equeue);

	/*
	 * Paired with tfw_srv_conn_get_if_live() via sched_srv_conn callback which
	 * increments the reference counter.
	 */
	tfw_srv_conn_put(srv_conn);

	return;

cleanup:
	tfw_http_msg_free(hmreq);
}

/**
 * Calculate the key of an HTTP request by hashing URI and Host header values.
 */
unsigned long
tfw_http_req_key_calc(TfwHttpReq *req)
{
	TfwStr host;

	if (req->hash)
		return req->hash;

	req->hash = tfw_hash_str(&req->uri_path);

	if (test_bit(TFW_HTTP_B_HMONITOR, req->flags))
		return req->hash;

	tfw_http_msg_clnthdr_val(req, &req->h_tbl->tbl[TFW_HTTP_HDR_HOST],
				 TFW_HTTP_HDR_HOST, &host);
	if (!TFW_STR_EMPTY(&host))
		req->hash ^= tfw_hash_str(&host);

	return req->hash;
}

static TfwConnHooks http_conn_hooks = {
	.conn_init	= tfw_http_conn_init,
	.conn_repair	= tfw_http_conn_repair,
	.conn_close	= tfw_http_conn_close,
	.conn_drop	= tfw_http_conn_drop,
	.conn_release	= tfw_http_conn_release,
	.conn_send	= tfw_http_conn_send,
};

/*
 * ------------------------------------------------------------------------
 *	configuration handling
 * ------------------------------------------------------------------------
 */

static int
tfw_cfgop_define_block_action(const char *action, unsigned short mask,
			      unsigned short *flags)
{
	if (!strcasecmp(action, "reply")) {
		*flags |= mask;
	} else if (!strcasecmp(action, "drop")) {
		*flags &= ~mask;
	} else {
		T_ERR_NL("Unsupported argument: '%s'\n", action);
		return -EINVAL;
	}
	return 0;
}

static int
tfw_cfgop_define_block_nolog(TfwCfgEntry *ce, unsigned short mask,
			     unsigned short *flags)
{
	if (ce->val_n == 3) {
		if (!strcasecmp(ce->vals[2], "nolog"))
			*flags |= mask;
		else {
			T_ERR_NL("Unsupported argument: '%s'\n", ce->vals[2]);
			return -EINVAL;
		}
	} else {
		*flags &= ~mask;
	}
	return 0;
}

static int
tfw_cfgop_block_action(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	if (ce->val_n < 2 || ce->val_n > 3) {
		T_ERR_NL("Invalid number of arguments: %zu\n", ce->val_n);
		return -EINVAL;
	}
	if (ce->attr_n) {
		T_ERR_NL("Unexpected attributes\n");
		return -EINVAL;
	}

	if (!strcasecmp(ce->vals[0], "error")) {
		if (tfw_cfgop_define_block_action(ce->vals[1],
						  TFW_BLK_ERR_REPLY,
						  &tfw_blk_flags) ||
		    tfw_cfgop_define_block_nolog(ce,
						 TFW_BLK_ERR_NOLOG,
						 &tfw_blk_flags))
			return -EINVAL;
	} else if (!strcasecmp(ce->vals[0], "attack")) {
		if (tfw_cfgop_define_block_action(ce->vals[1],
						  TFW_BLK_ATT_REPLY,
						  &tfw_blk_flags) ||
		    tfw_cfgop_define_block_nolog(ce,
						 TFW_BLK_ATT_NOLOG,
						 &tfw_blk_flags))
			return -EINVAL;
	} else {
		T_ERR_NL("Unsupported argument: '%s'\n", ce->vals[0]);
		return -EINVAL;
	}

	return 0;
}

static void
tfw_cfgop_cleanup_block_action(TfwCfgSpec *cs)
{
	tfw_blk_flags = TFW_CFG_BLK_DEF;
}

/* Macros specific to *_set_body() functions. */
#define __TFW_STR_SET_BODY()						\
	msg->len += l_size - clen_str->len + b_size - body_str->len;	\
	body_str->data = new_body;					\
	body_str->len = b_size;						\
	clen_str->data = new_length;					\
	clen_str->len = l_size;

static void
tfw_http_set_body(resp_code_t code, char *new_length, size_t l_size,
		  char *new_body, size_t b_size)
{
	unsigned long prev_len;
	TfwStr *msg = &http_predef_resps[code];
	TfwStr *clen_str = TFW_STR_CLEN_CH(msg);
	TfwStr *body_str = TFW_STR_BODY_CH(msg);
	void *prev_body_ptr = body_str->data;
	void *prev_clen_ptr = NULL;

	if (prev_body_ptr) {
		prev_clen_ptr = clen_str->data;
		prev_len = clen_str->len + body_str->len;
	}

	__TFW_STR_SET_BODY();

	if (!prev_body_ptr)
		return;

	BUG_ON(!prev_clen_ptr);
	if (prev_body_ptr != __TFW_STR_CH(&http_4xx_resp_body, 1)->data &&
	    prev_body_ptr != __TFW_STR_CH(&http_5xx_resp_body, 1)->data)
	{
		free_pages((unsigned long)prev_clen_ptr, get_order(prev_len));
	}
}

static int
tfw_http_set_common_body(int status_code, char *new_length, size_t l_size,
			 char *new_body, size_t b_size)
{
	TfwStr *msg;
	resp_code_t i, begin, end;
	TfwStr *clen_str;
	TfwStr *body_str;
	unsigned long prev_len;
	void *prev_clen_ptr = NULL;
	void *prev_body_ptr = NULL;

	switch(status_code) {
	case HTTP_STATUS_4XX:
		begin = RESP_4XX_BEGIN;
		end = RESP_4XX_END;
		msg = &http_4xx_resp_body;
		break;
	case HTTP_STATUS_5XX:
		begin = RESP_5XX_BEGIN;
		end = RESP_5XX_END;
		msg = &http_5xx_resp_body;
		break;
	default:
		T_ERR_NL("undefined HTTP status group: [%d]\n", status_code);
		return -EINVAL;
	}

	clen_str = __TFW_STR_CH(msg, 0);
	body_str = __TFW_STR_CH(msg, 1);
	prev_body_ptr = body_str->data;

	if (prev_body_ptr) {
		prev_clen_ptr = clen_str->data;
		prev_len = clen_str->len + body_str->len;
	}

	__TFW_STR_SET_BODY();

	for (i = begin; i < end; ++i) {
		TfwStr *msg = &http_predef_resps[i];
		TfwStr *body_str = TFW_STR_BODY_CH(msg);
		if (!body_str->data ||
		    body_str->data == prev_body_ptr)
		{
			TfwStr *clen_str = TFW_STR_CLEN_CH(msg);
			__TFW_STR_SET_BODY();
		}
	}

	if (!prev_body_ptr) {
		BUG_ON(prev_clen_ptr);
		return 0;
	}

	BUG_ON(!prev_clen_ptr);
	free_pages((unsigned long)prev_clen_ptr, get_order(prev_len));

	return 0;
}

/**
 * Allocate memory to store `Content-length' header and body located in file
 * @filename. Memory is allocated via __get_free_pages(), thus free_pages()
 * must be used on cleanup;
 * @c_len	- Content-Length header template. __TFW_STR_CH(&c_len, 1) must
 *		  be NULL, meaning that content-length value must be inserted
 *		  at that chunk.
 * @len		- total length of body data including headers.
 * @body_offset	- the body offset in result;
 */
static char *
__tfw_http_msg_body_dup(const char *filename, TfwStr *c_len_hdr, size_t *len,
			size_t *body_offset)
{
	char *body, *b_start, *res = NULL;
	size_t b_sz, t_sz = 0;
	char buff[TFW_ULTOA_BUF_SIZ] = {0};
	TfwStr *cl_buf = c_len_hdr ? __TFW_STR_CH(c_len_hdr, 1) : 0;

	body = tfw_cfg_read_file(filename, &b_sz, 0);
	if (!body) {
		*len = *body_offset = 0;
		return NULL;
	}
	if (c_len_hdr) {
		cl_buf->data = buff;
		cl_buf->len = tfw_ultoa(b_sz, cl_buf->data, TFW_ULTOA_BUF_SIZ);
		if (unlikely(!cl_buf->len)) {
			T_ERR_NL("Can't copy file %s: too big\n", filename);
			goto err;
		}

		c_len_hdr->len += cl_buf->len;
		t_sz += c_len_hdr->len;
	}

	t_sz += b_sz;
	b_start = res = (char *)__get_free_pages(GFP_KERNEL, get_order(t_sz));
	if (!res) {
		T_ERR_NL("Can't allocate memory storing file %s as response "
			 "body\n", filename);
		goto err_2;
	}

	if (c_len_hdr) {
		tfw_str_to_cstr(c_len_hdr, res, t_sz);
		b_start += c_len_hdr->len;
	}
	memcpy_fast(b_start, body, b_sz);

	*len = t_sz;
	*body_offset = b_start - res;
err_2:
	if (c_len_hdr)
		c_len_hdr->len -= cl_buf->len;
err:
	free_pages((unsigned long)body, get_order(b_sz));

	return res;
}

/**
 * Copy @filename content to allocated memory. Memory is allocated
 * via __get_free_pages(), thus free_pages() must be used on cleanup.
 * Unlike in @__tfw_http_msg_body_dup() content-length header is not added
 * to the body.
 * @len		- total length of body data including headers.
 */
char *
tfw_http_msg_body_dup(const char *filename, size_t *len)
{
	size_t b_off;

	return __tfw_http_msg_body_dup(filename, NULL, len, &b_off);
}


/**
 * Set message body for predefined response with corresponding code.
 */
static int
tfw_http_config_resp_body(int status_code, const char *filename)
{
	resp_code_t code;
	size_t cl_sz, b_sz, sz, b_off;
	char *cl, *body;
	TfwStr c_len_hdr = {
		.chunks = (TfwStr []){
			{ .data = S_CRLF S_F_CONTENT_LENGTH,
			  .len = SLEN(S_CRLF S_F_CONTENT_LENGTH) },
			{ .data = NULL, .len = 0 },
			{ .data = S_CRLF, .len = SLEN(S_CRLF) },
		},
		.len = SLEN(S_CRLF S_F_CONTENT_LENGTH S_CRLF),
		.nchunks = 3
	};

	if (!(cl = __tfw_http_msg_body_dup(filename, &c_len_hdr, &sz, &b_off)))
		return -EINVAL;

	cl_sz = b_off;
	body = cl + b_off;
	b_sz = sz - b_off;

	if (status_code == HTTP_STATUS_4XX || status_code == HTTP_STATUS_5XX) {
		tfw_http_set_common_body(status_code, cl, cl_sz, body, b_sz);
		return 0;
	}

	code = tfw_http_enum_resp_code(status_code);
	if (code == RESP_NUM) {
		T_ERR_NL("Unexpected status code: [%d]\n", status_code);
		return -EINVAL;
	}

	tfw_http_set_body(code, cl, cl_sz, body, b_sz);

	return 0;
}

/**
 * Restore initial Content-Length header value (chunk 4 of http_predef_resps).
 *
 * @hdr		- TFW_STR_CLEN_CH(http_predef_resps[@resp_num]);
 * @resp_num	- response number in resp_code_t.
*/
static void
tfw_cfgop_resp_body_restore_clen(TfwStr *hdr, int resp_num)
{
#define CLEN_STR_INIT(s) { hdr->data = s; hdr->len = SLEN(s); }
	switch (resp_num)
	{
	case RESP_200:
		CLEN_STR_INIT(S_200_PART_02);
		break;
	case RESP_400:
		CLEN_STR_INIT(S_400_PART_02);
		break;
	case RESP_403:
		CLEN_STR_INIT(S_403_PART_02);
		break;
	case RESP_404:
		CLEN_STR_INIT(S_404_PART_02);
		break;
	case RESP_412:
		CLEN_STR_INIT(S_412_PART_02);
		break;
	case RESP_500:
		CLEN_STR_INIT(S_500_PART_02);
		break;
	case RESP_502:
		CLEN_STR_INIT(S_502_PART_02);
		break;
	case RESP_503:
		CLEN_STR_INIT(S_503_PART_02);
		break;
	case RESP_504:
		CLEN_STR_INIT(S_504_PART_02);
		break;
	default:
		T_WARN("Bug in 'response_body' directive cleanup.\n");
		CLEN_STR_INIT(S_DEF_PART_02);
		break;
	}
#undef CLEN_STR_INIT
}

/**
 * Delete all dynamically allocated message bodies for predefined
 * responses (for the cleanup case during shutdown).
 */
static void
tfw_cfgop_cleanup_resp_body(TfwCfgSpec *cs)
{
	TfwStr *clen_str_4xx = __TFW_STR_CH(&http_4xx_resp_body, 0);
	TfwStr *body_str_4xx = __TFW_STR_CH(&http_4xx_resp_body, 1);
	TfwStr *clen_str_5xx = __TFW_STR_CH(&http_5xx_resp_body, 0);
	TfwStr *body_str_5xx = __TFW_STR_CH(&http_5xx_resp_body, 1);
	resp_code_t i;

	for (i = 0; i < RESP_NUM; ++i) {
		TfwStr *clen_str;
		TfwStr *body_str = TFW_STR_BODY_CH(&http_predef_resps[i]);
		if (!body_str->data)
			continue;

		if (body_str->data == body_str_4xx->data ||
		    body_str->data == body_str_5xx->data)
			continue;

		clen_str = TFW_STR_CLEN_CH(&http_predef_resps[i]);
		free_pages((unsigned long)clen_str->data,
			   get_order(clen_str->len + body_str->len));
		TFW_STR_INIT(body_str);
		tfw_cfgop_resp_body_restore_clen(clen_str, i);
	}

	if (body_str_4xx->data) {
		BUG_ON(!clen_str_4xx->data);
		free_pages((unsigned long)clen_str_4xx->data,
			   get_order(clen_str_4xx->len + body_str_4xx->len));
		TFW_STR_INIT(body_str_4xx);
		TFW_STR_INIT(clen_str_4xx);
	}
	if (body_str_5xx->data) {
		BUG_ON(!clen_str_5xx->data);
		free_pages((unsigned long)clen_str_5xx->data,
			   get_order(clen_str_5xx->len + body_str_5xx->len));
		TFW_STR_INIT(body_str_5xx);
		TFW_STR_INIT(clen_str_5xx);
	}
}

int
tfw_cfgop_parse_http_status(const char *status, int *out)
{
	int i;
	for (i = 0; status[i]; ++i) {
		if (isdigit(status[i]))
			continue;

		if (i == 1 && status[i] == '*' && !status[i+1]) {
			/*
			 * For status groups only two-character
			 * sequences with first digit are
			 * acceptable (e.g. 4* or 5*).
			 */
			if (tfw_http_check_wildcard_status(status[0], out))
				return 0;
		}
		return -EINVAL;
	}
	/*
	 * For simple HTTP status value only
	 * three-digit numbers are acceptable
	 * currently.
	 */
	if (i != 3 || kstrtoint(status, 10, out))
		return -EINVAL;

	return tfw_cfg_check_range(*out, HTTP_CODE_MIN, HTTP_CODE_MAX);
}

static int
tfw_cfgop_resp_body(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int code;

	if (tfw_cfg_check_val_n(ce, 2))
		return -EINVAL;

	if (ce->attr_n) {
		T_ERR_NL("Unexpected attributes\n");
		return -EINVAL;
	}

	if (tfw_cfgop_parse_http_status(ce->vals[0], &code)) {
		T_ERR_NL("Unable to parse HTTP code value in '%s' directive: "
			 "'%s'\n", cs->name, ce->vals[0]);
		return -EINVAL;
	}

	return tfw_http_config_resp_body(code, ce->vals[1]);
}

static int
tfw_cfgop_whitelist_mark(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	unsigned int i;
	const char *val;

	if (!ce->val_n) {
		T_ERR_NL("%s: At least one argument is required", cs->name);
		return -EINVAL;
	}
	if (ce->attr_n) {
		T_ERR_NL("Unexpected attributes\n");
		return -EINVAL;
	}

	tfw_wl_marks.sz = ce->val_n;
	if (!(tfw_wl_marks.mrks = kmalloc(ce->val_n * sizeof(unsigned int),
					  GFP_KERNEL)))
		return -ENOMEM;

	TFW_CFG_ENTRY_FOR_EACH_VAL(ce, i, val) {
		if (tfw_cfg_parse_int(val, &tfw_wl_marks.mrks[i])) {
			T_ERR_NL("Unable to parse whitelist mark value: '%s'\n",
				 val);
			kfree(tfw_wl_marks.mrks);
			return -EINVAL;
		}
	}

	sort(tfw_wl_marks.mrks, tfw_wl_marks.sz, sizeof(tfw_wl_marks.mrks[0]),
	     tfw_http_marks_cmp, NULL);

	return 0;
}

static void
tfw_cfgop_cleanup_whitelist_mark(TfwCfgSpec *cs)
{
	kfree(tfw_wl_marks.mrks);
	memset(&tfw_wl_marks, 0, sizeof(tfw_wl_marks));
}

static int
__cfgop_brange_hndl(TfwCfgSpec *cs, TfwCfgEntry *ce, unsigned char *a)
{
	unsigned int i;
	const char *val;

	if (!ce->val_n) {
		T_ERR_NL("%s: At least one argument is required", cs->name);
		return -EINVAL;
	}
	if (ce->attr_n) {
		T_ERR_NL("Unexpected attributes\n");
		return -EINVAL;
	}

	TFW_CFG_ENTRY_FOR_EACH_VAL(ce, i, val) {
		unsigned long i0 = 0, i1 = 0;

		if (tfw_cfg_parse_intvl(val, &i0, &i1)) {
			T_ERR_NL("Cannot parse %s interval: '%s'\n",
				 cs->name, val);
			return -EINVAL;
		}
		if (i0 > 255 || i1 > 255) {
			T_ERR_NL("Too large interval bounds in %s: '%s'\n",
				 cs->name, val);
			return -EINVAL;
		}

		a[i0++] = 1;
		while (i0 <= i1)
			a[i0++] = 1;
	}

	return 0;
}

#define TFW_HTTP_CFG_CUSTOM_BRANGE(name)				\
static int								\
tfw_cfgop_brange_##name(TfwCfgSpec *cs, TfwCfgEntry *ce)		\
{									\
	int r;								\
	unsigned char a[256] = {};					\
	if ((r = __cfgop_brange_hndl(cs, ce, a)))			\
		return r;						\
	tfw_init_custom_##name(a);					\
	return 0;							\
}									\
static void								\
tfw_cfgop_cleanup_brange_##name(TfwCfgSpec *cs)				\
{									\
	tfw_init_custom_##name(NULL);					\
}

TFW_HTTP_CFG_CUSTOM_BRANGE(uri);
TFW_HTTP_CFG_CUSTOM_BRANGE(token);
TFW_HTTP_CFG_CUSTOM_BRANGE(qetoken);
TFW_HTTP_CFG_CUSTOM_BRANGE(nctl);
TFW_HTTP_CFG_CUSTOM_BRANGE(ctext_vchar);
TFW_HTTP_CFG_CUSTOM_BRANGE(xff);
TFW_HTTP_CFG_CUSTOM_BRANGE(cookie);

static TfwCfgSpec tfw_http_specs[] = {
	{
		.name = "block_action",
		.deflt = NULL,
		.handler = tfw_cfgop_block_action,
		.allow_repeat = true,
		.allow_none = true,
		.cleanup = tfw_cfgop_cleanup_block_action,
	},
	{
		.name = "response_body",
		.deflt = NULL,
		.handler = tfw_cfgop_resp_body,
		.allow_repeat = true,
		.allow_none = true,
		.cleanup = tfw_cfgop_cleanup_resp_body,
	},
	{
		.name = "whitelist_mark",
		.deflt = NULL,
		.handler = tfw_cfgop_whitelist_mark,
		.allow_none = true,
		.cleanup = tfw_cfgop_cleanup_whitelist_mark,
	},
	{
		.name = "http_uri_brange",
		.deflt = NULL,
		.handler = tfw_cfgop_brange_uri,
		.allow_none = true,
		.cleanup = tfw_cfgop_cleanup_brange_uri,
	},
	{
		.name = "http_token_brange",
		.deflt = NULL,
		.handler = tfw_cfgop_brange_token,
		.allow_none = true,
		.cleanup = tfw_cfgop_cleanup_brange_token,
	},
	{
		.name = "http_qetoken_brange",
		.deflt = NULL,
		.handler = tfw_cfgop_brange_qetoken,
		.allow_none = true,
		.cleanup = tfw_cfgop_cleanup_brange_qetoken,
	},
	{
		.name = "http_nctl_brange",
		.deflt = NULL,
		.handler = tfw_cfgop_brange_nctl,
		.allow_none = true,
		.cleanup = tfw_cfgop_cleanup_brange_nctl,
	},
	{
		.name = "http_ctext_vchar_brange",
		.deflt = NULL,
		.handler = tfw_cfgop_brange_ctext_vchar,
		.allow_none = true,
		.cleanup = tfw_cfgop_cleanup_brange_ctext_vchar,
	},
	{
		.name = "http_xff_brange",
		.deflt = NULL,
		.handler = tfw_cfgop_brange_xff,
		.allow_none = true,
		.cleanup = tfw_cfgop_cleanup_brange_xff,
	},
	{
		.name = "http_cookie_brange",
		.deflt = NULL,
		.handler = tfw_cfgop_brange_cookie,
		.allow_none = true,
		.cleanup = tfw_cfgop_cleanup_brange_cookie,
	},
	{ 0 }
};

TfwMod tfw_http_mod  = {
	.name	= "http",
	.specs	= tfw_http_specs,
};

/*
 * ------------------------------------------------------------------------
 *	init/exit
 * ------------------------------------------------------------------------
 */

int __init
tfw_http_init(void)
{
	int r;

	r = tfw_gfsm_register_fsm(TFW_FSM_HTTP, tfw_http_msg_process);
	if (r)
		return r;

	tfw_connection_hooks_register(&http_conn_hooks, TFW_FSM_HTTP);

	ghprio = tfw_gfsm_register_hook(TFW_FSM_TLS,
					TFW_GFSM_HOOK_PRIORITY_ANY,
					TFW_TLS_FSM_DATA_READY,
					TFW_FSM_HTTP, TFW_HTTP_FSM_INIT);
	if (ghprio < 0) {
		tfw_connection_hooks_unregister(TFW_FSM_HTTP);
		tfw_gfsm_unregister_fsm(TFW_FSM_HTTP);
		return ghprio;
	}

	tfw_mod_register(&tfw_http_mod);

	return 0;
}

void
tfw_http_exit(void)
{
	tfw_mod_unregister(&tfw_http_mod);
	tfw_gfsm_unregister_hook(TFW_FSM_TLS, ghprio, TFW_TLS_FSM_DATA_READY);
	tfw_connection_hooks_unregister(TFW_FSM_HTTP);
	tfw_gfsm_unregister_fsm(TFW_FSM_HTTP);
}
