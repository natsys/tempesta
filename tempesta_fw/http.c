/**
 *		Tempesta FW
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
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/sort.h>
#include <linux/bsearch.h>

#include "lib/hash.h"
#include "lib/str.h"
#include "cache.h"
#include "http_limits.h"
#include "http_tbl.h"
#include "http_parser.h"
#include "client.h"
#include "http_msg.h"
#include "http_sess.h"
#include "log.h"
#include "procfs.h"
#include "server.h"
#include "tls.h"
#include "apm.h"

#include "sync_socket.h"

#define TFW_WARN_ADDR_STATUS(msg, addr_ptr, print_port, status)		\
	TFW_WITH_ADDR_FMT(addr_ptr, print_port, addr_str,		\
			  TFW_WARN("%s, status %d: %s\n",		\
				   msg, status, addr_str))

#define RESP_BUF_LEN			128
static DEFINE_PER_CPU(char[RESP_BUF_LEN], g_buf);
int ghprio; /* GFSM hook priority. */

#define TFW_CFG_BLK_DEF		(TFW_BLK_ERR_REPLY)
unsigned short tfw_blk_flags = TFW_CFG_BLK_DEF;

/* Array of whitelist marks for request's skb. */
static struct {
	unsigned int *mrks;
	unsigned int sz;
} tfw_wl_marks;

/* Proxy buffering size for client connections. */
static size_t tfw_cfg_cli_msg_buff_sz __read_mostly;
/* Proxy buffering size for server connections. */
static size_t tfw_cfg_srv_msg_buff_sz __read_mostly;

#define S_CRLFCRLF		"\r\n\r\n"
#define S_HTTP			"http://"
#define S_HTTPS			"https://"

#define S_0			"HTTP/1.1 "
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

#define S_F_HOST		"Host: "
#define S_F_DATE		"Date: "
#define S_F_CONTENT_LENGTH	"Content-Length: "
#define S_F_LOCATION		"Location: "
#define S_F_CONNECTION		"Connection: "
#define S_F_ETAG		"ETag: "
#define S_F_RETRY_AFTER		"Retry-After: "
#define S_F_SERVER		"Server: "

#define S_V_DATE		"Sun, 06 Nov 1994 08:49:37 GMT"
#define S_V_CONTENT_LENGTH	"9999"
#define S_V_CONN_CLOSE		"close"
#define S_V_CONN_KA		"keep-alive"
#define S_V_RETRY_AFTER		"10"

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

unsigned long tfw_hash_str(const TfwStr *str);

#define S_REDIR_302	S_302 S_CRLF
#define S_REDIR_503	S_503 S_CRLF
#define S_REDIR_GEN	" Redirection" S_CRLF
#define S_REDIR_P_01	S_F_DATE
#define S_REDIR_P_02	S_CRLF S_F_LOCATION
#define S_REDIR_P_03	S_CRLF S_F_SET_COOKIE
#define S_REDIR_KEEP	S_CRLF S_F_CONNECTION S_V_CONN_KA S_CRLF
#define S_REDIR_CLOSE	S_CRLF S_F_CONNECTION S_V_CONN_CLOSE S_CRLF
#define S_REDIR_C_LEN	S_F_CONTENT_LENGTH "0" S_CRLFCRLF

/**
 * The response redirects the client to the same URI as the original request,
 * but it includes 'Set-Cookie:' header field that sets Tempesta sticky cookie.
 * If JS challenge is enabled, then body contained JS challenge is provided.
 * Body string contains the 'Content-Legth' header, CRLF and body itself.
 */
int
tfw_http_prep_redirect(TfwHttpMsg *resp, unsigned short status, TfwStr *rmark,
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
	static TfwStr c_len_crlf = {
		.data = S_REDIR_C_LEN, .len = SLEN(S_REDIR_C_LEN) };
	static TfwStr protos[] = {
		{ .data = S_HTTP, .len = SLEN(S_HTTP) },
		{ .data = S_HTTPS, .len = SLEN(S_HTTPS) },
	};
	TfwStr *proto = &protos[TFW_CONN_PROTO(req->conn) == TFW_FSM_HTTPS];
	TfwStr host, *rh, *cookie_crlf = &crlf, *r_end;

	if (status == 302) {
		rh = &rh_302;
	} else if (status == 503) {
		rh = &rh_503;
	} else {
		tfw_ultoa(status, __TFW_STR_CH(&rh_gen, 1)->data, 3);
		rh = &rh_gen;
	}
	if (body)
		r_end = body;
	else
		r_end = &c_len_crlf;

	if (req->host.len)
		host = req->host;
	else
		tfw_http_msg_clnthdr_val(&req->h_tbl->tbl[TFW_HTTP_HDR_HOST],
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
	data_len += cookie_crlf->len + r_end->len;

	if (tfw_http_msg_setup(resp, &it, data_len))
		return TFW_BLOCK;

	tfw_http_prep_date(__TFW_STR_CH(&h_common_1, 1)->data);

	ret = tfw_msg_write(&it, rh);
	ret = tfw_msg_write(&it, &h_common_1);
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
	ret |= tfw_msg_write(&it, r_end);

	return ret;
}

#define S_304_PART_01	S_304 S_CRLF
#define S_304_KEEP	S_F_CONNECTION S_V_CONN_KA S_CRLF
#define S_304_CLOSE	S_F_CONNECTION S_V_CONN_CLOSE S_CRLF
/*
 * HTTP 304 response: Not Modified.
 */
int
tfw_http_prep_304(TfwHttpMsg *resp, TfwHttpReq *req, TfwMsgIter *it,
		  size_t hdrs_size)
{
	size_t data_len = SLEN(S_304_PART_01);
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

	/* Add variable part of data length to get the total */
	data_len += hdrs_size;
	if (end)
		data_len += end->len;

	if (tfw_http_msg_setup(resp, it, data_len))
		return TFW_BLOCK;

	ret = tfw_msg_write(it, &rh);
	if (end)
		ret |= tfw_msg_write(it, end);

	TFW_DBG("Send HTTP 304 response\n");

	return ret ? TFW_BLOCK : TFW_PASS;
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
static void
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
		 */
		__cmpxchg((unsigned long *)&hm->conn->msg, (unsigned long)hm,
			  0UL, sizeof(long));
		tfw_connection_put(hm->conn);
	}

	tfw_http_msg_free(hm);
}

/*
 * Free request after removing it from seq_queue. This function is
 * needed in cases when response is not sent to client for some reasons.
 */
static inline void
tfw_http_conn_req_clean(TfwHttpReq *req)
{
	spin_lock_bh(&((TfwCliConn *)req->conn)->seq_qlock);
	if (likely(!list_empty(&req->msg.seq_list)))
		list_del_init(&req->msg.seq_list);
	spin_unlock_bh(&((TfwCliConn *)req->conn)->seq_qlock);
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
__tfw_http_send_resp(TfwHttpReq *req, resp_code_t code)
{
	TfwMsgIter it;
	TfwHttpResp *resp;
	TfwStr *date, *crlf, *body;
	TfwStr msg = {
		.chunks = (TfwStr []){ {}, {}, {}, {}, {}, {} },
		.len = 0,
		.nchunks = 6
	};

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
	if (tfw_http_msg_setup((TfwHttpMsg *)resp, &it, msg.len))
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
	TFW_DBG2("%s: Response message allocation error: conn=[%p]\n",
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
tfw_http_req_init_ss_flags(TfwHttpReq *req)
{
	req->msg.ss_flags |= SS_F_KEEP_SKB;
}

/*
 * No special flags are required for stream part of the request. It's
 * not stored inside Tempesta and released right after send.
 */
static inline void
tfw_http_req_spart_init_ss_flags(TfwHttpStream *hm)
{
	return;
}

static inline void
tfw_http_resp_init_ss_flags(TfwHttpResp *resp)
{
	if (test_bit(TFW_HTTP_B_CONN_CLOSE, resp->req->flags))
		resp->msg.ss_flags |= SS_F_CONN_CLOSE;
}

/**
 * Check if a message is streamed.
 */
static inline bool
tfw_http_msg_is_stream_done(TfwHttpMsg *hm)
{
	if (!tfw_http_msg_is_streamed(hm))
		return true;
	return test_bit(TFW_HTTP_B_STREAM_DONE, hm->flags);
}

/**
 * Return @true if the message was fully read from sender connection and
 * @false if sender is expected to stream more data as a part of current message.
 */
static inline bool
tfw_http_msg_is_stream_read(TfwHttpMsg *hm)
{
	if (!tfw_http_msg_is_streamed(hm))
		return true;
	return test_bit(TFW_HTTP_B_STREAM_LAST_PART, hm->stream->flags);
}

/**
 * Locally generated responses has no connection member set.
 */
static inline bool
tfw_http_resp_is_local(TfwHttpResp *resp)
{
	return (resp && !resp->conn);
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
 * It's on hold it the request that was sent last was non-idempotent.
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

static inline void
tfw_http_error_resp_switch(TfwHttpReq *req, int status)
{
	resp_code_t code = tfw_http_enum_resp_code(status);
	if (code == RESP_NUM) {
		TFW_WARN("Unexpected response error code: [%d]\n", status);
		code = RESP_500;
	}
	__tfw_http_send_resp(req, code);
}

/* Common interface for sending error responses. */
void
tfw_http_send_resp(TfwHttpReq *req, int status, const char *reason)
{
	if (!(tfw_blk_flags & TFW_BLK_ERR_NOLOG)) {
		TFW_WARN_ADDR_STATUS(reason, &req->conn->peer->addr,
		                     TFW_WITH_PORT, status);
	}
	tfw_http_error_resp_switch(req, status);
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
			TFW_WARN_ADDR_STATUS("server has been suspended: limit "
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

	TFW_DBG2("%s: queue is %sempty\n",
		 __func__, list_empty(eq) ? "" : "NOT ");
	if (list_empty(eq))
		return;

	list_for_each_entry_safe(req, tmp, eq, fwd_list) {
		list_del_init(&req->fwd_list);
		if (!test_bit(TFW_HTTP_B_REQ_DROP, req->flags))
			tfw_http_send_resp(req, req->httperr.status,
					   req->httperr.reason);
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
	if (unlikely(test_bit(TFW_HTTP_B_REQ_DROP, req->flags))) {
		TFW_DBG2("%s: Eviction: req=[%p] client disconnected\n",
			 __func__, req);
		if (srv_conn)
			tfw_http_req_delist(srv_conn, req);
		tfw_http_conn_msg_free((TfwHttpMsg *)req);
		TFW_INC_STAT_BH(clnt.msgs_otherr);
		return true;
	}
	return false;
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
		TFW_DBG2("%s: Eviction: req=[%p] overdue=[%dms]\n",
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
 * It's not possible to re-forward streamed request, since we don't store
 * it's body.
 */
static inline bool
tfw_http_req_evict_retries(TfwSrvConn *srv_conn, TfwServer *srv,
			   TfwHttpReq *req, struct list_head *eq)
{
	if (unlikely(req->retries++ >= srv->sg->max_refwd)
	    || tfw_http_msg_is_streamed((TfwHttpMsg *)req))
	{
		TFW_DBG2("%s: Eviction: req=[%p] retries=[%d]\n",
			 __func__, req, req->retries);
		tfw_http_req_err(srv_conn, req, eq, 504,
				 "request evicted: the number of retries "
				 "exceeded");
		return true;
	}
	return false;
}

static inline bool
tfw_http_req_evict_err_stream(TfwSrvConn *srv_conn, TfwHttpReq *req,
			      struct list_head *eq)
{
	if (unlikely(test_bit(TFW_HTTP_B_STREAM_ERR, req->flags))) {
		TFW_DBG2("%s: Eviction: req=[%p] stream read error\n",
			 __func__, req);
		tfw_http_req_err(srv_conn, req, eq, 504,
				 "request evicted: stream read error");
		return true;
	}
	return false;
}

static inline bool
tfw_http_req_evict_stale_req(TfwSrvConn *srv_conn, TfwServer *srv,
			     TfwHttpReq *req, struct list_head *eq)
{
	return tfw_http_req_evict_dropped(srv_conn, req)
	       || tfw_http_req_evict_err_stream(srv_conn, req, eq)
	       || tfw_http_req_evict_timeout(srv_conn, srv, req, eq);
}

static inline bool
tfw_http_req_evict(TfwSrvConn *srv_conn, TfwServer *srv, TfwHttpReq *req,
		   struct list_head *eq)
{
	return tfw_http_req_evict_dropped(srv_conn, req)
	       || tfw_http_req_evict_err_stream(srv_conn, req, eq)
	       || tfw_http_req_evict_timeout(srv_conn, srv, req, eq)
	       || tfw_http_req_evict_retries(srv_conn, srv, req, eq);
}

/**
 * Send streamed part of the request to the server, buffered part was already
 * sent in tfw_http_req_fwd_send().
 */
static bool
tfw_http_req_stream_send(TfwSrvConn *srv_conn, TfwServer *srv,
			 TfwHttpReq *req, struct list_head *eq)
{
	TfwHttpStream *hmpart = req->stream;
	bool r = true;

	spin_lock(&hmpart->stream_lock);
	hmpart->rcv_conn = (TfwConn *)srv_conn;

	if (test_bit(TFW_HTTP_B_STREAM_ON_HOLD, hmpart->flags)
	    || !hmpart->msg.skb_head)
	{
		goto done;
	}
	TFW_DBG2("%s: Stream req=[%p],part=[%p] to srv_conn=[%p]\n",
		 __func__, req, hmpart, srv_conn);

	tfw_http_req_spart_init_ss_flags(hmpart);
	/*
	 * Requests originated by Tempesta are never streamed, error
	 * processing is simpler than for tfw_http_req_fwd_send()
	 */
	if (tfw_connection_send((TfwConn *)srv_conn, &hmpart->msg)) {
		TFW_DBG2("%s: Streaming error: conn=[%p] req=[%p]\n",
			 __func__, srv_conn, req);
		tfw_http_req_err(srv_conn, req, eq, 500,
				 "request dropped: streaming error");
		r = false;
		goto done;
	}

	if (test_bit(TFW_HTTP_B_STREAM_LAST_PART, hmpart->flags)) {
		TFW_DBG2("%s: Streaming done for req=[%p]\n", __func__, req);
		set_bit(TFW_HTTP_B_STREAM_DONE, req->flags);
		hmpart->rcv_conn = NULL;
	}

	/*
	 * Stream part was sent to server, we don't keep the skbs and release
	 * them after transmission. Allow client to send more data.
	 */
	if (likely(!test_bit(TFW_HTTP_B_REQ_DROP, req->flags)))
		tfw_cli_rmem_release((TfwCliConn *)req->conn, hmpart->msg.len);
	tfw_http_msg_collapse_streamed(hmpart);
done:
	spin_unlock(&hmpart->stream_lock);

	return r;
}

/*
 * If forwarding of @req to server @srv_conn is not successful, then
 * move it to the error queue @eq for sending an error response later.
 *
 * TODO: Perhaps, there's a small optimization. Ultimately, the thread
 * ends up in ss_send(). In some cases a connection is still active when
 * it's obtained, but not active by the time the thread is in ss_send().
 * In that case -EBADF is returned, and nothing destructive happens to
 * the request. So, perhaps, instead of sending an error in that case
 * these unlucky requests can be re-sent when the connection is restored.
 */
static bool
tfw_http_req_fwd_send(TfwSrvConn *srv_conn, TfwServer *srv,
		      TfwHttpReq *req, struct list_head *eq)
{
	TFW_DBG2("%s: Forward req=[%p] to srv_conn=[%p]\n",
		 __func__, req, srv_conn);
	req->jtxtstamp = jiffies;
	tfw_http_req_init_ss_flags(req);

	if (tfw_connection_send((TfwConn *)srv_conn, &req->msg)) {
		TFW_DBG2("%s: Forwarding error: conn=[%p] req=[%p]\n",
			 __func__, srv_conn, req);
		if (test_bit(TFW_HTTP_B_HMONITOR, req->flags)) {
			tfw_http_req_delist(srv_conn, req);
			WARN_ON_ONCE(req->pair);
			tfw_http_msg_free((TfwHttpMsg *)req);
			TFW_WARN_ADDR("Unable to send health"
			              " monitoring request to server",
			              &srv_conn->peer->addr, TFW_WITH_PORT);
		} else {
			tfw_http_req_err(srv_conn, req, eq, 500,
					 "request dropped: forwarding error");
		}
		return false;
	}

	if (!tfw_http_msg_is_streamed((TfwHttpMsg *)req))
		return true;

	return tfw_http_req_stream_send(srv_conn, srv, req, eq);
}

/*
 * Forward one request @req to server connection @srv_conn.
 * Return false if forwarding must be stopped, or true otherwise.
 */
static inline bool
tfw_http_req_fwd_single(TfwSrvConn *srv_conn, TfwServer *srv,
			TfwHttpReq *req, struct list_head *eq)
{
	if (tfw_http_req_evict_stale_req(srv_conn, srv, req, eq))
		return false;
	if (!tfw_http_req_fwd_send(srv_conn, srv, req, eq))
		return false;
	srv_conn->msg_sent = (TfwMsg *)req;
	TFW_INC_STAT_BH(clnt.msgs_forwarded);
	return true;
}

static void __tfw_http_pop_stream_req(TfwSrvConn *srv_conn, TfwHttpReq *req);
/*
 * Forward unsent requests in server connection @srv_conn. The requests
 * are forwarded until a non-idempotent request is found in the queue.
 * It's assumed that the forwarding queue in @srv_conn is locked and
 * NOT drained.
 */
static void
tfw_http_conn_fwd_unsent(TfwSrvConn *srv_conn, struct list_head *eq)
{
	TfwHttpReq *req, *tmp;
	TfwServer *srv = (TfwServer *)srv_conn->peer;
	struct list_head *fwd_queue = &srv_conn->fwd_queue;

	TFW_DBG2("%s: conn=%pK\n", __func__, srv_conn);
	WARN_ON(!spin_is_locked(&srv_conn->fwd_qlock));

	/* Try to finish stream first. */
	if (srv_conn->msg_sent
	    && !tfw_http_msg_is_stream_done((TfwHttpMsg *)srv_conn->msg_sent))
	{
		/* srv_conn->msg sent is buffered part of the request. */
		req = (TfwHttpReq *)srv_conn->msg_sent;

		if (!tfw_http_req_stream_send(srv_conn, srv, req, eq)
		    || !test_bit(TFW_HTTP_B_STREAM_DONE, req->flags))
		{
			return;
		}
		if (req->resp) {
			__tfw_http_pop_stream_req(srv_conn, req);
			set_bit(TFW_HTTP_B_RESP_READY, req->resp->flags);
			/* req mustn't be used from now on. */
			if (list_empty(&srv_conn->fwd_queue))
				return;
		}
		else if (list_is_last(&req->fwd_list, &srv_conn->fwd_queue)) {
			return;
		}
	}
	if (tfw_http_conn_on_hold(srv_conn))
		return;

	BUG_ON(tfw_http_conn_drained(srv_conn));

	req = srv_conn->msg_sent
	    ? list_next_entry((TfwHttpReq *)srv_conn->msg_sent, fwd_list)
	    : list_first_entry(fwd_queue, TfwHttpReq, fwd_list);

	list_for_each_entry_safe_from(req, tmp, fwd_queue, fwd_list) {
		if (!tfw_http_req_fwd_single(srv_conn, srv, req, eq))
			continue;
		/* Stop forwarding if streamed request is not fully received. */
		if (!tfw_http_msg_is_stream_done((TfwHttpMsg *)req))
			break;
		/* Stop forwarding if the request is non-idempotent. */
		if (tfw_http_req_is_nip(req))
			break;
		/* See if the idempotent request was non-idempotent. */
		tfw_http_req_nip_delist(srv_conn, req);
	}
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
static void
tfw_http_req_fwd(TfwSrvConn *srv_conn, TfwHttpReq *req, struct list_head *eq)
{
	TFW_DBG2("%s: srv_conn=%pK req=%pK\n", __func__, srv_conn, req);
	BUG_ON(!(TFW_CONN_TYPE(srv_conn) & Conn_Srv));

	spin_lock_bh(&srv_conn->fwd_qlock);
	list_add_tail(&req->fwd_list, &srv_conn->fwd_queue);
	srv_conn->qsize++;
	if (tfw_http_req_is_nip(req))
		tfw_http_req_nip_enlist(srv_conn, req);
	if (tfw_http_conn_on_hold(srv_conn)) {
		spin_unlock_bh(&srv_conn->fwd_qlock);
		return;
	}
	tfw_http_conn_fwd_unsent(srv_conn, eq);
	spin_unlock_bh(&srv_conn->fwd_qlock);
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
 */
static TfwMsg *
tfw_http_conn_resend(TfwSrvConn *srv_conn, bool first, struct list_head *eq)
{
	TfwHttpReq *req, *tmp, *req_resent = NULL;
	TfwServer *srv = (TfwServer *)srv_conn->peer;
	struct list_head *end, *fwd_queue = &srv_conn->fwd_queue;

	TFW_DBG2("%s: conn=[%p] first=[%s]\n",
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
		if (tfw_http_req_evict(srv_conn, srv, req, eq))
			continue;
		if (!tfw_http_req_fwd_send(srv_conn, srv, req, eq))
			continue;
		req_resent = req;
		if (unlikely(first))
			break;
	}

	return (TfwMsg *)req_resent;
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
static void
tfw_http_conn_fwd_repair(TfwSrvConn *srv_conn, struct list_head *eq)
{
	TFW_DBG2("%s: conn=[%p]\n", __func__, srv_conn);
	WARN_ON(!spin_is_locked(&srv_conn->fwd_qlock));
	BUG_ON(!tfw_srv_conn_restricted(srv_conn));

	if (tfw_srv_conn_reenable_if_done(srv_conn))
		return;
	if (test_bit(TFW_CONN_B_QFORWD, &srv_conn->flags)) {
		if (tfw_http_conn_need_fwd(srv_conn))
			tfw_http_conn_fwd_unsent(srv_conn, eq);
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
		if (srv_conn->msg_sent)
			srv_conn->msg_sent =
				tfw_http_conn_resend(srv_conn, false, eq);
		set_bit(TFW_CONN_B_QFORWD, &srv_conn->flags);
		if (tfw_http_conn_need_fwd(srv_conn))
			tfw_http_conn_fwd_unsent(srv_conn, eq);
	}
	tfw_srv_conn_reenable_if_done(srv_conn);
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
static void
tfw_http_req_resched(TfwHttpReq *req, TfwServer *srv, struct list_head *eq)
{
	TfwSrvConn *sch_conn;

	/*
	 * Health monitoring requests must be re-scheduled to
	 * the same server (other servers may not have enabled
	 * health monitor).
	 */
	if (test_bit(TFW_HTTP_B_HMONITOR, req->flags)) {
		sch_conn = srv->sg->sched->sched_srv_conn((TfwMsg *)req,
							  srv);
		if (!sch_conn) {
			list_del_init(&req->fwd_list);
			tfw_http_conn_msg_free((TfwHttpMsg *)req);
			TFW_WARN_ADDR("Unable to find connection to"
			              " reschedule health monitoring"
			              " request on server", &srv->addr,
			              TFW_WITH_PORT);
			return;
		}
	} else if (!(sch_conn = tfw_http_get_srv_conn((TfwMsg *)req))) {
		TFW_DBG("Unable to find a backend server\n");
		tfw_http_send_resp(req, 502, "request dropped: unable to"
				   " find an available back end server");
		TFW_INC_STAT_BH(clnt.msgs_otherr);
		return;
	} else {
		tfw_http_hm_srv_update((TfwServer *)sch_conn->peer,
				       req);
	}
	tfw_http_req_fwd(sch_conn, req, eq);
	tfw_srv_conn_put(sch_conn);
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

	TFW_DBG2("%s: conn=[%p]\n", __func__, srv_conn);

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
	TfwHttpReq *req, *tmp;
	TfwServer *srv = (TfwServer *)srv_conn->peer;

	TFW_DBG2("%s: conn=[%p]\n", __func__, srv_conn);

	spin_lock_bh(&srv_conn->fwd_qlock);

	if (list_empty(&srv_conn->fwd_queue)) {
		spin_unlock_bh(&srv_conn->fwd_qlock);
		return;
	}
	list_splice_tail_init(&srv_conn->fwd_queue, &schq);
	srv_conn->qsize = 0;
	srv_conn->msg_sent = NULL;
	INIT_LIST_HEAD(&srv_conn->nip_queue);
	clear_bit(TFW_CONN_B_HASNIP, &srv_conn->flags);

	spin_unlock_bh(&srv_conn->fwd_qlock);

	/*
	 * Evict timed-out requests and requests with depleted number of re-send
	 * attempts. Reschedule all the other requests from the forwarding
	 * queue. NIP requests are only at or after msg_sent, but splitting the
	 * loop to not to check NIP requests introduces unnecessary complexity
	 * and seems doesn't improve anything.
	 */
	list_for_each_entry_safe(req, tmp, &schq, fwd_list) {
		INIT_LIST_HEAD(&req->nip_list);
		INIT_LIST_HEAD(&req->fwd_list);
		if (tfw_http_req_evict(NULL, srv, req, &eq))
			continue;
		if (unlikely(tfw_http_req_is_nip(req)
			     && !(srv->sg->flags & TFW_SRV_RETRY_NIP)))
		{
			tfw_http_nip_req_resched_err(NULL, req, &eq);
			continue;
		}
		tfw_http_req_resched(req, srv, &eq);
	}

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
	TfwSrvConn *srv_conn = (TfwSrvConn *)conn;
	LIST_HEAD(eq);

	TFW_DBG2("%s: conn=[%p]\n", __func__, srv_conn);
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
	if (srv_conn->msg_sent)
		if (unlikely(!tfw_http_conn_resend(srv_conn, true, &eq)))
			srv_conn->msg_sent = NULL;
	/* If none re-sent, then send the remaining unsent requests. */
	if (!srv_conn->msg_sent) {
		if (!list_empty(&srv_conn->fwd_queue)) {
			set_bit(TFW_CONN_B_QFORWD, &srv_conn->flags);
			tfw_http_conn_fwd_unsent(srv_conn, &eq);
		}
		tfw_srv_conn_reenable_if_done(srv_conn);
	}

	spin_unlock_bh(&srv_conn->fwd_qlock);

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

	TFW_WARN("Paired request missing, HTTP Response Splitting attack?\n");
	TFW_INC_STAT_BH(serv.msgs_otherr);

	return -EINVAL;
}

/*
 * Allocate a new HTTP message structure and link it with the connection
 * instance. Increment the number of users of the instance. Initialize
 * GFSM for the message.
 */
static TfwHttpMsg *
tfw_http_conn_msg_alloc(TfwConn *conn)
{
	int type = TFW_CONN_TYPE(conn);
	TfwHttpMsg *hm = __tfw_http_msg_alloc(type, true);
	if (unlikely(!hm))
		return NULL;

	hm->conn = conn;
	tfw_connection_get(conn);

	if (type & Conn_Clnt)
		tfw_http_init_parser_req((TfwHttpReq *)hm);
	else
		tfw_http_init_parser_resp((TfwHttpResp *)hm);

	if (type & Conn_Clnt) {
		TFW_INC_STAT_BH(clnt.rx_messages);
	} else {
		if (unlikely(tfw_http_resp_pair(hm))) {
			tfw_http_conn_msg_free(hm);
			return NULL;
		}
		TFW_INC_STAT_BH(serv.rx_messages);
	}

	return hm;
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
	TFW_DBG2("%s: conn=[%p]\n", __func__, conn);

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
	TfwSrvConn *srv_conn = (TfwSrvConn *)conn;
	TfwHttpReq *req, *tmp;
	LIST_HEAD(zap_queue);

	TFW_DBG2("%s: conn=[%p]\n", __func__, srv_conn);
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
		if (unlikely(!list_empty_careful(&req->msg.seq_list))) {
			spin_lock_bh(&((TfwCliConn *)req->conn)->seq_qlock);
			if (unlikely(!list_empty(&req->msg.seq_list)))
				list_del_init(&req->msg.seq_list);
			spin_unlock_bh(&((TfwCliConn *)req->conn)->seq_qlock);
		}
		tfw_http_conn_msg_free((TfwHttpMsg *)req);
	}
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
 * Error happen, current request @req will be discarded. Connection should
 * be closed after response for the previous request.
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

	if (list_empty_careful(&cli_conn->seq_queue))
		return false;

	spin_lock(&cli_conn->seq_qlock);

	prev = (!list_empty(&req->msg.seq_list)) ? req->msg.seq_list.prev
						 : cli_conn->seq_queue.prev;
	if (prev != &cli_conn->seq_queue) {
		last_req = list_entry(prev, TfwHttpReq, msg.seq_list);
		tfw_http_req_set_conn_close(last_req);
	}

	spin_unlock(&cli_conn->seq_qlock);

	return last_req;
}

/**
 * Incomplete streamed request is dropped.
 * If
 *   req is not streamed to backend and served from cache or
 *   req is not streamed to backend *yet*
 * there is nothing to do;
 * If req was streamed, but not in full, then close the server connection to
 * recover.
 */
static void
tfw_http_conn_cli_drop_stream_req(TfwHttpReq *req)
{
	TfwHttpStream *hmpart;
	TfwSrvConn *srv_conn;
	TfwHttpReq *req_prev;

	TFW_DBG2("%s: req=[%p]\n", __func__, req);

	set_bit(TFW_HTTP_B_STREAM_ERR, req->flags);
	hmpart = req->stream;
	spin_lock(&hmpart->stream_lock);

	if (!(srv_conn = (TfwSrvConn *)hmpart->rcv_conn)) {
		/* Request wasn't scheduled yet or served from cache. */
		spin_unlock(&hmpart->stream_lock);
		return;
	}

	spin_unlock(&hmpart->stream_lock);
	spin_lock_bh(&srv_conn->fwd_qlock);

	if ((TfwHttpReq *)srv_conn->msg_sent != req)
		goto out;
	req_prev = (TfwHttpReq *)__tfw_http_conn_msg_sent_prev(srv_conn);
	/*
	 * Don't close the server connection immediately, there can be sent
	 * but not replied responses. Wait for them and close the connection
	 * after that. Immediate close will cause resending of such requests.
	 * Streamed and NIP requests from other clients can't be re-sent,
	 * quality of service will be degraded.
	 */
	if (!req_prev)
		tfw_connection_close((TfwConn *)srv_conn, true);
	else
		set_bit(TFW_HTTP_B_FORCE_CLOSE, req_prev->flags);

out:
	spin_unlock_bh(&srv_conn->fwd_qlock);
}

/**
 * Client connection is closed, unregister all 'acquired' memory from socket
 * memory.
 */
static inline void
tfw_http_conn_cli_mem_release(TfwCliConn *cli_conn, TfwHttpReq *req)
{
	TfwHttpStream *hmpart = req->stream;

	tfw_cli_rmem_release(cli_conn, req->msg.len);
	if (hmpart)
		tfw_cli_rmem_release(cli_conn, hmpart->msg.len);
}

/**
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

	TFW_DBG2("%s: conn=[%p]\n", __func__, cli_conn);
	BUG_ON(!(TFW_CONN_TYPE(cli_conn) & Conn_Clnt));

	if (list_empty_careful(seq_queue)) {
		req = (TfwHttpReq *)cli_conn->msg;
		if (req)
			tfw_http_conn_cli_mem_release(cli_conn, req);
		return;
	}

	/*
	 * Disintegration of the list must be done under the lock.
	 * The list can't be just detached from seq_queue, and then
	 * be disintegrated without the lock. That would open a race
	 * condition with freeing of a request in tfw_http_resp_fwd().
	 */
	spin_lock(&cli_conn->seq_qlock);

	list_for_each_entry_safe(req, tmp, seq_queue, msg.seq_list) {
		set_bit(TFW_HTTP_B_REQ_DROP, req->flags);
		list_del_init(&req->msg.seq_list);
		tfw_http_conn_cli_mem_release(cli_conn, req);
		if (unlikely(!tfw_http_msg_is_stream_read((TfwHttpMsg *)req))) {
			tfw_http_conn_cli_drop_stream_req(req);
			cli_conn->msg = NULL;
		}
		/*
		 * Response is processed and removed from fwd_queue, need to be
		 * destroyed.
		 */
		if (req->resp
		    && test_bit(TFW_HTTP_B_RESP_READY, req->resp->flags))
		{
			tfw_http_resp_pair_free(req);
			TFW_INC_STAT_BH(serv.msgs_otherr);
		}
	}

	spin_unlock(&cli_conn->seq_qlock);
}

/**
 * Connection with the server is dropped. New parts of streamed request can't
 * be delivered. Don't wait for end of request transmission and close client
 * connection now. This will allow the client to recover.
 *
 * The client connection is not closed immediately, try to respond to all the
 * previous requests first.
 */
static void
tfw_http_conn_srv_drop(TfwSrvConn *srv_conn)
{
	TfwHttpReq *req;
	TFW_DBG2("%s: conn=[%p]\n", __func__, srv_conn);

	spin_lock_bh(&srv_conn->fwd_qlock);
	req = (TfwHttpReq *)srv_conn->msg_sent;
	if (req && !tfw_http_msg_is_stream_read((TfwHttpMsg *)req)) {
		if (test_bit(TFW_HTTP_B_REQ_DROP, req->flags))
			tfw_http_conn_msg_free(req->pair);
		else if (!tfw_http_req_prev_conn_close(req))
			tfw_connection_close(req->conn, true);
	}
	spin_unlock_bh(&srv_conn->fwd_qlock);
}

static void tfw_http_resp_terminate(TfwHttpMsg *hm);

/*
 * Connection with a peer is dropped.
 *
 * Release resources that are not needed anymore, and keep other
 * resources that are needed while there are users of the connection.
 */
static void
tfw_http_conn_drop(TfwConn *conn)
{
	TFW_DBG2("%s: conn=[%p]\n", __func__, conn);

	if (TFW_CONN_TYPE(conn) & Conn_Clnt) {
		tfw_http_conn_cli_drop((TfwCliConn *)conn);
	}
	else { /* Conn_Srv */
		if (conn->msg
		    && tfw_http_parse_terminate((TfwHttpMsg *)conn->msg))
		{
			tfw_http_resp_terminate((TfwHttpMsg *)conn->msg);
		}
		tfw_http_conn_srv_drop((TfwSrvConn *)conn);
	}
	tfw_http_conn_msg_free((TfwHttpMsg *)conn->msg);
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
 * Create a sibling for @msg message.
 * Siblings in HTTP are pipelined HTTP messages that shared the same SKB.
 * The shared @skb must be split before call.
 */
static TfwHttpMsg *
tfw_http_msg_create_sibling(TfwHttpMsg *hm, struct sk_buff *skb)
{
	TfwHttpMsg *shm;

	TFW_DBG2("Create sibling message: conn %p, msg: %p, skb %p\n",
		 hm->conn, hm, skb);

	/* The sibling message belongs to the same connection. */
	shm = tfw_http_conn_msg_alloc(hm->conn);
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
	r = tfw_http_msg_hdr_xfrm(hm, "Date", sizeof("Date") - 1,
				  s_date, SLEN(S_V_DATE),
				  TFW_HTTP_HDR_RAW, 0);
	if (r)
		TFW_ERR("Unable to add Date: header to msg [%p]\n", hm);
	else
		TFW_DBG2("Added Date: header to msg [%p]\n", hm);
	return r;
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
			TFW_WARN("Cannot delete Keep-Alive header (%d)\n", r);
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

static int
tfw_http_add_hdr_via(TfwHttpMsg *hm)
{
	int r;
	static const char * const s_http_version[] = {
		[0 ... _TFW_HTTP_VER_COUNT] = NULL,
		[TFW_HTTP_VER_09] = "0.9 ",
		[TFW_HTTP_VER_10] = "1.0 ",
		[TFW_HTTP_VER_11] = "1.1 ",
		[TFW_HTTP_VER_20] = "2.0 ",
	};
	TfwGlobal *g_vhost = tfw_vhost_get_global();
	const TfwStr rh = {
#define S_VIA	"Via: "
		.chunks = (TfwStr []) {
			{ .data = S_VIA, .len = SLEN(S_VIA) },
			{ .data = (void *)s_http_version[hm->version],
			  .len = 4 },
			{ .data = *this_cpu_ptr(&g_buf),
			  .len = g_vhost->hdr_via_len },
		},
		.len = SLEN(S_VIA) + 4 + g_vhost->hdr_via_len,
		.eolen = 2,
		.nchunks = 3
#undef S_VIA
	};

	memcpy_fast(__TFW_STR_CH(&rh, 2)->data, g_vhost->hdr_via,
		    g_vhost->hdr_via_len);

	r = tfw_http_msg_hdr_add(hm, &rh);
	if (r)
		TFW_ERR("Unable to add Via: header to msg [%p]\n", hm);
	else
		TFW_DBG2("Added Via: header to msg [%p]\n", hm);
	return r;
}

static int
tfw_http_add_x_forwarded_for(TfwHttpMsg *hm)
{
	int r;
	char *p, *buf = *this_cpu_ptr(&g_buf);

	p = ss_skb_fmt_src_addr(hm->msg.skb_head, buf);

	r = tfw_http_msg_hdr_xfrm(hm, "X-Forwarded-For",
				  sizeof("X-Forwarded-For") - 1, buf, p - buf,
				  TFW_HTTP_HDR_X_FORWARDED_FOR, true);
	if (r)
		TFW_ERR("can't add X-Forwarded-For header for %.*s to msg %p",
			(int)(p - buf), buf, hm);
	else
		TFW_DBG2("added X-Forwarded-For header for %*s\n",
			 (int)(p - buf), buf);
	return r;
}

/**
 * Modify message header as stated in '(req|resp)_hdr_add' and
 * '(req|resp)_hdr_set' directives.
 *
 * @hm		- message to modify;
 * @req		- request message to determine header modification list;
 * @mod_type	- TFW_VHOST_HDRMOD_REQ or TFW_VHOST_HDRMOD_RESP;
 * @trailer	- modification is done to the trailer headers of streamed
 *		  messages;
 *
 * If the @hm is fully buffered, modification is simple, just call
 * tfw_http_msg_hdr_xfrm_str() to do the job. Processing of streamed messages
 * is actually split in two parts: modification of primary header and
 * modification of trailer header. Trailer headers modification takes place
 * after all modifications was already applied to primary headers. Thus
 * we must only remove all headers from the trailer that match
 * '(req|resp)_hdr_add' and '(req|resp)_hdr_set' directives.
 */
static int
__tfw_http_set_loc_hdrs(TfwHttpMsg *hm, TfwHttpReq *req, int mod_type,
			bool trailer)
{
	int r;
	size_t i;
	TfwHdrMods *h_mods = tfw_vhost_get_hdr_mods(req->location, req->vhost,
						    mod_type);
	if (!h_mods)
		return 0;

	for (i = 0; i < h_mods->sz; ++i) {
		TfwHdrModsDesc *d = &h_mods->hdrs[i];
		TfwStr mod = *d->hdr;
		bool append = trailer ? false : d->append;

		if (trailer) {
			if (d->hid != TFW_HTTP_HDR_RAW)
				continue;
			mod.nchunks = 2;
		}

		r = tfw_http_msg_hdr_xfrm_str(hm, &mod, d->hid, append);
		if (r) {
			TFW_ERR("can't update location-specific header in msg %p\n",
				hm);
			return r;
		}
		TFW_DBG2("updated location-specific header in msg %p\n", hm);
	}

	return 0;
}

static inline int
tfw_http_set_loc_hdrs_req(TfwHttpMsg *hm)
{
	return __tfw_http_set_loc_hdrs(hm, (TfwHttpReq *)hm,
				       TFW_VHOST_HDRMOD_REQ, false);
}

static inline int
tfw_http_set_loc_hdrs_resp(TfwHttpMsg *hm)
{
	return __tfw_http_set_loc_hdrs(hm, hm->req, TFW_VHOST_HDRMOD_RESP,
				       false);
}

static inline int
tfw_http_set_loc_hdrs_req_spart(TfwHttpStream *hmpart)
{
	if (!test_bit(TFW_HTTP_B_CHUNKED, hmpart->head->flags))
		return 0;
	return __tfw_http_set_loc_hdrs((TfwHttpMsg *)hmpart,
				       (TfwHttpReq *)hmpart->head,
				       TFW_VHOST_HDRMOD_REQ,
				       true);
}

static inline int
tfw_http_set_loc_hdrs_resp_spart(TfwHttpStream *hmpart)
{
	if (!test_bit(TFW_HTTP_B_CHUNKED, hmpart->head->flags))
		return 0;
	return __tfw_http_set_loc_hdrs((TfwHttpMsg *)hmpart,
				       hmpart->head->req,
				       TFW_VHOST_HDRMOD_RESP,
				       true);
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
 * Adjust the request before proxying it to real server.
 */
static int
tfw_http_adjust_req(TfwHttpReq *req)
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

	r = tfw_http_set_loc_hdrs_req(hm);
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

	r = tfw_http_sess_resp_process(resp);
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

	r = tfw_http_set_loc_hdrs_resp(hm);
	if (r < 0)
		return r;

	if (test_bit(TFW_HTTP_B_RESP_STALE, resp->flags)) {
#define S_WARN_110 "Warning: 110 - Response is stale"
		/* TODO: adjust for #865 */
		TfwStr wh = {
			.data		= S_WARN_110,
			.len		= SLEN(S_WARN_110),
			.eolen		= 2
		};
		r = tfw_http_msg_hdr_add(hm, &wh);
		if (r)
			return r;
#undef S_WARN_110
	}

	if (!test_bit(TFW_HTTP_B_HDR_DATE, resp->flags)) {
		r =  tfw_http_set_hdr_date(hm);
		if (r < 0)
			return r;
	}

	return TFW_HTTP_MSG_HDR_XFRM(hm, "Server", TFW_NAME "/" TFW_VERSION,
				     TFW_HTTP_HDR_SERVER, 0);
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
		unsigned int sz = req->msg.len;
		BUG_ON(!req->resp);
		/*
		 * Release memory before forwarding response to client to set
		 * proper window size.
		 */
		tfw_cli_rmem_release(cli_conn, sz);
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

void
tfw_http_resp_fwd_unsent(TfwCliConn *cli_conn)
{
	TfwHttpReq *req;
	struct list_head *seq_queue = &cli_conn->seq_queue;
	struct list_head *req_retent = NULL;
	LIST_HEAD(ret_queue);

	spin_lock_bh(&cli_conn->seq_qlock);

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
	 * which is controlled by the lock. To allow other threads pair
	 * requests with responses, unlock the seq_queue lock and use
	 * different lock @ret_qlock for sending.
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
	tfw_cli_conn_get(cli_conn);
	spin_lock_bh(&cli_conn->ret_qlock);
	spin_unlock_bh(&cli_conn->seq_qlock);

	__tfw_http_resp_fwd(cli_conn, &ret_queue);

	spin_unlock_bh(&cli_conn->ret_qlock);
	tfw_cli_conn_put(cli_conn);

	/* Zap request/responses that were not sent due to an error. */
	if (!list_empty(&ret_queue)) {
		TfwHttpReq *tmp;
		list_for_each_entry_safe(req, tmp, &ret_queue, msg.seq_list) {
			TFW_DBG2("%s: Forwarding error: conn=[%p] resp=[%p]\n",
				 __func__, cli_conn, req->resp);
			BUG_ON(!req->resp);
			list_del_init(&req->msg.seq_list);
			tfw_http_resp_pair_free(req);
			TFW_INC_STAT_BH(serv.msgs_otherr);
		}
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

	TFW_DBG2("%s: req=[%p], resp=[%p]\n", __func__, req, resp);
	WARN_ON_ONCE(req->resp != resp);

	/*
	 * TODO: process TFW_HTTP_FSM_LOCAL_RESP_FILTER hook:
	 * tfw_gfsm_move(TFW_HTTP_FSM_LOCAL_RESP_FILTER);
	 *
	 * Locally generated responses are not assigned to any connection,
	 * thus resp->conn->state can't be used unlike to other HTTP FSM
	 * hooks calls. More over, TFW_HTTP_FSM_LOCAL_RESP_FILTER is
	 * actually egress state, while others stands to ingress traffic
	 * processing. It's not a good idea to mix up egress and ingress
	 * states.
	 *
	 * It's not a right place to discard the response, we have already
	 * spent resources to generate it. Locally generated response is
	 * reaction to client behaviour, so hooks must apply restrictions
	 * to client connections and not to the response.
	 */

	/*
	 * If the list is empty, then it's either a bug, or the client
	 * connection had been closed. If it's a bug, then the correct
	 * order of responses to requests may be broken. The connection
	 * with the client must be closed immediately.
	 *
	 * Doing tfw_connection_close() on client connection's socket is safe
	 * as long as @req that holds a reference to the connection is
	 * not freed.
	 */
	if (unlikely(list_empty_careful(seq_queue))) {
		BUG_ON(!list_empty(&req->msg.seq_list));
		TFW_DBG2("%s: The client was disconnected, drop resp and req: "
			 "conn=[%p]\n",
			 __func__, cli_conn);
		tfw_connection_close((TfwConn *)cli_conn, true);
		tfw_http_resp_pair_free(req);
		TFW_INC_STAT_BH(serv.msgs_otherr);
		return;
	}
	BUG_ON(list_empty(&req->msg.seq_list));
	/*
	 * Don't send response until request is fully received. Some servers
	 * may respond before payload is fully received.
	 */
	if (tfw_http_msg_is_stream_read((TfwHttpMsg *)req))
		set_bit(TFW_HTTP_B_RESP_READY, resp->flags);

	tfw_http_resp_fwd_unsent(cli_conn);
}

static inline void
tfw_http_req_mark_error(TfwHttpReq *req, int status)
{
	tfw_http_req_set_conn_close(req);
	tfw_http_error_resp_switch(req, status);
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
	TfwCliConn *cli_conn = (TfwCliConn *)req->conn;

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
	reply &= !test_bit(TFW_HTTP_B_REQ_DROP, req->flags);

	if (!nolog)
		TFW_WARN_ADDR(msg, &req->conn->peer->addr, TFW_WITH_PORT);
	/* The client connection is to be closed with the last resp sent. */
	if (reply) {
		if (on_req_recv_event) {
			WARN_ONCE(!list_empty_careful(&req->msg.seq_list),
				  "Request is already in seq_queue\n");
			tfw_connection_unlink_msg(req->conn);
			spin_lock(&cli_conn->seq_qlock);
			list_add_tail(&req->msg.seq_list, &cli_conn->seq_queue);
			spin_unlock(&cli_conn->seq_qlock);
		}
		else {
			WARN_ONCE(list_empty_careful(&req->msg.seq_list),
				  "Request is not in in seq_queue\n");
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
		tfw_http_error_resp_switch(req, status);
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

/**
 * Attack or error was detected while processing the streamed part of the
 * request. Buffered part of the request is already
 */
static void
tfw_http_cli_stream_error_log(TfwHttpReq *req, const char *msg, bool attack)
{
	bool nolog;

	if (attack)
		nolog = tfw_blk_flags & TFW_BLK_ATT_NOLOG;
	else
		nolog = tfw_blk_flags & TFW_BLK_ERR_NOLOG;

	if (!nolog)
		TFW_WARN_ADDR(msg, &req->conn->peer->addr, TFW_NO_PORT);
	if (!attack)
		tfw_http_req_prev_conn_close(req);
	tfw_http_conn_cli_drop_stream_req(req);
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

	if (tfw_http_adjust_resp(resp)) {
		tfw_http_conn_msg_free((TfwHttpMsg *)resp);
		tfw_http_send_resp(req, 500, "response dropped:"
				   " processing error");
		TFW_INC_STAT_BH(clnt.msgs_otherr);
		return;
	}
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
	TfwHttpReq *req = (TfwHttpReq *)msg;
	TfwSrvConn *srv_conn = NULL;
	LIST_HEAD(eq);

	TFW_DBG2("%s: req = %p, resp = %p\n", __func__, req, req->resp);

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
		TFW_DBG("Unable to find a backend server\n");
		goto send_502;
	}

	if (tfw_http_adjust_req(req))
		goto send_500;

	/* Account current request in APM health monitoring statistics */
	tfw_http_hm_srv_update((TfwServer *)srv_conn->peer, req);

	/* Forward request to the server. */
	tfw_http_req_fwd(srv_conn, req, &eq);
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
	TFW_DBG2("non-idempotent: method=[%d] uri=[%.*s]\n",
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

/**
 * Drop successfully processed response for the health monitoring
 * subsystem request.
 */
static inline void
tfw_http_hm_drop_resp(TfwHttpResp *resp)
{
	TfwHttpReq *req = resp->req;

	tfw_apm_update(((TfwServer *)resp->conn->peer)->apmref,
		       resp->jrxtstamp, resp->jrxtstamp - req->jtxtstamp);
	tfw_http_conn_msg_free((TfwHttpMsg *)resp);
	tfw_http_msg_free((TfwHttpMsg *)req);
}

/**
 * @return TFW_PASS if the message is streamed and can be processed,
 * and TFW_POSTPONE if more buffering is required.
 */
static int
tfw_http_msg_stream_process(TfwHttpMsg *hm, size_t buff_lim)
{
	/* Not the first part of the message, stream if it's safe. */
	if (test_bit(TFW_HTTP_B_STREAM_PART, hm->flags)) {
		int r = tfw_http_parser_msg_may_stream(hm);
		if (r == TFW_POSTPONE)
			set_bit(TFW_HTTP_B_STREAM_ON_HOLD, hm->flags);
		return r;
	}

	/* TODO: lower down buff lim if its bigger than sk->sk_rcvbuf */
	if ((hm->msg.len <= buff_lim) ||
	    (tfw_http_parser_msg_may_stream(hm) == TFW_POSTPONE))
		return TFW_POSTPONE;

	__set_bit(TFW_HTTP_B_STREAM, hm->flags);

	if (!tfw_http_msg_alloc_stream_part(hm))
		return TFW_BLOCK;

	return TFW_PASS;
}

static inline int
tfw_http_req_stream_process(TfwHttpMsg *hm)
{
	return tfw_http_msg_stream_process(hm, tfw_cfg_cli_msg_buff_sz);
}

static int
tfw_http_req_stream(TfwHttpStream *hmpart)
{
	LIST_HEAD(eq);
	TfwHttpMsg *hmreq = hmpart->head;
	TfwSrvConn *srv_conn = (TfwSrvConn *)hmpart->rcv_conn;
	TfwCliConn *cli_conn = (TfwCliConn *)hmpart->head->conn;
	int r = TFW_BLOCK;

	TFW_DBG2("%s: req=[%p], part=[%p]\n", __func__, hmreq, hmpart);
	BUG_ON(!test_bit(TFW_HTTP_B_STREAM_PART, hmpart->flags));

	/* Drop the streamed part for requests served by Tempesta. */
	if (tfw_http_resp_is_local(hmreq->resp)) {
		r = TFW_PASS;
		TFW_DBG2("%s: skip streamed part for req=[%p], part=[%p]\n",
			 __func__, hmreq, hmpart);
		if (!test_bit(TFW_HTTP_B_STREAM_ON_HOLD, hmpart->flags)) {
			tfw_cli_rmem_release((TfwCliConn *)hmreq->conn,
					     hmpart->msg.len);
			tfw_http_msg_collapse_streamed(hmpart);
		}
		goto done;
	}

	/* Process streamed message part. */
	if (test_bit(TFW_HTTP_B_STREAM_LAST_PART, hmpart->flags)) {
		if (tfw_http_set_loc_hdrs_req_spart(hmpart))
			goto done;
	}

	/* paired with tfw_http_msg_process() */
	spin_unlock(&hmpart->stream_lock);
	if (!srv_conn)
		/* Server connection is not ready to receive streamed part. */
		return TFW_PASS;

	spin_lock_bh(&srv_conn->fwd_qlock);
	tfw_http_conn_fwd_unsent(srv_conn, &eq);
	spin_unlock_bh(&srv_conn->fwd_qlock);
	tfw_http_req_zap_error(&eq);

	tfw_http_resp_fwd_unsent(cli_conn);

	return TFW_PASS;
done:
	/* paired with tfw_http_msg_process() */
	spin_unlock(&hmpart->stream_lock);

	set_bit(TFW_HTTP_B_RESP_READY, hmreq->resp->flags);
	/* hmreq mustn't be used from now on. */
	tfw_http_resp_fwd_unsent(cli_conn);

	return r;
}

static inline TfwHttpMsg *
tfw_http_req_create_sibling(TfwHttpMsg *hmreq, struct sk_buff *skb)
{
	TfwHttpMsg *hmsib = NULL;

	/*
	 * Pipelined requests: create a new sibling message.
	 */
	if (!test_bit(TFW_HTTP_B_CONN_CLOSE, hmreq->flags) && skb) {
		hmsib = tfw_http_msg_create_sibling(hmreq, skb);
		if (unlikely(!hmsib)) {
			TFW_INC_STAT_BH(clnt.msgs_otherr);
			set_bit(TFW_HTTP_B_CONN_CLOSE, hmreq->flags);
			/* skb is orphaned now and must be manually released. */
		}
	}

	return hmsib;
}


/**
 * In general case the @skb, even if it has TLS record header @off and tag
 * @tail, it can be at any place of resulting HTTP message. Now we have to
 * chop the TLS extra data. It'd be good to preserve the room for the message
 * adjusting (e.g. adding a new header), but typically we need a space only in
 * skbs carrying CRLF and just before the CRLF pointer. So TLS rooms can be
 * reused only if they're just before CRLF (very rarely). Thus we just chop
 * the data.
 *
 * TODO #1103: this should be revised for the new placement strategies.
 */
static int
tfw_http_chop_skb(TfwHttpMsg *hm, struct sk_buff *skb,
		  unsigned int off, unsigned int trail)
{
	return ss_skb_chop_head_tail(hm->msg.skb_head, skb, off, trail);
}

/**
 * @return zero on success and negative value otherwise.
 * TODO enter the function depending on current GFSM state.
 */
static int
tfw_http_req_process(TfwConn *conn, const TfwFsmData *data)
{
	int req_conn_close, r = TFW_BLOCK;
	bool block;
	unsigned int parsed, curr_skb_trail;
	unsigned int off = data->off, trail = data->trail;
	struct sk_buff *skb = data->skb;
	TfwHttpReq *req;
	TfwHttpMsg *hmsib, *hm;
	TfwHttpParser *parser;
	TfwFsmData data_up;
	TfwHttpError err = {0};
	bool on_stream;

	BUG_ON(!conn->msg);
	BUG_ON(off >= skb->len);
	BUG_ON(trail >= skb->len);

	TFW_DBG2("Received %u client data bytes on conn=%p msg=%p\n",
		 skb->len - off, conn, conn->msg);

	/*
	 * Process pipelined requests in a loop
	 * until all data in the SKB is processed.
	 */
next_msg:
	block = false;
	parsed = 0;
	hmsib = NULL;
	req = (TfwHttpReq *)conn->msg;
	hm = (TfwHttpMsg *)conn->msg;
	parser = &conn->parser;
	on_stream = false;

	r = ss_skb_process(skb, off, trail, tfw_http_parse_req, req,
			   &req->chunk_cnt, &parsed);
	req->msg.len += parsed;
	tfw_cli_rmem_reserve((TfwCliConn *)req->conn, parsed);
	curr_skb_trail = off + parsed + trail < skb->len ? 0 : trail;
	TFW_ADD_STAT_BH(parsed, clnt.rx_bytes);

	TFW_DBG2("Request parsed: len=%u next=%pK parsed=%d msg_len=%lu"
		 " ver=%d res=%d\n",
		 skb->len, skb->next, parsed, req->msg.len, req->version, r);

	/*
	 * We have to keep @data the same to pass it as is to FSMs
	 * registered with lower priorities after us, but we must
	 * feed the new data version to FSMs registered on our states.
	 */
	data_up.skb = skb;
	data_up.off = off;
	data_up.trail = curr_skb_trail;
	data_up.resp = NULL;
	data_up.req = (TfwMsg *)(test_bit(TFW_HTTP_B_STREAM_PART, hm->flags)
				 ? hm->head
				 : hm);

	switch (r) {
	default:
		TFW_ERR("Unrecognized HTTP request parser return code, %d\n",
			r);
		err.reason = "Unrecognized HTTP request parser return code";
		TFW_INC_STAT_BH(clnt.msgs_parserr);
		goto drop;

	case TFW_BLOCK:
		/*
		 * Request can't be parsed. Either the client tries to attack,
		 * or unintentionally sent us invalid request. Don't block
		 * the client for now, left worries for the Frang.
		 */
		TFW_DBG2("Block invalid HTTP request\n");
		err.reason = "failed to parse request";
		TFW_INC_STAT_BH(clnt.msgs_parserr);
		goto drop;

	case TFW_POSTPONE:
		r = tfw_gfsm_move(&conn->state, TFW_HTTP_FSM_REQ_CHUNK,
				  &data_up);
		TFW_DBG3("TFW_HTTP_FSM_REQ_CHUNK return code %d\n", r);
		if (r == TFW_BLOCK) {
			TFW_INC_STAT_BH(clnt.msgs_filtout);
			err.status = 403;
			err.reason =  "postponed request has been filtered out";
			goto drop;
		}
		r = tfw_http_req_stream_process(hm);
		if (unlikely(r == TFW_BLOCK)) {
			err.status = 500;
			err.reason =  "can't allocate memory for streamed "
				      "request";
			TFW_INC_STAT_BH(clnt.msgs_otherr);
			goto drop;
		}
		/* A new part of streamed request. */
		if (test_bit(TFW_HTTP_B_STREAM_PART, hm->flags)) {
			if (r == TFW_PASS)
				r = tfw_http_req_stream((TfwHttpStream *)hm);
			else
				/* paired with tfw_http_msg_process() */
				spin_unlock(&((TfwHttpStream *)hm)->stream_lock);
			goto out;
		}
		/* Buffered part of request. */
		if (r == TFW_POSTPONE) {
			goto out;
		}
		TFW_DBG2("Process buffered part of streamed request\n");
		on_stream = true;
		break;

	case TFW_PASS:
		if (test_bit(TFW_HTTP_B_STREAM_PART, hm->flags)) {
			set_bit(TFW_HTTP_B_STREAM_LAST_PART, hm->flags);
			break; /* skip parser integrity checks. */
		}
		if (unlikely(!test_bit(TFW_HTTP_B_CHUNKED, hm->flags)
			     && (hm->content_length != hm->body.len)))
		{
			err.reason = "Internal parser error";
			TFW_INC_STAT_BH(clnt.msgs_parserr);
			goto drop;
		}
		/* The request is fully parsed, fall through and process it. */
	}

	/*
	 * Chop TLS overhead for current skb after ss_skb_process() which
	 * works with offset and trail on its own and before we split the skb.
	 */
	if (tfw_http_chop_skb((TfwHttpMsg *)req, skb, off, curr_skb_trail))
		return TFW_BLOCK;

	/*
	 * The message is fully parsed, the rest of the data in the
	 * stream may represent another request or its part.
	 * If skb splitting has failed, the request can't be forwarded
	 * to backend server or request-response sequence can be broken.
	 * @skb is replaced with pointer to a new SKB.
	 */
	if (parsed < skb->len) {
		skb = ss_skb_split(skb, parsed);
		if (unlikely(!skb)) {
			TFW_INC_STAT_BH(clnt.msgs_otherr);
			err.status = 500;
			err.reason = "Can't detach message from the stream";
			goto drop;
		}
		off = 0;
	} else {
		skb = NULL;
	}

	/*
	 * Last part of streamed request. Stream it and proceed to the
	 * sibling message if any.
	 */
	if (test_bit(TFW_HTTP_B_STREAM_LAST_PART, hm->flags)) {
		TfwHttpMsg *req_head = hm->head;

		r = tfw_gfsm_move(&conn->state, TFW_HTTP_FSM_REQ_MSG, &data_up);
		TFW_DBG3("TFW_HTTP_FSM_REQ_MSG return code %d\n", r);
		if (r == TFW_BLOCK) {
			err.reason = "parsed request has been filtered out";
			err.status = 403;
			goto block;
		}

		hmsib = tfw_http_req_create_sibling(req_head, skb);
		tfw_connection_unlink_msg(conn);
		req_conn_close = test_bit(TFW_HTTP_B_CONN_CLOSE, req_head->flags);
		clear_bit(TFW_HTTP_B_STREAM_ON_HOLD, hm->flags);
		r = tfw_http_req_stream((TfwHttpStream *)hm);

		goto post_process;
	}

	req = (TfwHttpReq *)hm;
	/*
	 * Sticky cookie module must be used before request can reach cache.
	 * Unauthorised clients mustn't be able to get any resource on
	 * protected service and stress cache subsystem. The module is also
	 * the quickest way to obtain target VHost and target backend server
	 * connection since it allows to avoid expensive tables lookups.
	 *
	 * TODO: #685 Sticky cookie are to be configured per-vhost. Http_tables
	 * used to assign target vhost can be extremely long, while the
	 * client may use just a few cookie variants. Even if different
	 * sticky cookies are used for each vhost, the sticky module should
	 * be faster than tfw_http_tbl_vhost().
	 *
	 * TODO: #1043 sticky cookie module must assign correct vhost when it
	 * returns TFW_HTTP_SESS_SUCCESS or TFW_HTTP_SESS_REDIRECT_NEED;
	 */
	switch (tfw_http_sess_obtain(req))
	{
	case TFW_HTTP_SESS_SUCCESS:
		break;

	case TFW_HTTP_SESS_REDIRECT_NEED:
		/* Response is built and stored in @req->resp. */
		break;

	case TFW_HTTP_SESS_VIOLATE:
		err.status = 503;
		err.reason = "request dropped: sticky cookie challenge was "
			     "failed";
		goto block;

	case TFW_HTTP_SESS_JS_NOT_SUPPORTED:
		/*
		 * Requested resource can't be challenged, forward all pending
		 * responses and close the connection to allow client to recover.
		 */
		TFW_INC_STAT_BH(clnt.msgs_filtout);
		err.status = 503;
		err.reason = "request dropped: can't send JS challenge.";
		goto drop;

	default:
		TFW_INC_STAT_BH(clnt.msgs_otherr);
		err.status = 500;
		err.reason = "request dropped: internal error in Sticky module";
		goto drop;
	}

	/*
	 * Assign the right virtual host for current request if it
	 * wasn't assigned by a sticky module. VHost is not assigned
	 * if client doesn't support cookies or sticky cookies are
	 * disabled.
	 *
	 * In the same time location may differ between requests, so the
	 * sticky module can't fill it.
	 */
	if (!req->vhost)
		req->vhost = tfw_http_tbl_vhost((TfwMsg *)req, &block);
	if (req->vhost)
		req->location = tfw_location_match(req->vhost,
						   &req->uri_path);
	if (block) {
		TFW_INC_STAT_BH(clnt.msgs_filtout);
		err.status = 403;
		err.reason = "request has been filtered out via http table";
		goto drop;
	}

	r = tfw_gfsm_move(&conn->state, TFW_HTTP_FSM_REQ_MSG, &data_up);
	TFW_DBG3("TFW_HTTP_FSM_REQ_MSG return code %d\n", r);
	/* Don't accept any following requests from the peer. */
	if (r == TFW_BLOCK) {
		err.reason = "parsed request has been filtered out";
		err.status = 403;
		goto block;
	}

	/*
	 * The time the request was received is used for age
	 * calculations in cache, and for eviction purposes.
	 */
	req->cache_ctl.timestamp = tfw_current_timestamp();
	req->jrxtstamp = jiffies;

	/*
	 * In HTTP 0.9 the server always closes the connection
	 * after sending the response.
	 *
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
	 * Pipelined requests: create a new sibling message.
	 * Sibling message will never be created for streamed message,
	 * since skb is NULL here.
	 */
	hmsib = tfw_http_req_create_sibling(hm, skb);

	/*
	 * Complete HTTP message has been collected and processed
	 * with success. Mark the message as complete in @conn as
	 * further handling of @conn depends on that. Future SKBs
	 * will be put in a new message.
	 * On an error the function returns from anywhere inside
	 * the loop. @conn->msg holds the reference to the message,
	 * which can be used to release it.
	 */
	tfw_connection_unlink_msg(conn);
	if (unlikely(tfw_http_msg_is_streamed(hm)))
		conn->msg = (TfwMsg *)hm->stream;

	/*
	 * Add the request to the list of the client connection
	 * to preserve the correct order of responses to requests.
	 */
	tfw_http_req_add_seq_queue(req);

	/* The request may be freed after response is sent */
	req_conn_close = test_bit(TFW_HTTP_B_CONN_CLOSE, req->flags);
	/*
	 * Response is already prepared for the client.
	 */
	if (unlikely(req->resp)) {
		tfw_http_resp_fwd(req->resp);
	}
	/*
	 * If no virtual host has been found for current request, there
	 * is no sense for its further processing, so we drop it, send
	 * error response to client and move on to the next request.
	 */
	else if (!req->vhost) {
		tfw_http_send_resp(req, 404, "request dropped: cannot find"
					     " appropriate virtual host");
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
		/* Proceed to the next request. */
	}

post_process:
	/*
	 * According to RFC 7230 6.3.2, connection with a client
	 * must be dropped after a response is sent to that client,
	 * if the client sends "Connection: close" header field in
	 * the request. Subsequent requests from the client coming
	 * over the same connection are ignored.
	 *
	 * Note: This connection's @conn must not be dereferenced
	 * from this point on.
	 */
	if (!req_conn_close && hmsib) {
		/*
		 * Switch connection to the new sibling message.
		 * Data processing will continue with the new SKB.
		 */
		conn->msg = (TfwMsg *)hmsib;
		goto next_msg;
	}
	else {
		if (skb) {
			__kfree_skb(skb);
			r = TFW_BLOCK;
		}
		/*
		 * The connection is to be closed after response to the last
		 * one request is sent. Mark the connection with @Conn_Stop
		 * flag - to left it alive for sending responses
		 * and, at the same time, to stop passing data for processing
		  * from the lower layer.
		 */
		if (req_conn_close && !on_stream)
			TFW_CONN_TYPE(conn) |= Conn_Stop;
	}

out:	/*
	 * TFW_POSTPONE status means that parsing succeeded
	 * but more data is needed to complete it. Lower layers
	 * just supply data for parsing. They only want to know
	 * if processing of a message should continue or not.
	 */
	if (r == TFW_POSTPONE)
		r = TFW_PASS;
	return r;

drop:	/*
	 * Unrecoverable error. Stop from parsing new requests,
	 * but continue to serve previous requests.
	 */
	if (!test_bit(TFW_HTTP_B_STREAM_PART, hm->flags)) {
		tfw_http_req_parse_drop((TfwHttpReq *)hm, err.status, err.reason);
	} else {
		/* paired with tfw_http_msg_process() */
		spin_unlock(&((TfwHttpStream *)hm)->stream_lock);
		tfw_http_cli_stream_error_log((TfwHttpReq *)hm->head,
					      err.reason, false);
	}

	return TFW_BLOCK;

block:	/*
	 * An attack was detected. Shutdown the client connection immediately
	 * and drop all pending requests.
	 */
	TFW_INC_STAT_BH(clnt.msgs_filtout);
	if (!test_bit(TFW_HTTP_B_STREAM_PART, hm->flags)) {
		tfw_http_req_parse_block(req, err.status, err.reason);
	} else {
		/* paired with tfw_http_msg_process() */
		spin_unlock(&((TfwHttpStream *)hm)->stream_lock);
		tfw_http_cli_stream_error_log((TfwHttpReq *)hm->head,
					      err.reason, true);
	}

	return TFW_BLOCK;
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
	TfwHttpReq *req = resp->req;

	TFW_DBG2("%s: req = %p, resp = %p\n", __func__, req, resp);
	/*
	 * A client can disconnect at any time after the request was
	 * forwarded to backend. In this case the response will never be sent
	 * to the client. Keep the response until it's saved in the cache,
	 * so other clients can served from cache. After response is saved to
	 * cache it can be dropped.
	 */
	if (unlikely(test_bit(TFW_HTTP_B_REQ_DROP, req->flags))) {
		TFW_DBG2("%s: resp=[%p] dropped: client disconnected\n",
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
	TfwHttpReq *req = hmresp->req;
	TfwSrvConn *srv_conn = (TfwSrvConn *)hmresp->conn;
	LIST_HEAD(eq);

	spin_lock(&srv_conn->fwd_qlock);
	if ((TfwMsg *)req == srv_conn->msg_sent)
		srv_conn->msg_sent = NULL;
	tfw_http_req_delist(srv_conn, req);
	tfw_http_conn_nip_adjust(srv_conn);
	/*
	 * Run special processing if the connection is in repair
	 * mode. Otherwise, forward pending requests to the server.
	 *
	 * @hmresp is holding a reference to the server connection
	 * while forwarding is done, so there's no need to take an
	 * additional reference.
	 */
	if (unlikely(tfw_srv_conn_restricted(srv_conn)))
		tfw_http_conn_fwd_repair(srv_conn, &eq);
	else if (tfw_http_conn_need_fwd(srv_conn))
		tfw_http_conn_fwd_unsent(srv_conn, &eq);
	spin_unlock(&srv_conn->fwd_qlock);

	tfw_http_req_zap_error(&eq);
}

/**
 * Same as tfw_http_popreq() but called in tfw_http_conn_fwd_unsent().
 * See comment in tfw_http_resp_cache().
 *
 * Called under srv_conn->fwd_qlock lock.
 */
static void
__tfw_http_pop_stream_req(TfwSrvConn *srv_conn, TfwHttpReq *req)
{
	srv_conn->msg_sent = NULL;
	tfw_http_req_delist(srv_conn, req);
	tfw_http_conn_nip_adjust(srv_conn);
	/*
	 * Run special processing if the connection is in repair
	 * mode. First request was forwarded and replied, now we
	 * can pipeline more requests.
	 */
	if (unlikely(tfw_srv_conn_restricted(srv_conn)))
		tfw_srv_conn_reenable_if_done(srv_conn);
}

/*
 * Set up the response @hmresp with data needed down the road,
 * get the paired request, and then pass the response to cache
 * for further processing.
 */
static void
tfw_http_resp_cache(TfwHttpMsg *hmresp)
{
	TfwHttpReq *req = hmresp->req;
	TfwFsmData data;
	time_t timestamp = tfw_current_timestamp();
	TfwHttpError err;
	int r;

	/*
	 * The time the response was received is used in cache
	 * for age calculations, and for APM and Load Balancing.
	 */
	hmresp->cache_ctl.timestamp = timestamp;
	((TfwHttpResp *)hmresp)->jrxtstamp = jiffies;
	/*
	 * If 'Date:' header is missing in the response, then
	 * set the date to the time the response was received.
	 */
	if (!test_bit(TFW_HTTP_B_HDR_DATE, hmresp->flags))
		((TfwHttpResp *)hmresp)->date = timestamp;
	/*
	 * Response is fully received, delist corresponding request from
	 * fwd_queue. Actually server may send response before request is fully
	 * received. E.g. Nginx sends 200 OK to GET before request payload is
	 * received. Or server may break the streaming with 4xx response and
	 * close the connection at any time (as we do). Pop the request
	 * once it's fully sent.
	 */
	if (tfw_http_msg_is_stream_read(hmresp->pair))
		tfw_http_popreq(hmresp, true);
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
	data.off = 0;
	data.req = (TfwMsg *)req;
	data.resp = (TfwMsg *)hmresp;
	r = tfw_gfsm_move(&hmresp->conn->state, TFW_HTTP_FSM_RESP_MSG_FWD,
			  &data);
	TFW_DBG3("TFW_HTTP_FSM_RESP_MSG_FWD return code %d\n", r);
	if (r == TFW_BLOCK) {
		err.status = 403;
		err.reason = "response dropped: filtered out";
		TFW_INC_STAT_BH(serv.msgs_filtout);
		goto err;
	}

	if (tfw_cache_process(hmresp, tfw_http_resp_cache_cb)) {
		err.status = 500;
		err.reason = "response dropped: processing error";
		TFW_INC_STAT_BH(serv.msgs_otherr);
		goto err;
	}

	return;

err:	/*
	 * Response processing has failed, but the server connection is OK.
	 * Filter out current response and proceed to the next one. The same
	 * request from the client may cause the same error, so send error
	 * response to the client.
	 */
	tfw_http_conn_msg_free(hmresp);
	tfw_http_send_resp(req, err.status, err.reason);
}

/**
 * Response can't be parsed or processed. This is not a network failure,
 * it's very likely that the same situation happen if the corresponding
 * request will be sent once again. Keep buggy request away from
 * servers: remove the request from forward and nip queues and send
 * a 403 response if necessary.
 *
 * If the issue was treated as the attack, disconnect the client and
 * discard all pending requests.
 */
static void
tfw_http_resp_process_failed(TfwHttpMsg *hmresp, bool attack)
{
	TfwHttpReq *bad_req = hmresp->req;

	tfw_http_req_delist((TfwSrvConn *)hmresp->conn, bad_req);
	tfw_http_conn_msg_free(hmresp);
	if (test_bit(TFW_HTTP_B_HMONITOR, bad_req->flags)) {
		tfw_http_msg_free((TfwHttpMsg *)bad_req);
		/*
		 * TODO: Response to health monitoring request can't be parsed
		 * and normally processed. That definitely means that the server
		 * doesn't perform well.
		 */
	}
	else if (attack) {
		tfw_http_req_block(bad_req, 403,
				   "response blocked: filtered out");
	}
	else {
		tfw_http_req_drop(bad_req, 403,
				  "response dropped: processing error");
	}
}

/*
 * Finish a response that is terminated by closing the connection.
 */
static void
tfw_http_resp_terminate(TfwHttpMsg *hm)
{
	TfwFsmData data;
	int r;

	/*
	 * Note that in this case we don't have data to process.
	 * All data has been processed already. The response needs
	 * to go through Tempesta's post-processing, and then be
	 * sent to the client. The full skb->len is used as the
	 * offset to mark this case in the post-processing phase.
	 */
	data.skb = ss_skb_peek_tail(&hm->msg.skb_head);
	BUG_ON(!data.skb);
	data.off = data.skb->len;
	data.trail = 0;
	data.req = NULL;
	data.resp = (TfwMsg *)hm;

	r = tfw_gfsm_move(&hm->conn->state, TFW_HTTP_FSM_RESP_MSG, &data);
	TFW_DBG3("TFW_HTTP_FSM_RESP_MSG return code %d\n", r);
	if (r != TFW_PASS) {
		/* Connection is closed, all FSMs must finish their work. */
		TFW_INC_STAT_BH(serv.msgs_filtout);
		tfw_http_resp_process_failed(hm, true);
	}
	else {
		tfw_http_resp_cache(hm);
	}
}

static inline TfwHttpMsg *
tfw_http_resp_create_sibling(TfwHttpMsg *hmresp, struct sk_buff *skb)
{
	TfwHttpMsg *hmsib = NULL;

	if (!skb)
		return NULL;
	/*
	 * Pipelined responses: create a new sibling message.
	 */
	hmsib = tfw_http_msg_create_sibling(hmresp, skb);
	if (unlikely(!hmsib)) {
		TFW_INC_STAT_BH(serv.msgs_otherr);
		/* skb is orphaned now and must be manually released. */
	}

	return hmsib;
}

/**
 * @return zero on success and negative value otherwise.
 * TODO enter the function depending on current GFSM state.
 */
static int
tfw_http_resp_process(TfwConn *conn, TfwFsmData *data)
{
	int r = TFW_BLOCK;
	unsigned int chunks_unused, parsed;
	unsigned int off = data->off;
	struct sk_buff *skb = data->skb;
	TfwHttpMsg *hmresp, *hmsib;
	TfwHttpParser *parser;
	TfwFsmData data_up;
	bool attack = false;

	BUG_ON(!conn->msg);
	/*
	 * #769: There is no client side TLS, so we don't read HTTP responses
	 * through TLS connection, so trail and off should be zero.
	 * However, TCP overlapping segments still may produce non-zero offset
	 * in ss_tcp_process_skb().
	 */
	WARN_ON_ONCE(data->trail);
	BUG_ON(off >= skb->len);

	TFW_DBG2("Received %u server data bytes on conn=%p msg=%p\n",
		skb->len, conn, conn->msg);
	/*
	 * Process pipelined requests in a loop
	 * until all data in the SKB is processed.
	 */
next_msg:
	parsed = 0;
	hmsib = NULL;
	hmresp = (TfwHttpMsg *)conn->msg;
	parser = &conn->parser;

	r = ss_skb_process(skb, off, 0, tfw_http_parse_resp, hmresp,
			   &chunks_unused, &parsed);
	hmresp->msg.len += parsed;
	TFW_ADD_STAT_BH(parsed, serv.rx_bytes);

	TFW_DBG2("Response parsed: len=%u parsed=%d msg_len=%lu"
		 " ver=%d res=%d\n",
		 skb->len, parsed, hmresp->msg.len, hmresp->version, r);

	/*
	 * We have to keep @data the same to pass it as is to FSMs
	 * registered with lower priorities after us, but we must
	 * feed the new data version to FSMs registered on our states.
	 */
	data_up.skb = skb;
	data_up.off = off;
	data_up.trail = 0;
	data_up.req = NULL;
	data_up.resp = (TfwMsg *)hmresp;

	switch (r) {
	default:
		TFW_ERR("Unrecognized HTTP response parser return code, %d\n",
			r);
	case TFW_BLOCK:
		/*
		 * The response has not been fully parsed. There's no
		 * choice but report a critical error. The lower layer
		 * will close the connection and release the response
		 * message, and well as all request messages that went
		 * out on this connection and are waiting for paired
		 * response messages.
		 */
		TFW_DBG2("Block invalid HTTP response\n");
		TFW_INC_STAT_BH(serv.msgs_parserr);
		goto bad_msg;
	case TFW_POSTPONE:
		r = tfw_gfsm_move(&conn->state, TFW_HTTP_FSM_RESP_CHUNK,
				  &data_up);
		TFW_DBG3("TFW_HTTP_FSM_RESP_CHUNK return code %d\n", r);
		if (r == TFW_BLOCK) {
			TFW_INC_STAT_BH(serv.msgs_filtout);
			attack = true;
			goto bad_msg;
		}
		goto out;

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
			TFW_INC_STAT_BH(serv.msgs_parserr);
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
	if (off + parsed < skb->len) {
		skb = ss_skb_split(skb, off + parsed);
		if (unlikely(!skb)) {
			TFW_INC_STAT_BH(serv.msgs_otherr);
			goto bad_msg;
		}
	}
	else {
		skb = NULL;
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
	r = tfw_gfsm_move(&hmresp->conn->state, TFW_HTTP_FSM_RESP_MSG, data);
	TFW_DBG3("TFW_HTTP_FSM_RESP_MSG return code %d\n", r);
	if (r == TFW_BLOCK) {
		TFW_INC_STAT_BH(serv.msgs_filtout);
		attack = true;
		goto bad_msg;
	}

	/*
	 * If @skb's data has not been processed in full, then
	 * we have pipelined responses. Create a sibling message.
	 * @skb is replaced with a pointer to a new SKB.
	 */
	if (unlikely(test_bit(TFW_HTTP_B_FORCE_CLOSE, hmresp->req->flags))) {
		r = TFW_BLOCK;
	}
	else
		hmsib = tfw_http_resp_create_sibling(hmresp, skb);
	/*
	 * Complete HTTP message has been collected with success. Mark
	 * the message as complete in @conn as further handling of @conn
	 * depends on that. Future SKBs will be put in a new message.
	 */
	tfw_connection_unlink_msg(hmresp->conn);
	/*
	 * Pass the response to cache for further processing.
	 * In the end, the response is sent on to the client.
	 */
	tfw_http_resp_cache(hmresp);

	if (hmsib) {
		/*
		 * Switch the connection to the sibling message.
		 * Data processing will continue with the new SKB.
		 */
		conn->msg = (TfwMsg *)hmsib;
		goto next_msg;
	}
	else if (skb) {
		__kfree_skb(skb);
		r = TFW_BLOCK;
	}

out:
	/*
	 * TFW_POSTPONE status means that parsing succeeded
	 * but more data is needed to complete it. Lower layers
	 * just supply data for parsing. They only want to know
	 * if processing of a message should continue or not.
	 */
	if (r == TFW_POSTPONE)
		r = TFW_PASS;
	return r;

bad_msg:
	tfw_http_resp_process_failed(hmresp, attack);

	return TFW_BLOCK;
}

/**
 * @return status (application logic decision) of the message processing.
 */
static int
__tfw_http_msg_process(void *conn, TfwFsmData *data)
{
	TfwConn *c = (TfwConn *)conn;
	TfwHttpMsg *hm = (TfwHttpMsg *)c->msg;
	int r = TFW_BLOCK;

	tfw_connection_get(conn);

	if (unlikely(!hm)) {
		hm = tfw_http_conn_msg_alloc(c);
		if (unlikely(!hm)) {
			__kfree_skb(data->skb);
			goto err;
		}
		c->msg = (TfwMsg *)hm;
		tfw_http_mark_wl_new_msg(c, hm, data->skb);
		TFW_DBG2("Link new msg %p with connection %p\n", hm, c);
	}
	else if (test_bit(TFW_HTTP_B_STREAM_PART, hm->flags)) {
		spin_lock(&((TfwHttpStream *)hm)->stream_lock);
		((TfwHttpStream *)hm)->proc_off = hm->body.len;
	}

	TFW_DBG2("Add skb %p to message %p\n", data->skb, hm);
	ss_skb_queue_tail(&hm->msg.skb_head, data->skb);

	r = (TFW_CONN_TYPE(c) & Conn_Clnt)
		? tfw_http_req_process(c, data)
		: tfw_http_resp_process(c, data);

err:
	tfw_connection_put(conn);

	return r;
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
	unsigned int trail = data->trail;
	struct sk_buff *next;

	if (data->skb->prev)
		data->skb->prev->next = NULL;
	for (next = data->skb->next; data->skb;
	     data->skb = next, next = next ? next->next : NULL, data->off = 0)
	{
		if (likely(r == T_OK || r == T_POSTPONE)) {
			data->skb->next = data->skb->prev = NULL;
			data->trail = !next ? trail : 0;
			r = __tfw_http_msg_process(conn, data);
		} else {
			kfree(data->skb);
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

	if (!(req = tfw_http_msg_alloc_req_light()))
		return;
	hmreq = (TfwHttpMsg *)req;
	if (tfw_http_msg_setup(hmreq, &it, msg.len))
		goto cleanup;
	if (tfw_msg_write(&it, &msg))
		goto cleanup;

	__set_bit(TFW_HTTP_B_HMONITOR, req->flags);
	req->jrxtstamp = jiffies;

	srv_conn = srv->sg->sched->sched_srv_conn((TfwMsg *)req, srv);
	if (!srv_conn) {
		TFW_WARN_ADDR("Unable to find connection for health"
		              " monitoring of backend server", &srv->addr,
		              TFW_WITH_PORT);
		goto cleanup;
	}

	tfw_http_req_fwd(srv_conn, req, &equeue);
	tfw_http_req_zap_error(&equeue);

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

	tfw_http_msg_clnthdr_val(&req->h_tbl->tbl[TFW_HTTP_HDR_HOST],
				 TFW_HTTP_HDR_HOST, &host);
	if (!TFW_STR_EMPTY(&host))
		req->hash ^= tfw_hash_str(&host);

	return req->hash;
}
EXPORT_SYMBOL(tfw_http_req_key_calc);

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
		TFW_ERR_NL("Unsupported argument: '%s'\n", action);
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
			TFW_ERR_NL("Unsupported argument: '%s'\n", ce->vals[2]);
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
		TFW_ERR_NL("Invalid number of arguments: %zu\n", ce->val_n);
		return -EINVAL;
	}
	if (ce->attr_n) {
		TFW_ERR_NL("Unexpected attributes\n");
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
		TFW_ERR_NL("Unsupported argument: '%s'\n", ce->vals[0]);
		return -EINVAL;
	}

	return 0;
}

static void
tfw_cfgop_cleanup_block_action(TfwCfgSpec *cs)
{
	tfw_blk_flags = TFW_CFG_BLK_DEF;
}

/**
 * Control message buffering options.
 *
 * Tempesta has two message forwarding strategies: buffering and streaming.
 * In buffering mode the message is fully assembled (buffered) before it
 * may be forwarded to destination. It's recommended mode: resources planning
 * is simple and fast, backend connections are never blocked and performance
 * is maximized.
 *
 * But buffering mode doesn't suit all situations. It not wise to assemble
 * DVD images in memory, better to stream such huge messages by parts.
 * Long polling events are another candidate to use stream mode.
 * There are also disadvantages. Usually clients are much slower than servers,
 * so the server connection will be blocked for other requests until streamed
 * request is fully streamed to backend. Performance may be degraded for
 * environments where majority of the requests are streamed.
 *
 * The streamed message may still be buffered for some amount of time if
 * receiver is not ready for streaming. E.g. there are a number of request
 * in servers 'fwd_queue'. Or there are other not responded request in
 * client's 'seq_queue'. This is so called streaming bufferbloat problem.
 *
 * The option SHOULD be used with 'client_rmem' directive. Optimal
 * configuration - equal values for 'client_rmem' and 'client_msg_buffering'.
 * In this case bufferbloat problem wouldn't appear: the 'client_rmem' provides
 * flow control to slow down client.
 *
 * Session persistence is a best way to cope bufferbloat problem for server
 * connections. If all requests from the same client are served by the same
 * server connection, client will mostly always be ready for incoming streaming
 * transmissions. Doesn't work for proxyied connections, since single
 * connection may multiplex hundreds of distinct HTTP sessions.
 *
 * There is no same option for server connections. See 'client_rmem' for
 * explanations.
 *
 * User can configure the buffering limit:
 * 0	- Full streaming mode. Message headers are fully buffered, payload is
 *	  streamed;
 * N	- At least first N bytes of message is buffered (including message
 *	  headers), the rest of payload is streamed;
 * -1	- Alias to set maximum possible value: LONG_MAX.
 * The limit is doesn't mean that exactly N bytes will be buffered. To optimize
 * performance Tempesta buffer single SKB at once, so more than N bytes may be
 * buffered. Headers, including trailer part, are always buffered, since
 * They must be processed before forwarding.
 *
 * Possible enhancements, further research is required:
 *
 * - Add minimal chunk size for streaming and maximum buffering timeout.
 *   I.e. don't stream messages byte by byte, buffer some data before forward
 *   it; if timeout is exceeded, stream as many data as available, don't wait
 *   for more. It can be rather long wait in case of long polling. The idea
 *   behind is same as for Nagle algorithm in TCP.
 *
 * - Per-location buffering limits.
 *   Normally it's recommended to set buffering limit as bigger as possible.
 *   But some locations may stand for long polling responses, thus full-stream
 *   may be more suitable for such locations.
 *
 * - Dynamically allocate server connections for streaming.
 *   Streaming over server connection can significantly degrade APM statistics
 *   for the connection.
 */
static int
tfw_cfgop_proxy_buffering(TfwCfgSpec *cs, TfwCfgEntry *ce,
			  size_t *proxy_buff_sz)
{
	int r;
	long val = 0;

	cs->dest = &val;

	if ((r = tfw_cfg_set_long(cs, ce)))
		return r;

	if (val == -1)
		*proxy_buff_sz = LONG_MAX;
	else
		*proxy_buff_sz = val;

	return 0;
}

static int
tfw_cfgop_cli_proxy_buffering(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfgop_proxy_buffering(cs, ce, &tfw_cfg_cli_msg_buff_sz);
}

static int
tfw_cfgop_srv_proxy_buffering(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfgop_proxy_buffering(cs, ce, &tfw_cfg_srv_msg_buff_sz);
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
		TFW_ERR_NL("undefined HTTP status group: [%d]\n", status_code);
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
char *
__tfw_http_msg_body_dup(const char *filename, TfwStr *c_len_hdr, size_t *len,
			size_t *body_offset)
{
	char *body, *b_start, *res = NULL;
	size_t b_sz, t_sz;
	char buff[TFW_ULTOA_BUF_SIZ] = {0};
	TfwStr *cl_buf = __TFW_STR_CH(c_len_hdr, 1);

	body = tfw_cfg_read_file(filename, &b_sz);
	if (!body) {
		*len = *body_offset = 0;
		return NULL;
	}
	cl_buf->data = buff;
	cl_buf->len = tfw_ultoa(b_sz, cl_buf->data, TFW_ULTOA_BUF_SIZ);
	if (unlikely(!cl_buf->len)) {
		TFW_ERR_NL("Can't copy file %s: too big\n", filename);
		goto err;
	}

	c_len_hdr->len += cl_buf->len;
	t_sz = c_len_hdr->len + b_sz;
	res = (char *)__get_free_pages(GFP_KERNEL, get_order(t_sz));
	if (!res) {
		TFW_ERR_NL("Can't allocate memory storing file %s "
			   "as response body\n", filename);
		goto err_2;
	}

	tfw_str_to_cstr(c_len_hdr, res, t_sz);
	b_start = res + c_len_hdr->len;
	memcpy_fast(b_start, body, b_sz);

	*len = t_sz;
	*body_offset = b_start - res;
err_2:
	c_len_hdr->len -= cl_buf->len;
err:
	cl_buf->data = NULL;
	cl_buf->len = 0;
	free_pages((unsigned long)body, get_order(b_sz));

	return res;
}

/**
 * Copy @filename content to allocated memory as compound of
 * `Content-length' header, crlfcrlf and message body. Memory is allocated
 * via __get_free_pages(), thus free_pages() must be used on cleanup;
 * @len		- total length of body data including headers.
 */
char *
tfw_http_msg_body_dup(const char *filename, size_t *len)
{
	TfwStr c_len_hdr = {
		.chunks = (TfwStr []){
			{ .data = S_F_CONTENT_LENGTH,
			  .len = SLEN(S_F_CONTENT_LENGTH) },
			{ .data = NULL, .len = 0 },
			{ .data = S_CRLFCRLF, .len = SLEN(S_CRLFCRLF) },
		},
		.len = SLEN(S_F_CONTENT_LENGTH S_CRLFCRLF),
		.nchunks = 3
	};
	size_t b_off;

	return __tfw_http_msg_body_dup(filename, &c_len_hdr, len, &b_off);
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
		TFW_ERR_NL("Unexpected status code: [%d]\n",
			   status_code);
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
		TFW_WARN("Bug in 'response_body' directive cleanup.\n");
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
		TFW_ERR_NL("Unexpected attributes\n");
		return -EINVAL;
	}

	if (tfw_cfgop_parse_http_status(ce->vals[0], &code)) {
		TFW_ERR_NL("Unable to parse HTTP code value in"
			   " 'response_body' directive: '%s'\n",
			   ce->vals[0]);
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
		TFW_ERR_NL("%s: At least one argument is required", cs->name);
		return -EINVAL;
	}
	if (ce->attr_n) {
		TFW_ERR_NL("Unexpected attributes\n");
		return -EINVAL;
	}

	tfw_wl_marks.sz = ce->val_n;
	if (!(tfw_wl_marks.mrks = kmalloc(ce->val_n * sizeof(unsigned int),
					  GFP_KERNEL)))
		return -ENOMEM;

	TFW_CFG_ENTRY_FOR_EACH_VAL(ce, i, val) {
		int r;

		if ((r = tfw_cfg_parse_int(val, &tfw_wl_marks.mrks[i]))) {
			kfree(tfw_wl_marks.mrks);
			return r;
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
		TFW_ERR_NL("%s: At least one argument is required", cs->name);
		return -EINVAL;
	}
	if (ce->attr_n) {
		TFW_ERR_NL("Unexpected attributes\n");
		return -EINVAL;
	}

	TFW_CFG_ENTRY_FOR_EACH_VAL(ce, i, val) {
		unsigned long i0 = 0, i1 = 0;
		int r;

		if ((r = tfw_cfg_parse_intvl(val, &i0, &i1))) {
			TFW_ERR_NL("Cannot parse %s interval: '%s'\n",
				   cs->name, val);
			return r;
		}
		if (i0 > 255 || i1 > 255) {
			TFW_ERR_NL("Too large interval bounds in %s: '%s'\n",
				   cs->name, val);
			return -EINVAL;
		}

		a[i0++] = 1;
		while (i0 <= i1)
			a[i0++] = 1;
	}

	return 0;
}

static int
tfw_cfgop_brange_uri(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;
	unsigned char a[256] = {};

	r = __cfgop_brange_hndl(cs, ce, a);
	if (r)
		return r;
	tfw_init_custom_uri(a);

	return 0;
}

static void
tfw_cfgop_cleanup_brange_uri(TfwCfgSpec *cs)
{
	tfw_init_custom_uri(NULL);
}

static int
tfw_cfgop_brange_token(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;
	unsigned char a[256] = {};

	r = __cfgop_brange_hndl(cs, ce, a);
	if (r)
		return r;
	tfw_init_custom_token(a);

	return 0;
}

static void
tfw_cfgop_cleanup_brange_token(TfwCfgSpec *cs)
{
	tfw_init_custom_token(NULL);
}

static int
tfw_cfgop_brange_qetoken(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;
	unsigned char a[256] = {};

	r = __cfgop_brange_hndl(cs, ce, a);
	if (r)
		return r;
	tfw_init_custom_qetoken(a);

	return 0;
}

static void
tfw_cfgop_cleanup_brange_qetoken(TfwCfgSpec *cs)
{
	tfw_init_custom_qetoken(NULL);
}

static int
tfw_cfgop_brange_nctl(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;
	unsigned char a[256] = {};

	r = __cfgop_brange_hndl(cs, ce, a);
	if (r)
		return r;
	tfw_init_custom_nctl(a);

	return 0;
}

static void
tfw_cfgop_cleanup_brange_nctl(TfwCfgSpec *cs)
{
	tfw_init_custom_nctl(NULL);
}

static int
tfw_cfgop_brange_xff(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;
	unsigned char a[256] = {};

	r = __cfgop_brange_hndl(cs, ce, a);
	if (r)
		return r;
	tfw_init_custom_xff(a);

	return 0;
}

static void
tfw_cfgop_cleanup_brange_xff(TfwCfgSpec *cs)
{
	tfw_init_custom_xff(NULL);
}

static int
tfw_cfgop_brange_cookie(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;
	unsigned char a[256] = {};

	r = __cfgop_brange_hndl(cs, ce, a);
	if (r)
		return r;
	tfw_init_custom_cookie(a);

	return 0;
}

static void
tfw_cfgop_cleanup_brange_cookie(TfwCfgSpec *cs)
{
	tfw_init_custom_cookie(NULL);
}

static int
tfw_http_cfgend(void)
{
	if (tfw_cfg_cli_rmem < tfw_cfg_cli_msg_buff_sz) {
		TFW_WARN_NL("client_msg_buffering: client receive window (%u) "
			    "is too small to buffer message of size %zu, "
			    "set client_msg_buffering to %u.\n",
			    tfw_cfg_cli_rmem, tfw_cfg_cli_msg_buff_sz,
			    tfw_cfg_cli_rmem);
		tfw_cfg_cli_msg_buff_sz = tfw_cfg_cli_rmem;
	}

	return 0;
}

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
		.name = "client_msg_buffering",
		.deflt = "1048576", /* 1 MB */
		.handler = tfw_cfgop_cli_proxy_buffering,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { -1, LONG_MAX },
		},
		.allow_none = true,
	},
	{
		.name = "server_msg_buffering",
		.deflt = "10485760", /* 10 MB */
		.handler = tfw_cfgop_srv_proxy_buffering,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { -1, LONG_MAX },
		},
		.allow_none = true,
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
	.cfgend = tfw_http_cfgend,
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
