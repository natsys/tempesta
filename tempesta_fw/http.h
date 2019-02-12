/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2019 Tempesta Technologies, Inc.
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
#ifndef __TFW_HTTP_H__
#define __TFW_HTTP_H__

#include <crypto/sha.h>

#include "http_types.h"
#include "connection.h"
#include "gfsm.h"
#include "msg.h"
#include "server.h"
#include "str.h"
#include "vhost.h"

/**
 * HTTP Generic FSM states.
 *
 * We (as Apache HTTP Server and other Web-servers do) define several phases
 * on HTTP message processing. However we set the hooks also to response
 * processing (local and received from backend server) as well as to request
 * processing. We can depict the phases as following:
 *
 *	Client			Tempesta			Server
 *	~~~~~~			~~~~~~~~			~~~~~~
 *
 * 	[req]		-->	(I) (process)	-->		[req]
 *
 * 	[resp]		<--	(process) (II)	<--		[resp]
 *
 * 	[resp]		<--	(III) (process) <-+
 * 						   \
 * 						(local cache)
 *
 * So generally hooks are called on receiving client request (I), on receiving
 * server response (II) and after generation of local response (III).
 *
 * TODO generic callback note. We need to:
 * 1. store all callbacks in fixed size array to eliminate random memory access
 *    on callbacks;
 * 2. modules must register a callback only if it has work to do (not just when
 *    it's loaded into kernel).
 */
#define TFW_GFSM_HTTP_STATE(s)	((TFW_FSM_HTTP << TFW_GFSM_FSM_SHIFT) | (s))
enum {
	/* HTTP FSM initial state, not hookable. */
	TFW_HTTP_FSM_INIT		= TFW_GFSM_HTTP_STATE(0),

	/* Called on request End-Of-Skb (EOS). */
	TFW_HTTP_FSM_REQ_CHUNK		= TFW_GFSM_HTTP_STATE(1),

	/* Whole request is read. */
	TFW_HTTP_FSM_REQ_MSG		= TFW_GFSM_HTTP_STATE(2),

	/* Called on response EOS. */
	TFW_HTTP_FSM_RESP_CHUNK		= TFW_GFSM_HTTP_STATE(3),

	/* Whole response is read. */
	TFW_HTTP_FSM_RESP_MSG		= TFW_GFSM_HTTP_STATE(4),

	/* Response from backend server is received and ready to be processed. */
	TFW_HTTP_FSM_RESP_MSG_FWD	= TFW_GFSM_HTTP_STATE(5),

	/*
	 * Run just before locally generated response sending.
	 * This is egress state unlike others, see tfw_http_resp_fwd().
	 */
	TFW_HTTP_FSM_LOCAL_RESP_FILTER	= TFW_GFSM_HTTP_STATE(6),

	TFW_HTTP_FSM_DONE	= TFW_GFSM_HTTP_STATE(TFW_GFSM_STATE_LAST)
};

/* TODO: When CONNECT will be added, add it to tfw_handle_validation_req() */
typedef enum {
	_TFW_HTTP_METH_NONE,
	/*
	 * Most popular methods, registered in IANA.
	 * https://www.iana.org/assignments/http-methods/http-methods.xhtml
	 */
	TFW_HTTP_METH_COPY,
	TFW_HTTP_METH_DELETE,
	TFW_HTTP_METH_GET,		/* Safe. */
	TFW_HTTP_METH_HEAD,		/* Safe. */
	TFW_HTTP_METH_LOCK,		/* Non-idempotent. */
	TFW_HTTP_METH_MKCOL,
	TFW_HTTP_METH_MOVE,
	TFW_HTTP_METH_OPTIONS,		/* Safe. */
	TFW_HTTP_METH_PATCH,		/* Non-idempotent. */
	TFW_HTTP_METH_POST,		/* Non-idempotent. */
	TFW_HTTP_METH_PROPFIND,		/* Safe. */
	TFW_HTTP_METH_PROPPATCH,
	TFW_HTTP_METH_PUT,
	TFW_HTTP_METH_TRACE,		/* Safe. */
	TFW_HTTP_METH_UNLOCK,
	/* Well-known methods, not listed in RFCs. */
	TFW_HTTP_METH_PURGE,
	/* Unknown method, passed to upstream without additional processing. */
	_TFW_HTTP_METH_UNKNOWN,
	_TFW_HTTP_METH_COUNT
} tfw_http_meth_t;

/* HTTP protocol versions. */
enum {
	__TFW_HTTP_VER_INVALID,
	TFW_HTTP_VER_09,
	TFW_HTTP_VER_10,
	TFW_HTTP_VER_11,
	TFW_HTTP_VER_20,
	_TFW_HTTP_VER_COUNT
};

/* CC directives common to requests and responses. */
#define TFW_HTTP_CC_NO_CACHE		0x00000001
#define TFW_HTTP_CC_NO_STORE		0x00000002
#define TFW_HTTP_CC_NO_TRANSFORM	0x00000004
#define TFW_HTTP_CC_MAX_AGE		0x00000008
/* Request only CC directives. */
#define TFW_HTTP_CC_MAX_STALE		0x00000010
#define TFW_HTTP_CC_MIN_FRESH		0x00000020
#define TFW_HTTP_CC_OIFCACHED		0x00000040
/* Response only CC directives. */
#define TFW_HTTP_CC_MUST_REVAL		0x00000100
#define TFW_HTTP_CC_PROXY_REVAL		0x00000200
#define TFW_HTTP_CC_PUBLIC		0x00000400
#define TFW_HTTP_CC_PRIVATE		0x00000800
#define TFW_HTTP_CC_S_MAXAGE		0x00001000
/* Mask to indicate that CC header is present. */
#define TFW_HTTP_CC_IS_PRESENT		0x0000ffff
/* Headers that affect Cache Control. */
#define TFW_HTTP_CC_PRAGMA_NO_CACHE	0x00010000
#define TFW_HTTP_CC_HDR_AGE		0x00020000
#define TFW_HTTP_CC_HDR_EXPIRES		0x00040000
#define TFW_HTTP_CC_HDR_AUTHORIZATION	0x00080000
/* Config directives that affect Cache Control. */
#define TFW_HTTP_CC_CFG_CACHE_BYPASS	0x01000000

typedef struct {
	unsigned int	flags;
	unsigned int	max_age;
	unsigned int	s_maxage;
	unsigned int	max_stale;
	unsigned int	min_fresh;
	time_t		timestamp;
	time_t		age;
	time_t		expires;
} TfwCacheControl;

/**
 * Http headers table.
 *
 * Singular headers (in terms of RFC 7230 3.2.2) go first to protect header
 * repetition attacks. See __hdr_is_singular() and don't forget to
 * update the static headers array when add a new singular header here.
 * If the new header is hop-by-hop (must not be forwarded and cached by Tempesta)
 * it must be listed in tfw_http_init_parser_req()/tfw_http_init_parser_resp()
 * for unconditionally hop-by-hop header or in __parse_connection() otherwize.
 * If the header is end-to-end it must be listed in __hbh_parser_add_data().
 *
 * Note: don't forget to update __http_msg_hdr_val() and
 * tfw_http_msg_(resp|req)_spec_hid() upon adding a new header.
 *
 * Cookie: singular according to RFC 6265 5.4.
 *
 * TODO split the enumeration to separate server and client sets to avoid
 * wasting of headers array slots.
 */
typedef enum {
	TFW_HTTP_HDR_HOST,
	TFW_HTTP_HDR_CONTENT_LENGTH,
	TFW_HTTP_HDR_CONTENT_TYPE,
	TFW_HTTP_HDR_USER_AGENT,
	TFW_HTTP_HDR_SERVER = TFW_HTTP_HDR_USER_AGENT,
	TFW_HTTP_HDR_COOKIE,
	TFW_HTTP_HDR_REFERER,
	TFW_HTTP_HDR_IF_NONE_MATCH,
	TFW_HTTP_HDR_ETAG = TFW_HTTP_HDR_IF_NONE_MATCH,

	/* End of list of singular header. */
	TFW_HTTP_HDR_NONSINGULAR,

	TFW_HTTP_HDR_CONNECTION = TFW_HTTP_HDR_NONSINGULAR,
	TFW_HTTP_HDR_X_FORWARDED_FOR,
	TFW_HTTP_HDR_KEEP_ALIVE,
	TFW_HTTP_HDR_TRANSFER_ENCODING,

	/* Start of list of generic (raw) headers. */
	TFW_HTTP_HDR_RAW,

	TFW_HTTP_HDR_NUM	= 16,
} tfw_http_hdr_t;

enum {
	/* Common flags for requests and responses. */
	TFW_HTTP_FLAGS_COMMON	= 0,
	/*
	 * Connection management flags.
	 *
	 * CONN_CLOSE: the connection is to be closed after response is
	 * forwarded to the client. Set if:
	 * - 'Connection:' header contains 'close' term;
	 * - there is no possibility to serve further requests from the same
	 * connection due to errors or protocol restrictions.
	 *
	 * CONN_KA: 'Connection:' header contains 'keep-alive' term. The flag
	 * is not set for HTTP/1.1 connections which are persistent by default.
	 * CONN_EXTRA: 'Connection:' header contains additional terms.
	 *
	 * There is no requirement for mutual exclusivity for CONN_CLOSE and
	 * CONN_KA flags, their meaning is not limited by connection
	 * persistence and states about 'Connection:' header value. CONN_CLOSE
	 * always takes precedence over CONN_KA flag.
	 */
	TFW_HTTP_B_CONN_CLOSE	= TFW_HTTP_FLAGS_COMMON,
	TFW_HTTP_B_CONN_KA,
	TFW_HTTP_B_CONN_EXTRA,
	/* Chunked transfer encoding. */
	TFW_HTTP_B_CHUNKED,
	/* Media type is multipart/form-data. */
	TFW_HTTP_B_CT_MULTIPART,
	/* Multipart/form-data request has a boundary parameter. */
	TFW_HTTP_B_CT_MULTIPART_HAS_BOUNDARY,
	/* Singular header presents more than once. */
	TFW_HTTP_B_FIELD_DUPENTRY,

	/* Streaming flags: Buffered message part only */
	/* Message is not fully buffered and has a streamed part. */
	TFW_HTTP_B_STREAM,
	/* All streamed parts are fully sent, may proceed to the next message. */
	TFW_HTTP_B_STREAM_DONE,
	/*
	 * Error/attack happened while receiving the stream. It'll be never
	 * received in full.
	 */
	TFW_HTTP_B_STREAM_ERR,

	/* Streaming flags: Streamed message part only */
	/* The message represents stream part, not a full-size one. */
	TFW_HTTP_B_STREAM_PART,
	/* It's the last part of the stream. */
	TFW_HTTP_B_STREAM_LAST_PART,
	/* Need to buffer the stream for now, don't send it. */
	TFW_HTTP_B_STREAM_ON_HOLD,

	/* Request flags. */
	TFW_HTTP_FLAGS_REQ,
	/* Sticky cookie is found and verified. */
	TFW_HTTP_B_HAS_STICKY	= TFW_HTTP_FLAGS_REQ,
	/* URI has form http://authority/path, not just /path */
	TFW_HTTP_B_URI_FULL,
	/* Request is non-idempotent. */
	TFW_HTTP_B_NON_IDEMP,
	/* Request stated 'Accept: text/html' header */
	TFW_HTTP_B_ACCEPT_HTML,
	/* Request is created by HTTP health monitor. */
	TFW_HTTP_B_HMONITOR,
	/* Request from whitelist: skip frang and sticky modules processing. */
	TFW_HTTP_B_WHITELIST,
	/* Client was disconnected, drop the request. */
	TFW_HTTP_B_REQ_DROP,
	/*
	 * Force server connection close after response to this request is
	 * received.
	 */
	TFW_HTTP_B_FORCE_CLOSE,

	/* Response flags */
	TFW_HTTP_FLAGS_RESP,
	/* Response has no body. */
	TFW_HTTP_B_VOID_BODY	= TFW_HTTP_FLAGS_RESP,
	/* Response has header 'Date:'. */
	TFW_HTTP_B_HDR_DATE,
	/* Response has header 'Last-Modified:'. */
	TFW_HTTP_B_HDR_LMODIFIED,
	/* Response is stale, but pass with a warning. */
	TFW_HTTP_B_RESP_STALE,
	/* Response is fully processed and ready to be forwarded to the client. */
	TFW_HTTP_B_RESP_READY,

	_TFW_HTTP_FLAGS_NUM
};

#define __TFW_HTTP_MSG_M_CONN						\
	(BIT(TFW_HTTP_B_CONN_CLOSE) | BIT(TFW_HTTP_B_CONN_KA))

/**
 * The structure to hold data for an HTTP error response.
 * An error response is sent later in an unlocked queue context.
 *
 * @reason	- the error response message;
 * @status	- HTTP error response status;
 */
typedef struct {
	const char	*reason;
	unsigned short	status;
} TfwHttpError;

/**
 * Common HTTP message members.
 *
 * @msg			- the base data of an HTTP message;
 * @pool		- message's memory allocation pool;
 * @h_tbl		- table of message's HTTP headers in internal form;
 * @pair		- the message paired with this one;
 * @req			- the request paired with this response;
 * @resp		- the response paired with this request;
 * @head		- the buffered part of the streamed message;
 * @stream		- the streamed part of the streamed message;
 * @httperr		- HTTP error data used to form an error response;
 * @cache_ctl		- cache control data for a message;
 * @version		- HTTP version (1.0 and 1.1 are only supported);
 * @flags		- message related flags. The flags are tested
 *			  concurrently, but concurrent updates aren't
 *			  allowed. Use atomic operations if concurrent
 *			  updates are possible;
 * @content_length	- the value of Content-Length header field;
 * @keep_alive		- the value of timeout specified in Keep-Alive header;
 * @conn		- connection which the message was received on;
 * @destructor		- called when a connection is destroyed;
 * @crlf		- pointer to CRLF between headers and body;
 * @body		- pointer to the body of a message;
 *
 * TfwStr members must be the last for efficient scanning.
 *
 * When the HTTP message is streamed, it can be received and forwarded
 * simultaneously, so the lock must be taken to prevent access to the
 * HTTP message from multiple threads. The TfwHttpMsg struct has now such locks
 * though. Instead it's split into two parts:
 * - buffered part @head with the full set of headers except trailer ones and
 *   a body part;
 * - and proxied continuation part @stream, containing the rest of the body and
 *   the trailer headers.
 *
 * Since HTTP message can't be processed until the full set of headers is
 * received, buffered part won't be accessed by receiving and forwarding code
 * path simultaneously and the lock in the buffered path is not required.
 *
 * The streamed part may be parsed and forwarded simultaneously, thus
 * TfwHttpStream implements the lock. Then the streamed part is parsed or
 * processed it must not modify the buffered part, the buffered part is already
 * processed or even sent out.
 */
#define TFW_HTTP_MSG_COMMON						\
	TfwMsg		msg;						\
	TfwPool		*pool;						\
	TfwHttpHdrTbl	*h_tbl;						\
	union {								\
		TfwHttpMsg	*pair;					\
		TfwHttpReq	*req;					\
		TfwHttpResp	*resp;					\
	};								\
	union {								\
		TfwHttpMsg	*head;					\
		TfwHttpStream	*stream;				\
	};								\
	TfwHttpError	httperr;					\
	TfwCacheControl	cache_ctl;					\
	unsigned char	version;					\
	unsigned int	keep_alive;					\
	unsigned long	content_length;					\
	DECLARE_BITMAP	(flags, _TFW_HTTP_FLAGS_NUM);			\
	TfwConn		*conn;						\
	void (*destructor)(void *msg);					\
	TfwStr		crlf;						\
	TfwStr		body;

static inline void
tfw_http_copy_flags(unsigned long *to, unsigned long *from)
{
	bitmap_copy(to, from, _TFW_HTTP_FLAGS_NUM);
}

/**
 * A helper structure for operations common for requests and responses.
 * Just don't want to use explicit inheritance.
 */
struct tfw_http_msg_t {
	TFW_HTTP_MSG_COMMON;
};

#define __MSG_STR_START(m)		(&(m)->crlf)

#define TFW_HTTP_COND_IF_MSINCE		0x0001
#define TFW_HTTP_COND_ETAG_ANY		0x0002
#define TFW_HTTP_COND_ETAG_LIST		0x0004

/**
 * Conditional Request.
 *
 * @flags	- Which conditional headers are used,
 * @m_date	- requested modification date
 */
typedef struct {
	unsigned int	flags;
	time_t		m_date;
} TfwHttpCond;

/**
 * HTTP Request.
 *
 * @vhost	- virtual host for the request;
 * @location	- URI location;
 * @sess	- HTTP session descriptor, required for scheduling;
 * @userinfo	- userinfo in URI, not mandatory.
 * @host	- host in URI, may differ from Host header;
 * @uri_path	- path + query + fragment from URI (RFC3986.3);
 * @mark	- special hash mark for redirects handling in session module;
 * @multipart_boundary_raw - multipart boundary as is, maybe with escaped chars;
 * @multipart_boundary - decoded multipart boundary;
 * @fwd_list	- member in the queue of forwarded/backlogged requests;
 * @nip_list	- member in the queue of non-idempotent requests;
 * @method	- HTTP request method, one of GET/PORT/HEAD/etc;
 * @node	- NUMA node where request is serviced;
 * @frang_st	- current state of FRANG classifier;
 * @chunk_cnt	- header or body chunk count for Frang classifier;
 * @jtxtstamp	- time the request is forwarded to a server, in jiffies;
 * @jrxtstamp	- time the request is received from a client, in jiffies;
 * @tm_header	- time HTTP header started coming;
 * @tm_bchunk	- time previous chunk of HTTP body had come at;
 * @hash	- hash value for caching calculated for the request;
 * @retries	- the number of re-send attempts;
 *
 * TfwStr members must be the first for efficient scanning.
 */
struct tfw_http_req_t {
	TFW_HTTP_MSG_COMMON;
	TfwVhost		*vhost;
	TfwLocation		*location;
	TfwHttpSess		*sess;
	TfwHttpCond		cond;
	TfwStr			userinfo;
	TfwStr			host;
	TfwStr			uri_path;
	TfwStr			mark;
	TfwStr			multipart_boundary_raw;
	TfwStr			multipart_boundary;
	struct list_head	fwd_list;
	struct list_head	nip_list;
	unsigned char		method;
	unsigned short		node;
	unsigned int		frang_st;
	unsigned int		chunk_cnt;
	unsigned long		jtxtstamp;
	unsigned long		jrxtstamp;
	unsigned long		tm_header;
	unsigned long		tm_bchunk;
	unsigned long		hash;
	unsigned short		retries;
};

#define TFW_HTTP_REQ_STR_START(r)	__MSG_STR_START(r)
#define TFW_HTTP_REQ_STR_END(r)		((&(r)->uri_path) + 1)

/**
 * HTTP Response.
 * TfwStr members must be the first for efficient scanning.
 *
 * @jrxtstamp	- time the message has been received, in jiffies;
 */
struct tfw_http_resp_t {
	TFW_HTTP_MSG_COMMON;
	TfwStr			s_line;
	unsigned short		status;
	time_t			date;
	time_t			last_modified;
	unsigned long		jrxtstamp;
};

#define TFW_HTTP_RESP_STR_START(r)	__MSG_STR_START(r)
#define TFW_HTTP_RESP_STR_END(r)	((&(r)->body) + 1)

/**
 * Streamed part of response or request.
 *
 * @stream_lock		- lock between parse/stream operations;
 * @rcv_conn		- connection receiving the stream;
 * @off			- offset from the buffer part end;
 * @proc_off		- offset of unprocessed data in @body
 *
 * It's not always possible to stream the message as soon as it arrives,
 * receiver may not be ready for this particular message, e.g. if there is one
 * more streamed and not fully received message in its queue. So the streamed
 * message is actually get buffered until the receiver is ready. There are also
 * some cases when a more of the message must be buffered before is can be
 * processed, e.g. trailer header processing.
 *
 * When the streamed part is buffered, the @body member becomes longer during
 * parsing operations, so @proc_off shows how many bytes of the body was
 * already processed.
 *
 * The stream part may contain trailer header part. RFC allows intermediates
 * to ignore the headers, but Tempesta still needs to validate the headers
 * format and probably modify them.
 */
struct tfw_http_msg_stream_t {
	TFW_HTTP_MSG_COMMON;
	spinlock_t		stream_lock;
	TfwConn			*rcv_conn;
	size_t			off;
	size_t			proc_off;
};

#define __FOR_EACH_HDR_FIELD(pos, end, msg, soff, eoff)			\
	for ((pos) = &(msg)->h_tbl->tbl[soff], 				\
	     (end) = &(msg)->h_tbl->tbl[eoff];				\
	     (pos) < (end); 						\
	     ++(pos))

#define FOR_EACH_HDR_FIELD(pos, end, msg)				\
	__FOR_EACH_HDR_FIELD(pos, end, msg, 0, (msg)->h_tbl->off)

#define FOR_EACH_HDR_FIELD_SPECIAL(pos, end, msg)			\
	__FOR_EACH_HDR_FIELD(pos, end, msg, 0, TFW_HTTP_HDR_RAW)

#define FOR_EACH_HDR_FIELD_RAW(pos, end, msg)				\
	__FOR_EACH_HDR_FIELD(pos, end, msg, TFW_HTTP_HDR_RAW,		\
					    (msg)->h_tbl->off)

#define FOR_EACH_HDR_FIELD_FROM(pos, end, msg, soff)			\
	__FOR_EACH_HDR_FIELD(pos, end, msg, soff, (msg)->h_tbl->off)

/* Bit flags for block action behaviour. */
#define TFW_BLK_ERR_REPLY		0x0001
#define TFW_BLK_ATT_REPLY		0x0002
#define TFW_BLK_ERR_NOLOG		0x0004
#define TFW_BLK_ATT_NOLOG		0x0008

/* HTTP codes enumeration for predefined responses */
typedef enum {
	RESP_200,
	RESP_4XX_BEGIN,
	RESP_400	= RESP_4XX_BEGIN,
	RESP_403,
	RESP_404,
	RESP_412,
	RESP_4XX_END,
	RESP_5XX_BEGIN	= RESP_4XX_END,
	RESP_500	= RESP_5XX_BEGIN,
	RESP_502,
	RESP_503,
	RESP_504,
	RESP_5XX_END,
	RESP_NUM	= RESP_5XX_END
} resp_code_t;

enum {
	HTTP_STATUS_1XX = 1,
	HTTP_STATUS_2XX,
	HTTP_STATUS_3XX,
	HTTP_STATUS_4XX,
	HTTP_STATUS_5XX
};

#define HTTP_CODE_MIN 100
#define HTTP_CODE_MAX 599
#define HTTP_CODE_BIT_NUM(code) ((code) - HTTP_CODE_MIN)

/* Get current timestamp in secs. */
static inline time_t
tfw_current_timestamp(void)
{
	struct timespec ts;
	getnstimeofday(&ts);
	return ts.tv_sec;
}

static inline int
tfw_http_resp_code_range(const int n)
{
	return n <= HTTP_CODE_MAX && n >= HTTP_CODE_MIN;
}

typedef void (*tfw_http_cache_cb_t)(TfwHttpMsg *);

/* External HTTP functions. */
int tfw_http_msg_process(void *conn, TfwFsmData *data);
unsigned long tfw_http_req_key_calc(TfwHttpReq *req);
void tfw_http_req_destruct(void *msg);
void tfw_http_resp_fwd(TfwHttpResp *resp);
void tfw_http_resp_build_error(TfwHttpReq *req);
int tfw_cfgop_parse_http_status(const char *status, int *out);
void tfw_http_hm_srv_send(TfwServer *srv, char *data, unsigned long len);

static inline bool
tfw_http_msg_is_streamed(TfwHttpMsg *hm)
{
	return test_bit(TFW_HTTP_B_STREAM, hm->flags);
}

/*
 * Functions to send an HTTP error response to a client.
 */
int tfw_http_prep_redirect(TfwHttpMsg *resp, unsigned short status,
			   TfwStr *rmark, TfwStr *cookie, TfwStr *body);
int tfw_http_prep_304(TfwHttpMsg *resp, TfwHttpReq *req, TfwMsgIter *msg_it,
		      size_t hdrs_size);
void tfw_http_send_resp(TfwHttpReq *req, int status, const char *reason);

/* Helper functions */
char *tfw_http_msg_body_dup(const char *filename, size_t *len);

#endif /* __TFW_HTTP_H__ */
