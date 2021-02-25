/**
 *		Tempesta FW
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
#include "client.h"

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

	/* Run just before locally generated response sending. */
	TFW_HTTP_FSM_LOCAL_RESP_FILTER	= TFW_GFSM_HTTP_STATE(5),

	TFW_HTTP_FSM_RESP_MSG_FWD	= TFW_GFSM_HTTP_STATE(6),

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
	TFW_HTTP_STATUS_LINE,
	TFW_HTTP_HDR_H2_STATUS = TFW_HTTP_STATUS_LINE,
	TFW_HTTP_HDR_H2_METHOD = TFW_HTTP_HDR_H2_STATUS,
	TFW_HTTP_HDR_H2_SCHEME,
	TFW_HTTP_HDR_H2_AUTHORITY,
	TFW_HTTP_HDR_H2_PATH,
	TFW_HTTP_HDR_REGULAR,
	TFW_HTTP_HDR_HOST = TFW_HTTP_HDR_REGULAR,
	TFW_HTTP_HDR_CONTENT_LENGTH,
	TFW_HTTP_HDR_CONTENT_TYPE,
	TFW_HTTP_HDR_USER_AGENT,
	TFW_HTTP_HDR_SERVER = TFW_HTTP_HDR_USER_AGENT,
	TFW_HTTP_HDR_COOKIE,
	TFW_HTTP_HDR_SET_COOKIE = TFW_HTTP_HDR_COOKIE,
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
	/* Chunked is last transfer encoding. */
	TFW_HTTP_B_CHUNKED,
	/* Chunked in the middle of applied transfer encodings. */
	TFW_HTTP_B_CHUNKED_APPLIED,
	/* Message has chunked trailer headers part. */
	TFW_HTTP_B_CHUNKED_TRAILER,
	/* Message has transfer encodings other than chunked. */
	TFW_HTTP_B_TE_EXTRA,
	/* The message body is limited by the connection closing. */
	TFW_HTTP_B_UNLIMITED,
	/* Media type is multipart/form-data. */
	TFW_HTTP_B_CT_MULTIPART,
	/* Multipart/form-data request has a boundary parameter. */
	TFW_HTTP_B_CT_MULTIPART_HAS_BOUNDARY,
	/* Singular header presents more than once. */
	TFW_HTTP_B_FIELD_DUPENTRY,
	/* Message headers are fully parsed */
	TFW_HTTP_B_HEADERS_PARSED,
	/* Message is fully parsed */
	TFW_HTTP_B_FULLY_PARSED,
	/* Message has HTTP/2 format. */
	TFW_HTTP_B_H2,
	/* Message has all mandatory pseudo-headers (applicable for HTTP/2 mode only) */
	TFW_HTTP_B_H2_HDRS_FULL,
	/* Message in HTTP/2 transformation (applicable for HTTP/2 mode only). */
	TFW_HTTP_B_H2_TRANS_ENTERED,

	/* Request flags. */
	TFW_HTTP_FLAGS_REQ,
	/* Sticky cookie is found and verified. */
	TFW_HTTP_B_HAS_STICKY	= TFW_HTTP_FLAGS_REQ,
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

	/* Response flags */
	TFW_HTTP_FLAGS_RESP,
	/* Response has no body. */
	TFW_HTTP_B_VOID_BODY	= TFW_HTTP_FLAGS_RESP,
	/* Response has header 'Date:'. */
	TFW_HTTP_B_HDR_DATE,
	/* Response has header 'Last-Modified:'. */
	TFW_HTTP_B_HDR_LMODIFIED,
	/* Response is fully processed and ready to be forwarded to the client. */
	TFW_HTTP_B_RESP_READY,

	_TFW_HTTP_FLAGS_NUM
};

#define __TFW_HTTP_MSG_M_CONN						\
	(BIT(TFW_HTTP_B_CONN_CLOSE) | BIT(TFW_HTTP_B_CONN_KA))

#define TFW_MSG_H2(hmmsg)						\
	test_bit(TFW_HTTP_B_H2, ((TfwHttpMsg *)hmmsg)->flags)

#define TFW_RESP_TO_H2(hmmsg)						\
	((!hmmsg->conn || TFW_CONN_TYPE(hmmsg->conn) & Conn_Srv) &&	\
	 hmmsg->pair && TFW_MSG_H2(hmmsg->pair))

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
 * @httperr		- HTTP error data used to form an error response;
 * @pair		- the message paired with this one;
 * @req			- the request paired with this response;
 * @resp		- the response paired with this request;
 * @stream		- stream which the message is linked with;
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
	TfwStream	*stream;					\
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
 * @peer	- end-to-end peer. The peer is not set if
 *		  hop-by-hop peer (TfwConnection->peer) and end-to-end peer are
 *		  the same;
 * @pit		- iterator for tracking transformed data allocation (applicable
 *		  for HTTP/2 mode only);
 * @userinfo	- userinfo in URI, not mandatory;
 * @host	- host in URI, may differ from Host header;
 * @uri_path	- path + query + fragment from URI (RFC3986.3);
 * @mark	- special hash mark for redirects handling in session module;
 * @multipart_boundary_raw - multipart boundary as is, maybe with escaped chars;
 * @multipart_boundary - decoded multipart boundary;
 * @fwd_list	- member in the queue of forwarded/backlogged requests;
 * @nip_list	- member in the queue of non-idempotent requests;
 * @jtxtstamp	- time the request is forwarded to a server, in jiffies;
 * @jrxtstamp	- time the request is received from a client, in jiffies;
 * @tm_header	- time HTTP header started coming;
 * @tm_bchunk	- time previous chunk of HTTP body had come at;
 * @hash	- hash value for caching calculated for the request;
 * @frang_st	- current state of FRANG classifier;
 * @chunk_cnt	- header or body chunk count for Frang classifier;
 * @node	- NUMA node where request is serviced;
 * @retries	- the number of re-send attempts;
 * @method	- HTTP request method, one of GET/PORT/HEAD/etc;
 * @method_override - Overridden HTTP request method, passed in request headers.
 *
 * TfwStr members must be the first for efficient scanning.
 */
struct tfw_http_req_t {
	TFW_HTTP_MSG_COMMON;
	TfwVhost		*vhost;
	TfwLocation		*location;
	TfwHttpSess		*sess;
	TfwClient		*peer;
	TfwHttpCond		cond;
	TfwMsgParseIter		pit;
	TfwStr			userinfo;
	TfwStr			host;
	TfwStr			uri_path;
	TfwStr			mark;
	TfwStr			multipart_boundary_raw;
	TfwStr			multipart_boundary;
	struct list_head	fwd_list;
	struct list_head	nip_list;
	unsigned long		jtxtstamp;
	unsigned long		jrxtstamp;
	unsigned long		tm_header;
	unsigned long		tm_bchunk;
	unsigned long		hash;
	unsigned int		frang_st;
	unsigned int		chunk_cnt;
	unsigned int		host_port;
	unsigned short		node;
	unsigned short		retries;
	unsigned char		method;
	unsigned char		method_override;
};

#define TFW_HTTP_REQ_STR_START(r)	__MSG_STR_START(r)
#define TFW_HTTP_REQ_STR_END(r)		((&(r)->uri_path) + 1)

#define TFW_IDX_BITS		12
#define TFW_D_IDX_BITS		4

/**
 * Representation of operation with the next header (in order of headers in the
 * message) during HTTP/1.1=>HTTP/2 transformation process.
 *
 * @s_hdr	- source header for transformation;
 * @off		- offset of not copied data from last processed @chunk;
 * @chunk	- last chunk to be processed from @s_hdr;
 * @op		- transformation operation which should be executed.
 */
typedef struct {
	TfwStr		s_hdr;
	unsigned long	off;
	unsigned int	chunk;
	TfwH2TransOp	op;
} TfwNextHdrOp;

/**
 * The indirection map entry.
 *
 * @idx		- header index in @h_tbl;
 * @d_idx	- header's order in the array of duplicates of particular
 *		  @h_tbl record.
 */
typedef struct {
	unsigned short	idx	: TFW_IDX_BITS;
	unsigned short	d_idx	: TFW_D_IDX_BITS;
} TfwHdrIndex;

/**
 * Indirection map which links the header's order with its index in @h_tbl.
 *
 * @count	- the actual count of headers in the map (equal to the amount
 *		  of all headers in the message);
 * @size	- the size of the map (in entries);
 * @index	- array of the indexes (which are located in the order of
 *		  corresponding headers' appearance in the message).
 */
typedef struct {
	unsigned int	size;
	unsigned int	count;
	TfwHdrIndex	index[0];
} TfwHttpHdrMap;

/**
 * Iterator for message HTTP/2 transformation process.
 *
 * @map		- indirection map for tracking headers order in skb;
 * @start_off	- initial offset during copying response data into
 *		  skb (for subsequent insertion of HTTP/2 frame header);
 * @curr	- current header index in the @map;
 * @next	- operation (with necessary attributes) which should be executed
 *		  with next header;
 * @found	- bit mask of configured headers found in the message.
 * @curr_ptr	- pointer in the skb to write the current header;
 * @bnd		- pointer to the boundary data (which should not be
 *		  overwritten);
 * @iter	- skb expansion iterator;
 * @acc_len	- accumulated length of transformed message.
 */
typedef struct {
	TfwHttpHdrMap	*map;
	unsigned int	start_off;
	unsigned int	curr;
	TfwNextHdrOp	next;
	DECLARE_BITMAP	(found, TFW_USRHDRS_ARRAY_SZ);
	char		*curr_ptr;
	char		*bnd;
	TfwMsgIter	iter;
	unsigned long	acc_len;
} TfwHttpTransIter;

/**
 * HTTP Response.
 * TfwStr members must be the first for efficient scanning.
 *
 * @jrxtstamp	- time the message has been received, in jiffies;
 * @mit		- iterator for controlling HTTP/1.1 => HTTP/2 message
 *		  transformation process (applicable for HTTP/2 mode only).
 */
struct tfw_http_resp_t {
	TFW_HTTP_MSG_COMMON;
	unsigned short		status;
	time_t			date;
	time_t			last_modified;
	unsigned long		jrxtstamp;
	TfwHttpTransIter	mit;
};

#define TFW_HDR_MAP_INIT_CNT		32
#define TFW_HDR_MAP_SZ(cnt)		(sizeof(TfwHttpHdrMap)		\
					 + sizeof(TfwHdrIndex) * (cnt))

#define TFW_HTTP_RESP_STR_START(r)	__MSG_STR_START(r)
#define TFW_HTTP_RESP_STR_END(r)	((&(r)->body) + 1)

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

static inline int
tfw_http_resp_code_range(const int n)
{
	return n <= HTTP_CODE_MAX && n >= HTTP_CODE_MIN;
}

/*
 * Static index determination for response ':status' pseudo-header (see RFC
 * 7541 Appendix A for details).
 */
static inline unsigned short
tfw_h2_pseudo_index(unsigned short status)
{
	switch (status) {
	case 200:
		return 8;
	case 204:
		return 9;
	case 206:
		return 10;
	case 304:
		return 11;
	case 400:
		return 12;
	case 404:
		return 13;
	case 500:
		return 14;
	default:
		return 0;
	}
}

typedef void (*tfw_http_cache_cb_t)(TfwHttpMsg *);

/* External HTTP functions. */
int tfw_http_msg_process(void *conn, TfwFsmData *data);
int tfw_http_msg_process_generic(TfwConn *conn, TfwStream *stream,
				 TfwFsmData *data);
unsigned long tfw_http_req_key_calc(TfwHttpReq *req);
void tfw_http_req_destruct(void *msg);
void tfw_http_resp_fwd(TfwHttpResp *resp);
void tfw_http_resp_build_error(TfwHttpReq *req);
int tfw_cfgop_parse_http_status(const char *status, int *out);
void tfw_http_hm_srv_send(TfwServer *srv, char *data, unsigned long len);
int tfw_h1_set_loc_hdrs(TfwHttpMsg *hm, bool is_resp, bool from_cache);
int tfw_http_expand_stale_warn(TfwHttpResp *resp);
int tfw_http_expand_hdr_date(TfwHttpResp *resp);
int tfw_http_expand_hdr_clen(TfwHttpResp *resp, size_t len);
int tfw_http_expand_hbh(TfwHttpResp *resp, unsigned short status);
int tfw_http_expand_hdr_via(TfwHttpResp *resp);
void tfw_h2_resp_fwd(TfwHttpResp *resp);
int tfw_h2_hdr_map(TfwHttpResp *resp, const TfwStr *hdr, unsigned int id);
int tfw_h2_add_hdr_date(TfwHttpResp *resp, TfwH2TransOp op, bool cache);
int tfw_h2_set_stale_warn(TfwHttpResp *resp);
int tfw_h2_resp_add_loc_hdrs(TfwHttpResp *resp, const TfwHdrMods *h_mods,
			     bool cache);
int tfw_h2_resp_status_write(TfwHttpResp *resp, unsigned short status,
			     TfwH2TransOp op, bool cache);
/*
 * Functions to send an HTTP error response to a client.
 */
int tfw_h2_prep_redirect(TfwHttpResp *resp, unsigned short status,
			 TfwStr *rmark, TfwStr *cookie, TfwStr *body);
int tfw_h1_prep_redirect(TfwHttpResp *resp, unsigned short status,
			 TfwStr *rmark, TfwStr *cookie, TfwStr *body);
int tfw_http_prep_304(TfwHttpReq *req, struct sk_buff **skb_head,
		      TfwMsgIter *it);
void tfw_http_conn_msg_free(TfwHttpMsg *hm);
void tfw_http_send_resp(TfwHttpReq *req, int status, const char *reason);

/* Helper functions */
char *tfw_http_msg_body_dup(const char *filename, size_t *len);
unsigned long tfw_http_hdr_split(TfwStr *hdr, TfwStr *name_out, TfwStr *val_out,
				 bool inplace);
unsigned long tfw_h2_hdr_size(unsigned long n_len, unsigned long v_len,
			      unsigned short st_index);
int tfw_h2_frame_fwd_resp(TfwHttpResp *resp, unsigned int stream_id,
			  unsigned long h_len);
int tfw_h2_frame_local_resp(TfwHttpResp *resp, unsigned int stream_id,
			    unsigned long h_len, const TfwStr *body);

#endif /* __TFW_HTTP_H__ */
