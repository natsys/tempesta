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
#include <linux/types.h>
#include <asm/fpu/api.h>
#include <linux/vmalloc.h>

#include "http_msg.h"
#include "http_parser.h"

#include "test.h"
#include "helpers.h"
#include "fuzzer.h"

static TfwHttpReq *req, *sample_req;
static TfwHttpResp *resp;
static size_t hm_exp_len = 0;
static int chunks = 1;

#define SAMPLE_REQ_STR	"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
#define RMARK_NAME	"__tfw_name"

static int
split_and_parse_n(unsigned char *str, int type, size_t len, size_t chunks)
{
	size_t chlen = len / chunks, rem = len % chunks, pos = 0, step;
	unsigned int parsed;
	int r = 0;
	TfwHttpMsg *hm = (type == FUZZ_REQ)
			? (TfwHttpMsg *)req
			: (TfwHttpMsg *)resp;

	while (pos < len) {
		step = chlen;
		if (rem) {
			step += rem;
			rem = 0;
		}

		TEST_DBG3("split: len=%zu pos=%zu, chunks=%zu step=%zu\n",
			  len, pos, chunks, step);
		if (type == FUZZ_REQ)
			r = tfw_http_parse_req(req, str + pos, step, &parsed);
		else
			r = tfw_http_parse_resp(resp, str + pos, step, &parsed);

		pos += step;
		hm->msg.len += parsed;

		if (r != TFW_POSTPONE)
			return r;
	}

	return r;
}

/**
 * Response must be paired with request to be parsed correctly. Update sample
 * request for further response parsing.
 */
static int
set_sample_req(unsigned char *str)
{
	size_t len = strlen(str);
	int r;
	unsigned int parsed;

	if (sample_req)
		test_req_free(sample_req);
	sample_req = test_req_alloc(len);

	r = tfw_http_parse_req(sample_req, str, len, &parsed);

	return r;
}

static void
test_case_parse_prepare(const char *str, size_t sz_diff)
{
	chunks = 1;
	hm_exp_len = strlen(str) - sz_diff;
}

/**
 * The function is designed to be called in a loop, e.g.
 *   while(!do_split_and_parse(str, type));
 *
 * type may be FUZZ_REQ or FUZZ_RESP.
 *
 * On each iteration it splits the @str into fragments and pushes
 * them to the HTTP parser.
 *
 * That is done because:
 *  - HTTP pipelining: the feature implies that such a "split" may occur at
 *    any position of the input string. THe HTTP parser should be able to handle
 *    that, and we would like to test it.
 *  - Code coverage: the parser contains some optimizations for non-fragmented
 *    data, so we need to generate all possible fragments to test both "fast
 *    path" and "slow path" execution.
 *
 * The function is stateful:
 *  - It puts the parsed request or response to the global variable
 *  @req or @resp (on each call, depending on the message type).
 *  - It maintains the internal state between calls.
 *
 * Return value:
 *  == 0 - OK: current step of the loop is done without errors, proceed.
 *  <  0 - Error: the parsing is failed.
 *  >  0 - EOF: all possible fragments are parsed, terminate the loop.
 */
static int
do_split_and_parse(unsigned char *str, int type)
{
	int r;
	static size_t len;

	BUG_ON(!str);

	if (chunks == 1)
		len = strlen(str);

	if (type == FUZZ_REQ) {
		if (req)
			test_req_free(req);

		req = test_req_alloc(len);
	}
	else if (type == FUZZ_RESP) {
		if (resp)
			test_resp_free(resp);

		resp = test_resp_alloc(len);
		tfw_http_msg_pair(resp, sample_req);
	}
	else {
		BUG();
	}

	r = split_and_parse_n(str, type, len, chunks);
	/*
	 * Return any value which non-TFW_* constant to
	 * stop splitting message into pieces bigger than
	 * the message itself.
	 */
	if (++chunks > len)
		return 1;

	return r;
}

/**
 * To validate message parsing we provide text string which describes
 * HTTP message from start to end. If there any unused bytes after
 * message is successfully parsed, then parsing was incorrect.
 */
static int
validate_data_fully_parsed(int type)
{
	TfwHttpMsg *hm = (type == FUZZ_REQ)
			? (TfwHttpMsg *)req
			: (TfwHttpMsg *)resp;

	EXPECT_EQ(hm->msg.len, hm_exp_len);
	return hm->msg.len == hm_exp_len;
}

#define TRY_PARSE_EXPECT_PASS(str, type)			\
({ 								\
	int _err = do_split_and_parse(str, type);		\
	if (_err == TFW_BLOCK || _err == TFW_POSTPONE		\
	    || !validate_data_fully_parsed(type))		\
		TEST_FAIL("can't parse %s (code=%d):\n%s",	\
			  (type == FUZZ_REQ ? "request" :	\
				              "response"),	\
			  _err, (str)); 			\
	_err == TFW_PASS;					\
})

#define TRY_PARSE_EXPECT_BLOCK(str, type)			\
({								\
	int _err = do_split_and_parse(str, type);		\
	if (_err == TFW_PASS)					\
		TEST_FAIL("%s is not blocked as expected:\n%s",	\
			       (type == FUZZ_REQ ? "request" :	\
						   "response"),	\
			       (str));				\
	_err == TFW_BLOCK || _err == TFW_POSTPONE;		\
})


#define __FOR_REQ(str, sz_diff)					\
	TEST_LOG("=== request: [%s]\n", str);			\
	test_case_parse_prepare(str, sz_diff);			\
	while (TRY_PARSE_EXPECT_PASS(str, FUZZ_REQ))

#define FOR_REQ(str)	__FOR_REQ(str, 0)

#define EXPECT_BLOCK_REQ(str)					\
do {								\
	TEST_LOG("=== request: [%s]\n", str);			\
	test_case_parse_prepare(str, 0);			\
	while (TRY_PARSE_EXPECT_BLOCK(str, FUZZ_REQ));		\
} while (0)

#define __FOR_RESP(str, sz_diff)				\
	TEST_LOG("=== response: [%s]\n", str);			\
	test_case_parse_prepare(str, sz_diff);			\
	while (TRY_PARSE_EXPECT_PASS(str, FUZZ_RESP))

#define FOR_RESP(str)	__FOR_RESP(str, 0)

#define EXPECT_BLOCK_RESP(str)					\
do {								\
	TEST_LOG("=== response: [%s]\n", str);			\
	test_case_parse_prepare(str, 0);			\
	while (TRY_PARSE_EXPECT_BLOCK(str, FUZZ_RESP));		\
} while (0)

TEST(http_parser, leading_eol)
{
	FOR_REQ("GET / HTTP/1.1\r\nHost: foo.com\r\n\r\n");
	FOR_REQ("\r\nGET / HTTP/1.1\r\nHost: foo.com\r\n\r\n");
	FOR_REQ("\nGET / HTTP/1.1\r\nHost: foo.com\r\n\r\n");
	FOR_REQ("\n\n\nGET / HTTP/1.1\r\nHost: foo.com\r\n\r\n");

	FOR_RESP("HTTP/1.1 200 OK\r\n"
		 "Content-Length: 10\r\n"
		"\r\n"
		"0123456789");

	FOR_RESP("\n"
		 "HTTP/1.1 200 OK\r\n"
		 "Content-Length: 10\r\n"
		"\r\n"
		"0123456789");

	FOR_RESP("\r\n"
		 "HTTP/1.1 200 OK\r\n"
		 "Content-Length: 10\r\n"
		"\r\n"
		"0123456789");

	FOR_RESP("\n\n\n"
		 "HTTP/1.1 200 OK\r\n"
		 "Content-Length: 10\r\n"
		"\r\n"
		"0123456789");
}

TEST(http_parser, parses_req_method)
{
	FOR_REQ("COPY /filename HTTP/1.1\r\n\r\n") {
		EXPECT_EQ(req->method, TFW_HTTP_METH_COPY);
	}

	FOR_REQ("DELETE /filename HTTP/1.1\r\n\r\n") {
		EXPECT_EQ(req->method, TFW_HTTP_METH_DELETE);
	}

	FOR_REQ("GET / HTTP/1.1\r\n\r\n") {
		EXPECT_EQ(req->method, TFW_HTTP_METH_GET);
	}

	FOR_REQ("HEAD /? HTTP/1.1\r\n\r\n") {
		EXPECT_EQ(req->method, TFW_HTTP_METH_HEAD);
	}

	FOR_REQ("LOCK /filename HTTP/1.1\r\n\r\n") {
		EXPECT_EQ(req->method, TFW_HTTP_METH_LOCK);
	}

	FOR_REQ("MKCOL /filename HTTP/1.1\r\n\r\n") {
		EXPECT_EQ(req->method, TFW_HTTP_METH_MKCOL);
	}

	FOR_REQ("MOVE /filename HTTP/1.1\r\n\r\n") {
		EXPECT_EQ(req->method, TFW_HTTP_METH_MOVE);
	}

	FOR_REQ("OPTIONS /filename HTTP/1.1\r\n\r\n") {
		EXPECT_EQ(req->method, TFW_HTTP_METH_OPTIONS);
	}

	FOR_REQ("PATCH /filename HTTP/1.1\r\n\r\n") {
		EXPECT_EQ(req->method, TFW_HTTP_METH_PATCH);
	}

	FOR_REQ("POST /a?p=1 HTTP/1.1\r\n\r\n") {
		EXPECT_EQ(req->method, TFW_HTTP_METH_POST);
	}

	FOR_REQ("PROPFIND /filename HTTP/1.1\r\n\r\n") {
		EXPECT_EQ(req->method, TFW_HTTP_METH_PROPFIND);
	}

	FOR_REQ("PROPPATCH /filename HTTP/1.1\r\n\r\n") {
		EXPECT_EQ(req->method, TFW_HTTP_METH_PROPPATCH);
	}

	FOR_REQ("PUT /filename HTTP/1.1\r\n\r\n") {
		EXPECT_EQ(req->method, TFW_HTTP_METH_PUT);
	}

	FOR_REQ("TRACE /filename HTTP/1.1\r\n\r\n") {
		EXPECT_EQ(req->method, TFW_HTTP_METH_TRACE);
	}

	FOR_REQ("UNLOCK /filename HTTP/1.1\r\n\r\n") {
		EXPECT_EQ(req->method, TFW_HTTP_METH_UNLOCK);
	}

	/* Supported Non-RFC methods. */
	FOR_REQ("PURGE /filename HTTP/1.1\r\n\r\n") {
		EXPECT_EQ(req->method, TFW_HTTP_METH_PURGE);
	}

	/* RFC methods, not supported by TempestaFW. */
	FOR_REQ("ACL /filename HTTP/1.1\r\n\r\n") {
		EXPECT_EQ(req->method, _TFW_HTTP_METH_UNKNOWN);
	}
	FOR_REQ("BASELINE-CONTROL /filename HTTP/1.1\r\n\r\n") {
		EXPECT_EQ(req->method, _TFW_HTTP_METH_UNKNOWN);
	}
	FOR_REQ("BIND /filename HTTP/1.1\r\n\r\n") {
		EXPECT_EQ(req->method, _TFW_HTTP_METH_UNKNOWN);
	}
	FOR_REQ("CHECKIN /filename HTTP/1.1\r\n\r\n") {
		EXPECT_EQ(req->method, _TFW_HTTP_METH_UNKNOWN);
	}
	FOR_REQ("CHECKOUT /filename HTTP/1.1\r\n\r\n") {
		EXPECT_EQ(req->method, _TFW_HTTP_METH_UNKNOWN);
	}
	FOR_REQ("CONNECT /filename HTTP/1.1\r\n\r\n") {
		EXPECT_EQ(req->method, _TFW_HTTP_METH_UNKNOWN);
	}
	FOR_REQ("LABEL /filename HTTP/1.1\r\n\r\n") {
		EXPECT_EQ(req->method, _TFW_HTTP_METH_UNKNOWN);
	}
	FOR_REQ("LINK /filename HTTP/1.1\r\n\r\n") {
		EXPECT_EQ(req->method, _TFW_HTTP_METH_UNKNOWN);
	}
	FOR_REQ("MERGE /filename HTTP/1.1\r\n\r\n") {
		EXPECT_EQ(req->method, _TFW_HTTP_METH_UNKNOWN);
	}
	FOR_REQ("MKACTIVITY /filename HTTP/1.1\r\n\r\n") {
		EXPECT_EQ(req->method, _TFW_HTTP_METH_UNKNOWN);
	}
	FOR_REQ("MKCALENDAR /filename HTTP/1.1\r\n\r\n") {
		EXPECT_EQ(req->method, _TFW_HTTP_METH_UNKNOWN);
	}
	FOR_REQ("MKREDIRECTREF /filename HTTP/1.1\r\n\r\n") {
		EXPECT_EQ(req->method, _TFW_HTTP_METH_UNKNOWN);
	}
	FOR_REQ("MKWORKSPACE /filename HTTP/1.1\r\n\r\n") {
		EXPECT_EQ(req->method, _TFW_HTTP_METH_UNKNOWN);
	}
	FOR_REQ("ORDERPATCH /filename HTTP/1.1\r\n\r\n") {
		EXPECT_EQ(req->method, _TFW_HTTP_METH_UNKNOWN);
	}
	FOR_REQ("PRI /filename HTTP/1.1\r\n\r\n") {
		EXPECT_EQ(req->method, _TFW_HTTP_METH_UNKNOWN);
	}
	FOR_REQ("REBIND /filename HTTP/1.1\r\n\r\n") {
		EXPECT_EQ(req->method, _TFW_HTTP_METH_UNKNOWN);
	}
	FOR_REQ("REPORT /filename HTTP/1.1\r\n\r\n") {
		EXPECT_EQ(req->method, _TFW_HTTP_METH_UNKNOWN);
	}
	FOR_REQ("SEARCH /filename HTTP/1.1\r\n\r\n") {
		EXPECT_EQ(req->method, _TFW_HTTP_METH_UNKNOWN);
	}
	FOR_REQ("UNBIND /filename HTTP/1.1\r\n\r\n") {
		EXPECT_EQ(req->method, _TFW_HTTP_METH_UNKNOWN);
	}
	FOR_REQ("UNCHECKOUT /filename HTTP/1.1\r\n\r\n") {
		EXPECT_EQ(req->method, _TFW_HTTP_METH_UNKNOWN);
	}
	FOR_REQ("UNLINK /filename HTTP/1.1\r\n\r\n") {
		EXPECT_EQ(req->method, _TFW_HTTP_METH_UNKNOWN);
	}
	FOR_REQ("UPDATE /filename HTTP/1.1\r\n\r\n") {
		EXPECT_EQ(req->method, _TFW_HTTP_METH_UNKNOWN);
	}
	FOR_REQ("UPDATEREDIRECTREF /filename HTTP/1.1\r\n\r\n") {
		EXPECT_EQ(req->method, _TFW_HTTP_METH_UNKNOWN);
	}
	FOR_REQ("VERSION-CONTROL /filename HTTP/1.1\r\n\r\n") {
		EXPECT_EQ(req->method, _TFW_HTTP_METH_UNKNOWN);
	}

	/* Unknown methods. */
	FOR_REQ("UNKNOWN /filename HTTP/1.1\r\n\r\n") {
		EXPECT_EQ(req->method, _TFW_HTTP_METH_UNKNOWN);
	}
}

#define EXPECT_TFWSTR_EQ(tfw_str, cstr) \
	EXPECT_EQ(true, tfw_str_eq_cstr(tfw_str, cstr, strlen(cstr), 0))

TEST(http_parser, parses_req_uri)
{
	/* Relative part of the URI only. */

	FOR_REQ("GET / HTTP/1.1\r\n\r\n") {
		EXPECT_TFWSTR_EQ(&req->uri_path, "/");
	}

	FOR_REQ("GET /? HTTP/1.1\r\n\r\n") {
		EXPECT_TFWSTR_EQ(&req->uri_path, "/?");
	}

	FOR_REQ("GET /foo/b_a_r/baz.html HTTP/1.1\r\n\r\n") {
		EXPECT_TFWSTR_EQ(&req->uri_path, "/foo/b_a_r/baz.html");
	}

	FOR_REQ("GET /a/b/c/dir/ HTTP/1.1\r\n\r\n") {
		EXPECT_TFWSTR_EQ(&req->uri_path, "/a/b/c/dir/");
	}

	FOR_REQ("GET /a/b/c/dir/?foo=1&bar=2#abcd HTTP/1.1\r\n\r\n") {
		EXPECT_TFWSTR_EQ(&req->uri_path,
				 "/a/b/c/dir/?foo=1&bar=2#abcd");
	}

	/*
	 * Absolute URI.
	 * NOTE: we combine host and port URI parts into one field 'req->host'.
	 */
	FOR_REQ("GET http://natsys-lab.com/ HTTP/1.1\r\n\r\n") {
		EXPECT_TFWSTR_EQ(&req->host, "natsys-lab.com");
		EXPECT_TFWSTR_EQ(&req->uri_path, "/");
	}

	FOR_REQ("GET http://natsys-lab.com HTTP/1.1\r\n\r\n") {
		EXPECT_TFWSTR_EQ(&req->host, "natsys-lab.com");
		EXPECT_TFWSTR_EQ(&req->uri_path, "");
	}

	FOR_REQ("GET http://natsys-lab.com:8080/ HTTP/1.1\r\n\r\n") {
		EXPECT_TFWSTR_EQ(&req->host, "natsys-lab.com:8080");
		EXPECT_TFWSTR_EQ(&req->uri_path, "/");
	}

	FOR_REQ("GET http://natsys-lab.com:8080 HTTP/1.1\r\n\r\n") {
		EXPECT_TFWSTR_EQ(&req->host, "natsys-lab.com:8080");
		EXPECT_TFWSTR_EQ(&req->uri_path, "");
	}

	FOR_REQ("GET http://natsys-lab.com/foo/ HTTP/1.1\r\n\r\n") {
		EXPECT_TFWSTR_EQ(&req->host, "natsys-lab.com");
		EXPECT_TFWSTR_EQ(&req->uri_path, "/foo/");
	}

	FOR_REQ("GET http://natsys-lab.com:8080/cgi-bin/show.pl?entry=tempesta"
		" HTTP/1.1\r\n\r\n")
	{
		EXPECT_TFWSTR_EQ(&req->host, "natsys-lab.com:8080");
		EXPECT_TFWSTR_EQ(&req->uri_path,
				 "/cgi-bin/show.pl?entry=tempesta");
	}

	EXPECT_BLOCK_REQ("GET \x7f HTTP/1.1\r\n"
			 "Host: test\r\n"
			 "\r\n");

	EXPECT_BLOCK_REQ("GET /\x03uri HTTP/1.1\r\n"
			 "Host: test\r\n"
			 "\r\n");
}

TEST(http_parser, parses_enforce_ext_req)
{
	FOR_REQ("GET / HTTP/1.1\r\n"
		"\r\n")
	{
		EXPECT_TFWSTR_EQ(&req->uri_path, "/");
	}

	FOR_REQ("GET /index.html HTTP/1.1\r\n"
		"Connection: Keep-Alive\r\n"
		"X-Forwarded-For: 127.0.0.1\r\n"
		"\r\n")
	{
		EXPECT_TFWSTR_EQ(&req->uri_path, "/index.html");
	}

	FOR_REQ("GET http://natsys-lab.com/ HTTP/1.1\r\n"
		"User-Agent: Wget/1.13.4 (linux-gnu)\r\n"
		"Accept: */*\r\n"
		"\r\n")
	{
		EXPECT_TFWSTR_EQ(&req->host, "natsys-lab.com");
		EXPECT_TFWSTR_EQ(&req->uri_path, "/");
	}

	FOR_REQ("GET http://natsys-lab.com:8080/cgi-bin/show.pl HTTP/1.1\r\n"
		"Connection: Keep-Alive\r\n"
		"Cookie: session=42\r\n"
		"Accept: */*\r\n"
		"\r\n")
	{
		EXPECT_TFWSTR_EQ(&req->host, "natsys-lab.com:8080");
		EXPECT_TFWSTR_EQ(&req->uri_path, "/cgi-bin/show.pl");
	}
}

TEST(http_parser, parses_enforce_ext_req_rmark)
{
/*
 * Redirection attempt number, timestamp and calculated valid
 * HMAC (see 'test_http_sticky.c' file for details about
 * calculation process).
 */
#define ATT_NO		"00000001"
#define TIMESTAMP	"535455565758595a"
#define HMAC		"9cf5585388196965871bf4240ef44a52d0ffb23d"
#define RMARK		"/" RMARK_NAME "=" ATT_NO TIMESTAMP HMAC

#define URI_1		"/"
#define URI_2		"/static/test/index.html"
#define URI_3		"/foo/"
#define URI_4		"/cgi-bin/show.pl?entry=tempesta"

#define HOST		"natsys-lab.com"
#define PORT		"80"
#define AUTH		"http://" HOST ":" PORT

	FOR_REQ("GET " RMARK URI_1 " HTTP/1.1\r\n\r\n")	{
		EXPECT_TFWSTR_EQ(&req->mark, RMARK);
		EXPECT_TFWSTR_EQ(&req->uri_path, URI_1);
	}

	FOR_REQ("GET " RMARK URI_2 " HTTP/1.1\r\n\r\n")	{
		EXPECT_TFWSTR_EQ(&req->mark, RMARK);
		EXPECT_TFWSTR_EQ(&req->uri_path, URI_2);
	}

	FOR_REQ("GET " RMARK URI_3 " HTTP/1.1\r\n\r\n")	{
		EXPECT_TFWSTR_EQ(&req->mark, RMARK);
		EXPECT_TFWSTR_EQ(&req->uri_path, URI_3);
	}

	FOR_REQ("GET " RMARK URI_4 " HTTP/1.1\r\n\r\n")	{
		EXPECT_TFWSTR_EQ(&req->mark, RMARK);
		EXPECT_TFWSTR_EQ(&req->uri_path, URI_4);
	}

	FOR_REQ("GET " AUTH RMARK URI_1 " HTTP/1.1\r\n\r\n") {
		EXPECT_TFWSTR_EQ(&req->host, HOST ":" PORT);
		EXPECT_TFWSTR_EQ(&req->mark, RMARK);
		EXPECT_TFWSTR_EQ(&req->uri_path, URI_1);
	}

	FOR_REQ("GET " AUTH RMARK URI_3 " HTTP/1.1\r\n\r\n") {
		EXPECT_TFWSTR_EQ(&req->host, HOST ":" PORT);
		EXPECT_TFWSTR_EQ(&req->mark, RMARK);
		EXPECT_TFWSTR_EQ(&req->uri_path, URI_3);
	}

	FOR_REQ("GET " AUTH RMARK URI_4 " HTTP/1.1\r\n\r\n") {
		EXPECT_TFWSTR_EQ(&req->host, HOST ":" PORT);
		EXPECT_TFWSTR_EQ(&req->mark, RMARK);
		EXPECT_TFWSTR_EQ(&req->uri_path, URI_4);
	}

	/* Wrong RMARK formats. */
	EXPECT_BLOCK_REQ("GET " ATT_NO HMAC URI_1 " HTTP/1.1\r\n\r\n");

	EXPECT_BLOCK_REQ("GET " "/" RMARK_NAME "=" URI_1 " HTTP/1.1\r\n\r\n");

	EXPECT_BLOCK_REQ("GET " RMARK HMAC URI_1 " HTTP/1.1\r\n\r\n");

#undef ATT_NO
#undef TIMESTAMP
#undef HMAC
#undef RMARK

#undef URI_1
#undef URI_2
#undef URI_3
#undef URI_4

#undef HOST
#undef PORT
#undef AUTH
}

/* TODO add HTTP attack examples. */
TEST(http_parser, mangled_messages)
{
	EXPECT_BLOCK_REQ("GET / HTTP/1.1\r\n"
			 "POST / HTTP/1.1\r\n"
			 "Host: test\r\n"
			 "\r\n");

	EXPECT_BLOCK_REQ("GET / HTTP/1.1\r\n"
			 "Host: test\r\n"
			 "\x1fX-Foo: test\r\n"
			 "\r\n");

	EXPECT_BLOCK_REQ("GET / HTTP/1.1\r\n"
			 "Host: test\r\n"
			 "Connection: close, \"foo\"\r\n"
			 "\r\n");
	/*
	 * "Content-Length:" and "Transfer-Encoding:" header fields
	 * may not be present together in a request.
	 */
	EXPECT_BLOCK_REQ("GET / HTTP/1.1\r\n"
			 "Content-Length: 4\r\n"
			 "Transfer-Encoding: chunked\r\n"
			 "\r\n"
			 "4\r\n"
			 "12345\r\n"
			 "0\r\n"
			 "\r\n");
	/*
	 * "chunked" coding must be present in a request if there's
	 * any other coding (i.e. "Transfer-Encoding" is present).
	 */
	EXPECT_BLOCK_REQ("GET / HTTP/1.1\r\n"
			 "Transfer-Encoding: gzip\r\n"
			 "\r\n"
			 "4\r\n"
			 "12345\r\n");

	/* "chunked" coding must be the last coding. */
	EXPECT_BLOCK_REQ("GET / HTTP/1.1\r\n"
			 "Transfer-Encoding: chunked, gzip\r\n"
			 "\r\n"
			 "4\r\n"
			 "12345\r\n"
			 "0\r\n"
			 "\r\n");

	/* "chunked" coding may not be applied twice. */
	EXPECT_BLOCK_REQ("GET / HTTP/1.1\r\n"
			 "Transfer-Encoding: gzip, chunked\r\n"
			 "Transfer-Encoding: chunked\r\n"
			 "\r\n"
			 "4\r\n"
			 "12345\r\n"
			 "0\r\n"
			 "\r\n");

	EXPECT_BLOCK_RESP("HTTP/1.0 200 OK\r\n"
			 "Content-Type: foo/aa-\x19np\r\n"
			 "\r\n");

	EXPECT_BLOCK_RESP("HTTP/1.0 200 OK\r\n"
			  "Content-Length: 0\r\n"
			  "X-Foo: t\x7fst\r\n"
			  "\r\n");
	/*
	 * "Content-Length:" and "Transfer-Encoding:" header fields
	 * may not be present together in a response.
	 */
	EXPECT_BLOCK_RESP("HTTP/1.0 200 OK\r\n"
			  "Content-Length: 7\r\n"
			  "Server: test server\r\n"
			  "Transfer-Encoding: chunked\r\n"
			  "\r\n"
			  "7\r\n"
			  "1234567\r\n"
			  "0\r\n"
			  "\r\n");
	/*
	 * "chunked" coding may be missing in a response, but that
	 * means "unlimited body" which is tested by other means.
	 */

	/* "chunked" coding must be the last coding. */
	EXPECT_BLOCK_RESP("HTTP/1.0 200 OK\r\n"
			  "Server: test server\r\n"
			  "Transfer-Encoding: chunked, gzip\r\n"
			  "\r\n"
			  "7\r\n"
			  "1234567\r\n"
			  "0\r\n"
			  "\r\n");

	/* "chunked" coding may not be applied twice. */
	EXPECT_BLOCK_RESP("HTTP/1.0 200 OK\r\n"
			  "Server: test server\r\n"
			  "Transfer-Encoding: gzip, chunked\r\n"
			  "Transfer-Encoding: chunked\r\n"
			  "\r\n"
			  "7\r\n"
			  "1234567\r\n"
			  "0\r\n"
			  "\r\n");
}

/**
 * Test for allowed characters in different parts of HTTP message.
 */
TEST(http_parser, alphabets)
{
	FOR_REQ("GET / HTTP/1.1\r\n"
		"Host: test\r\n"
		/* We don't match open and closing quotes. */
		"Content-Type: Text/HTML;Charset=utf-8\"\t  \n"
		"Pragma: no-cache, fooo \r\n"
		"\r\n");

	/* Trailing SP in request. */
	FOR_REQ("GET /foo HTTP/1.1\r\n"
		"Host: localhost\t  \r\n"
		"User-Agent: Wget/1.13.4 (linux-gnu)\t  \r\n"
		"Accept: */*\t \r\n"
		"Connection: Keep-Alive \t \r\n"
		"X-Custom-Hdr: custom header values \t  \r\n"
		"X-Forwarded-For: 127.0.0.1, example.com    \t \r\n"
		"Content-Type: text/html; charset=iso-8859-1  \t \r\n"
		"Cache-Control: max-age=0, private, min-fresh=42 \t \r\n"
		"Transfer-Encoding: compress, deflate, gzip, chunked\t  \r\n"
		"Cookie: session=42; theme=dark  \t \r\n"
		"\r\n"
		"3\r\n"
		"123\r\n"
		"0\r\n"
		"\r\n");

	/* Trailing SP in response. */
	FOR_RESP("HTTP/1.1 200 OK\r\n"
		"Connection: Keep-Alive \t \r\n"
		"X-header: 6  \t  \t \r\n"
		"Content-Type: text/html; charset=iso-8859-1 \t \r\n"
		"Cache-Control: max-age=0, private, min-fresh=42 \t \r\n"
		"Expires: Tue, 31 Jan 2012 15:02:53 GMT \t \r\n"
		"Keep-Alive: timeout=600, max=65526 \t \r\n"
		"Transfer-Encoding: compress, deflate, gzip, chunked \t \r\n"
		"Server: Apache/2.4.6 (CentOS)  \t  \r\n"
		"\r\n"
		"4\r\n"
		"1234\r\n"
		"0\r\n"
		"\r\n");
}

TEST(http_parser, fills_hdr_tbl_for_req)
{
	TfwHttpHdrTbl *ht;
	TfwStr *h_accept, *h_xch, *h_dummy4, *h_dummy9, *h_cc, *h_pragma,
	       *h_auth;
	TfwStr h_host, h_connection, h_conttype, h_xff, h_user_agent, h_cookie,
	       h_te;

	/* Expected values for special headers. */
	const char *s_host = "localhost";
	const char *s_connection = "Keep-Alive";
	const char *s_xff = "127.0.0.1, example.com";
	const char *s_ct = "text/html; charset=iso-8859-1";
	const char *s_user_agent = "Wget/1.13.4 (linux-gnu)";
	const char *s_cookie = "session=42; theme=dark";
	/* Expected values for raw headers. */
	const char *s_accept = "Accept: */*";
	const char *s_xch = "X-Custom-Hdr: custom header values";
	const char *s_dummy9 = "Dummy9: 9";
	const char *s_dummy4 = "Dummy4: 4";
	const char *s_cc  = "Cache-Control: max-age=1, no-store, min-fresh=30";
	const char *s_te  = "compress, gzip, chunked";
	/* Trailing spaces are stored within header strings. */
	const char *s_pragma =  "Pragma: no-cache, fooo ";
	const char *s_auth =  "Authorization: "
			      "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\t ";

	FOR_REQ("GET /foo HTTP/1.1\r\n"
		"User-Agent: Wget/1.13.4 (linux-gnu)\r\n"
		"Accept: */*\r\n"
		"Host: localhost\r\n"
		"Connection: Keep-Alive\r\n"
		"X-Custom-Hdr: custom header values\r\n"
		"X-Forwarded-For: 127.0.0.1, example.com\r\n"
		"Dummy0: 0\r\n"
		"Dummy1: 1\r\n"
		"Dummy2: 2\r\n"
		"Dummy3: 3\r\n"
		"Dummy4: 4\r\n"
		"Dummy5: 5\r\n"
		"Dummy6: 6\r\n"
		"Content-Type: text/html; charset=iso-8859-1\r\n"
		"Dummy7: 7\r\n"
		"Dummy8: 8\r\n" /* That is done to check table reallocation. */
		"Dummy9: 9\r\n"
		"Cache-Control: max-age=1, no-store, min-fresh=30\r\n"
		"Pragma: no-cache, fooo \r\n"
		"Transfer-Encoding: compress, gzip, chunked\r\n"
		"Cookie: session=42; theme=dark\r\n"
		"Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\t \n"
		"\r\n"
		"6\r\n"
		"123456\r\n"
		"0\r\n"
		"\r\n");
	{
		ht = req->h_tbl;

		/* Special headers: */
		tfw_http_msg_clnthdr_val(&ht->tbl[TFW_HTTP_HDR_HOST],
					 TFW_HTTP_HDR_HOST, &h_host);
		tfw_http_msg_clnthdr_val(&ht->tbl[TFW_HTTP_HDR_CONNECTION],
					 TFW_HTTP_HDR_CONNECTION,
					 &h_connection);
		tfw_http_msg_clnthdr_val(&ht->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
					 TFW_HTTP_HDR_CONTENT_TYPE,
					 &h_conttype);
		tfw_http_msg_clnthdr_val(&ht->tbl[TFW_HTTP_HDR_X_FORWARDED_FOR],
					 TFW_HTTP_HDR_X_FORWARDED_FOR, &h_xff);
		tfw_http_msg_clnthdr_val(&ht->tbl[TFW_HTTP_HDR_USER_AGENT],
					 TFW_HTTP_HDR_USER_AGENT,
					 &h_user_agent);
		tfw_http_msg_clnthdr_val(&ht->tbl[TFW_HTTP_HDR_TRANSFER_ENCODING],
					 TFW_HTTP_HDR_TRANSFER_ENCODING, &h_te);
		tfw_http_msg_clnthdr_val(&ht->tbl[TFW_HTTP_HDR_COOKIE],
					 TFW_HTTP_HDR_COOKIE, &h_cookie);

		/* Common (raw) headers: 16 total with 10 dummies. */
		EXPECT_EQ(ht->off, TFW_HTTP_HDR_RAW + 15);

		h_accept = &ht->tbl[TFW_HTTP_HDR_RAW + 0];
		h_xch = &ht->tbl[TFW_HTTP_HDR_RAW + 1];
		h_dummy4 = &ht->tbl[TFW_HTTP_HDR_RAW + 6];
		h_dummy9 = &ht->tbl[TFW_HTTP_HDR_RAW + 11];
		h_cc = &ht->tbl[TFW_HTTP_HDR_RAW + 12];
		h_pragma = &ht->tbl[TFW_HTTP_HDR_RAW + 13];
		h_auth = &ht->tbl[TFW_HTTP_HDR_RAW + 14];

		EXPECT_TRUE(tfw_str_eq_cstr(&h_host, s_host,
					    strlen(s_host), 0));
		EXPECT_TRUE(tfw_str_eq_cstr(&h_connection, s_connection,
					    strlen(s_connection), 0));
		EXPECT_TRUE(tfw_str_eq_cstr(&h_conttype, s_ct,
					    strlen(s_ct), 0));
		EXPECT_TRUE(tfw_str_eq_cstr(&h_xff, s_xff,
					    strlen(s_xff), 0));
		EXPECT_TRUE(tfw_str_eq_cstr(&h_user_agent, s_user_agent,
					    strlen(s_user_agent), 0));
		EXPECT_TRUE(tfw_str_eq_cstr(&h_te, s_te,
					    strlen(s_te), 0));
		EXPECT_TRUE(tfw_str_eq_cstr(&h_cookie, s_cookie,
					    strlen(s_cookie), 0));

		EXPECT_TRUE(tfw_str_eq_cstr(h_accept, s_accept,
					    strlen(s_accept), 0));
		EXPECT_TRUE(tfw_str_eq_cstr(h_xch, s_xch,
					    strlen(s_xch), 0));
		EXPECT_TRUE(tfw_str_eq_cstr(h_dummy4, s_dummy4,
					    strlen(s_dummy4), 0));
		EXPECT_TRUE(tfw_str_eq_cstr(h_dummy9, s_dummy9,
					    strlen(s_dummy9), 0));
		EXPECT_TRUE(tfw_str_eq_cstr(h_cc, s_cc,
					    strlen(s_cc), 0));
		EXPECT_TRUE(tfw_str_eq_cstr(h_pragma, s_pragma,
					    strlen(s_pragma), 0));
		EXPECT_TRUE(tfw_str_eq_cstr(h_auth, s_auth,
					    strlen(s_auth), 0));

		EXPECT_TRUE(req->method = TFW_HTTP_METH_GET);
		EXPECT_TRUE(req->content_length == 0);
		EXPECT_TRUE(req->cache_ctl.flags & TFW_HTTP_CC_NO_STORE);
		EXPECT_TRUE(req->cache_ctl.flags & TFW_HTTP_CC_MIN_FRESH);
		EXPECT_TRUE(req->cache_ctl.flags & TFW_HTTP_CC_MAX_AGE);
		EXPECT_TRUE(req->cache_ctl.min_fresh == 30);
		EXPECT_TRUE(req->cache_ctl.max_age == 1);
		EXPECT_TRUE(ht->tbl[TFW_HTTP_HDR_HOST].eolen == 2);
	}
}

TEST(http_parser, fills_hdr_tbl_for_resp)
{
	TfwHttpHdrTbl *ht;
	TfwStr *h_dummy4, *h_dummy9, *h_cc, *h_age, *h_date, *h_exp;
	TfwStr h_connection, h_conttype, h_srv, h_te, h_ka;

	/* Expected values for special headers. */
	const char *s_connection = "Keep-Alive";
	const char *s_ct = "text/html; charset=iso-8859-1";
	const char *s_srv = "Apache/2.4.6 (CentOS) OpenSSL/1.0.1e-fips"
			    " mod_fcgid/2.3.9";
	/* Expected values for raw headers. */
	const char *s_dummy9 = "Dummy9: 9";
	const char *s_dummy4 = "Dummy4: 4";
	const char *s_cc = "Cache-Control: "
			   "max-age=5, private, no-cache, ext=foo";
	const char *s_te = "compress, gzip, chunked";
	const char *s_exp = "Expires: Tue, 31 Jan 2012 15:02:53 GMT";
	const char *s_ka = "timeout=600, max=65526";
	/* Trailing spaces are stored within header strings. */
	const char *s_age = "Age: 12  ";
	const char *s_date = "Date: Sun, 9 Sep 2001 01:46:40 GMT\t";

	FOR_RESP("HTTP/1.1 200 OK\r\n"
		"Connection: Keep-Alive\r\n"
		"Dummy0: 0\r\n"
		"Dummy1: 1\r\n"
		"Dummy2: 2\r\n"
		"Dummy3: 3\r\n"
		"Dummy4: 4\r\n"
		"Dummy5: 5\r\n"
		"Dummy6: 6\r\n"
		"Content-Type: text/html; charset=iso-8859-1\r\n"
		"Dummy7: 7\r\n"
		"Dummy8: 8\r\n"
		"Cache-Control: max-age=5, private, no-cache, ext=foo\r\n"
		"Dummy9: 9\r\n" /* That is done to check table reallocation. */
		"Expires: Tue, 31 Jan 2012 15:02:53 GMT\r\n"
		"Keep-Alive: timeout=600, max=65526\r\n"
		"Transfer-Encoding: compress, gzip, chunked\r\n"
		"Server: Apache/2.4.6 (CentOS) OpenSSL/1.0.1e-fips"
		        " mod_fcgid/2.3.9\r\n"
		"Age: 12  \n"
		"Date: Sun, 9 Sep 2001 01:46:40 GMT\t\n"
		"\r\n"
		"3\r\n"
		"012\r\n"
		"0\r\n"
		"\r\n");
	{
		ht = resp->h_tbl;

		EXPECT_TRUE(tfw_str_eq_cstr(&resp->s_line, "HTTP/1.1 200 OK",
			    strlen("HTTP/1.1 200 OK"), 0));

		/* Special headers: */
		tfw_http_msg_srvhdr_val(&ht->tbl[TFW_HTTP_HDR_CONNECTION],
					TFW_HTTP_HDR_CONNECTION,
					&h_connection);
		tfw_http_msg_srvhdr_val(&ht->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
					TFW_HTTP_HDR_CONTENT_TYPE,
					&h_conttype);
		tfw_http_msg_srvhdr_val(&ht->tbl[TFW_HTTP_HDR_SERVER],
					TFW_HTTP_HDR_SERVER, &h_srv);
		tfw_http_msg_srvhdr_val(&ht->tbl[TFW_HTTP_HDR_TRANSFER_ENCODING],
					TFW_HTTP_HDR_TRANSFER_ENCODING, &h_te);
		tfw_http_msg_srvhdr_val(&ht->tbl[TFW_HTTP_HDR_KEEP_ALIVE],
					TFW_HTTP_HDR_KEEP_ALIVE, &h_ka);

		/*
		 * Common (raw) headers: 10 dummies, Cache-Control,
		 * Expires, Age, Date.
		 */
		EXPECT_EQ(ht->off, TFW_HTTP_HDR_RAW + 14);

		h_dummy4 = &ht->tbl[TFW_HTTP_HDR_RAW + 4];
		h_cc = &ht->tbl[TFW_HTTP_HDR_RAW + 9];
		h_dummy9 = &ht->tbl[TFW_HTTP_HDR_RAW + 10];
		h_exp = &ht->tbl[TFW_HTTP_HDR_RAW + 11];
		h_age = &ht->tbl[TFW_HTTP_HDR_RAW + 12];
		h_date = &ht->tbl[TFW_HTTP_HDR_RAW + 13];

		EXPECT_TRUE(tfw_str_eq_cstr(&h_connection, s_connection,
					    strlen(s_connection), 0));
		EXPECT_TRUE(tfw_str_eq_cstr(&h_conttype, s_ct,
					    strlen(s_ct), 0));
		EXPECT_TRUE(tfw_str_eq_cstr(&h_srv, s_srv,
					    strlen(s_srv), 0));
		EXPECT_TRUE(tfw_str_eq_cstr(&h_te, s_te,
					    strlen(s_te), 0));
		EXPECT_TRUE(tfw_str_eq_cstr(&h_ka, s_ka,
					    strlen(s_ka), 0));

		EXPECT_TRUE(tfw_str_eq_cstr(h_dummy4, s_dummy4,
					    strlen(s_dummy4), 0));
		EXPECT_TRUE(tfw_str_eq_cstr(h_cc, s_cc,
					    strlen(s_cc), 0));
		EXPECT_TRUE(tfw_str_eq_cstr(h_dummy9, s_dummy9,
					    strlen(s_dummy9), 0));
		EXPECT_TRUE(tfw_str_eq_cstr(h_exp, s_exp,
					    strlen(s_exp), 0));
		EXPECT_TRUE(tfw_str_eq_cstr(h_age, s_age,
					    strlen(s_age), 0));
		EXPECT_TRUE(tfw_str_eq_cstr(h_date, s_date,
					    strlen(s_date), 0));

		EXPECT_TRUE(resp->status == 200);
		EXPECT_TRUE(resp->cache_ctl.flags & TFW_HTTP_CC_PRIVATE);
		EXPECT_TRUE(resp->cache_ctl.flags & TFW_HTTP_CC_NO_CACHE);
		EXPECT_TRUE(resp->cache_ctl.flags & TFW_HTTP_CC_MAX_AGE);
		EXPECT_TRUE(resp->cache_ctl.max_age == 5);
		EXPECT_TRUE(resp->keep_alive == 600);
		/*
		 *  $ date -u --date='@1000000000'
		 *  Sun Sep  9 01:46:40 UTC 2001
		 */
		EXPECT_TRUE(resp->date == 1000000000);
		EXPECT_TRUE(h_dummy9->eolen == 2);
	}
}

TEST(http_parser, cache_control_flags)
{
	FOR_RESP("HTTP/1.1 200 OK\r\n"
		 "Content-Length: 0\r\n"
		 "Connection: Keep-Alive\r\n"
		 "Content-Type: text/html; charset=iso-8859-1\r\n"
		 "Cache-Control: max-age=5, private, no-cache, ext=foo\r\n"
		 "\r\n");
	{
		EXPECT_TRUE(resp->cache_ctl.flags & TFW_HTTP_CC_PRIVATE);
		EXPECT_TRUE(resp->cache_ctl.flags & TFW_HTTP_CC_NO_CACHE);
		EXPECT_TRUE(resp->cache_ctl.flags & TFW_HTTP_CC_MAX_AGE);
		EXPECT_FALSE(
			resp->cache_ctl.flags & TFW_HTTP_CC_PRAGMA_NO_CACHE);
	}

	FOR_RESP("HTTP/1.1 200 OK\r\n"
		 "Content-Length: 0\r\n"
		 "Connection: Keep-Alive\r\n"
		 "Content-Type: text/html; charset=iso-8859-1\r\n"
		 "Pragma: no-cache\r\n"
		 "\r\n");
	{
		EXPECT_FALSE(resp->cache_ctl.flags & TFW_HTTP_CC_PRIVATE);
		EXPECT_FALSE(resp->cache_ctl.flags & TFW_HTTP_CC_NO_CACHE);
		EXPECT_FALSE(resp->cache_ctl.flags & TFW_HTTP_CC_MAX_AGE);
		EXPECT_TRUE(
			resp->cache_ctl.flags & TFW_HTTP_CC_PRAGMA_NO_CACHE);
	}

	FOR_RESP("HTTP/1.1 200 OK\r\n"
		 "Content-Length: 0\r\n"
		 "Connection: Keep-Alive\r\n"
		 "Content-Type: text/html; charset=iso-8859-1\r\n"
		 "\r\n");
	{
		EXPECT_FALSE(resp->cache_ctl.flags & TFW_HTTP_CC_PRIVATE);
		EXPECT_FALSE(resp->cache_ctl.flags & TFW_HTTP_CC_NO_CACHE);
		EXPECT_FALSE(resp->cache_ctl.flags & TFW_HTTP_CC_MAX_AGE);
		EXPECT_FALSE(
			resp->cache_ctl.flags & TFW_HTTP_CC_PRAGMA_NO_CACHE);
	}

	FOR_RESP("HTTP/1.1 200 OK\r\n"
		 "Content-Length: 0\r\n"
		 "Connection: Keep-Alive\r\n"
		 "Pragma: nocache\r\n"
		 "Content-Type: text/html; charset=iso-8859-1\r\n"
		 "\r\n");
	{
		/* Contents of "Pragma" is not "no-cache" exactly. */
		EXPECT_FALSE(
			resp->cache_ctl.flags & TFW_HTTP_CC_PRAGMA_NO_CACHE);
	}
}

TEST(http_parser, suspicious_x_forwarded_for)
{
	FOR_REQ("GET / HTTP/1.1\r\n"
		"X-Forwarded-For:   [::1]:1234,5.6.7.8   ,"
		"  natsys-lab.com:65535  \r\n"
		"\r\n")
	{
		const TfwStr *h = &req->h_tbl->tbl[TFW_HTTP_HDR_X_FORWARDED_FOR];
		EXPECT_GT(h->len, 0);
	}

	EXPECT_BLOCK_REQ("GET / HTTP/1.1\r\n"
			 "X-Forwarded-For: 1.2.3.4, , 5.6.7.8\r\n"
			 "\r\n");

	EXPECT_BLOCK_REQ("GET / HTTP/1.1\r\n"
			 "X-Forwarded-For: foo!\r\n"
			 "\r\n");

	EXPECT_BLOCK_REQ("GET / HTTP/1.1\r\n"
			 "X-Forwarded-For: \r\n"
			 "\r\n");
}

TEST(http_parser, parses_connection_value)
{
	FOR_REQ("GET / HTTP/1.1\r\n"
		"Connection: Keep-Alive\r\n"
		"\r\n")
	{
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CONN_CLOSE, req->flags));
		EXPECT_TRUE(test_bit(TFW_HTTP_B_CONN_KA, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CONN_EXTRA, req->flags));
	}

	FOR_REQ("GET / HTTP/1.1\r\n"
		"Connection: Close\r\n"
		"\r\n")
	{
		EXPECT_TRUE(test_bit(TFW_HTTP_B_CONN_CLOSE, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CONN_KA, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CONN_EXTRA, req->flags));
	}
}

TEST(http_parser, content_length)
{
	EXPECT_BLOCK_REQ("GET / HTTP/1.1\r\n"
			  "Content-Length: 0\r\n"
			  "Content-Length: 0\r\n"
			  "\r\n");

	EXPECT_BLOCK_REQ("GET / HTTP/1.1\r\n"
			 "Content-Length: 10, 10\r\n"
			 "\r\n"
			 "0123456789");

	EXPECT_BLOCK_RESP("HTTP/1.0 200 OK\r\n"
			  "Content-Length: 0\r\n"
			  "Content-Length: 0\r\n"
			  "\r\n");

	EXPECT_BLOCK_RESP("HTTP/1.0 200 OK\r\n"
			  "Content-Length: 10, 10\r\n"
			  "\r\n"
			  "0123456789");

	EXPECT_BLOCK_RESP("HTTP/1.0 200 OK\r\n"
			  "Content-Length: -1\r\n"
			  "\r\n"
			  "aaaaaa\n"
			  "\r\n");
}

TEST(http_parser, eol_crlf)
{
	FOR_REQ("\rGET / HTTP/1.1\r\n"
		"Host: d.com\r\n"
		"\r\n");

	__FOR_REQ("POST / HTTP/1.1\n"
		  "Host: a.com\n"
		  "Content-Length: 5\n"
		  "\n"
		  "a=24\n"
		  "\n",  /* the LF is ignored. */
		  1)
	{
		TfwHttpHdrTbl *ht = req->h_tbl;

		EXPECT_TRUE(req->crlf.len == 1);
		EXPECT_TRUE(req->body.len == 5);
		EXPECT_TRUE(ht->tbl[TFW_HTTP_HDR_HOST].eolen == 1);
		EXPECT_TRUE(ht->tbl[TFW_HTTP_HDR_CONTENT_LENGTH].eolen == 1);
	}

	/*
	 * It seems RFC 7230 3.3 doesn't prohibit message body
	 * for GET requests.
	 */
	__FOR_REQ("GET / HTTP/1.1\n"
		  "Host: b.com\n"
		  "Content-Length: 6\n"
		  "\r\n"
		  "b=24\r\n"
		  "\r\n",  /* the CRLF is ignored. */
		  2)
	{
		EXPECT_TRUE(req->crlf.len == 2);
		EXPECT_TRUE(req->body.len == 6);
	}

	EXPECT_BLOCK_REQ("GET / HTTP/1.1\r\r\n"
			 "Host: c.com\r\n"
			 "\r\n");
	EXPECT_BLOCK_REQ("GET\r/ HTTP/1.1\r\n"
			 "Host: e.com\r\n"
			 "\r\n");
	EXPECT_BLOCK_REQ("GET / HTTP/1.1\r\n"
			 "Host: f.com\r\r\n"
			 "\r\n");
	EXPECT_BLOCK_REQ("GET / HTTP/1.1\r\n"
			 "Host: g.com\r\r\n"
			 "\r\r\n");
}

/*
 * This test ensures that there's not retrogression in handling CRLF.
 * The bug was that in case of trailing headers CRLF that was set to
 * point at location after the headers at the beginning of a message
 * was later reset to point at location after the trailing headers.
 */
TEST(http_parser, crlf_trailer)
{
	unsigned int id;
	DEFINE_TFW_STR(s_custom, "Custom-Hdr:");

	/*
	 * Use a trick with different CRLF length to differentiate
	 * between the correct CRLF and an incorrect CRLF.
	 */
	FOR_REQ("GET / HTTP/1.1\r\n"
		"Transfer-Encoding: chunked\r\n"
		"\n"
		"4\r\n"
		"1234\r\n"
		"0\r\n"
		"Custom-Hdr: custom-data\r\n"
		"\r\n")
	{
		/* 'Custom-Hdr:' is the first raw header in this example. */
		id = tfw_http_msg_hdr_lookup((TfwHttpMsg *)req, &s_custom);

		EXPECT_TRUE(id == TFW_HTTP_HDR_RAW);
		EXPECT_TRUE(req->body.len == 12);
		EXPECT_TRUE(req->crlf.len == 1);
	}

	FOR_RESP("HTTP/1.1 200 OK\r\n"
		 "Transfer-Encoding: chunked\r\n"
		 "\n"
		 "5\r\n"
		 "abcde\r\n"
		 "0\r\n"
		 "Custom-Hdr: custom-data\r\n"
		 "\r\n")
	{
		/* 'Custom-Hdr:' is the first raw header in this example. */
		id = tfw_http_msg_hdr_lookup((TfwHttpMsg *)resp, &s_custom);

		EXPECT_TRUE(id == TFW_HTTP_HDR_RAW);
		EXPECT_TRUE(resp->body.len == 13);
		EXPECT_TRUE(resp->crlf.len == 1);
	}
}

TEST(http_parser, ows)
{
	FOR_REQ("GET /a.html HTTP/1.1\r\n"
		"Host: 		 foo.com 	\r\n"
		"Connection:   close   \r\n"
		"Cookie: 	a=5	 \r\n"
		"X-Forwarded-For:   1.2.3.4   \r\n"
		"\n");

	FOR_RESP("HTTP/1.1 200 OK\r\n"
		 "Content-Length: 10  	\r\n"
		 "Age:   12   \r\n"
		"\n"
		"0123456789");

	FOR_REQ("GET / HTTP/1.1\r\n"
		"Host:foo.com\r\n"
		"\r\n");

	EXPECT_BLOCK_REQ("GET / HTTP/1.1\r\n"
			 "Host :foo.com\r\n"
			 "\r\n");

	EXPECT_BLOCK_REQ("GET	/ HTTP/1.1\r\n"
			 "Host: foo.com\r\n"
			 "\r\n");

	EXPECT_BLOCK_REQ("GET /\tHTTP/1.1\r\n"
			 "Host: foo.com\r\n"
			 "\r\n");

	EXPECT_BLOCK_REQ("GET / HTTP/1.1 \r\n"
			 "Host: foo.com\r\n"
			 "\r\n");

	EXPECT_BLOCK_REQ("GET / HTTP/1.1\t\r\n"
			 "Host: foo.com\r\n"
			 "\r\n");

	EXPECT_BLOCK_REQ("GET / HTTP/1.1\r \n"
			 "Host: foo.com\r\n"
			 "\r\n");

	EXPECT_BLOCK_REQ("GET / HTTP/1.1\r\n"
			 " Host: foo.com\r\n"
			 "\r\n");
}

TEST(http_parser, folding)
{
	EXPECT_BLOCK_REQ("GET / HTTP/1.1\r\n"
			 "Host:    \r\n"
			 "   foo.com\r\n"
			 "Connection: close\r\n"
			 "\n");

	EXPECT_BLOCK_REQ("GET / HTTP/1.1\r\n"
			 "Host: 	foo.com\r\n"
			 "Connection:\n"
			 "	close\r\n"
			 "\n");
}

TEST(http_parser, accept)
{
	FOR_REQ("GET / HTTP/1.1\r\n"
		"Accept:  text/html \r\n"
		"\r\n")
	{
		EXPECT_TRUE(test_bit(TFW_HTTP_B_ACCEPT_HTML, req->flags));
	}

	FOR_REQ("GET / HTTP/1.1\r\n"
		"Accept:  text/html, application/xhtml+xml \r\n"
		"\r\n")
	{
		EXPECT_TRUE(test_bit(TFW_HTTP_B_ACCEPT_HTML, req->flags));
	}

	FOR_REQ("GET / HTTP/1.1\r\n"
		"Accept:  text/html;q=0.8 \r\n"
		"\r\n")
	{
		EXPECT_TRUE(test_bit(TFW_HTTP_B_ACCEPT_HTML, req->flags));
	}

	FOR_REQ("GET / HTTP/1.1\r\n"
		"Accept: text/html,application/xhtml+xml,application/xml;"
		"q=0.9,image/webp,image/apng,*/*;q=0.8\r\n"
		"\r\n")
	{
		EXPECT_TRUE(test_bit(TFW_HTTP_B_ACCEPT_HTML, req->flags));
	}

	FOR_REQ("GET / HTTP/1.1\r\n"
		"Accept:  text/*  \r\n"
		"\r\n")
	{
		EXPECT_FALSE(test_bit(TFW_HTTP_B_ACCEPT_HTML, req->flags));
	}

	FOR_REQ("GET / HTTP/1.1\r\n"
		"Accept:  text/html, */*  \r\n"
		"\r\n")
	{
		EXPECT_TRUE(test_bit(TFW_HTTP_B_ACCEPT_HTML, req->flags));
	}

	FOR_REQ("GET / HTTP/1.1\r\n"
		"Accept:  */*  \r\n"
		"\r\n")
	{
		EXPECT_TRUE(test_bit(TFW_HTTP_B_ACCEPT_HTML, req->flags));
	}
}

TEST(http_parser, empty_host)
{
	FOR_REQ("GET / HTTP/1.1\r\n"
		"Host:\r\n"
		"Connection: close\r\n"
		"\r\n");

	FOR_REQ("GET / HTTP/1.1\n"
		"Host:  \n"
		"\n");
}

TEST(http_parser, chunked)
{
	TfwHttpHdrTbl *ht;
	TfwStr *h_trailer;
	const char *s_trailer = "Trailer-Hdr: some-hdr-var";

	FOR_REQ("POST / HTTP/1.1\r\n"
		"Host:\r\n"
		"Transfer-Encoding: chunked\r\n"
		"\r\n"
		"5;cext=val\r\n"
		"abcde\r\n"
		"a\r\n"
		"f=01234567\r\n"
		"2;a=1\n"
		"89\r\n"
		"0\n"
		"Trailer-Hdr: some-hdr-var\r\n"
		"\r\n")
	{
		ht = req->h_tbl;

		EXPECT_TRUE(req->body.len == 46);

		h_trailer = &ht->tbl[TFW_HTTP_HDR_RAW];
		EXPECT_TRUE(tfw_str_eq_cstr(h_trailer, s_trailer,
					    strlen(s_trailer), 0));
	}

	FOR_RESP("HTTP/1.1 200 OK\r\n"
		 "Transfer-Encoding: chunked\r\n"
		 "\n"
		 "5\r\n"
		 "abcde\r\n"
		 "0;test\n"
		 "Trailer-Hdr: some-hdr-var\r\n"
		 "\r\n")
	{
		ht = resp->h_tbl;

		EXPECT_TRUE(resp->body.len == 17);

		h_trailer = &ht->tbl[TFW_HTTP_HDR_RAW];
		EXPECT_TRUE(tfw_str_eq_cstr(h_trailer, s_trailer,
					    strlen(s_trailer), 0));
	}

	EXPECT_BLOCK_REQ("GET / HTTP/1.1\r\n"
			 "Host:\r\n"
			 "Transfer-Encoding: chunked\r\n"
			 "\r\n"
			 "5;cext=val\r\n"
			 "abcde\r\n"
			 "10\r\n" /* decimal length instead of hex */
			 "f=01234567\r\n"
			 "2;a=1\n"
			 "89\r\n"
			 "0\n"
			 "Trailer-Hdr: some-hdr-var\r\n"
			 "\r\n");

	/* Forbidden headers in trailer: */
	EXPECT_BLOCK_REQ("HTTP/1.1 200 OK\r\n"
			 "Transfer-Encoding: chunked\r\n"
			 "\n"
			 "5\r\n"
			 "abcde\r\n"
			 "0;test\n"
			 "Connection: close\r\n" /* Can't be in trailer. */
			 "\r\n");
}

TEST(http_parser, chunk_size)
{
	EXPECT_BLOCK_REQ("POST / HTTP/1.1\r\n"
			 "Host:\r\n"
			 "Transfer-Encoding: chunked\r\n"
			 "\r\n"
			 "00000000000000007\r\n"
			 "abcdefg\r\n"
			 "0\n"
			 "\r\n");

	EXPECT_BLOCK_REQ("POST / HTTP/1.1\r\n"
			 "Host:\r\n"
			 "Transfer-Encoding: chunked\r\n"
			 "\r\n"
			 "7\r\n"
			 "abcdefg\r\n"
			 "00000000000000000\r\n"
			 "\r\n");

	EXPECT_BLOCK_REQ("POST / HTTP/1.1\r\n"
			 "Host:\r\n"
			 "Transfer-Encoding: chunked\r\n"
			 "\r\n"
			 "8000000000000000\r\n"
			 "abcdefg\r\n"
			 "0\r\n"
			 "\r\n");

	FOR_REQ("POST / HTTP/1.1\r\n"
		"Host:\r\n"
		"Transfer-Encoding: chunked\r\n"
		"\r\n"
		"0000000000000007\r\n"
		"abcdefg\r\n"
		"0\r\n"
		"\r\n");
}

TEST(http_parser, cookie)
{
	FOR_REQ("GET / HTTP/1.1\r\n"
		"Host:\r\n"
		"Cookie: session=42; theme=dark\r\n"
		"\r\n")
	{
		TfwStr *end, *c;
		TfwStr *cookie = &req->h_tbl->tbl[TFW_HTTP_HDR_COOKIE];
		struct {
			unsigned int flags;
			const char *str;
		} kv[] = {
			{ 0, "Cookie: " },
			{ TFW_STR_NAME, "session=" },
			{ TFW_STR_VALUE, "42" },
			{ 0, "; " },
			{ TFW_STR_NAME, "theme=" },
			{ TFW_STR_VALUE, "dark" },
		};
		size_t kv_count = sizeof(kv) / sizeof(kv[0]);
		int kv_idx;

		/*
		 * Even if the entire cookie field is in a continuous chunk,
		 * the parser splits it into multiple chunks of data, for every
		 * key and value of a cookie parameter to start at the beginning
		 * of a chunk.
		 * Other code expects keys and values to always begin at the
		 * left border of a chunk. Verifying it here.
		 */

		EXPECT_TRUE(cookie->nchunks >= kv_count);

		kv_idx = 0;
		c = cookie->chunks;
		end = c + cookie->nchunks;
		while (c < end) {
			TfwStr *part_end = c;
			TfwStr part = {};
			unsigned int part_flags = c->flags;

			/*
			 * Chunks with keys and values are marked with special
			 * flags.
			 */
			while (part_end < end && part_end->flags == part_flags)
				part_end++;

			if (part_end - c > 1) {
				part.chunks = c;
				part.nchunks = part_end - c;
			} else {
				part = *c;
			}

			c = part_end;

			EXPECT_TRUE(kv_idx < kv_count);
			EXPECT_TRUE(tfw_str_eq_cstr(&part, kv[kv_idx].str,
			                            strlen(kv[kv_idx].str), 0));
			EXPECT_EQ(part_flags, kv[kv_idx].flags);
			kv_idx++;
		}
	}

	EXPECT_BLOCK_REQ("GET / HTTP/1.1\r\n"
			 "Host: g.com\r\n"
			 "Cookie: session=42;theme=dark\r\n"
			 "\r\n");

	EXPECT_BLOCK_REQ("GET / HTTP/1.1\r\n"
			 "Host: g.com\r\n"
			 "Cookie: session=42, theme=dark\r\n"
			 "\r\n");

	EXPECT_BLOCK_REQ("GET / HTTP/1.1\r\n"
			 "Host: g.com\r\n"
			 "Cookie: session=42 theme=dark\r\n"
			 "\r\n");

	EXPECT_BLOCK_REQ("GET / HTTP/1.1\r\n"
			 "Host: g.com\r\n"
			 "Cookie: session=42\ttheme=dark\r\n"
			 "\r\n");

	/*
	 * This actually should be blocked due to unclosed DQUOTE.
	 * But cookie values are opaque for us, this is job for application
	 * layer to accurately parse cookie values.
	 */
	FOR_REQ("GET / HTTP/1.1\r\n"
		"Host: g.com\r\n"
		"Cookie: session=\"42; theme=dark\r\n"
		"\r\n");
}

TEST(http_parser, etag)
{
#define RESP_ETAG_START							\
	"HTTP/1.1 200 OK\r\n"						\
	"Date: Mon, 23 May 2005 22:38:34 GMT\r\n"			\
	"Content-Type: text/html; charset=UTF-8\r\n"			\
	"Content-Encoding: UTF-8\r\n"					\
	"Content-Length: 10\r\n"					\
	"Last-Modified: Wed, 08 Jan 2003 23:11:55 GMT\r\n"		\
	"Server: Apache/1.3.3.7 (Unix) (Red-Hat/Linux)\r\n"

#define RESP_ETAG_END							\
	"Accept-Ranges: bytes\r\n"					\
	"Connection: close\r\n"						\
	"\r\n"								\
	"0123456789"

#define ETAG_VALUE	"3f80f-1b6-3e1cb03b"
#define ETAG_H		"ETag:   \""
#define ETAG_TAIL	"\"  \r\n"
#define ETAG		ETAG_H ETAG_VALUE ETAG_TAIL
#define ETAG_H_WEAK	"ETag:   W/\""
#define ETAG_WEAK	ETAG_H_WEAK ETAG_VALUE ETAG_TAIL

	FOR_RESP(RESP_ETAG_START
		 ETAG
		 RESP_ETAG_END)
	{
		TfwStr h_etag, s_etag;
		DEFINE_TFW_STR(exp_etag, ETAG_VALUE "\"");

		tfw_http_msg_srvhdr_val(&resp->h_tbl->tbl[TFW_HTTP_HDR_ETAG],
					TFW_HTTP_HDR_ETAG,
					&h_etag);
		s_etag = tfw_str_next_str_val(&h_etag);
		EXPECT_EQ(tfw_strcmpspn(&s_etag, &exp_etag, '"'), 0);
		if (!TFW_STR_EMPTY(&s_etag)) {
			EXPECT_FALSE((TFW_STR_CHUNK(&s_etag, 0))->flags
				     & TFW_STR_ETAG_WEAK);
		}

		s_etag = tfw_str_next_str_val(&s_etag);
		EXPECT_TRUE(TFW_STR_EMPTY(&s_etag));
	}

	FOR_RESP(RESP_ETAG_START
		 ETAG_WEAK
		 RESP_ETAG_END)
	{
		TfwStr h_etag, s_etag;
		DEFINE_TFW_STR(exp_etag, ETAG_VALUE "\"");

		tfw_http_msg_srvhdr_val(&resp->h_tbl->tbl[TFW_HTTP_HDR_ETAG],
					TFW_HTTP_HDR_ETAG,
					&h_etag);
		s_etag = tfw_str_next_str_val(&h_etag);
		EXPECT_EQ(tfw_strcmpspn(&s_etag, &exp_etag, '"'), 0);
		if (!TFW_STR_EMPTY(&s_etag)) {
			EXPECT_TRUE((TFW_STR_CHUNK(&s_etag, 0))->flags
				    & TFW_STR_ETAG_WEAK);
		}

		s_etag = tfw_str_next_str_val(&s_etag);
		EXPECT_TRUE(TFW_STR_EMPTY(&s_etag));
	}

	FOR_RESP(RESP_ETAG_START
		 "ETag: \"\" \r\n"
		 RESP_ETAG_END)
	{
		TfwStr h_etag, s_etag;
		DEFINE_TFW_STR(exp_etag, "\"");

		tfw_http_msg_srvhdr_val(&resp->h_tbl->tbl[TFW_HTTP_HDR_ETAG],
					TFW_HTTP_HDR_ETAG,
					&h_etag);
		s_etag = tfw_str_next_str_val(&h_etag);
		EXPECT_EQ(tfw_strcmpspn(&s_etag, &exp_etag, '"'), 0);
		if (!TFW_STR_EMPTY(&s_etag)) {
			EXPECT_FALSE((TFW_STR_CHUNK(&s_etag, 0))->flags
				     & TFW_STR_ETAG_WEAK);
		}

		s_etag = tfw_str_next_str_val(&s_etag);
		EXPECT_TRUE(TFW_STR_EMPTY(&s_etag));
	}

	EXPECT_BLOCK_RESP(RESP_ETAG_START
			  "ETag: \"3f80f-1b6-3e1cb03b\"\r\n"
			  "ETag: \"3f80f-1b6-3e1cb03b\"\r\n"
			  RESP_ETAG_END);

	EXPECT_BLOCK_RESP(RESP_ETAG_START
			  "ETag: \"3f80f-1b6-3e1cb03b\r\n"
			  RESP_ETAG_END);

	EXPECT_BLOCK_RESP(RESP_ETAG_START
			  "ETag: 3f80f-1b6-3e1cb03b\"\r\n"
			  RESP_ETAG_END);

	EXPECT_BLOCK_RESP(RESP_ETAG_START
			  "ETag: W/  \"3f80f-1b6-3e1cb03b\"\r\n"
			  RESP_ETAG_END);

	/* Same code is used to parse ETag header and If-None-Match header. */
	EXPECT_BLOCK_RESP(RESP_ETAG_START
			  "ETag: \"3f80f\", \"3e1cb03b\"\r\n"
			  RESP_ETAG_END);

	EXPECT_BLOCK_RESP(RESP_ETAG_START
			  "ETag: *\r\n"
			  RESP_ETAG_END);

#undef RESP_ETAG_START
#undef RESP_ETAG_END
#undef ETAG
#undef ETAG_WEAK
#undef ETAG_H
#undef ETAG_H_WEAK
#undef ETAG_TAIL
#undef ETAG_VALUE
}

TEST(http_parser, if_none_match)
{
#define ETAG_1		"3f80f-1b6-3e1cb03b"
#define ETAG_2		"dhjkshfkjSDFDS"
#define ETAG_3		"3f80f"

	FOR_REQ("GET / HTTP/1.1\r\n"
		"If-None-Match:    \"" ETAG_1 "\"  \r\n"
		"\r\n")
	{
		TfwStr h_inm = req->h_tbl->tbl[TFW_HTTP_HDR_IF_NONE_MATCH];
		TfwStr s_etag;
		DEFINE_TFW_STR(exp_etag, ETAG_1 "\"");

		s_etag = tfw_str_next_str_val(&h_inm);
		EXPECT_EQ(tfw_strcmpspn(&s_etag, &exp_etag, '"'), 0);
		if (!TFW_STR_EMPTY(&s_etag)) {
			EXPECT_FALSE((TFW_STR_CHUNK(&s_etag, 0))->flags
				     & TFW_STR_ETAG_WEAK);
		}

		s_etag = tfw_str_next_str_val(&s_etag);
		EXPECT_TRUE(TFW_STR_EMPTY(&s_etag));

		EXPECT_FALSE(req->cond.flags & TFW_HTTP_COND_ETAG_ANY);
	}

	FOR_REQ("GET / HTTP/1.1\r\n"
		"If-None-Match:    \"\"  \r\n"
		"\r\n")
	{
		TfwStr h_inm = req->h_tbl->tbl[TFW_HTTP_HDR_IF_NONE_MATCH];
		TfwStr s_etag;
		DEFINE_TFW_STR(exp_etag, "\"");

		s_etag = tfw_str_next_str_val(&h_inm);
		EXPECT_EQ(tfw_strcmpspn(&s_etag, &exp_etag, '"'), 0);
		if (!TFW_STR_EMPTY(&s_etag)) {
			EXPECT_FALSE((TFW_STR_CHUNK(&s_etag, 0))->flags
				     & TFW_STR_ETAG_WEAK);
		}

		s_etag = tfw_str_next_str_val(&s_etag);
		EXPECT_TRUE(TFW_STR_EMPTY(&s_etag));

		EXPECT_FALSE(req->cond.flags & TFW_HTTP_COND_ETAG_ANY);
	}

	FOR_REQ("GET / HTTP/1.1\r\n"
		"If-None-Match:    \"" ETAG_1 "\", \"" ETAG_2 "\"  \r\n"
		"\r\n")
	{
		TfwStr h_inm = req->h_tbl->tbl[TFW_HTTP_HDR_IF_NONE_MATCH];
		TfwStr s_etag;
		DEFINE_TFW_STR(exp_etag_1, ETAG_1 "\"");
		DEFINE_TFW_STR(exp_etag_2, ETAG_2 "\"");

		s_etag = tfw_str_next_str_val(&h_inm);
		EXPECT_EQ(tfw_strcmpspn(&s_etag, &exp_etag_1, '"'), 0);
		if (!TFW_STR_EMPTY(&s_etag)) {
			EXPECT_FALSE((TFW_STR_CHUNK(&s_etag, 0))->flags
				     & TFW_STR_ETAG_WEAK);
		}

		s_etag = tfw_str_next_str_val(&s_etag);
		EXPECT_EQ(tfw_strcmpspn(&s_etag, &exp_etag_2, '"'), 0);
		if (!TFW_STR_EMPTY(&s_etag)) {
			EXPECT_FALSE((TFW_STR_CHUNK(&s_etag, 0))->flags
				     & TFW_STR_ETAG_WEAK);
		}

		s_etag = tfw_str_next_str_val(&s_etag);
		EXPECT_TRUE(TFW_STR_EMPTY(&s_etag));

		EXPECT_FALSE(req->cond.flags & TFW_HTTP_COND_ETAG_ANY);
	}

	FOR_REQ("GET / HTTP/1.1\r\n"
		"If-None-Match:    \"" ETAG_1 "\", W/\"" ETAG_2 "\", \"" ETAG_3 "\"  \r\n"
		"\r\n")
	{
		TfwStr h_inm = req->h_tbl->tbl[TFW_HTTP_HDR_IF_NONE_MATCH];
		TfwStr s_etag;
		DEFINE_TFW_STR(exp_etag_1, ETAG_1 "\"");
		DEFINE_TFW_STR(exp_etag_2, ETAG_2 "\"");
		DEFINE_TFW_STR(exp_etag_3, ETAG_3 "\"");

		s_etag = tfw_str_next_str_val(&h_inm);
		EXPECT_EQ(tfw_strcmpspn(&s_etag, &exp_etag_1, '"'), 0);
		if (!TFW_STR_EMPTY(&s_etag)) {
			EXPECT_FALSE((TFW_STR_CHUNK(&s_etag, 0))->flags
				     & TFW_STR_ETAG_WEAK);
		}

		s_etag = tfw_str_next_str_val(&s_etag);
		EXPECT_EQ(tfw_strcmpspn(&s_etag, &exp_etag_2, '"'), 0);
		if (!TFW_STR_EMPTY(&s_etag)) {
			EXPECT_TRUE((TFW_STR_CHUNK(&s_etag, 0))->flags
				    & TFW_STR_ETAG_WEAK);
		}

		s_etag = tfw_str_next_str_val(&s_etag);
		EXPECT_EQ(tfw_strcmpspn(&s_etag, &exp_etag_3, '"'), 0);
		if (!TFW_STR_EMPTY(&s_etag)) {
			EXPECT_FALSE((TFW_STR_CHUNK(&s_etag, 0))->flags
				     & TFW_STR_ETAG_WEAK);
		}

		s_etag = tfw_str_next_str_val(&s_etag);
		EXPECT_TRUE(TFW_STR_EMPTY(&s_etag));

		EXPECT_FALSE(req->cond.flags & TFW_HTTP_COND_ETAG_ANY);
	}

	FOR_REQ("GET / HTTP/1.1\r\n"
		"If-None-Match:   *  \r\n"
		"\r\n")
	{
		EXPECT_TRUE(req->cond.flags & TFW_HTTP_COND_ETAG_ANY);
	}

	/* Empty header */
	EXPECT_BLOCK_REQ("GET / HTTP/1.1\r\n"
			 "If-None-Match: \r\n"
			 "\r\n");
	/* Not quoted value. */
	EXPECT_BLOCK_REQ("GET / HTTP/1.1\r\n"
			 "If-None-Match: " ETAG_1 "\r\n"
			 "\r\n");
	/* No closing quote. */
	EXPECT_BLOCK_REQ("GET / HTTP/1.1\r\n"
			 "If-None-Match: \"" ETAG_1 "\r\n"
			 "\r\n");
	/* No opening quote. */
	EXPECT_BLOCK_REQ("GET / HTTP/1.1\r\n"
			 "If-None-Match: " ETAG_1 "\"\r\n"
			 "\r\n");
	/* Duplicated header. */
	EXPECT_BLOCK_REQ("GET / HTTP/1.1\r\n"
			 "If-None-Match: \"" ETAG_1 "\"\r\n"
			 "If-None-Match: \"" ETAG_1 "\"\r\n"
			 "\r\n");
	/* Incomplete header. */
	EXPECT_BLOCK_REQ("GET / HTTP/1.1\r\n"
			 "If-None-Match: \"" ETAG_1 "\", \r\n"
			 "\r\n");
	/* No delimiter. */
	EXPECT_BLOCK_REQ("GET / HTTP/1.1\r\n"
			 "If-None-Match: \"" ETAG_1 "\" \"" ETAG_2 "\" \r\n"
			 "\r\n");
	/* Etag list + Any etag. */
	EXPECT_BLOCK_REQ("GET / HTTP/1.1\r\n"
			 "If-None-Match: \"" ETAG_1 "\", * \r\n"
			 "\r\n");
	EXPECT_BLOCK_REQ("GET / HTTP/1.1\r\n"
			 "If-None-Match: *, \"" ETAG_1 "\" \r\n"
			 "\r\n");

#undef ETAG_1
#undef ETAG_2
#undef ETAG_3
}

TEST(http_parser, referer)
{
	TfwHttpHdrTbl *ht;
	TfwStr h_referer;

	const char *s_referer1 =
		"http://tempesta-tech.com:8080"
		"/cgi-bin/show.pl?entry=tempesta      ";
	const char *s_referer2 =
		"/cgi-bin/show.pl?entry=tempesta";
	const char *s_referer3 =
		"http://[2001:0db8:11a3:09d7:1f34:8a2e:07a0:765d]"
		":8080/cgi-bin/show.pl?entry=tempesta";

	FOR_REQ("GET /foo HTTP/1.1\r\n"
		"Referer:    http://tempesta-tech.com:8080"
		"/cgi-bin/show.pl?entry=tempesta      \r\n"
		"\r\n")
	{
		ht = req->h_tbl;
		tfw_http_msg_clnthdr_val(&ht->tbl[TFW_HTTP_HDR_REFERER],
					 TFW_HTTP_HDR_REFERER,
					 &h_referer);
		EXPECT_TRUE(tfw_str_eq_cstr(&h_referer, s_referer1,
					    strlen(s_referer1), 0));
	}

	FOR_REQ("GET /foo HTTP/1.1\r\n"
		"Referer:  /cgi-bin/show.pl?entry=tempesta\r\n"
		"\r\n")
	{
		ht = req->h_tbl;
		tfw_http_msg_clnthdr_val(&ht->tbl[TFW_HTTP_HDR_REFERER],
					 TFW_HTTP_HDR_REFERER,
					 &h_referer);
		EXPECT_TRUE(tfw_str_eq_cstr(&h_referer, s_referer2,
					    strlen(s_referer2), 0));
	}

	FOR_REQ("GET /foo HTTP/1.1\r\n"
		"Referer: http://[2001:0db8:11a3:09d7:1f34:8a2e:07a0:765d]:8080"
		"/cgi-bin/show.pl?entry=tempesta\r\n"
		"\r\n")
	{
		ht = req->h_tbl;
		tfw_http_msg_clnthdr_val(&ht->tbl[TFW_HTTP_HDR_REFERER],
					 TFW_HTTP_HDR_REFERER,
					 &h_referer);
		EXPECT_TRUE(tfw_str_eq_cstr(&h_referer, s_referer3,
					    strlen(s_referer3), 0));
	}
}

TEST(http_parser, req_hop_by_hop)
{
	TfwHttpHdrTbl *ht;
	TfwStr *field;
	long id;
#define REQ_HBH_START							\
	"GET /foo HTTP/1.1\r\n"						\
	"User-Agent: Wget/1.13.4 (linux-gnu)\r\n"			\
	"Accept: */*\r\n"						\
	"Host: localhost\r\n"						\
	"X-Custom-Hdr: custom header values\r\n"			\
	"X-Forwarded-For: 127.0.0.1, example.com\r\n"			\
	"Dummy0: 0\r\n"							\
	"Dummy1: 1\r\n"							\
	"Foo: is hop-by-hop header\r\n"					\
	"Dummy2: 2\r\n"							\
	"Dummy3: 3\r\n"							\
	"Keep-Alive: timeout=600, max=65526\r\n"

#define REQ_HBH_END							\
	"Dummy4: 4\r\n"							\
	"Dummy5: 5\r\n"							\
	"Foo: is hop-by-hop header\r\n"					\
	"Dummy6: 6\r\n"							\
	"Content-Length: 0\r\n"						\
	"Content-Type: text/html; charset=iso-8859-1\r\n"		\
	"Dummy7: 7\r\n"							\
	"Dummy8: 8\r\n"							\
	"Buzz: is hop-by-hop header\r\n"				\
	"Dummy9: 9\r\n"							\
	"Cache-Control: max-age=1, no-store, min-fresh=30\r\n"		\
	"Pragma: no-cache, fooo \r\n"					\
	"Cookie: session=42; theme=dark\r\n"				\
	"Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\t \n"	\
	"\r\n"								\

	/* No Hop-by-hop headers */
	FOR_REQ(REQ_HBH_START
		REQ_HBH_END)
	{
		ht = req->h_tbl;
		/* Common (raw) headers: 17 total with 10 dummies. */
		EXPECT_EQ(ht->off, TFW_HTTP_HDR_RAW + 17);

		for(id = 0; id < ht->off; ++id) {
			field = &ht->tbl[id];
			EXPECT_FALSE(field->flags & TFW_STR_HBH_HDR);
		}
	}

	/* Hop-by-hop headers: Connection, Keep-Alive */
	FOR_REQ(REQ_HBH_START
		"Connection: Keep-Alive\r\n"
		REQ_HBH_END)
	{
		ht = req->h_tbl;
		/* Common (raw) headers: 17 total with 10 dummies. */
		EXPECT_EQ(ht->off, TFW_HTTP_HDR_RAW + 17);

		for(id = 0; id < ht->off; ++id) {
			field = &ht->tbl[id];
			switch (id) {
			case TFW_HTTP_HDR_CONNECTION:
			case TFW_HTTP_HDR_KEEP_ALIVE:
				EXPECT_TRUE(field->flags & TFW_STR_HBH_HDR);
				break;
			default:
				EXPECT_FALSE(field->flags & TFW_STR_HBH_HDR);
				break;
			}
		}
	}

	/* Hop-by-hop headers: Connection, Keep-Alive and user headers */
	FOR_REQ(REQ_HBH_START
		"Connection: Foo, Keep-Alive, Bar, Buzz\r\n"
		REQ_HBH_END)
	{
		ht = req->h_tbl;
		/* Common (raw) headers: 17 total with 10 dummies. */
		EXPECT_EQ(ht->off, TFW_HTTP_HDR_RAW + 17);

		for(id = 0; id < ht->off; ++id) {
			field = &ht->tbl[id];
			switch (id) {
			case TFW_HTTP_HDR_CONNECTION:
			case TFW_HTTP_HDR_KEEP_ALIVE:
			case TFW_HTTP_HDR_RAW + 4:
			case TFW_HTTP_HDR_RAW + 12:
				EXPECT_TRUE(field->flags & TFW_STR_HBH_HDR);
				break;
			default:
				EXPECT_FALSE(field->flags & TFW_STR_HBH_HDR);
				break;
			}
		}
	}

	/* Connection header lists end-to-end spec headers */
	EXPECT_BLOCK_REQ(REQ_HBH_START
			 "Connection: Host\r\n"
			 REQ_HBH_END);
	EXPECT_BLOCK_REQ(REQ_HBH_START
			 "Connection: Content-Length\r\n"
			 REQ_HBH_END);
	EXPECT_BLOCK_REQ(REQ_HBH_START
			 "Connection: Content-Type\r\n"
			 REQ_HBH_END);
	EXPECT_BLOCK_REQ(REQ_HBH_START
			 "Connection: Connection\r\n"
			 REQ_HBH_END);
	EXPECT_BLOCK_REQ(REQ_HBH_START
			 "Connection: X-Forwarded-For\r\n"
			 REQ_HBH_END);
	EXPECT_BLOCK_REQ(REQ_HBH_START
			 "Connection: Transfer-Encoding\r\n"
			 REQ_HBH_END);
	EXPECT_BLOCK_REQ(REQ_HBH_START
			 "Connection: User-Agent\r\n"
			 REQ_HBH_END);
	EXPECT_BLOCK_REQ(REQ_HBH_START
			 "Connection: Server\r\n"
			 REQ_HBH_END);
	EXPECT_BLOCK_REQ(REQ_HBH_START
			 "Connection: Cookie\r\n"
			 REQ_HBH_END);

	/* Connection header lists end-to-end raw headers */
	EXPECT_BLOCK_REQ(REQ_HBH_START
			 "Connection: authorization\r\n"
			 REQ_HBH_END);
	EXPECT_BLOCK_REQ(REQ_HBH_START
			 "Connection: cache-control\r\n"
			 REQ_HBH_END);
	EXPECT_BLOCK_REQ(REQ_HBH_START
			 "Connection: pragma\r\n"
			 REQ_HBH_END);

	/* Too lot of connection tokens */
	EXPECT_BLOCK_REQ(REQ_HBH_START
			 "Connection: t1, t2, t3, t4, t5, t6, t7, t8, t9, t10,"
			 "t11, t12, t13, t14, t15, t16, t17\r\n"
			 REQ_HBH_END);

#undef REQ_HBH_START
#undef REQ_HBH_END
}

TEST(http_parser, resp_hop_by_hop)
{
	TfwHttpHdrTbl *ht;
	TfwStr *field;
	long id;
#define RESP_HBH_START							\
	"HTTP/1.1 200 OK\r\n"						\
	"Dummy0: 0\r\n"							\
	"Dummy1: 1\r\n"							\
	"Dummy2: 2\r\n"							\
	"Foo: is hop-by-hop header\r\n"					\
	"Dummy3: 3\r\n"							\
	"Dummy4: 4\r\n"							\
	"Dummy5: 5\r\n"

#define RESP_HBH_END							\
	"Dummy6: 6\r\n"							\
	"Content-Length: 3\r\n"						\
	"Content-Type: text/html; charset=iso-8859-1\r\n"		\
	"Dummy7: 7\r\n"							\
	"Buzz: is hop-by-hop header\r\n"				\
	"Dummy8: 8\r\n"							\
	"Foo: is hop-by-hop header\r\n"					\
	"Cache-Control: max-age=5, private, no-cache, ext=foo\r\n"	\
	"Dummy9: 9\r\n"							\
	"Expires: Tue, 31 Jan 2012 15:02:53 GMT\r\n"			\
	"Keep-Alive: timeout=600, max=65526\r\n"			\
	"Server: Apache/2.4.6 (CentOS) OpenSSL/1.0.1e-fips"		\
		" mod_fcgid/2.3.9\r\n"					\
	"Age: 12  \n"							\
	"Date: Sun, 9 Sep 2001 01:46:40 GMT\t\n"			\
	"\r\n"								\
	"012"

	/* No Hop-by-hop headers */
	FOR_RESP(RESP_HBH_START
		 RESP_HBH_END)
	{
		ht = resp->h_tbl;
		/* Common (raw) headers: 16 total with 10 dummies. */
		EXPECT_EQ(ht->off, TFW_HTTP_HDR_RAW + 16);

		for(id = 0; id < ht->off; ++id) {
			field = &ht->tbl[id];
			switch (id) {
			case TFW_HTTP_HDR_SERVER:
				EXPECT_TRUE(field->flags & TFW_STR_HBH_HDR);
				break;
			default:
				EXPECT_FALSE(field->flags & TFW_STR_HBH_HDR);
				break;
			}
		}
	}

	/* Hop-by-hop headers: Connection, Keep-Alive */
	FOR_RESP(RESP_HBH_START
		 "Connection: Keep-Alive\r\n"
		 RESP_HBH_END)
	{
		ht = resp->h_tbl;
		/* Common (raw) headers: 16 total with 10 dummies. */
		EXPECT_EQ(ht->off, TFW_HTTP_HDR_RAW + 16);

		for(id = 0; id < ht->off; ++id) {
			field = &ht->tbl[id];
			switch (id) {
			case TFW_HTTP_HDR_SERVER:
			case TFW_HTTP_HDR_CONNECTION:
			case TFW_HTTP_HDR_KEEP_ALIVE:
				EXPECT_TRUE(field->flags & TFW_STR_HBH_HDR);
				break;
			default:
				EXPECT_FALSE(field->flags & TFW_STR_HBH_HDR);
				break;
			}
		}
	}

	/* Hop-by-hop headers: Connection, Keep-Alive and user headers */
	FOR_RESP(RESP_HBH_START
		 "Connection: Foo, Keep-Alive, Bar, Buzz\r\n"
		 RESP_HBH_END)
	{
		ht = resp->h_tbl;
		/* Common (raw) headers: 16 total with 10 dummies. */
		EXPECT_EQ(ht->off, TFW_HTTP_HDR_RAW + 16);

		for(id = 0; id < ht->off; ++id) {
			field = &ht->tbl[id];
			switch (id) {
			case TFW_HTTP_HDR_SERVER:
			case TFW_HTTP_HDR_CONNECTION:
			case TFW_HTTP_HDR_KEEP_ALIVE:
			case TFW_HTTP_HDR_RAW + 3:
			case TFW_HTTP_HDR_RAW + 9:
				EXPECT_TRUE(field->flags & TFW_STR_HBH_HDR);
				break;
			default:
				EXPECT_FALSE(field->flags & TFW_STR_HBH_HDR);
				break;
			}
		}
	}

	/* Connection header lists end-to-end spec headers */
	EXPECT_BLOCK_RESP(RESP_HBH_START
			  "Connection: Host\r\n"
			  RESP_HBH_END);
	EXPECT_BLOCK_RESP(RESP_HBH_START
			  "Connection: Content-Length\r\n"
			  RESP_HBH_END);
	EXPECT_BLOCK_RESP(RESP_HBH_START
			  "Connection: Content-Type\r\n"
			  RESP_HBH_END);
	EXPECT_BLOCK_RESP(RESP_HBH_START
			  "Connection: Connection\r\n"
			  RESP_HBH_END);
	EXPECT_BLOCK_RESP(RESP_HBH_START
			  "Connection: X-Forwarded-For\r\n"
			  RESP_HBH_END);
	EXPECT_BLOCK_RESP(RESP_HBH_START
			  "Connection: Transfer-Encoding\r\n"
			  RESP_HBH_END);
	EXPECT_BLOCK_RESP(RESP_HBH_START
			  "Connection: User-Agent\r\n"
			  RESP_HBH_END);
	EXPECT_BLOCK_RESP(RESP_HBH_START
			  "Connection: Server\r\n"
			  RESP_HBH_END);
	EXPECT_BLOCK_RESP(RESP_HBH_START
			  "Connection: Cookie\r\n"
			  RESP_HBH_END);

	/* Connection header lists end-to-end raw headers */
	EXPECT_BLOCK_RESP(RESP_HBH_START
			  "Connection: age\r\n"
			  RESP_HBH_END);
	EXPECT_BLOCK_RESP(RESP_HBH_START
			  "Connection: authorization\r\n"
			  RESP_HBH_END);
	EXPECT_BLOCK_RESP(RESP_HBH_START
			  "Connection: cache-control\r\n"
			  RESP_HBH_END);
	EXPECT_BLOCK_RESP(RESP_HBH_START
			  "Connection: date\r\n"
			  RESP_HBH_END);
	EXPECT_BLOCK_RESP(RESP_HBH_START
			  "Connection: expires\r\n"
			  RESP_HBH_END);
	EXPECT_BLOCK_RESP(RESP_HBH_START
			  "Connection: pragma\r\n"
			  RESP_HBH_END);

	/* Too lot of connection tokens */
	EXPECT_BLOCK_RESP(RESP_HBH_START
			  "Connection: t1, t2, t3, t4, t5, t6, t7, t8, t9, t10,"
			  "t11, t12, t13, t14, t15, t16, t17\r\n"
			  RESP_HBH_END);

#undef RESP_HBH_START
#undef RESP_HBH_END
}

#define N 6	// Count of generations
#define MOVE 1	// Mutations per generation

TEST(http_parser, fuzzer)
{
	size_t len = 10 * 1024 * 1024;
	char *str;
	int field, i, ret;
	TfwFuzzContext context;

	kernel_fpu_end();
	str = vmalloc(len);
	kernel_fpu_begin();

	fuzz_init(&context, false);

	for (field = SPACES; field < N_FIELDS; field++) {
		for (i = 0; i < N; i++) {
			TEST_DBG3("start field: %d request: %d\n", field, i);
			ret = fuzz_gen(&context, str, str + len, field, MOVE,
				       FUZZ_REQ);
			switch (ret) {
			case FUZZ_VALID:
				test_case_parse_prepare(str, 0);
				TRY_PARSE_EXPECT_PASS(str, FUZZ_REQ);
				break;
			case FUZZ_INVALID:
				test_case_parse_prepare(str, 0);
				TRY_PARSE_EXPECT_BLOCK(str, FUZZ_REQ);
				break;
			case FUZZ_END:
			default:
				goto resp;
			}
		}
	}
resp:
	fuzz_init(&context, false);

	for (field = SPACES; field < N_FIELDS; field++) {
		for (i = 0; i < N; i++) {
			TEST_DBG3("start field: %d response: %d\n", field, i);
			ret = fuzz_gen(&context, str, str + len, field, MOVE,
				       FUZZ_RESP);
			switch (ret) {
			case FUZZ_VALID:
				test_case_parse_prepare(str, 0);
				TRY_PARSE_EXPECT_PASS(str, FUZZ_RESP);
				break;
			case FUZZ_INVALID:
				test_case_parse_prepare(str, 0);
				TRY_PARSE_EXPECT_BLOCK(str, FUZZ_RESP);
				break;
			case FUZZ_END:
			default:
				goto end;
			}
		}
	}
end:
	kernel_fpu_end();
	vfree(str);
	kernel_fpu_begin();
}

TEST(http_parser, content_type_line_parser)
{
#define HEAD "POST / HTTP/1.1\r\nHost: localhost.localdomain\r\nContent-Type: "
#define TAIL "\nContent-Length: 0\r\nKeep-Alive: timeout=98765\r\n\r\n"

#define CT01 "multIPart/forM-data  ;    bouNDary=1234567890 ; otherparam=otherval  "

	FOR_REQ(HEAD CT01 TAIL) {
		EXPECT_TRUE(test_bit(TFW_HTTP_B_CT_MULTIPART, req->flags));
		EXPECT_TRUE(test_bit(TFW_HTTP_B_CT_MULTIPART_HAS_BOUNDARY,
				     req->flags));
		EXPECT_TFWSTR_EQ(&req->multipart_boundary_raw, "1234567890");
		EXPECT_TFWSTR_EQ(&req->multipart_boundary, "1234567890");
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "Content-Type: " CT01);
	}

	FOR_REQ(HEAD "multipart/form-data; boundary=\"1234\\56\\\"7890\"" TAIL) {
		EXPECT_TRUE(test_bit(TFW_HTTP_B_CT_MULTIPART, req->flags));
		EXPECT_TRUE(test_bit(TFW_HTTP_B_CT_MULTIPART_HAS_BOUNDARY,
				     req->flags));
		EXPECT_TFWSTR_EQ(&req->multipart_boundary_raw,
		                 "\"1234\\56\\\"7890\"");
		EXPECT_TFWSTR_EQ(&req->multipart_boundary, "123456\"7890");
	}

	FOR_REQ(HEAD "multipart/form-data" TAIL) {
		EXPECT_TRUE(test_bit(TFW_HTTP_B_CT_MULTIPART, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART_HAS_BOUNDARY,
				      req->flags));
	}

	FOR_REQ(HEAD "multipart/form-data " TAIL) {
		EXPECT_TRUE(test_bit(TFW_HTTP_B_CT_MULTIPART, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART_HAS_BOUNDARY,
				      req->flags));
	}

	FOR_REQ(HEAD "multipart/form-data \t" TAIL) {
		EXPECT_TRUE(test_bit(TFW_HTTP_B_CT_MULTIPART, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART_HAS_BOUNDARY,
				      req->flags));
	}

	FOR_REQ(HEAD "multipart/form-data1" TAIL) {
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART_HAS_BOUNDARY,
				      req->flags));
	}

	FOR_REQ(HEAD "multipart/form-data1; param=value" TAIL) {
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART_HAS_BOUNDARY,
				      req->flags));
	}

	FOR_REQ(HEAD "multihello/world" TAIL) {
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART_HAS_BOUNDARY,
				      req->flags));
	}

	FOR_REQ(HEAD "multihello/world; param=value" TAIL) {
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART_HAS_BOUNDARY,
				      req->flags));
	}

	FOR_REQ(HEAD "multipart/form-dat" TAIL) {
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART_HAS_BOUNDARY,
				      req->flags));
	}

	FOR_REQ(HEAD "multipart/form-other; param=value" TAIL) {
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART_HAS_BOUNDARY,
				      req->flags));
	}

	FOR_REQ(HEAD "multipart/form-data; xboundary=1234567890" TAIL) {
		EXPECT_TRUE(test_bit(TFW_HTTP_B_CT_MULTIPART, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART_HAS_BOUNDARY,
				      req->flags));
	}

	FOR_REQ(HEAD "application/octet-stream" TAIL) {
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART_HAS_BOUNDARY,
				      req->flags));
	}

	/* Multipart requests with multiple boundaries are clearly malicious. */
	EXPECT_BLOCK_REQ(HEAD"multipart/form-data; boundary=1; boundary=2"TAIL);

	/* Comma is not a valid separator here. */
	EXPECT_BLOCK_REQ(HEAD "multipart/form-data, boundary=123" TAIL);

	/* Unfinished quoted parameter value */
	EXPECT_BLOCK_REQ(HEAD "multipart/form-data; boundary=\"123" TAIL);

	/* Spaces where they do not belong */
	EXPECT_BLOCK_REQ(HEAD "multipart/form-data; boundary =123" TAIL);
	EXPECT_BLOCK_REQ(HEAD "multipart/form-data; boundary= 123" TAIL);
	EXPECT_BLOCK_REQ(HEAD "multipart/form-data; boundary=12 3" TAIL);
	EXPECT_BLOCK_REQ(HEAD "multipart/form-data; boun dary=123" TAIL);

	/*
	 * Other media types are not restricted in terms of boundary parameter
	 * quantities.
	 */
	FOR_REQ(HEAD "text/plain; boundary=1; boundary=2" TAIL);
	FOR_REQ(HEAD "text/plain; boundary=1; boundary=2; boundary=3" TAIL);
	FOR_REQ(HEAD "textqwe/plain; boundary=1; other=3" TAIL);

	/* Parameter should be in format name=value. */
	EXPECT_BLOCK_REQ(HEAD "text/plain; name" TAIL);
	EXPECT_BLOCK_REQ(HEAD "text/plain; name " TAIL);
	EXPECT_BLOCK_REQ(HEAD "text/plain; name\t " TAIL);

	/* Unfinished quoted parameter value */
	EXPECT_BLOCK_REQ(HEAD "text/plain; name=\"unfinished" TAIL);

	/* Other parameter quoted values. */
	FOR_REQ(HEAD "text/plain; name=\"value\"" TAIL);
	FOR_REQ(HEAD "text/plain; name=\"value\" " TAIL);
	FOR_REQ(HEAD "text/plain; name=\"value\";" TAIL);
	FOR_REQ(HEAD "text/plain; name=\"value\"; " TAIL);

	FOR_REQ(HEAD "text/plain; name=\"val\\\"ue\"" TAIL);
	FOR_REQ(HEAD "text/plain; name=\"val\\\"ue\" " TAIL);

	/* Line ended at '\\'. */
	EXPECT_BLOCK_REQ(HEAD "text/plain; name=\"val\\" TAIL);

#undef HEAD
#undef TAIL
}

TEST_SUITE(http_parser)
{
	int r;

	if ((r = set_sample_req(SAMPLE_REQ_STR))) {
		TEST_FAIL("can't parse sample request (code=%d):\n%s",
			  r, SAMPLE_REQ_STR);
		return;
	}

	TEST_RUN(http_parser, leading_eol);
	TEST_RUN(http_parser, parses_req_method);
	TEST_RUN(http_parser, parses_req_uri);
	TEST_RUN(http_parser, mangled_messages);
	TEST_RUN(http_parser, alphabets);
	TEST_RUN(http_parser, fills_hdr_tbl_for_req);
	TEST_RUN(http_parser, fills_hdr_tbl_for_resp);
	TEST_RUN(http_parser, cache_control_flags);
	TEST_RUN(http_parser, suspicious_x_forwarded_for);
	TEST_RUN(http_parser, parses_connection_value);
	TEST_RUN(http_parser, content_length);
	TEST_RUN(http_parser, eol_crlf);
	TEST_RUN(http_parser, crlf_trailer);
	TEST_RUN(http_parser, ows);
	TEST_RUN(http_parser, folding);
	TEST_RUN(http_parser, accept);
	TEST_RUN(http_parser, empty_host);
	TEST_RUN(http_parser, chunked);
	TEST_RUN(http_parser, chunk_size);
	TEST_RUN(http_parser, cookie);
	TEST_RUN(http_parser, etag);
	TEST_RUN(http_parser, if_none_match);
	TEST_RUN(http_parser, referer);
	TEST_RUN(http_parser, req_hop_by_hop);
	TEST_RUN(http_parser, resp_hop_by_hop);
	TEST_RUN(http_parser, fuzzer);
	TEST_RUN(http_parser, content_type_line_parser);

	/*
	 * Testing for correctness of redirection mark parsing (in
	 * extended enforced mode of 'http_sessions' module).
	 */
	test_helper_sticky_start(RMARK_NAME, 1);

	TEST_RUN(http_parser, parses_enforce_ext_req);
	TEST_RUN(http_parser, parses_enforce_ext_req_rmark);

	test_helper_sticky_stop();
}
