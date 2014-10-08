/**
 *		Tempesta FW
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
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

#include "test.h"
#include "http_match.h"
#include "http_msg.h"

TfwHttpMatchList *test_mlst;
TfwHttpReq *test_req;


static void
http_match_suite_setup(void)
{
	test_mlst = tfw_http_match_list_alloc();
	BUG_ON(!test_mlst);

	test_req = (TfwHttpReq *)tfw_http_msg_alloc(Conn_Clnt);
	BUG_ON(!test_req);
}

static void
http_match_suite_teardown(void)
{
	tfw_http_msg_free((TfwHttpMsg *)test_req);
	test_req = NULL;

	tfw_http_match_list_free(test_mlst);
	test_mlst = NULL;
}


typedef struct {
	int test_id;
	TfwHttpMatchRule rule;
} MatchEntry;

static void
test_mlst_add(int test_id, tfw_http_match_fld_t req_field,
              tfw_http_match_op_t op, const char *str_arg)
{
	MatchEntry *e;
	size_t len = strlen(str_arg);

	e = tfw_http_match_entry_new(test_mlst, MatchEntry, rule, len);
	e->test_id = test_id;
	e->rule.field = req_field;
	e->rule.op = op;
	e->rule.arg.len = len;
	memcpy(e->rule.arg.str, str_arg, len);
}

int
test_mlst_match(void)
{
	MatchEntry *e;

	e = tfw_http_match_req_entry(test_req, test_mlst, MatchEntry, rule);
	if (e)
		return e->test_id;

	return -1;
}

static void
set_tfw_str(TfwStr *str, const char *cstr)
{
	str->ptr = (void *)cstr;
	str->len = strlen(cstr);
}


TEST(tfw_http_match_req, returns_first_matching_rule)
{
	const TfwHttpMatchRule *match;
	TfwHttpMatchRule *r1, *r2, *r3;

	r1 = tfw_http_match_rule_new(test_mlst, sizeof(r1->arg.method));
	r2 = tfw_http_match_rule_new(test_mlst, sizeof(r2->arg.method));
	r3 = tfw_http_match_rule_new(test_mlst, sizeof(r3->arg.method));

	r1->field = r2->field = r3->field = TFW_HTTP_MATCH_F_METHOD;
	r1->op = r2->op = r3->op = TFW_HTTP_MATCH_O_EQ;
	r1->arg.method = TFW_HTTP_METH_POST;
	r2->arg.method = TFW_HTTP_METH_GET;
	r3->arg.method = TFW_HTTP_METH_GET;

	test_req->method = TFW_HTTP_METH_GET;

	match = tfw_http_match_req(test_req, test_mlst);

	EXPECT_EQ(r2, match);
}

TEST(http_match, uri_prefix)
{
	int match_id;

	test_mlst_add(1, TFW_HTTP_MATCH_F_URI, TFW_HTTP_MATCH_O_PREFIX,
	              "/foo/bar/baz");
	test_mlst_add(2, TFW_HTTP_MATCH_F_URI, TFW_HTTP_MATCH_O_PREFIX,
	              "/foo/ba");
	test_mlst_add(3, TFW_HTTP_MATCH_F_URI, TFW_HTTP_MATCH_O_PREFIX,
	              "/");

	set_tfw_str(&test_req->uri, "/foo/bar/baz.html");
	match_id = test_mlst_match();
	EXPECT_EQ(1, match_id);

	set_tfw_str(&test_req->uri, "/FOO/BAR/");
	match_id = test_mlst_match();
	EXPECT_EQ(2, match_id);

	set_tfw_str(&test_req->uri, "/baz");
	match_id = test_mlst_match();
	EXPECT_EQ(3, match_id);

	set_tfw_str(&test_req->uri, "../foo");
	match_id = test_mlst_match();
	EXPECT_EQ(-1, match_id);
}

TEST(http_match, host_eq)
{
	int match_id;

	test_mlst_add(1, TFW_HTTP_MATCH_F_HOST, TFW_HTTP_MATCH_O_EQ,
	              "www.natsys-lab.com");
	test_mlst_add(2, TFW_HTTP_MATCH_F_HOST, TFW_HTTP_MATCH_O_EQ,
	              "natsys-lab");
	test_mlst_add(3, TFW_HTTP_MATCH_F_HOST, TFW_HTTP_MATCH_O_EQ,
	              "NATSYS-LAB.COM");

	set_tfw_str(&test_req->host, "natsys-lab.com");
	match_id = test_mlst_match();
	EXPECT_EQ(3, match_id);
}

TEST(http_match, headers_eq)
{
	int match_id;

	test_mlst_add(1, TFW_HTTP_MATCH_F_HEADERS, TFW_HTTP_MATCH_O_EQ,
	             "User-Agent: U880D/4.0 (CP/M; 8-bit)");
	test_mlst_add(2, TFW_HTTP_MATCH_F_HEADERS, TFW_HTTP_MATCH_O_EQ,
	             "Connection: close");
	test_mlst_add(3, TFW_HTTP_MATCH_F_HEADERS, TFW_HTTP_MATCH_O_EQ,
	             "Connection: Keep-Alive");

	set_tfw_str(&test_req->h_tbl->tbl[TFW_HTTP_HDR_CONNECTION].field,
	            "Connection: Keep-Alive");
	match_id = test_mlst_match();
	EXPECT_EQ(3, match_id);

	set_tfw_str(&test_req->h_tbl->tbl[TFW_HTTP_HDR_CONNECTION].field,
	            "Connection: cLoSe");
	match_id = test_mlst_match();
	EXPECT_EQ(2, match_id);
}

TEST_SUITE(http_match)
{
	TEST_SETUP(http_match_suite_setup);
	TEST_TEARDOWN(http_match_suite_teardown);

	TEST_RUN(tfw_http_match_req, returns_first_matching_rule);
	TEST_RUN(http_match, uri_prefix);
	TEST_RUN(http_match, host_eq);
	TEST_RUN(http_match, headers_eq);
}
