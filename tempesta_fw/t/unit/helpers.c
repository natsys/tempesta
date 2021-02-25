/**
 *		Tempesta FW
 *
 * This file contains utils that help to test certain Tempesta FW modules.
 * They implement things like stubbing, mocking, generating data for testing.
 *
 * Actually things contained in this file are wrong a bit.
 * Good code tends to have most of the logic in pure stateless loosely-coupled
 * well-isolated functions that may be tested without faking any state.
 * But this is not reachable most of the time, especially when performance is
 * a goal and you have to build the architecture keeping it in mind.
 * So over time, we expect to see a decent amount of helpers here.
 *
 * These things are specific to Tempesta FW, so they are located here,
 * and generic testing functions/macros are located in test.c/test.h
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2020 Tempesta Technologies, Inc.
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
#include "http_msg.h"

static TfwConn conn_req, conn_resp;

TfwHttpReq *
test_req_alloc(size_t data_len)
{
	int ret;
	TfwMsgIter it;
	TfwHttpMsg *hmreq;

	/* Actually there were more code here, mostly it was copy-paste from
	 * tfw_http_msg_alloc(). It is removed because we need to test how it
	 * initializes the message and we would not like to test the copy-paste.
	 */
	hmreq = __tfw_http_msg_alloc(Conn_HttpClnt, true);
	BUG_ON(!hmreq);

	ret = tfw_http_msg_setup(hmreq, &it, data_len, 0);
	BUG_ON(ret);

	memset(&conn_req, 0, sizeof(TfwConn));
	tfw_connection_init(&conn_req);
	conn_req.proto.type = Conn_HttpClnt;
	hmreq->conn = &conn_req;
	hmreq->stream = &conn_req.stream;
	tfw_http_init_parser_req((TfwHttpReq *)hmreq);

	return (TfwHttpReq *)hmreq;
}

void
test_req_free(TfwHttpReq *req)
{
	/* In tests we are stricter: we don't allow to free a NULL pointer
	 * to be sure exactly what we are freeing and to catch bugs early. */
	BUG_ON(!req);

	tfw_http_msg_free((TfwHttpMsg *)req);
}

TfwHttpResp *
test_resp_alloc(size_t data_len)
{
	int ret;
	TfwMsgIter it;
	TfwHttpMsg *hmresp;

	hmresp = __tfw_http_msg_alloc(Conn_HttpSrv, true);
	BUG_ON(!hmresp);

	ret = tfw_http_msg_setup(hmresp, &it, data_len, 0);
	BUG_ON(ret);

	memset(&conn_resp, 0, sizeof(TfwConn));
	conn_resp.proto.type = Conn_HttpSrv;
	tfw_connection_init(&conn_req);
	conn_resp.stream.parser.pool = __tfw_pool_new(0);
	BUG_ON(!conn_resp.stream.parser.pool);
	hmresp->conn = &conn_resp;
	hmresp->stream = &conn_resp.stream;
	tfw_http_init_parser_resp((TfwHttpResp *)hmresp);

	return (TfwHttpResp *)hmresp;
}

void
test_resp_free(TfwHttpResp *resp)
{
	BUG_ON(!resp);
	tfw_http_msg_free((TfwHttpMsg *)resp);
}

/*
 * Testing mocks to start/stop minimum functionality, necessary for the parser
 * environment.
 */
struct {} *tfw_perfstat;

void
tfw_client_set_expires_time(unsigned int expires_time)
{
}

void
tfw_client_put(TfwClient *cli)
{
}

int
tfw_cli_conn_send(TfwCliConn *cli_conn, TfwMsg *msg)
{
	return 0;
}

int
tfw_gfsm_dispatch(TfwGState *st, void *obj, TfwFsmData *data)
{
	return 0;
}

void
tfw_gfsm_state_init(TfwGState *st, void *obj, int st0)
{
}

TfwCfgSpec tfw_http_sess_specs[0];

int
tfw_http_sess_cfgop_finish(TfwVhost *vhost, TfwCfgSpec *cs)
{
	return 0;
}

int
tfw_http_sess_cfgop_begin(TfwVhost *vhost, TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return 0;
}

void
tfw_http_sess_cfgop_cleanup(TfwCfgSpec *cs)
{
}

void
tfw_http_sess_cookie_clean(TfwVhost *vhost)
{
}

int
tfw_http_sess_cfg_finish(TfwVhost *vhost)
{
	return 0;
}

void tfw_http_sess_cfgstart(void)
{
}

int tfw_http_sess_cfgend(void)
{
	return 0;
}

int
tfw_cache_process(TfwHttpMsg *msg, tfw_http_cache_cb_t action)
{
	return 0;
}

void
tfw_tls_cfg_configured(bool global)
{
}

void
tfw_tls_match_any_sni_to_dflt(bool match)
{
}
