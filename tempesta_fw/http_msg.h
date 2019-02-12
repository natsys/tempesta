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
#ifndef __TFW_HTTP_MSG_H__
#define __TFW_HTTP_MSG_H__

#include "http.h"

#define S_F_SET_COOKIE		"Set-Cookie: "
#define S_CRLF			"\r\n"
#define S_DLM			": "

#define SLEN(s)			(sizeof(s) - 1)

TfwStr *tfw_http_msg_make_hdr(TfwPool *pool, const char *name, const char *val);
unsigned int tfw_http_msg_resp_spec_hid(const TfwStr *hdr);
unsigned int tfw_http_msg_req_spec_hid(const TfwStr *hdr);

const void *__tfw_http_msg_find_hdr(const TfwStr *hdr, const void *array,
				    size_t n, size_t member_sz);
#define tfw_http_msg_find_hdr(hdr, array)				\
	(TfwStr *)__tfw_http_msg_find_hdr(hdr, array,			\
					  ARRAY_SIZE(array), sizeof(TfwStr))

static inline void
__tfw_http_msg_set_str_data(TfwStr *str, void *data, struct sk_buff *skb)
{
	str->data = data;
	str->skb = skb;
}
#define tfw_http_msg_set_str_data(hm, str, data)			\
	__tfw_http_msg_set_str_data(str, data,				\
				    ss_skb_peek_tail(&hm->msg.skb_head))

void __http_msg_hdr_val(TfwStr *hdr, unsigned id, TfwStr *val, bool client);

static inline void
tfw_http_msg_clnthdr_val(TfwStr *hdr, unsigned id, TfwStr *val)
{
	__http_msg_hdr_val(hdr, id, val, true);
}

static inline void
tfw_http_msg_srvhdr_val(TfwStr *hdr, unsigned id, TfwStr *val)
{
	__http_msg_hdr_val(hdr, id, val, false);
}

void tfw_http_msg_pair(TfwHttpResp *resp, TfwHttpReq *req);
TfwHttpMsg *__tfw_http_msg_alloc(int type, bool full);

static inline TfwHttpReq *
tfw_http_msg_alloc_req_light(void)
{
	return (TfwHttpReq *)__tfw_http_msg_alloc(Conn_Clnt, false);
}

static inline TfwHttpResp *
__tfw_http_msg_alloc_resp(TfwHttpReq *req, bool full)
{
	TfwHttpResp *resp = (TfwHttpResp *)__tfw_http_msg_alloc(Conn_Srv, full);
	if (resp)
		tfw_http_msg_pair(resp, req);

	return resp;
}

static inline TfwHttpResp *
tfw_http_msg_alloc_resp(TfwHttpReq *req)
{
	return __tfw_http_msg_alloc_resp(req, true);
}

static inline TfwHttpResp *
tfw_http_msg_alloc_resp_light(TfwHttpReq *req)
{
	return __tfw_http_msg_alloc_resp(req, false);
}

TfwHttpMsg *tfw_http_msg_alloc_stream_part(TfwHttpMsg *hm_head);
void tfw_http_msg_collapse_streamed(TfwHttpStream *stream);

int __tfw_http_msg_add_str_data(TfwHttpMsg *hm, TfwStr *str, void *data,
				size_t len, struct sk_buff *skb);
#define tfw_http_msg_add_str_data(hm, str, data, len)			\
	__tfw_http_msg_add_str_data(hm, str, data, len,			\
				    ss_skb_peek_tail(&hm->msg.skb_head))

unsigned int tfw_http_msg_hdr_lookup(TfwHttpMsg *hm, const TfwStr *hdr);
int tfw_http_msg_hdr_add(TfwHttpMsg *hm, const TfwStr *hdr);
int tfw_http_msg_hdr_xfrm_str(TfwHttpMsg *hm, const TfwStr *hdr,
			      unsigned int hid, bool append);
int tfw_http_msg_hdr_xfrm(TfwHttpMsg *hm, char *name, size_t n_len,
			  char *val, size_t v_len, unsigned int hid, bool append);

#define TFW_HTTP_MSG_HDR_XFRM(hm, name, val, hid, append)		\
	tfw_http_msg_hdr_xfrm(hm, name, sizeof(name) - 1, val,		\
			      sizeof(val) - 1, hid, append)
#define TFW_HTTP_MSG_HDR_DEL(hm, name, hid)				\
	tfw_http_msg_hdr_xfrm(hm, name, sizeof(name) - 1, NULL, 0, hid, 0)

int tfw_http_msg_del_str(TfwHttpMsg *hm, TfwStr *str);
int tfw_http_msg_del_hbh_hdrs(TfwHttpMsg *hm);

int tfw_http_msg_setup(TfwHttpMsg *hm, TfwMsgIter *it, size_t data_len);
int tfw_http_msg_add_data(TfwMsgIter *it, TfwHttpMsg *hm, TfwStr *field,
			  const TfwStr *data);

void tfw_http_msg_hdr_open(TfwHttpMsg *hm, unsigned char *hdr_start);
int tfw_http_msg_hdr_close(TfwHttpMsg *hm, unsigned int id);
int tfw_http_msg_grow_hdr_tbl(TfwHttpMsg *hm);
void tfw_http_msg_free(TfwHttpMsg *m);

#endif /* __TFW_HTTP_MSG_H__ */
