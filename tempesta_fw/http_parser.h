/**
 *		Tempesta FW
 *
 * Copyright (C) 2018 Tempesta Technologies, Inc.
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
#ifndef __TFW_HTTP_PARSER_H__
#define __TFW_HTTP_PARSER_H__

#include "str.h"
#include "http_types.h"

typedef struct {
	unsigned int	size;	/* number of elements in the table */
	unsigned int	off;
	TfwStr		tbl[0];
} TfwHttpHdrTbl;

#define __HHTBL_SZ(o)			(TFW_HTTP_HDR_NUM * (o))
#define TFW_HHTBL_EXACTSZ(s)		(sizeof(TfwHttpHdrTbl)		\
					 + sizeof(TfwStr) * (s))
#define TFW_HHTBL_SZ(o)			TFW_HHTBL_EXACTSZ(__HHTBL_SZ(o))

/** Maximum of hop-by-hop tokens listed in Connection header. */
#define TFW_HBH_TOKENS_MAX		16

/**
 * Non-cacheable hop-by-hop headers in terms of RFC 7230.
 *
 * We don't store the headers in cache and create them from scratch if needed.
 * Adding a header is faster then modify it, so this speeds up headers
 * adjusting as well as saves cache storage.
 *
 * Headers unconditionally treated as hop-by-hop must be listed in
 * tfw_http_init_parser_req()/tfw_http_init_parser_resp() functions and must be
 * members of Special headers.
 * group.
 *
 * @spec	- bit array for special headers. Hop-by-hop special header is
 *		  stored as (0x1 << tfw_http_hdr_t[hid]);
 * @raw		- table of raw headers names, parsed form connection field;
 * @off		- offset of last added raw header name;
 */
typedef struct {
	unsigned int	spec;
	unsigned int	off;
	TfwStr		raw[TFW_HBH_TOKENS_MAX];
} TfwHttpHbhHdrs;

/**
 * We use goto/switch-driven automaton, so compiler typically generates binary
 * search code over jump labels, so it gives log(N) lookup complexity where
 * N is number of states. However, DFA for full HTTP processing can be quite
 * large and log(N) becomes expensive and hard to code.
 *
 * So we use states space splitting to avoid states explosion.
 * @_i_st is used to save current state and go to interior sub-automaton
 * (e.g. process OWS using @state while current state is saved in @_i_st
 * or using @_i_st parse value of a header described.
 *
 * @_cnt	- currently the count of hex digits in a body chunk size;
 * @to_go	- remaining number of bytes to process in the data chunk;
 *		  (limited by single packet size and never exceeds 64KB)
 * @state	- current parser state;
 * @_i_st	- helping (interior) state;
 * @to_read	- remaining number of bytes to read;
 * @_hdr_tag	- stores header id which must be closed on generic EoL handling
 *		  (see RGEN_EOL());
 * @_acc	- integer accumulator for parsing chunked integers;
 * @_tmp_chunk	- currently parsed (sub)string, possibly chunked;
 * @hdr		- currently parsed header.
 * @hbh_parser	- list of special and raw headers names to be treated as
 *		  hop-by-hop
 * @_date	- currently parsed http date value;
 */
typedef struct {
	unsigned short	to_go;
	unsigned short	_cnt;
	unsigned int	_hdr_tag;
	int		state;
	int		_i_st;
	long		to_read;
	unsigned long	_acc;
	time_t		_date;
	TfwStr		_tmp_chunk;
	TfwStr		hdr;
	TfwHttpHbhHdrs	hbh_parser;
} TfwHttpParser;

void tfw_http_init_parser_req(TfwHttpReq *req);
void tfw_http_init_parser_resp(TfwHttpResp *resp);

int tfw_http_parse_req(void *req_data, unsigned char *data, size_t len,
		       unsigned int *parsed);
int tfw_http_parse_resp(void *resp_data, unsigned char *data, size_t len,
			unsigned int *parsed);
bool tfw_http_parse_terminate(TfwHttpMsg *hm);
int tfw_http_parser_msg_may_stream(TfwHttpMsg *hm);
#endif /* __TFW_HTTP_PARSER_H__ */
