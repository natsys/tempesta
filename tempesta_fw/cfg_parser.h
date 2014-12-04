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
#ifndef __TFW_CFG_PARSER_H__
#define __TFW_CFG_PARSER_H__

#include <linux/types.h>

#include "addr.h"
#include "cfg_node.h"

int tfw_cfg_parse_int(const char *str, int *out_num);
int tfw_cfg_parse_bool(const char *str, bool *out_bool);
int tfw_cfg_parse_addr(const char *str, TfwAddr *out_addr);

TfwCfgNode *tfw_cfg_parse(const char *cfg_text);
TfwCfgNode *tfw_cfg_parse_single_node(const char *cfg_text);

#endif /* __TFW_CFG_PARSER_H__ */
