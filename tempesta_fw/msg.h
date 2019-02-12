/**
 *		Tempesta FW
 *
 * Generic protocol message.
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
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#ifndef __TFW_MSG_H__
#define __TFW_MSG_H__

#include <linux/skbuff.h>

#include "sync_socket.h"

/**
 * @seq_list	- member in the ordered queue of messages;
 * @ss_flags	- message processing flags;
 * @skb_head	- head of the list of sk_buff that belong to the message;
 * @len		- original (received) message length;
 *
 * TODO: Currently seq_list is used only in requests. Responses are not
 * put in any queues, they are simply attached to requests as req->resp.
 * However, a queue for responses may also be needed to mitigate sending
 * of responses and improve the distribution of load in Tempesta. Please
 * refer to issues #391 and #488.
 * After these issues are resolved, it may well be that seq_list is more
 * suitable to stay in TfwHttpReq{} rather than here in TfwMsg{}.
 */
typedef struct {
	struct list_head	seq_list;
	struct sk_buff		*skb_head;
	int			ss_flags;
	size_t			len;
} TfwMsg;

/**
 * Iterator for @skb fragments.
 *
 * @frag	- current fragment index or @skb->head if -1;
 * @skb		- current skb to process;
 * @skb_head	- head of the skb list.
 */
typedef struct {
	int		frag;
	struct sk_buff	*skb;
	struct sk_buff	*skb_head;
} TfwMsgIter;

int tfw_msg_write(TfwMsgIter *it, const TfwStr *data);
int tfw_msg_iter_setup(TfwMsgIter *it, struct sk_buff **skb_head,
		       size_t data_len);

#endif /* __TFW_MSG_H__ */
