/**
 *		Tempesta FW
 *
 * Copyright (C) 2015 Tempesta Technologies, Inc.
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
#ifndef __PEER_H__
#define __PEER_H__

#include <linux/list.h>
#include <linux/spinlock.h>

#include "addr.h"

/**
 * @conn_list		- connections list associated with the peer;
 * @conn_lock		- protects @conn_list;
 */
#define TFW_PEER_COMMON							\
	struct list_head	conn_list;				\
	rwlock_t		conn_lock;				\
	TfwAddr			addr;

typedef struct {
	TFW_PEER_COMMON;
} TfwPeer;

static inline void
tfw_peer_init(TfwPeer *p, const TfwAddr *addr)
{
	INIT_LIST_HEAD(&p->conn_list);
	rwlock_init(&p->conn_lock);

	memcpy(&p->addr, addr, sizeof(p->addr));
}

static inline void
tfw_peer_add_conn(TfwPeer *p, struct list_head *conn_list)
{
	write_lock(&p->conn_lock);

	list_add(conn_list, &p->conn_list);

	write_unlock(&p->conn_lock);
}

static inline void
tfw_peer_del_conn(TfwPeer *p, struct list_head *conn_list)
{
	write_lock(&p->conn_lock);

	list_del_init(conn_list);

	write_unlock(&p->conn_lock);
}

#endif /* __PEER_H__ */
