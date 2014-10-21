/**
 *		Tempesta FW
 *
 * Interface for requests scheduling and connections management to
 * back-end servers.
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
#ifndef __TFW_SCHED_H__
#define __TFW_SCHED_H__

#include "tempesta.h"
#include "msg.h"
#include "server.h"

/*
 * TODO In case of forward proxy manage connections to 'backend' servers
 * we can have too many 'backend' servers, so we need to prune low-active
 * connections from the connection pool.
 * Should we manage connections separate from requests management and move
 * the functionality to different module type?
 */


/**
 * The maximum number of servers that may be added to any scheduler.
 *
 * Schedulers are allowed to reject tfw_sched_add_srv() calls if the count of
 * servers reaches this number.
 */
#define TFW_SCHED_MAX_SERVERS 64

typedef struct {
	const char *name;

	TfwServer *	(*get_srv)(TfwMsg *msg);
	int		(*add_srv)(TfwServer *srv);
	int		(*del_srv)(TfwServer *srv);
} TfwScheduler;

TfwServer *tfw_sched_get_srv(TfwMsg *msg);
int tfw_sched_add_srv(TfwServer *srv);
int tfw_sched_del_srv(TfwServer *srv);


int tfw_sched_register(TfwScheduler *mod);
void tfw_sched_unregister(void);


#endif /* __TFW_SCHED_H__ */
