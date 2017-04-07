/**
 *		Tempesta FW
 *
 * Requst schedulers interface.
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2017 Tempesta Technologies, Inc.
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
#include "tempesta_fw.h"
#include "log.h"
#include "server.h"
#include "http_sess.h"

/*
 * Normally, schedulers are separate modules. Schedulers register
 * and deregister themselves via register()/unregister() functions.
 * Registered schedulers are placed on the list and can be used by
 * Tempesta. The list is traversed on each HTTP message in search
 * for an outgoing connection, so the list traversal operation is
 * critical for speed. The event of a scheduler's registration or
 * deregistration is rare. The list of schedulers is traversed on
 * multiple CPUs simultaneously. These properties and the goals
 * make RCU locks a beneficial choice.
 */

static LIST_HEAD(sched_list);
static DEFINE_SPINLOCK(sched_lock);

/**
 * Find connection for a message @msg in @main_sg or @backup_sg server groups.
 *
 * If client support cookies the function is called under session's write lock,
 * and updates to session informations are possible.
 */
TfwSrvConn *
tfw_sched_get_sg_srv_conn(TfwMsg *msg, TfwSrvGroup *main_sg,
			  TfwSrvGroup *backup_sg)
{
	TfwHttpReq *req = (TfwHttpReq *)msg;
	TfwSrvConn *srv_conn;

	BUG_ON(!main_sg);
	TFW_DBG2("sched: use server group: '%s'\n", main_sg->name);

	tfw_http_sess_save_sg(req, main_sg, backup_sg);

	srv_conn = main_sg->sched->sched_sg_conn(msg, main_sg);

	if (unlikely(!srv_conn && backup_sg)) {
		TFW_DBG("sched: the main group is offline, use backup: '%s'\n",
			backup_sg->name);
		srv_conn = backup_sg->sched->sched_sg_conn(msg, backup_sg);
	}

	if (unlikely(!srv_conn))
		TFW_DBG2("sched: Unable to select server from group '%s'\n",
			 backup_sg ? backup_sg->name : main_sg->name);

	return srv_conn;
}
EXPORT_SYMBOL(tfw_sched_get_sg_srv_conn);

/**
 * Find an outgoing connection for an HTTP message.
 *
 * Where an HTTP message goes in controlled by schedulers. It may
 * or may not depend on properties of HTTP message itself. In any
 * case, schedulers are polled in sequential order until a result
 * is received. Schedulers that distribute HTTP messages among
 * server groups come first in the list. The search stops when
 * these schedulers run out.
 */
TfwSrvConn *
__tfw_sched_get_srv_conn(TfwMsg *msg)
{
	TfwSrvConn *srv_conn;
	TfwScheduler *sched;

	rcu_read_lock();
	list_for_each_entry_rcu(sched, &sched_list, list) {
		if (!sched->sched_grp)
			break;
		if ((srv_conn = sched->sched_grp(msg))) {
			rcu_read_unlock();
			return srv_conn;
		}
	}
	rcu_read_unlock();

	return NULL;
}

/*
 * Find an outgoing server connection for an HTTP message.
 *
 * This function is always called in SoftIRQ context.
 */
TfwSrvConn *
tfw_sched_get_srv_conn(TfwMsg *msg)
{
	TfwHttpReq *req = (TfwHttpReq *)msg;
	TfwHttpSess *sess = req->sess;

	/* Sticky cookies are disabled or client doesn't support cookies. */
	if (!sess)
		return __tfw_sched_get_srv_conn(msg);

	return tfw_http_sess_get_srv_conn(msg);
}

/*
 * Lookup a scheduler by name.
 *
 * If @name is NULL, then the first available scheduler is returned.
 * Called only in user context, and used in configuration routines.
 */
TfwScheduler *
tfw_sched_lookup(const char *name)
{
	TfwScheduler *sched;

	rcu_read_lock();
	list_for_each_entry_rcu(sched, &sched_list, list) {
		if (!name || !strcasecmp(name, sched->name)) {
			rcu_read_unlock();
			return sched;
		}
	}
	rcu_read_unlock();

	return NULL;
}

/*
 * Register a new scheduler.
 * Called only in user context.
 */
int
tfw_sched_register(TfwScheduler *sched)
{
	TFW_LOG("Registering new scheduler: %s\n", sched->name);
	BUG_ON(!list_empty(&sched->list));

	/* Add group scheduling schedulers at head of the list. */
	spin_lock(&sched_lock);
	if (sched->sched_grp)
		list_add_rcu(&sched->list, &sched_list);
	else
		list_add_tail_rcu(&sched->list, &sched_list);
	spin_unlock(&sched_lock);

	return 0;
}
EXPORT_SYMBOL(tfw_sched_register);

/*
 * Deregister a new scheduler.
 * Called only in user context.
 */
void
tfw_sched_unregister(TfwScheduler *sched)
{
	TFW_LOG("Un-registering scheduler: %s\n", sched->name);
	BUG_ON(list_empty(&sched->list));

	spin_lock(&sched_lock);
	list_del_rcu(&sched->list);
	spin_unlock(&sched_lock);

	/* Make sure the removed @sched is not used. */
	synchronize_rcu();
	/* Clear up scheduler for future use. */
	INIT_LIST_HEAD(&sched->list);
}
EXPORT_SYMBOL(tfw_sched_unregister);
