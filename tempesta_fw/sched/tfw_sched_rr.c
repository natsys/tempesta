/**
 *		Tempesta FW
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
#include <linux/kernel.h>
#include <linux/module.h>

#include "tempesta_fw.h"
#include "log.h"
#include "server.h"

MODULE_AUTHOR(TFW_AUTHOR);
MODULE_DESCRIPTION("Tempesta round-robin scheduler");
MODULE_VERSION("0.3.0");
MODULE_LICENSE("GPL");

/**
 * List of connections to an upstream server.
 * Connections can up and down during failover process and shouldn't be
 * taken into account by the scheduler.
 */
typedef struct {
	atomic64_t	rr_counter;
	size_t		conn_n;
	TfwServer	*srv;
	TfwSrvConn	*conns[TFW_SRV_MAX_CONN];
} TfwRrSrv;

/**
 * List of upstream servers.
 * The list is considered static, i.e. all the servers are alive during
 * whole run-time. This can be changed in future.
 */
typedef struct {
	atomic64_t	rr_counter;
	size_t		srv_n;
	TfwRrSrv	srvs[TFW_SG_MAX_SRV];
} TfwRrSrvList;

static void
tfw_sched_rr_alloc_data(TfwSrvGroup *sg)
{
	sg->sched_data = kzalloc(sizeof(TfwRrSrvList), GFP_KERNEL);
	BUG_ON(!sg->sched_data);
}

static void
tfw_sched_rr_free_data(TfwSrvGroup *sg)
{
	kfree(sg->sched_data);
}

/**
 * Add connection and server, if new, to the scheduler.
 * Called at configuration phase, no synchronization is required.
 */
static void
tfw_sched_rr_add_conn(TfwSrvGroup *sg, TfwServer *srv, TfwSrvConn *srv_conn)
{
	size_t s, c;
	TfwRrSrv *srv_cl;
	TfwRrSrvList *sl = sg->sched_data;

	BUG_ON(!sl);

	for (s = 0; s < sl->srv_n; ++s)
		if (sl->srvs[s].srv == srv)
			break;
	if (s == sl->srv_n) {
		sl->srvs[s].srv = srv;
		++sl->srv_n;
		BUG_ON(sl->srv_n > TFW_SG_MAX_SRV);
		srv->sched_data = &sl->srvs[s];
	}

	srv_cl = &sl->srvs[s];
	for (c = 0; c < srv_cl->conn_n; ++c)
		if (srv_cl->conns[c] == srv_conn) {
			TFW_WARN("sched_rr: Try to add existing connection,"
				 " srv=%zu conn=%zu\n", s, c);
			return;
		}
	srv_cl->conns[c] = srv_conn;
	++srv_cl->conn_n;
	BUG_ON(srv_cl->conn_n > TFW_SRV_MAX_CONN);
}

static inline TfwSrvConn *
__sched_srv(TfwRrSrv *srv_cl, int skipnip, int *nipconn)
{
	size_t c;

	for (c = 0; c < srv_cl->conn_n; ++c) {
		unsigned long idxval = atomic64_inc_return(&srv_cl->rr_counter);
		TfwSrvConn *srv_conn = srv_cl->conns[idxval % srv_cl->conn_n];

		if (unlikely(tfw_srv_conn_restricted(srv_conn)
			     || tfw_srv_conn_queue_full(srv_conn)))
			continue;
		if (skipnip && tfw_srv_conn_hasnip(srv_conn)) {
			if (likely(tfw_srv_conn_live(srv_conn)))
				++(*nipconn);
			continue;
		}
		if (likely(tfw_srv_conn_get_if_live(srv_conn)))
			return srv_conn;
	}

	return NULL;
}

/**
 * On each subsequent call the function returns the next server in the
 * group. Parallel connections to the same server are also rotated in
 * the round-robin manner.
 *
 * Dead connections and servers w/o live connections are skipped.
 * Initially, connections with non-idempotent requests are also skipped
 * in attempt to increase throughput. However, if all live connections
 * contain a non-idempotent request, then re-run the algorithm and get
 * the first live connection they way it is usually done.
 *
 * RR scheduler must be the fastest scheduler. Also, it's essential
 * to maintain strict round-robin fashion of getting the next server.
 * Usually the optimistic approach gives the fastest solution: we are
 * optimistic in that there are not many non-idempotent requests, and
 * there are available server connections.
 */
static TfwSrvConn *
tfw_sched_rr_get_sg_conn(TfwMsg *msg, TfwSrvGroup *sg)
{
	size_t s;
	int skipnip = 1, nipconn = 0;
	TfwRrSrvList *sl = sg->sched_data;

	BUG_ON(!sl);
rerun:
	for (s = 0; s < sl->srv_n; ++s) {
		unsigned long idxval = atomic64_inc_return(&sl->rr_counter);
		TfwRrSrv *srv_cl = &sl->srvs[idxval % sl->srv_n];
		TfwSrvConn *srv_conn;

		if ((srv_conn = __sched_srv(srv_cl, skipnip, &nipconn)))
				return srv_conn;
	}
	if (skipnip && nipconn) {
		skipnip = 0;
		goto rerun;
	}
	return NULL;
}

/**
 * Same as @tfw_sched_rr_get_sg_conn(), but but schedule for a specific server
 * in a group.
 */
static TfwSrvConn *
tfw_sched_rr_get_srv_conn(TfwMsg *msg, TfwServer *srv)
{
	int skipnip = 1, nipconn = 0;
	TfwRrSrv *srv_cl = srv->sched_data;
	TfwSrvConn *srv_conn;

	/*
	 * For @srv without connections srv_cl will be NULL, that normally
	 * does not happen in real life, but unit tests check that case.
	*/
	if (unlikely(!srv_cl))
		return NULL;

rerun:
	if ((srv_conn = __sched_srv(srv_cl, skipnip, &nipconn)))
		return srv_conn;

	if (skipnip && nipconn) {
		skipnip = 0;
		goto rerun;
	}
	return NULL;
}

static TfwScheduler tfw_sched_rr = {
	.name		= "round-robin",
	.list		= LIST_HEAD_INIT(tfw_sched_rr.list),
	.add_grp	= tfw_sched_rr_alloc_data,
	.del_grp	= tfw_sched_rr_free_data,
	.add_conn	= tfw_sched_rr_add_conn,
	.sched_sg_conn	= tfw_sched_rr_get_sg_conn,
	.sched_srv_conn	= tfw_sched_rr_get_srv_conn,
};

int
tfw_sched_rr_init(void)
{
	TFW_DBG("sched_rr: init\n");
	return tfw_sched_register(&tfw_sched_rr);
}
module_init(tfw_sched_rr_init);

void
tfw_sched_rr_exit(void)
{
	TFW_DBG("sched_rr: exit\n");
	tfw_sched_unregister(&tfw_sched_rr);
}
module_exit(tfw_sched_rr_exit);

