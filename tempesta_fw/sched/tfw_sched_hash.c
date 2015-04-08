/**
 *		Tempesta FW
 *
 * Hash-based HTTP request scheduler.
 *
 * The scheduler computes hash of URI and Host header fields of a HTTP request
 * and uses the hash value as a key for searching a TfwServer object.
 * Hence, HTTP requests with the same URI and Host always go to the same server
 * unless it is offline.
 *
 * Also, the scheduler utilizes the Rendezvous hashing (Highest Random Weight)
 * method that allows to stick every HTTP message to its server, preserving
 * this mapping when other servers go down or new servers added.
 * The scheduler hashes not only HTTP requests, but also servers (TfwServer
 * objects), and for each incoming HTTP request it searches for a best match
 * among all server hashes. Each Host/URI hash has only one best matching
 * TfwSrver hash which is chosen, and thus any request always goes to its home
 * server unless it is offline.
 *
 * TODO:
 *  - Refactoring: there is simpler logic in all scheduler modules related
 *    to lists of TfwServer objects. The code should be extracted and re-used.
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
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
 *
 */
#include <linux/hash.h>
#include <linux/module.h>

#include "http_msg.h"
#include "log.h"
#include "sched.h"

MODULE_AUTHOR(TFW_AUTHOR);
MODULE_DESCRIPTION("Tempesta hash-based scheduler");
MODULE_VERSION("0.0.2");
MODULE_LICENSE("GPL");

#define BANNER "tfw_sched_hash: "
#define ERR(...) TFW_ERR(BANNER __VA_ARGS__)
#define LOG(...) TFW_LOG(BANNER __VA_ARGS__)
#define DBG(...) TFW_DBG(BANNER __VA_ARGS__)

typedef struct {
	TfwServer *srv;
	unsigned long hash;
} TfwSrvHash;

/**
 * The list of TfwSrvHash implemented as array.
 *
 * The array is chosen instead of a linked list to allow easy binary search
 * implementation and perhaps to improve spatial locality of TfwSrvHash objects.
 *
 * The RCU mechanism is used to protect the list from being modified,
 * while the data is scanned by tfw_sched_hash_get_srv().
 *
 * @rcu is needed to make updates possible in an atomic context.
 * That happens if a server connection is lost, so the disconnect callback is
 * executed in a softirq context and a TfwServer is deleted from the scheduler.
 */
typedef struct {
	struct rcu_head rcu;
	size_t		n;
	TfwSrvHash	srv_hashes[];
} TfwSrvHashList;

#define TFW_SRV_HASH_LIST_SIZE(n) 					\
({									\
	/* We put two NULLs when the list is empty in order		\
	 * to simplify the algorithm in tfw_sched_hash_get_srv() */	\
	size_t _nulls = n ? 1 : 2;					\
	(sizeof(TfwSrvHashList) + ((n) + _nulls) * sizeof(TfwSrvHash));	\
})

/**
 * A NULL-terminated array of TfwSrvHash that stores all servers added to the
 * scheduler via tfw_sched_hash_add_srv().
 *
 * Concurrent RCU updaters must be synchronized with servers_update_lock.
 */
static TfwSrvHashList *tfw_srv_hash_list __rcu;
static DEFINE_SPINLOCK(srv_hashes_update_lock);

/**
 * Find an appropriate TfwServer for the HTTP request @msg.
 * The server is chosen based on the hash value of URI/Host fields of the @msg,
 * so multiple requests to the same resource are mapped to the same server.
 *
 * Higest Random Weight hashing method is involved: for each message we
 * calculate randomized weights as follows: (msg_hash ^ srv_hash), and pick a
 * server with the highest weight.
 * That sticks messages with certain Host/URI to certain IP addresses.
 * A server always receives requests with some URI/Host values bound to it,
 * and that holds if connection to the server is lost and then re-established,
 * and if other servers go offline, and even if Tempesta FW is restarted.
 *
 * The drawbacks of HRW hashing are:
 *  - A weak hash function adds unfairness to the load balancing.
 *    There may be a case when a server pulls all load from all other servers.
 *    And such condition (if it occurs although it is quite improbable) is
 *    quite stable: it cannot be fixed by adding/removing servers and restarting
 *    the Tempesta FW instance.
 *  - For every HTTP request, we have to scan the list of all servers to find
 *    a matching one with the highest weight. That adds some overhead.
 *    Currently the linear search is used. We may switch to binary search, but
 *    benchmarks are required to prove that it will behave better on the small
 *    number of servers that we usually have.
 */
static TfwServer *
tfw_sched_hash_get_srv(TfwMsg *msg)
{
	TfwServer *best_srv;
	TfwSrvHash *curr_srv_hash;
	TfwSrvHashList *srv_hash_list;
	unsigned long msg_hash, curr_weight, best_weight;

	msg_hash = tfw_http_req_key_calc((TfwHttpReq *)msg);

	rcu_read_lock();
	srv_hash_list = rcu_dereference(tfw_srv_hash_list);

	/* 1. Set best = first element of the list. */
	curr_srv_hash = &srv_hash_list->srv_hashes[0];
	best_srv = curr_srv_hash->srv;
	best_weight = msg_hash ^ curr_srv_hash->hash;

	/* 2. Try to find a better one among 2nd...Nth elements of the list.
	 * We don't check for N == 0 here; the list is terminated with two NULL
	 * elements when it is empty, so we can avoid the extra branch here. */
	while ((++curr_srv_hash)->srv) {
		curr_weight = msg_hash ^ curr_srv_hash->hash;
		if (curr_weight > best_weight) {
			best_weight = curr_weight;
			best_srv = curr_srv_hash->srv;
		}
		++curr_srv_hash;
	}

	rcu_read_unlock();

	return best_srv;
}

static unsigned long
tfw_sched_hash_calc_srv(TfwServer *srv)
{
	unsigned long hash;
	union {
		TfwAddr addr;
		unsigned char bytes[0];
	} a;
	size_t i, bytes_n;

	/**
	 * Here we just cast the whole TfwAddr to an array of bytes
	 * and use the standard hash_long() to calculate the hash.
	 *
	 * That only works if the following invariants are held:
	 *  - There are no gaps between structure fields.
	 *  - No structure fields (e.g. sin6_flowinfo) are changed if we
	 *    re-connect to the same server.
	 */
	tfw_server_get_addr(srv, &a.addr);
	bytes_n = tfw_addr_sa_len(&a.addr);

	hash = 0;
	for (i = 0; i < bytes_n; ++i) {
		hash = hash_long(hash ^ a.bytes[i], BITS_PER_LONG);
	}

	return hash;
}

static int
tfw_sched_hash_add_srv(TfwServer *srv)
{
	int ret = 0;
	TfwSrvHash *new_list_entry;
	TfwSrvHashList *new_list, *old_list;
	size_t new_list_size, old_list_size;

	spin_lock_bh(&srv_hashes_update_lock);

	old_list = tfw_srv_hash_list;
	old_list_size = TFW_SRV_HASH_LIST_SIZE(old_list->n);
	new_list_size = TFW_SRV_HASH_LIST_SIZE(old_list->n + 1);

	if (old_list->n >= TFW_SCHED_MAX_SERVERS) {
		ERR("maximum number of servers reached\n");
		ret = -ENOBUFS;
		goto out;
	}

	new_list = kzalloc(new_list_size, GFP_ATOMIC);
	if (!new_list) {
		ret = -ENOMEM;
		goto out;
	}

	memcpy(new_list, old_list, old_list_size);
	new_list_entry = &new_list->srv_hashes[new_list->n++];
	new_list_entry->srv = srv;
	new_list_entry->hash = tfw_sched_hash_calc_srv(srv);

	rcu_assign_pointer(tfw_srv_hash_list, new_list);
	kfree_rcu(old_list, rcu);
out:
	spin_unlock_bh(&srv_hashes_update_lock);
	return ret;
}

static int
tfw_sched_hash_del_srv(TfwServer *srv)
{
	int ret = 0;
	TfwSrvHash *curr;
	TfwSrvHashList *new_list, *old_list;
	size_t new_list_size, old_list_size;

	spin_lock_bh(&srv_hashes_update_lock);

	old_list = tfw_srv_hash_list;
	old_list_size = TFW_SRV_HASH_LIST_SIZE(old_list->n);
	new_list_size = TFW_SRV_HASH_LIST_SIZE(old_list->n - 1);

	new_list = kzalloc(new_list_size, GFP_ATOMIC);
	if (!new_list) {
		ret = -ENOMEM;
		goto out;
	}

	/* Copy entries to the new list excluding the one being deleted. */
	for (curr = old_list->srv_hashes; curr->srv; ++curr) {
		if (curr->srv != srv)
			new_list->srv_hashes[new_list->n++] = *curr;
	}
	BUG_ON(new_list->n != (old_list->n - 1));

	rcu_assign_pointer(tfw_srv_hash_list, new_list);
	kfree_rcu(old_list, rcu);
out:
	spin_unlock_bh(&srv_hashes_update_lock);
	return ret;
}

static TfwScheduler tfw_sched_hash_mod = {
	.name = "hash",
	.get_srv = tfw_sched_hash_get_srv,
	.add_srv = tfw_sched_hash_add_srv,
	.del_srv = tfw_sched_hash_del_srv
};

int
tfw_sched_hash_init(void)
{
	int r;

	LOG("init\n");

	/* Allocate a dummy list to avoid NULL checks in other functions. */
	tfw_srv_hash_list = kzalloc(TFW_SRV_HASH_LIST_SIZE(0), GFP_KERNEL);
	if (!tfw_srv_hash_list) {
		ERR("can't allocate empty server list\n");
	}

	r = tfw_sched_register(&tfw_sched_hash_mod);
	if (r) {
		ERR("can't register as a scheduler module of Tempesta FW\n");
		kfree(tfw_srv_hash_list);
	}

	return r;
}
module_init(tfw_sched_hash_init);

void
tfw_sched_hash_exit(void)
{
	/* At the moment of un-loading the module the list shall not be used. */
	BUG_ON(tfw_srv_hash_list->n);

	kfree(tfw_srv_hash_list);
	tfw_sched_unregister();
}
module_exit(tfw_sched_hash_exit);
