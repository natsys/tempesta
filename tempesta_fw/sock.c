/**
 *		Synchronous Socket API.
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
#include <linux/irq_work.h>
#include <linux/module.h>
#include <linux/tempesta.h>
#include <net/protocol.h>
#include <net/inet_common.h>
#include <net/ip6_route.h>

#if DBG_SS == 0
#undef DEBUG
#endif
#include "lib/str.h"
#include "addr.h"
#include "log.h"
#include "procfs.h"
#include "sync_socket.h"
#include "tempesta_fw.h"
#include "work_queue.h"

typedef enum {
	SS_SEND,
	SS_CLOSE,
} SsAction;

typedef struct {
	struct sock	*sk;
	struct sk_buff	*skb_head;
	int		flags;
	SsAction	action;
	unsigned long	__unused[1];
} SsWork;

/**
 * Backlog for synchronous close operations. Uses turnstile to keep order with
 * ring-buffer work queue. The work queue tail is used as a ticket for the
 * turnstile. The backlog is used in slow path if the-ring buffer work queue
 * is full.
 *
 * @head	- head of backlog queue;
 * @lock	- synchronization for the backlog (MPSC);
 * @turn	- last pop()'ed node ticket value, used to decide where to pop()
 * 		  a next item from without locking;
 * @size	- current backlog queue size, just for statistics;
 */
typedef struct {
	struct list_head	head;
	spinlock_t		lock;
	long			turn;
	size_t			size;
} SsCloseBacklog;

/**
 * Node of close backlog.
 *
 * @ticket	- the work ticket used in turnstile to order items from the
 * 		  backlog with ring-buffer items;
 * @list	- list entry in the backlog;
 * @sw		- work descriptor to perform.
 */
typedef struct {
	long			ticket;
	struct list_head	list;
	SsWork			sw;
} SsCblNode;

/* Socket states are needed at high support levels. */
#if defined(DEBUG) && (DEBUG >= 2)
static const char *ss_statename[] = {
	"Unused",	"Established",	"Syn Sent",	"Syn Recv",
	"Fin Wait 1",	"Fin Wait 2",	"Time Wait",	"Close",
	"Close Wait",	"Last ACK",	"Listen",	"Closing",
	"New Syn Recv"
};
#endif

#ifdef CONFIG_DEBUG_SPINLOCK
#define TFW_VALIDATE_SK_LOCK_OWNER(sk)	\
	BUG_ON(sk->sk_lock.slock.rlock.owner_cpu != raw_smp_processor_id())
#else
#define TFW_VALIDATE_SK_LOCK_OWNER(sk)
#endif

/**
 * Constants for active socket operations.
 * SS uses downcalls (SS functions calls from Tempesta layer) and upcalls
 * (SS callbacks), but all of them are executed in softirq context.
 * Meantime, system shutdown is performed in process context.
 * So __ss_act_cnt and the constants at the below are used to count number of
 * upcalls and downcalls on the fly and synchronize shutdown process with the
 * calls: the shutdown process must wait until all the calls finished and
 * no new calls can be executed.
 *
 * However, softirqs can call SS down- or upcall any time. Moreover, there could
 * be an ingress packet for some Tempesta's socket and it initiates new
 * Tempesta's calls in softirq. So to guarantee shutdown process convergence we
 * firstly finish all new established connections activity using
 * SS_V_ACT_NEWCONN and next we wait for finishing all active connections
 * using SS_V_ACT_LIVECONN.
 */
#define SS_V_ACT_NEWCONN	0x0000000000000001UL
#define SS_M_ACT_NEWCONN	0x00000000ffffffffUL
#define SS_V_ACT_LIVECONN	0x0000000100000000UL
#define SS_ACT_SHIFT		32

static bool __ss_active = false;
static DEFINE_PER_CPU(atomic64_t, __ss_act_cnt) ____cacheline_aligned
	= ATOMIC_INIT(0);
static DEFINE_PER_CPU(TfwRBQueue, si_wq);
static DEFINE_PER_CPU(struct irq_work, ipi_work);
/*
 * llist can not be used since llist_del_first() returns the newest added
 * item, while we need FIFO queue. Not a big deal - we use it only at slow
 * path.
 */
static DEFINE_PER_CPU(SsCloseBacklog, close_backlog);
static struct kmem_cache *ss_cbacklog_cache;

static void
ss_sk_incoming_cpu_update(struct sock *sk)
{
	if (sk->sk_incoming_cpu == -1)
		sk->sk_incoming_cpu = raw_smp_processor_id();
}

/**
 * Enters critical section synchronized with ss_synchronize().
 * Active networking operations which involves SS callback calls must be
 * protected by the guard: don't enter the section if the system is about
 * to shutdown. The only exception is closing activity - this is the only
 * activity allowed in progress of shutdown process.
 *
 * Returns zero (SS_OK) if we're in critical section and SS_BAD if shutdown
 * process in progress and we can't enter the section.
 */
static int
ss_active_guard_enter(unsigned long val)
{
	atomic64_t *acnt = this_cpu_ptr(&__ss_act_cnt);

	if (unlikely(!READ_ONCE(__ss_active)))
		return SS_BAD;
	atomic64_add(val, acnt);
	if (unlikely(!READ_ONCE(__ss_active))) {
		atomic64_sub(val, acnt);
		return SS_BAD;
	}

	return SS_OK;
}

static void
ss_active_guard_exit(unsigned long val)
{
	atomic64_sub(val, this_cpu_ptr(&__ss_act_cnt));
}

/**
 * Guard for calling connection error/drop callback for each established socket,
 * so we guarantee that all upper layer connections are closed.
 */
#define SS_CALL_GUARD_ENTER(cb, sk)					\
({									\
	ss_active_guard_enter(SS_V_ACT_LIVECONN);			\
	SS_CALL(cb, sk);						\
})

#define SS_CALL_GUARD_EXIT(cb, sk)					\
do {									\
	SS_CALL(cb, sk);						\
	ss_active_guard_exit(SS_V_ACT_LIVECONN);			\
} while (0)

static void
ss_ipi(struct irq_work *work)
{
	TfwRBQueue *wq = &per_cpu(si_wq, smp_processor_id());
	clear_bit(TFW_QUEUE_IPI, &wq->flags);
	raise_softirq(NET_TX_SOFTIRQ);
}

/**
 * The socket can move from one CPU to another, so we have to pass @cpu as
 * a parameter to guarantee that we use work queue and backlog for the same
 * CPU.
 */
static int
ss_turnstile_push(long ticket, SsWork *sw, int cpu)
{
	struct irq_work *iw = &per_cpu(ipi_work, cpu);
	SsCloseBacklog *cb = &per_cpu(close_backlog, cpu);
	TfwRBQueue *wq = &per_cpu(si_wq, cpu);
	SsCblNode *cn;

	cn = kmem_cache_alloc(ss_cbacklog_cache, GFP_ATOMIC);
	if (!cn)
		return -ENOMEM;
	cn->ticket = ticket;
	memcpy(&cn->sw, sw, sizeof(*sw));
	spin_lock_bh(&cb->lock);
	list_add_tail(&cn->list, &cb->head);
	cb->size++;
	if (cb->turn > ticket)
		cb->turn = ticket;
	spin_unlock_bh(&cb->lock);

	/*
	 * We do not need explicit memory barriers after
	 * spinlock operation.
	 */
	if (test_bit(TFW_QUEUE_IPI, &wq->flags))
		tfw_raise_softirq(cpu, iw, ss_ipi);

	return 0;
}

static void
ss_turnstile_update_turn(SsCloseBacklog *cb)
{
	if (list_empty(&cb->head)) {
		cb->turn = LONG_MAX;
	} else {
		SsCblNode *cn = list_first_entry(&cb->head, SsCblNode, list);
		cb->turn = cn->ticket;
	}
}

static void
ss_backlog_validate_cleanup(int cpu)
{
	SsCloseBacklog *cb = &per_cpu(close_backlog, cpu);

	WARN_ON(!list_empty(&cb->head));
	WARN_ON(cb->size);
	WARN_ON(cb->turn != LONG_MAX);
}

static long
ss_wq_push(SsWork *sw, int cpu)
{
	TfwRBQueue *wq = &per_cpu(si_wq, cpu);
	struct irq_work *iw = &per_cpu(ipi_work, cpu);
	long r;

	r = tfw_wq_push(wq, sw, cpu, iw, ss_ipi);
	if (r)
		TFW_INC_STAT_BH(ss.wq_full);
	return r;
}

static int
ss_wq_pop(TfwRBQueue *wq, SsWork *sw, long *ticket)
{
	SsCloseBacklog *cb = this_cpu_ptr(&close_backlog);

	/*
	 * Since backlog is used for closing only, items from the work queue
	 * are fetched first.
	 */
	if (!*ticket && !tfw_wq_pop_ticket(wq, sw, ticket))
		return 0;

	/*
	 * @turn stores @wq->head value of a next item to insert (the position
	 * was unavailable when we tried it), so if we fetched i'th item last
	 * time, then now we should fetch (i + 1)'th item from the backlog.
	 * While there are many producers, they have different head views and
	 * they can put the items to the backlog with wrong order. Thus, we
	 * should fetch all the items with small enough tickets.
	 */
	if (*ticket + 1 >= cb->turn) {
		SsCblNode *cn = NULL;

		spin_lock(&cb->lock);
		if (!list_empty(&cb->head)) {
			cn = list_first_entry(&cb->head, SsCblNode, list);
			list_del(&cn->list);
			ss_turnstile_update_turn(cb);
			cb->size--;
		}
		spin_unlock(&cb->lock);
		if (cn) {
			memcpy_fast(sw, &cn->sw, sizeof(*sw));
			kmem_cache_free(ss_cbacklog_cache, cn);
			return 0;
		}
	}

	return tfw_wq_pop_ticket(wq, sw, ticket);
}

static size_t
ss_wq_size(int cpu)
{
	TfwRBQueue *wq = &per_cpu(si_wq, cpu);
	SsCloseBacklog *cb = &per_cpu(close_backlog, cpu);

	return tfw_wq_size(wq) + cb->size;
}

static size_t
ss_wq_local_size(TfwRBQueue *wq)
{
	SsCloseBacklog *cb = this_cpu_ptr(&close_backlog);

	return tfw_wq_size(wq) + cb->size;
}

/*
 * Socket is in a usable state that allows processing
 * and sending of HTTP messages. This function must
 * be used consistently across all involved functions.
 */
static bool
ss_sock_active(struct sock *sk)
{
	return (1 << sk->sk_state) & (TCPF_ESTABLISHED | TCPF_CLOSE_WAIT);
}

/*
 * ------------------------------------------------------------------------
 *  	Server and client connections handling
 * ------------------------------------------------------------------------
 */
/**
 * @skb_head can be invalid after the function call, don't try to use it.
 */
static void
ss_do_send(struct sock *sk, struct sk_buff **skb_head, int flags)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;
	int size, mss = tcp_send_mss(sk, &size, MSG_DONTWAIT);
	unsigned int mark = (*skb_head)->mark;

	TFW_DBG3("[%d]: %s: sk=%pK queue_empty=%d send_head=%pK"
	         " sk_state=%d mss=%d size=%d\n",
	         smp_processor_id(), __func__,
	         sk, tcp_write_queue_empty(sk), tcp_send_head(sk),
	         sk->sk_state, mss, size);

	/* If the socket is inactive, there's no recourse. Drop the data. */
	if (unlikely(!ss_sock_active(sk))) {
		ss_skb_queue_purge(skb_head);
		return;
	}

	while ((skb = ss_skb_dequeue(skb_head))) {
		/*
		 * Zero-sized SKBs may appear when the message headers (or any
		 * other contents) are modified or deleted by Tempesta. Drop
		 * these SKBs.
		 */
		if (!skb->len) {
			TFW_DBG3("[%d]: %s: drop skb=%pK data_len=%u len=%u\n",
			         smp_processor_id(), __func__,
			         skb, skb->data_len, skb->len);
			kfree_skb(skb);
			continue;
		}

		ss_skb_init_for_xmit(skb);
		if (flags & SS_F_ENCRYPT)
			tempesta_tls_skb_settype(skb, SS_SKB_F2TYPE(flags));
		/* Propagate mark of message head skb.*/
		skb->mark = mark;

		TFW_DBG3("[%d]: %s: entail sk=%pK skb=%pK data_len=%u len=%u"
			 " truesize=%u mark=%u tls_type=%x\n",
			 smp_processor_id(), __func__, sk,
			 skb, skb->data_len, skb->len, skb->truesize, skb->mark,
			 tempesta_tls_skb_type(skb));

		skb_entail(sk, skb);

		tp->write_seq += skb->len;
		TCP_SKB_CB(skb)->end_seq += skb->len;
	}

	TFW_DBG3("[%d]: %s: sk=%p send_head=%p sk_state=%d flags=%x\n",
	         smp_processor_id(), __func__,
	         sk, tcp_send_head(sk), sk->sk_state, flags);

	/*
	 * If connection close flag is specified, then @ss_do_close is used to
	 * set FIN on final SKB and push all pending frames to the stack.
	 */
	if (flags & SS_F_CONN_CLOSE)
		return;

	tcp_push(sk, MSG_DONTWAIT, mss, TCP_NAGLE_OFF|TCP_NAGLE_PUSH, size);
}

/**
 * Directly insert all skbs from @skb_head into @sk TCP write queue regardless
 * write buffer size. This allows directly forward modified packets without
 * copying. See do_tcp_sendpages() and tcp_sendmsg() in linux/net/ipv4/tcp.c.
 *
 * Can be called in softirq context as well as from kernel thread.
 */
int
ss_send(struct sock *sk, struct sk_buff **skb_head, int flags)
{
	int cpu, r = 0;
	struct sk_buff *skb, *twin_skb;
	SsWork sw = {
		.sk	= sk,
		.flags  = flags,
		.action	= SS_SEND,
	};

	BUG_ON(!sk);
	if (WARN_ON_ONCE(!*skb_head))
		return 0;

	cpu = sk->sk_incoming_cpu;

	TFW_DBG3("[%d]: %s: sk=%p (cpu=%d) state=%s\n",
	         smp_processor_id(), __func__, sk, cpu,
		 ss_statename[sk->sk_state]);

	/*
	 * This isn't reliable check, but rather just an optimization to
	 * avoid expensive work queue operations.
	 */
	if (unlikely(!ss_sock_active(sk))) {
		TFW_DBG2("Attempt to send on inactive socket %p\n", sk);
		return -EBADF;
	}

	/*
	 * Remove the skbs from Tempesta lists if we won't use them,
	 * or copy them if they're going to be used by Tempesta during
	 * and after the transmission.
	 */
	if (flags & SS_F_KEEP_SKB) {
		skb = *skb_head;
		do {
			/* tcp_transmit_skb() will clone the skb. */
			twin_skb = pskb_copy_for_clone(skb, GFP_ATOMIC);
			if (!twin_skb) {
				TFW_WARN("Unable to copy an egress SKB.\n");
				r = -ENOMEM;
				goto err;
			}
			ss_skb_queue_tail(&sw.skb_head, twin_skb);
			skb = skb->next;
		} while (skb != *skb_head);
	} else {
		sw.skb_head = *skb_head;
		*skb_head = NULL;
	}

	/*
	 * Schedule the socket for TX softirq processing.
	 * Only part of list pointed by @skb_head could be passed to send queue.
	 *
	 * We can't transmit the data escaping the queueing because we have to
	 * order transmissions and other CPUs can push data to transmit for
	 * the socket while current CPU was servicing other sockets.
	 *
	 * Synchronous operations with the work queue are used to avoid memory
	 * leakage, so we never use synchronous sending.
	 */
	sock_hold(sk);
	if (ss_wq_push(&sw, cpu)) {
		TFW_DBG2("Cannot schedule socket %p for transmission"
			 " (queue size %d)\n", sk,
			 tfw_wq_size(&per_cpu(si_wq, cpu)));
		sock_put(sk);
		r = -EBUSY;
		goto err;
	}

	return 0;
err:
	ss_skb_queue_purge(&sw.skb_head);
	return r;
}
EXPORT_SYMBOL(ss_send);

/**
 * This is main body of the socket close function in Sync Sockets.
 *
 * inet_release() can sleep (as well as tcp_close()), so we make our own
 * non-sleepable socket closing.
 *
 * This function must be used only for data sockets.
 * Use standard sock_release() for listening sockets.
 *
 * In most cases it is called in softirq context and from ksoftirqd which
 * processes data from the socket (RSS and RPS distribute packets that way).
 *
 * Note: it used to be called in process context as well, at the time when
 * Tempesta starts or stops. That's not the case right now, but it may change.
 *
 * TODO In some cases we need to close socket aggressively w/o FIN_WAIT_2 state,
 * e.g. by sending RST. So we need to add second parameter to the function
 * which says how to close the socket.
 * One of the examples is rcl_req_limit() (it should reset connections).
 * See tcp_sk(sk)->linger2 processing in standard tcp_close().
 *
 * Called with locked socket.
 */
static void
ss_do_close(struct sock *sk)
{
	struct sk_buff *skb;
	int data_was_unread = 0;

	if (unlikely(!sk))
		return;
	TFW_DBG2("[%d]: Close socket %p (%s): account=%d refcnt=%u\n",
	         smp_processor_id(), sk, ss_statename[sk->sk_state],
		 sk_has_account(sk), refcount_read(&sk->sk_refcnt));
	assert_spin_locked(&sk->sk_lock.slock);
	TFW_VALIDATE_SK_LOCK_OWNER(sk);
	WARN_ON_ONCE(sk->sk_state == TCP_LISTEN);
	/* We must return immediately, so LINGER option is meaningless. */
	WARN_ON_ONCE(sock_flag(sk, SOCK_LINGER));
	/* We don't support virtual containers, so TCP_REPAIR is prohibited. */
	WARN_ON_ONCE(tcp_sk(sk)->repair);
	/* The socket must have atomic allocation mask. */
	WARN_ON_ONCE(!(sk->sk_allocation & GFP_ATOMIC));

	/* The below is mostly copy-paste from tcp_close(). */
	sk->sk_shutdown = SHUTDOWN_MASK;

	while ((skb = __skb_dequeue(&sk->sk_receive_queue)) != NULL) {
		u32 len = TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq -
			  tcp_hdr(skb)->fin;
		data_was_unread += len;
		TFW_DBG3("[%d]: free rcv skb %p\n", smp_processor_id(), skb);
		__kfree_skb(skb);
	}

	sk_mem_reclaim(sk);

	if (sk->sk_state == TCP_CLOSE)
		goto adjudge_to_death;

	if (data_was_unread) {
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPABORTONCLOSE);
		tcp_set_state(sk, TCP_CLOSE);
		tcp_send_active_reset(sk, sk->sk_allocation);
	}
	else if (tcp_close_state(sk)) {
		/* The code below is taken from tcp_send_fin(). */
		struct tcp_sock *tp = tcp_sk(sk);
		int mss_now = tcp_current_mss(sk);

		skb = tcp_write_queue_tail(sk);

		if (skb && tcp_send_head(sk)) {
			/* Send FIN with data if we have any. */
			TCP_SKB_CB(skb)->tcp_flags |= TCPHDR_FIN;
			TCP_SKB_CB(skb)->end_seq++;
			tp->write_seq++;
		}
		else {
			/* No data to send in the socket, allocate new skb. */
			skb = alloc_skb_fclone(MAX_TCP_HEADER,
					       sk->sk_allocation);
			if (!skb) {
				TFW_WARN("can't send FIN due to bad alloc");
			} else {
				skb_reserve(skb, MAX_TCP_HEADER);
				tcp_init_nondata_skb(skb, tp->write_seq,
						     TCPHDR_ACK | TCPHDR_FIN);
				tcp_queue_skb(sk, skb);
			}
		}
		__tcp_push_pending_frames(sk, mss_now, TCP_NAGLE_OFF);
	}

adjudge_to_death:
	sock_hold(sk);
	sock_orphan(sk);

	/*
	 * SS sockets are processed in softirq only,
	 * so backlog queue should be empty.
	 */
	WARN_ON(sk->sk_backlog.tail);

	percpu_counter_inc(sk->sk_prot->orphan_count);

	if (sk->sk_state == TCP_FIN_WAIT2) {
		const int tmo = tcp_fin_time(sk);
		if (tmo > TCP_TIMEWAIT_LEN) {
			inet_csk_reset_keepalive_timer(sk,
						tmo - TCP_TIMEWAIT_LEN);
		} else {
			tcp_time_wait(sk, TCP_FIN_WAIT2, tmo);
			return;
		}
	}
	if (sk->sk_state != TCP_CLOSE) {
		sk_mem_reclaim(sk);
		if (tcp_check_oom(sk, 0)) {
			tcp_set_state(sk, TCP_CLOSE);
			tcp_send_active_reset(sk, GFP_ATOMIC);
			__NET_INC_STATS(sock_net(sk),
					LINUX_MIB_TCPABORTONMEMORY);
		}
	}
	if (sk->sk_state == TCP_CLOSE) {
		struct request_sock *req = tcp_sk(sk)->fastopen_rsk;
		if (req != NULL)
			reqsk_fastopen_remove(sk, req, false);
		inet_csk_destroy_sock(sk);
	}
}

/**
 * This function is for internal Sync Sockets use only. It's called under the
 * socket lock taken by the kernel, and in the context of the socket that is
 * being closed.
 *
 * This is unintentional connection closing, usually due to some data errors.
 * This is not socket error, but still must lead to connection failovering
 * for server sockets. So connection_error callback is called here.
 */
static void
ss_linkerror(struct sock *sk)
{
	ss_do_close(sk);
	SS_CALL_GUARD_EXIT(connection_error, sk);
	sock_put(sk);	/* paired with ss_do_close() */
}

/**
 * The function should be called with SS_F_SYNC flag whenever possible to
 * improve performance. Without SS_F_SYNC the return value must be checked
 * and the call must be repeated in case of bad return value.
 * Note, that SS_F_SYNC doesn't mean that the socket will be closed immediately,
 * but rather it guarantees that the socket will be closed and the caller can
 * not care about return value.
 */
int
ss_close(struct sock *sk, int flags)
{
	int cpu;
	long ticket;
	SsWork sw = {
		.sk	= sk,
		.flags  = flags,
		.action	= SS_CLOSE,
	};

	if (unlikely(!sk))
		return SS_OK;

	ss_sk_incoming_cpu_update(sk);
	cpu = sk->sk_incoming_cpu;

	sock_hold(sk);
	ticket = ss_wq_push(&sw, cpu);
	if (!ticket)
		return SS_OK;
	if (!(flags & SS_F_SYNC))
		goto err;

	/*
	 * Slow path: the system is overloaded, but we have to close the socket,
	 * so use locked linked list with a turnstile to keep works order.
	 */
	if (ss_turnstile_push(ticket, &sw, cpu)) {
		TFW_WARN("Cannot schedule socket %p for closing\n", sk);
		goto err;
	}

	return SS_OK;
err:
	sock_put(sk);
	return SS_BAD;
}
EXPORT_SYMBOL(ss_close);

/*
 * Process a single SKB.
 */
static int
ss_tcp_process_skb(struct sock *sk, struct sk_buff *skb, int *processed)
{
	bool tcp_fin;
	int r = 0, offset, count;
	void *conn;
	struct sk_buff *skb_head = NULL;
	struct tcp_sock *tp = tcp_sk(sk);

	/* Calculate the offset into the SKB. */
	offset = tp->copied_seq - TCP_SKB_CB(skb)->seq;
	if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_SYN)
		offset--;

	/* SKB may be freed in processing. Save the flag. */
	tcp_fin = TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN;

	if (ss_skb_unroll(&skb_head, skb)) {
		__kfree_skb(skb);
		return SS_DROP;
	}

	while ((skb = ss_skb_dequeue(&skb_head))) {
		int off;

		WARN_ON_ONCE(skb->tail_lock);
		WARN_ON_ONCE(skb_has_frag_list(skb));
		WARN_ON_ONCE(skb->sk || skb->destructor);

		if (unlikely(offset >= skb->len)) {
			offset -= skb->len;
			__kfree_skb(skb);
			continue;
		}

		/*
		 * TCP can ship an skb with overlapped seqnos, so we have to
		 * work with the offset to avoid probably costly skb_pull().
		 */
		count = skb->len - offset;
		tp->copied_seq += count;
		*processed += count;
		off = offset;
		offset = 0;

		conn = sk->sk_user_data;
		/*
		 * If @sk_user_data is unset, then this connection
		 * had been dropped in a parallel thread. Dropping
		 * a connection is serialized with the socket lock.
		 * The receive queue must be empty in that case,
		 * and the execution path should never reach here.
		 */
		BUG_ON(conn == NULL);

		if (SS_CONN_TYPE(sk) & Conn_Stop) {
			__kfree_skb(skb);
			continue;
		}

		r = SS_CALL(connection_recv, conn, skb, off);

		if (r < 0) {
			TFW_DBG2("[%d]: Processing error: sk=%pK r=%d\n",
			         smp_processor_id(), sk, r);
			goto out; /* connection must be dropped */
		}
	}
	if (tcp_fin) {
		TFW_DBG2("Received data FIN on sk=%p, cpu=%d\n",
			 sk, smp_processor_id());
		++tp->copied_seq;
		r = SS_DROP;
	}
out:
	if (skb_head)
		ss_skb_queue_purge(&skb_head);

	return r;
}

/**
 * Calculates the appropriate TCP receive buffer space. Same as
 * tcp_rcv_space_adjust().
 */
static void
ss_rcv_space_adjust(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int time;
	int copied;

	tcp_mstamp_refresh(tp);
	time = tcp_stamp_us_delta(tp->tcp_mstamp, tp->rcvq_space.time);

	if (time < (tp->rcv_rtt_est.rtt_us >> 3) || tp->rcv_rtt_est.rtt_us == 0)
		return;

	copied = tp->copied_seq - tp->rcvq_space.seq;
	if (copied <= tp->rcvq_space.space)
		goto new_measure;

	/*
	 * Socket buffer size is locked (SOCK_RCVBUF_LOCK), we manually control
	 * its size and can moderate it to gain more speed.
	 */
	if (/* sysctl_tcp_moderate_rcvbuf */ true) {
		int rcvwin, rcvmem, rcvbuf;

		/* minimal window to cope with packet losses, assuming
		 * steady state. Add some cushion because of small variations.
		 */
		rcvwin = (copied << 1) + 16 * tp->advmss;

		/* If rate increased by 25%,
		 *	assume slow start, rcvwin = 3 * copied
		 * If rate increased by 50%,
		 *	assume sender can use 2x growth, rcvwin = 4 * copied
		 */
		if (copied >=
		    tp->rcvq_space.space + (tp->rcvq_space.space >> 2)) {
			if (copied >=
			    tp->rcvq_space.space + (tp->rcvq_space.space >> 1))
				rcvwin <<= 1;
			else
				rcvwin += (rcvwin >> 1);
		}

		rcvmem = SKB_TRUESIZE(tp->advmss + MAX_TCP_HEADER);
		while (tcp_win_from_space(rcvmem) < tp->advmss)
			rcvmem += 128;

		rcvbuf = min(rcvwin / tp->advmss * rcvmem, tfw_cfg_cli_rmem);
		if (rcvbuf > sk->sk_rcvbuf) {
			sk->sk_rcvbuf = rcvbuf;

			/* Make the window clamp follow along.  */
			tp->window_clamp = rcvwin;
		}
	}
	tp->rcvq_space.space = copied;

new_measure:
	tp->rcvq_space.seq = tp->copied_seq;
	tp->rcvq_space.time = tp->tcp_mstamp;
}

/**
 * Receive data on TCP socket. Very similar to standard tcp_recvmsg().
 *
 * We can't use standard tcp_read_sock() with our actor callback, because
 * tcp_read_sock() calls __kfree_skb() through sk_eat_skb() which is good
 * for copying data from skb, but we need to manage skb's ourselves.
 *
 * TODO #873 process URG.
 */
static bool
ss_tcp_process_data(struct sock *sk)
{
	bool droplink = true;
	int r, count, processed = 0;
	unsigned int skb_len, skb_seq;
	struct sk_buff *skb, *tmp;
	struct tcp_sock *tp = tcp_sk(sk);

	skb_queue_walk_safe(&sk->sk_receive_queue, skb, tmp) {
		if (unlikely(before(tp->copied_seq, TCP_SKB_CB(skb)->seq))) {
			TFW_WARN("recvmsg bug: TCP sequence gap at seq %X"
				 " recvnxt %X\n",
				 tp->copied_seq, TCP_SKB_CB(skb)->seq);
			goto drop;
		}

		__skb_unlink(skb, &sk->sk_receive_queue);
		skb_orphan(skb);

		WARN_ON_ONCE(skb_shared(skb));

		/* Save the original len and seq for reporting. */
		skb_len = skb->len;
		skb_seq = TCP_SKB_CB(skb)->seq;

		count = 0;
		r = ss_tcp_process_skb(sk, skb, &count);
		processed += count;

		if (r < 0)
			goto drop;
		else if (!count)
			TFW_WARN("recvmsg bug: overlapping TCP segment at %X"
				 " seq %X rcvnxt %X len %x\n",
				 tp->copied_seq, skb_seq, tp->rcv_nxt,
				 skb_len);
	}
	droplink = false;
drop:
	/*
	 * Recalculate an appropriate TCP receive buffer space
	 * and send ACK to a client with the new window.
	 */
	if (sk->sk_userlocks & SOCK_RCVBUF_LOCK)
		ss_rcv_space_adjust(sk);
	else
		tcp_rcv_space_adjust(sk);
	if (processed)
		tcp_cleanup_rbuf(sk, processed);

	return droplink;
}

/*
 * ------------------------------------------------------------------------
 *  	Socket callbacks
 * ------------------------------------------------------------------------
 */
/*
 * Called when a new data received on the socket.
 * Called under bh_lock_sock(sk) (see tcp_v4_rcv()).
 */
static void
ss_tcp_data_ready(struct sock *sk)
{
	TFW_DBG3("[%d]: %s: sk=%p state=%s\n",
	         smp_processor_id(), __func__, sk, ss_statename[sk->sk_state]);
	assert_spin_locked(&sk->sk_lock.slock);
	TFW_VALIDATE_SK_LOCK_OWNER(sk);

	if (unlikely(!skb_queue_empty(&sk->sk_error_queue))) {
		/*
		 * Error packet received.
		 * See sock_queue_err_skb() in linux/net/core/skbuff.c.
		 */
		TFW_ERR("error data in socket %p\n", sk);
	}
	else if (!skb_queue_empty(&sk->sk_receive_queue)) {
		if (ss_tcp_process_data(sk) &&
		    !(SS_CONN_TYPE(sk) & Conn_Stop)) {
			/*
			 * Drop connection in case of internal errors,
			 * banned packets, or FIN in the received packet,
			 * and only if it's not on hold until explicitly
			 * closed.
			 *
			 * ss_linkerror() is responsible for calling
			 * application layer connection closing callback.
			 * The callback will free all SKBs linked with
			 * the message that is currently being processed.
			 */
			ss_linkerror(sk);
		}
	}
	else {
		/*
		 * Check for URG data.
		 * TODO shouldn't we do it in ss_tcp_process_data()?
		 */
		struct tcp_sock *tp = tcp_sk(sk);
		if (tp->urg_data & TCP_URG_VALID) {
			tp->urg_data = 0;
			TFW_DBG3("[%d]: urgent data in socket %p\n",
			         smp_processor_id(), sk);
		}
	}
}

/**
 * Socket state change callback.
 */
static void
ss_tcp_state_change(struct sock *sk)
{
	TFW_DBG3("[%d]: %s: sk=%p state=%s\n",
	         smp_processor_id(), __func__, sk, ss_statename[sk->sk_state]);
	ss_sk_incoming_cpu_update(sk);
	assert_spin_locked(&sk->sk_lock.slock);
	TFW_VALIDATE_SK_LOCK_OWNER(sk);

	if (sk->sk_state == TCP_ESTABLISHED) {
		/* Process the new TCP connection. */
		SsProto *proto = sk->sk_user_data;
		struct sock *lsk = proto->listener;
		int r;

		/*
		 * Acquiring SS active NEWCONN and LIVECONN guards for
		 * sockets established through a listening socket, and
		 * acquiring SS active NEWCONN guard for sockets which came
		 * from ss_connect(). About LIVECONN guard ss_connect() cares
		 * on it's own.
		 * If we cannot acquire one or both guards, that means that
		 * Tempesta is shutting down. Tempesta isn't aware about any
		 * @sk except connections to server, so we have to close
		 * it on our own without calling upper layer hooks.
		 */
		if (ss_active_guard_enter(SS_V_ACT_NEWCONN)) {
			ss_do_close(sk);
			sock_put(sk);
			/*
			 * The case of a connect to an upstream server that
			 * cannot be completed now. Paired with ss_connect()
			 * and ss_active_guard_enter() there.
			 */
			if (!lsk)
				SS_CALL_GUARD_EXIT(connection_drop, sk);
			return;
		}

		if (lsk && ss_active_guard_enter(SS_V_ACT_LIVECONN)) {
			ss_do_close(sk);
			sock_put(sk);
			ss_active_guard_exit(SS_V_ACT_NEWCONN);
			return;
		}

		/*
		 * The callback is called from tcp_rcv_state_process().
		 *
		 * Server never sends data right after an active connection
		 * opening from our side. Passive open is processed from
		 * tcp_v4_rcv() under the socket lock. So there is no need
		 * for synchronization with ss_tcp_process_data().
		 */
		r = SS_CALL(connection_new, sk);
		if (r) {
			TFW_DBG2("[%d]: New connection hook failed, r=%d\n",
			         smp_processor_id(), r);
			ss_linkerror(sk);
			ss_active_guard_exit(SS_V_ACT_NEWCONN);
			return;
		}

		sock_set_flag(sk, SOCK_TEMPESTA);
		if (lsk) {
			/*
			 * This is a new socket for an accepted connect
			 * request that the kernel has allocated itself.
			 * Kernel initializes this field to GFP_KERNEL.
			 * Tempesta works with sockets in SoftIRQ context,
			 * so set it to atomic allocation.
			 */
			sk->sk_allocation = GFP_ATOMIC;
		}
		ss_active_guard_exit(SS_V_ACT_NEWCONN);
	}
	else if (sk->sk_state == TCP_CLOSE_WAIT) {
		/*
		 * Received FIN, connection is being closed.
		 *
		 * When FIN is received from the other side of a connection,
		 * this function is called first before ss_tcp_data_ready()
		 * is called, as the kernel moves the socket's state to
		 * TCP_CLOSE_WAIT. The usual action in Tempesta is to close
		 * the connection.
		 *
		 * It may happen that FIN comes with a data SKB, or there's
		 * still data in the socket's receive queue that hasn't been
		 * processed yet. That data needs to be processed before the
		 * connection is closed.
		 */
		if (!skb_queue_empty(&sk->sk_receive_queue))
			ss_tcp_process_data(sk);
		TFW_DBG2("[%d]: Peer connection closing\n", smp_processor_id());
		ss_linkerror(sk);
	}
	else if (sk->sk_state == TCP_CLOSE) {
		/*
		 * In current implementation we never reach TCP_CLOSE state
		 * in regular course of action. When a socket is moved from
		 * TCP_ESTABLISHED state to a closing state, we forcefully
		 * close the socket before it can reach the final state.
		 *
		 * We get here when an error has occurred in the connection.
		 * It could be that RST was received which may happen for
		 * multiple reasons. Or it could be a case of TCP timeout
		 * where the connection appears to be dead. In all of these
		 * cases the socket is moved directly to TCP_CLOSE state
		 * thus skipping all other states.
		 *
		 * It's safe to call the callback since we set socket callbacks
		 * either for just created, not connected, sockets or in the
		 * function above for ESTABLISHED state. sk_state_change()
		 * callback is never called for the same socket concurrently.
		 */
		WARN_ON(!skb_queue_empty(&sk->sk_receive_queue));
		ss_linkerror(sk);
	}
}

void
ss_proto_init(SsProto *proto, const SsHooks *hooks, int type)
{
	proto->hooks = hooks;
	proto->type = type;

	/*
	 * The memory allocated for @proto should be already zero'ed, so don't
	 * initialize this field to NULL, but instead check the invariant.
	 */
	WARN_ON_ONCE(proto->listener);
}
EXPORT_SYMBOL(ss_proto_init);

void
ss_proto_inherit(const SsProto *parent, SsProto *child, int child_type)
{
	*child = *parent;
	child->type |= child_type;
}

/**
 * Make data socket serviced by synchronous sockets.
 *
 * This function is called for each socket that is created by Tempesta.
 * It's run before a socket is bound or connected, so locking is not
 * required at that time. It's also called for each accepted socket,
 * and at that time it's run under the socket lock (see the comment
 * to TCP_ESTABLISHED case in ss_tcp_state_change()).
 */
void
ss_set_callbacks(struct sock *sk)
{
	/*
	 * ss_tcp_state_change() dereferences sk->sk_user_data as SsProto,
	 * so the caller must initialize it before setting callbacks.
	 */
	WARN_ON_ONCE(!sk->sk_user_data);

	sk->sk_data_ready = ss_tcp_data_ready;
	sk->sk_state_change = ss_tcp_state_change;
}
EXPORT_SYMBOL(ss_set_callbacks);

/**
 * Store listening socket as parent for all accepted connections,
 * and initialize first callbacks.
 *
 * The function is called against just created and still inactive socket,
 * so there is no need for socket synchronization.
 */
void
ss_set_listen(struct sock *sk)
{
	((SsProto *)sk->sk_user_data)->listener = sk;

	sk->sk_state_change = ss_tcp_state_change;
	sock_set_flag(sk, SOCK_TEMPESTA);
}
EXPORT_SYMBOL(ss_set_listen);

/*
 * Create a new socket for IPv4 or IPv6 protocol. The original functions
 * are inet_create() and inet6_create(). They are nearly identical and
 * only minor details are different. All of them are covered here.
 *
 * NOTE: This code assumes that both IPv4 and IPv6 are compiled in as
 * part of the Linux kernel, and not as separate loadable kernel modules.
 */
static int
ss_inet_create(struct net *net, int family,
	       int type, int protocol, struct sock **nsk)
{
	int err, pfinet;
	struct sock *sk;
	struct inet_sock *inet;
	struct proto *answer_prot;

	/* TCP only is supported for now. */
	WARN_ON_ONCE(type != SOCK_STREAM || protocol != IPPROTO_TCP);

	/*
	 * Get socket properties.
	 * See inet_protosw and tcpv6_protosw definitions.
	 */
	if (family == AF_INET) {
		pfinet = PF_INET;
		answer_prot = &tcp_prot;
	} else {
		pfinet = PF_INET6;
		answer_prot = &tcpv6_prot;
	}
	WARN_ON(!answer_prot->slab);

	if (!(sk = sk_alloc(net, pfinet, GFP_ATOMIC, answer_prot, 1)))
		return -ENOBUFS;

	inet = inet_sk(sk);
	inet->is_icsk = 1;
	inet->nodefrag = 0;
	inet->inet_id = 0;

	if (net->ipv4.sysctl_ip_no_pmtu_disc)
		inet->pmtudisc = IP_PMTUDISC_DONT;
	else
		inet->pmtudisc = IP_PMTUDISC_WANT;

	sock_init_data(NULL, sk);
	sk->sk_type = type;
	sk->sk_allocation = GFP_ATOMIC;
	sk->sk_incoming_cpu = -1; /* same as in sock_init_data() */
	sk->sk_destruct = inet_sock_destruct;
	sk->sk_protocol = protocol;
	sk->sk_backlog_rcv = sk->sk_prot->backlog_rcv;

	if (family == AF_INET6) {
		/* The next two lines are inet6_sk_generic(sk) */
		const int offset = sk->sk_prot->obj_size
				   - sizeof(struct ipv6_pinfo);
		struct ipv6_pinfo *np = (struct ipv6_pinfo *)
					(((u8 *)sk) + offset);
		np->hop_limit = -1;
		np->mcast_hops = IPV6_DEFAULT_MCASTHOPS;
		np->mc_loop = 1;
		np->pmtudisc = IPV6_PMTUDISC_WANT;
		sk->sk_ipv6only = net->ipv6.sysctl.bindv6only;
		inet->pinet6 = np;
	}

	inet->uc_ttl = -1;
	inet->mc_loop = 1;
	inet->mc_ttl = 1;
	inet->mc_all = 1;
	inet->mc_index = 0;
	inet->mc_list = NULL;
	inet->rcv_tos = 0;

	sk_refcnt_debug_inc(sk);
	if (sk->sk_prot->init && (err = sk->sk_prot->init(sk))) {
		TFW_ERR("cannot create socket, %d\n", err);
		sk_common_release(sk);
		return err;
	}

	*nsk = sk;

	return 0;
}

int
ss_sock_create(int family, int type, int protocol, struct sock **res)
{
	int ret;
	struct sock *sk = NULL;
	const struct net_proto_family *pf;

	rcu_read_lock_bh();
	if ((pf = get_proto_family(family)) == NULL)
		goto out_rcu_unlock;
	if (!try_module_get(pf->owner))
		goto out_rcu_unlock;
	rcu_read_unlock_bh();

	ret = ss_inet_create(&init_net, family, type, protocol, &sk);
	module_put(pf->owner);
	if (ret < 0)
		goto out_module_put;

	*res = sk;
	return 0;

out_module_put:
	module_put(pf->owner);
out_ret_error:
	return ret;
out_rcu_unlock:
	ret = -EAFNOSUPPORT;
	rcu_read_unlock_bh();
	goto out_ret_error;
}
EXPORT_SYMBOL(ss_sock_create);

/*
 * The original functions are inet_release() and inet6_release().
 * Executes tcp_close(), so must be called from process context only.
 */
void
ss_release(struct sock *sk)
{
	WARN_ON_ONCE(sock_flag(sk, SOCK_LINGER));

	sk->sk_prot->close(sk, 0);
}
EXPORT_SYMBOL(ss_release);

/**
 * The original function is inet_stream_connect() that is common
 * to IPv4 and IPv6.
 */
int
ss_connect(struct sock *sk, const TfwAddr *addr, int flags)
{
	int r;
	struct sockaddr *uaddr = tfw_addr_sa((TfwAddr *)addr);
	int uaddr_len = tfw_addr_sa_len((TfwAddr *)addr);

	WARN_ON_ONCE((sk->sk_family != AF_INET) && (sk->sk_family != AF_INET6));
	WARN_ON_ONCE((uaddr->sa_family != AF_INET)
		     && (uaddr->sa_family != AF_INET6));

	if (uaddr_len < sizeof(uaddr->sa_family))
		return -EINVAL;
	if (sk->sk_state != TCP_CLOSE)
		return -EISCONN;

	if (ss_active_guard_enter(SS_V_ACT_LIVECONN))
		return SS_SHUTDOWN;

	bh_lock_sock(sk);
	r = sk->sk_prot->connect(sk, uaddr, uaddr_len);
	bh_unlock_sock(sk);

	/*
	 * If connect() successfully returns, then the socket is living somewhere
	 * in TCP code and it will move to established or closed state.
	 * So we decrement __ss_act_cnt when the socket die, no need to do this now.
	 */
	if (unlikely(r))
		ss_active_guard_exit(SS_V_ACT_LIVECONN);

	return r;
}
EXPORT_SYMBOL(ss_connect);

/*
 * The original functions are inet_bind() and inet6_bind().
 * These two can be made a bit shorter should that become necessary.
 */
int
ss_bind(struct sock *sk, const TfwAddr *addr)
{
	struct socket sock = {
		.sk = sk,
		.type = sk->sk_type
	};

	WARN_ON_ONCE(sk->sk_family != AF_INET6);
	WARN_ON_ONCE(sk->sk_type != SOCK_STREAM);

	return inet6_bind(&sock, tfw_addr_sa((TfwAddr *)addr),
	                  tfw_addr_sa_len((TfwAddr *)addr));
}
EXPORT_SYMBOL(ss_bind);

/*
 * The original function is inet_listen() that is common to IPv4 and IPv6.
 * There isn't much to make shorter there, so just invoke it directly.
 */
int
ss_listen(struct sock *sk, int backlog)
{
	struct socket sock = {
		.sk = sk,
		.type = sk->sk_type,
		.state = SS_UNCONNECTED
	};

	WARN_ON_ONCE(sk->sk_type != SOCK_STREAM);

	return inet_listen(&sock, backlog);
}
EXPORT_SYMBOL(ss_listen);

/**
 * Mostly copy-pasted from inet_getname() and inet6_getname().
 * All Tempesta internal operations are with IPv6 addresses only,
 * as with more scalable and backward compatible with IPv4.
 */
void
ss_getpeername(struct sock *sk, TfwAddr *addr)
{
	struct inet_sock *inet = inet_sk(sk);

	if (unlikely(!inet->inet_dport
		     || ((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_SYN_SENT))))
		TFW_WARN("%s: bad socket dport=%x state=%x\n", __func__,
			 inet->inet_dport, sk->sk_state);

	addr->sin6_family = AF_INET6;
	addr->sin6_port = inet->inet_sport;
#if IS_ENABLED(CONFIG_IPV6)
	if (inet6_sk(sk)) {
		struct ipv6_pinfo *np = inet6_sk(sk);
		addr->sin6_addr = sk->sk_v6_daddr;
		addr->sin6_flowinfo = np->sndflow ? np->flow_label : 0;
		addr->in6_prefix = ipv6_iface_scope_id(&addr->sin6_addr,
						       sk->sk_bound_dev_if);
	} else
#endif
	{
		ipv6_addr_set_v4mapped(inet->inet_daddr, &addr->sin6_addr);
		addr->sin6_flowinfo = 0;
		addr->in6_prefix = 0;
	}
}
EXPORT_SYMBOL(ss_getpeername);

#define __sk_close_locked(sk)					\
do {								\
	ss_do_close(sk);					\
	bh_unlock_sock(sk);					\
	SS_CALL_GUARD_EXIT(connection_drop, sk);		\
	sock_put(sk); /* paired with ss_do_close() */		\
} while (0)

static void
ss_tx_action(void)
{
	SsWork sw;
	int budget;
	struct sk_buff *skb;
	TfwRBQueue *wq = this_cpu_ptr(&si_wq);
	long ticket = 0;

	/*
	 * @budget limits the loop to prevent live lock on constantly arriving
	 * new items. We use some small integer as a lower bound to catch just
	 * arriving items.
	 */
	budget = max(10UL, ss_wq_local_size(wq));
	while ((!ss_active() || budget--) && !ss_wq_pop(wq, &sw, &ticket)) {
		struct sock *sk = sw.sk;

		bh_lock_sock(sk);
		if (sock_flag(sk, SOCK_DEAD)) {
			/* We've closed the socket on earlier job. */
			bh_unlock_sock(sk);
			goto dead_sock;
		}
		switch (sw.action) {
		case SS_SEND:
			ss_do_send(sk, &sw.skb_head, sw.flags);
			if (!(sw.flags & SS_F_CONN_CLOSE)) {
				bh_unlock_sock(sk);
				break;
			}
			__sk_close_locked(sk); /* paired with bh_lock_sock() */
			break;
		case SS_CLOSE:
			if (!((1 << sk->sk_state)
			      & (TCPF_ESTABLISHED | TCPF_SYN_SENT)))
			{
				TFW_DBG2("[%d]: %s: Socket inactive: sk %p\n",
				         smp_processor_id(), __func__, sk);
				bh_unlock_sock(sk);
				break;
			}
			__sk_close_locked(sk); /* paired with bh_lock_sock() */
			break;
		default:
			BUG();
		}
dead_sock:
		sock_put(sk); /* paired with push() calls */
		while ((skb = ss_skb_dequeue(&sw.skb_head)))
			kfree_skb(skb);
	}

	/*
	 * Rearm softirq for local CPU if there are more jobs to do.
	 * If all jobs are finished, and work queue and backlog are
	 * empty, then enable IPI generation by producers (disabled
	 * in 'ss_ipi()' handler).
	 * ss_synchronize() is responsible for raising the softirq
	 * if there are more jobs in the work queue or the backlog.
	 */
	if (budget)
		TFW_WQ_IPI_SYNC(ss_wq_local_size, wq);

	raise_softirq(NET_TX_SOFTIRQ);
}

/*
 * ------------------------------------------------------------------------
 *  	Management stuff
 * ------------------------------------------------------------------------
 */
/**
 * Write per-CPU statistics to @stat.
 * @stat must point to large enough array.
 */
void
ss_get_stat(SsStat *stat)
{
	int cpu;

	for_each_online_cpu(cpu) {
		SsCloseBacklog *cb = &per_cpu(close_backlog, cpu);
		TfwRBQueue *wq = &per_cpu(si_wq, cpu);

		stat[cpu].rb_wq_sz = tfw_wq_size(wq);
		stat[cpu].backlog_sz = cb->size;
	}
}

/**
 * Synchronize with establishing new connections. It is guaranteed that there
 * will be no more new client connections and re-established connections to
 * backend servers after the call.
 */
void
ss_wait_newconn(void)
{
	int cpu;
	long acc = 0, acc_old = 0;
	unsigned long t0 = jiffies;

	might_sleep();
	while (1) {
		schedule(); /* let softirq finish works */
		for_each_online_cpu(cpu)
			acc += atomic64_read(per_cpu_ptr(&__ss_act_cnt, cpu));
		BUG_ON(acc < 0);
		if (!(acc & SS_M_ACT_NEWCONN))
			break;
		if (acc == acc_old) {
			if (t0 + HZ * 5 < jiffies) {
				TFW_WARN("pending listening sockets for 5s"
					 " (connections count %#lx)\n", acc);
				return;
			}
		} else {
			acc_old = acc;
			acc = 0;
		}
	}
}
EXPORT_SYMBOL(ss_wait_newconn);

/**
 * Wait until there are no queued works and no running tasklets.
 * The function should be used when all sockets are closed.
 * SS upcalls are protected with SS_V_ACT_LIVECONN.
 * Can sleep, so must be called from user-space context.
 */
void
ss_synchronize(void)
{
	int cpu, wq_acc = 0, wq_acc_old = 0;
	long acc = 0, acc_old = 0;
	unsigned long t0 = jiffies;

	might_sleep();
	while (1) {
		for_each_online_cpu(cpu) {
			atomic64_t *act_cnt = &per_cpu(__ss_act_cnt, cpu);
			int n_conn = atomic64_read(act_cnt) >> SS_ACT_SHIFT;
			int n_q = ss_wq_size(cpu);
			if (n_conn + n_q) {
				irq_work_sync(&per_cpu(ipi_work, cpu));
				schedule(); /* let softirq finish works */
			}
			acc += n_conn;
			wq_acc += n_q;
		}
		BUG_ON(acc < 0);
		if (!acc && !wq_acc)
			break;
		if (acc == acc_old && wq_acc == wq_acc_old) {
			if (t0 + HZ * 5 < jiffies) {
				TFW_WARN("pending active connections for 5s"
					 " (connections count %#lx,"
					 " queues count %d)\n", acc, wq_acc);
				for_each_online_cpu(cpu) {
					TfwRBQueue *wq = &per_cpu(si_wq, cpu);
					SsCloseBacklog *cb;
					cb = &per_cpu(close_backlog, cpu);
					TFW_WARN("  cpu %d(%d), backlog size %lu,"
						 " work queue size %d\n",
						 cpu, smp_processor_id(), cb->size,
						 tfw_wq_size(wq));
				}
				TFW_WARN("Memory leakage is possible\n");
				return;
			}
		}
		else if (acc + wq_acc < acc_old + wq_acc_old) {
			/* Reset the timeout if we're doing progress. */
			t0 = jiffies;
		}
		acc_old = acc;
		wq_acc_old = wq_acc;
		acc = wq_acc = 0;
	}
}
EXPORT_SYMBOL(ss_synchronize);

/**
 * We need the explicit flag about Tempesta intention to shutdown.
 * The problem is that there are upcalls from Linux TCP/IP layer allocating
 * new connections and downcalls from Tempesta layer working with sockets.
 * Shutdown code is also downcall executed in user context. There are socket
 * jobs waiting for tasklet to execute them. All in all we need the flag to be
 * able to wait while all upcalls are finished at each of several shutdown
 * stages such as closing listening sockets, closing client sockets and
 * finally closing server sockets.
 */
void
ss_start(void)
{
	/*
	 * Concurrent starts are synchronized at sysctl layer.
	 * Consecutive starts without stopping are for reconfiguration.
	 */
	if (tfw_runstate_is_reconfig())
		return;
	WRITE_ONCE(__ss_active, true);
}
EXPORT_SYMBOL(ss_start);

void
ss_stop(void)
{
	if (tfw_runstate_is_reconfig())
		return;
	WRITE_ONCE(__ss_active, false);
}
EXPORT_SYMBOL(ss_stop);

bool
ss_active(void)
{
	return READ_ONCE(__ss_active);
}
EXPORT_SYMBOL(ss_active);

int __init
tfw_sync_socket_init(void)
{
	int r, cpu;

	TFW_WQ_CHECKSZ(SsWork);
	ss_cbacklog_cache = kmem_cache_create("ss_cbacklog_cache",
					      sizeof(SsCblNode), 0, 0, NULL);
	if (!ss_cbacklog_cache)
		return -ENOMEM;
	for_each_online_cpu(cpu) {
		SsCloseBacklog *cb = &per_cpu(close_backlog, cpu);
		TfwRBQueue *wq = &per_cpu(si_wq, cpu);

		if ((r = tfw_wq_init(wq, cpu_to_node(cpu)))) {
			TFW_ERR_NL("Cannot initialize softirq tx work queue\n");
			kmem_cache_destroy(ss_cbacklog_cache);
			return r;
		}
		init_irq_work(&per_cpu(ipi_work, cpu), ss_ipi);

		INIT_LIST_HEAD(&cb->head);
		spin_lock_init(&cb->lock);
		cb->turn = LONG_MAX;
	}
	tempesta_set_tx_action(ss_tx_action);

	return 0;
}

void
tfw_sync_socket_exit(void)
{
	int cpu;

	tempesta_del_tx_action();
	for_each_online_cpu(cpu) {
		irq_work_sync(&per_cpu(ipi_work, cpu));
		tfw_wq_destroy(&per_cpu(si_wq, cpu));
		ss_backlog_validate_cleanup(cpu);
	}
	kmem_cache_destroy(ss_cbacklog_cache);
}
