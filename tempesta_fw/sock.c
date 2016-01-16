/**
 *		Synchronous Socket API.
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2016 Tempesta Technologies, Inc.
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

#include "log.h"
#include "sync_socket.h"
#include "work_queue.h"

typedef enum {
	SS_SEND,
	SS_CLOSE,
} SsAction;

typedef struct {
	struct sock	*sk;
	SsSkbList	skb_list;
	SsAction	action;
} SsWork;

#if defined(DEBUG) && (DEBUG >= 2)
static const char *ss_statename[] = {
	"Unused",	"Established",	"Syn Sent",	"Syn Recv",
	"Fin Wait 1",	"Fin Wait 2",	"Time Wait",	"Close",
	"Close Wait",	"Last ACK",	"Listen",	"Closing"
};
#endif

static DEFINE_PER_CPU(TfwRBQueue, si_wq);
static DEFINE_PER_CPU(struct irq_work, ipi_work);

#define SS_CALL(f, ...)							\
	(sk->sk_user_data && ((SsProto *)(sk)->sk_user_data)->hooks->f	\
	? ((SsProto *)(sk)->sk_user_data)->hooks->f(__VA_ARGS__)	\
	: 0)

static void
ss_ipi(struct irq_work *work)
{
	raise_softirq(NET_TX_SOFTIRQ);
}

static int
ss_wq_push(SsWork *sw)
{
	int cpu = sw->sk->sk_incoming_cpu;
	TfwRBQueue *wq = &per_cpu(si_wq, cpu);
	struct irq_work *iw = &per_cpu(ipi_work, cpu);

	return tfw_wq_push(wq, sw, cpu, iw);
}

/*
 * Socket is in a usable state that allows processing
 * and sending of HTTP messages. This function must
 * be used consistently across all involved functions.
 */
static inline bool
ss_sock_active(struct sock *sk)
{
	return (1 << sk->sk_state) & (TCPF_ESTABLISHED | TCPF_CLOSE_WAIT);
}

/**
 * Copied from net/netfilter/xt_TEE.c.
 */
static struct net *
ss_pick_net(struct sk_buff *skb)
{
#ifdef CONFIG_NET_NS
	const struct dst_entry *dst;

	if (skb->dev != NULL)
		return dev_net(skb->dev);
	dst = skb_dst(skb);
	if (dst != NULL && dst->dev != NULL)
		return dev_net(dst->dev);
#endif
	return &init_net;
}

static void
ss_skb_set_dst(struct sk_buff *skb, struct dst_entry *dst)
{
	skb_dst_drop(skb);
	skb_dst_set(skb, dst);
	skb->dev = dst->dev;
}

/**
 * Reroute a packet to the destination for IPv4 and IPv6.
 */
static struct dst_entry *
ss_skb_route(struct sk_buff *skb, struct tcp_sock *tp)
{
	struct inet_sock *isk = &tp->inet_conn.icsk_inet;
	struct dst_entry *dst = NULL;
#if IS_ENABLED(CONFIG_IPV6)
	struct ipv6_pinfo *np = inet6_sk(&isk->sk);

	if (np) {
		struct flowi6 fl6 = { .daddr = isk->sk.sk_v6_daddr };

		BUG_ON(isk->sk.sk_family != AF_INET6);
		BUG_ON(skb->protocol != htons(ETH_P_IPV6));

		dst = ip6_route_output(ss_pick_net(skb), NULL, &fl6);
		if (dst->error) {
			dst_release(dst);
			return NULL;
		}
	} else
#endif
	{
		struct rtable *rt;
		struct flowi4 fl4 = { .daddr = isk->inet_daddr };

		BUG_ON(isk->sk.sk_family != AF_INET);

		rt = ip_route_output_key(ss_pick_net(skb), &fl4);
		if (IS_ERR(rt))
			return NULL;
		dst = &rt->dst;
	}

	return dst;
}

static void
ss_skb_entail(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);

	skb->csum    = 0;
	tcb->seq     = tcb->end_seq = tp->write_seq;
	tcb->tcp_flags = TCPHDR_ACK;
	tcb->sacked  = 0;
	skb_header_release(skb);
	tcp_add_write_queue_tail(sk, skb);
	sk->sk_wmem_queued += skb->truesize;
	sk_mem_charge(sk, skb->truesize);
	if (tp->nonagle & TCP_NAGLE_PUSH)
		tp->nonagle &= ~TCP_NAGLE_PUSH;
}

/*
 * ------------------------------------------------------------------------
 *  	Server and client connections handling
 * ------------------------------------------------------------------------
 */
/**
 * @skb_list can be invalid after the function call, don't try to use it.
 */
static void
ss_do_send(struct sock *sk, SsSkbList *skb_list)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb, *iskb;
	struct dst_entry *dst = NULL;
	int r = 0, size, mss = tcp_send_mss(sk, &size, MSG_DONTWAIT);

	SS_DBG("%s: cpu=%d sk=%p queue_empty=%d send_head=%p"
	       " sk_state=%d mss=%d size=%d\n", __func__,
	       raw_smp_processor_id(), sk, tcp_write_queue_empty(sk),
	       tcp_send_head(sk), sk->sk_state, mss, size);

	if (unlikely(!ss_sock_active(sk)))
		return;

	for (iskb = ss_skb_peek(skb_list), skb = iskb;
	     iskb; iskb = ss_skb_next(skb_list, iskb), skb = iskb)
	{
		ss_skb_unlink(skb_list, skb);

		skb->ip_summed = CHECKSUM_PARTIAL;
		skb_shinfo(skb)->gso_segs = 0;

		/*
		 * TODO Mark all data with PUSH to force receiver to consume
		 * the data. Currently we do this for debugging purposes.
		 * We need to do this only for complete messages/skbs.
		 * Actually tcp_push() already does it for the last skb.
		 */
		tcp_mark_push(tp, skb);

		SS_DBG("%s: entail skb=%p data_len=%u len=%u\n",
		       __func__, skb, skb->data_len, skb->len);

		ss_skb_entail(sk, skb);

		tp->write_seq += skb->len;
		TCP_SKB_CB(skb)->end_seq += skb->len;

		/*
		 * Reuse routing information for the same connection.
		 *
		 * TODO should we rather use sk_dst_check()?
		 *
		 * TODO get route information for dst connection for
		 * retransmission or src for replying.
		 */
		if (!dst) {
			dst = ss_skb_route(skb, tp);
			if (!dst) {
				SS_WARN("cannot route skb %p\n", skb);
				r = -ENODEV;
				break;
			}
		} else {
			dst_hold(dst);
		}
		ss_skb_set_dst(skb, dst);
		BUG_ON(!skb->dev);
	}

	SS_DBG("%s: sk=%p send_head=%p sk_state=%d\n", __func__,
	       sk, tcp_send_head(sk), sk->sk_state);

	tcp_push(sk, MSG_DONTWAIT, mss, TCP_NAGLE_OFF|TCP_NAGLE_PUSH, size);

	if (unlikely(r))
		for (iskb = ss_skb_peek(skb_list), skb = iskb;
		     iskb; iskb = ss_skb_next(skb_list, iskb), skb = iskb)
			kfree_skb(skb);
}

/**
 * Directly insert all skbs from @skb_list into @sk TCP write queue regardless
 * write buffer size. This allows directly forward modified packets without
 * copying. See do_tcp_sendpages() and tcp_sendmsg() in linux/net/ipv4/tcp.c.
 *
 * Can be called in softirq context as well as from kernel thread.
 *
 * TODO use MSG_MORE untill we reach end of message.
 */
int
ss_send(struct sock *sk, SsSkbList *skb_list, bool pass_skb)
{
	int r = 0;
	struct sk_buff *skb, *iskb;
	SsWork sw = {
		.sk	= sk,
		.action	= SS_SEND,
	};

	BUG_ON(!sk);
	BUG_ON(ss_skb_queue_empty(skb_list));

	SS_DBG("%s: cpu=%d sk=%p (%s)\n", __func__,
	       raw_smp_processor_id(), sk, ss_statename[sk->sk_state]);

	/*
	 * Remove the skbs from Tempesta lists if we won't use them,
	 * or copy them if they're going to be used by Tempesta during
	 * and after the transmission.
	 */
	if (pass_skb) {
		memcpy(&sw.skb_list, skb_list, sizeof(*skb_list));
		ss_skb_queue_head_init(skb_list);
	} else {
		ss_skb_queue_head_init(&sw.skb_list);
		for (iskb = ss_skb_peek(skb_list), skb = iskb;
		     iskb; iskb = ss_skb_next(skb_list, iskb), skb = iskb)
		{
			/* tcp_transmit_skb() will clone the skb. */
			skb = pskb_copy_for_clone(skb, GFP_ATOMIC);
			if (!skb) {
				SS_WARN("Unable to copy an egress SKB.\n");
				r = -ENOMEM;
				goto err;
			}
			ss_skb_queue_tail(&sw.skb_list, skb);
		}
	}

	/*
	 * Schedule the socket for TX softirq processing.
	 * Only part of @skb_list could be passed to send queue.
	 */
	if (ss_wq_push(&sw)) {
		SS_WARN("Cannot schedule socket %p for transmission\n", sk);
		r = -EBUSY;
		goto err;
	}

	return 0;
err:
	if (!pass_skb)
		for (iskb = ss_skb_peek(&sw.skb_list), skb = iskb;
		     iskb; iskb = ss_skb_next(&sw.skb_list, iskb), skb = iskb)
			kfree_skb(skb);
	return r;
}

/**
 * This is main body of the socket close function in Sync Sockets.
 *
 * inet_release() can sleep (as well as tcp_close()), so we make our own
 * non-sleepable socket closing.
 *
 * This function must be used only for data sockets.
 * Use standard sock_release() for listening sockets.
 *
 * In most cases it's called from softirq and from softirqd which processes
 * data from the socket (RSS and RPS distributes packets in such way).
 * However, it also can be called from process context,
 * e.g. on module unloading.
 *
 * TODO In some cases we need to close socket agresively w/o FIN_WAIT_2 state,
 * e.g. by sending RST. So we need to add second parameter to the function
 * which says how to close the socket.
 * One of the examples is rcl_req_limit() (it should reset connections).
 * See tcp_sk(sk)->linger2 processing in standard tcp_close().
 */
static void
ss_do_close(struct sock *sk)
{
	struct sk_buff *skb;
	int data_was_unread = 0;
	int state;

	if (unlikely(!sk))
		return;
	BUG_ON(sk->sk_state == TCP_LISTEN);

	SS_DBG("Close socket %p (%s): cpu=%d account=%d sk_socket=%p"
	       " refcnt=%d\n",
	       sk, ss_statename[sk->sk_state], raw_smp_processor_id(),
	       sk_has_account(sk), sk->sk_socket, atomic_read(&sk->sk_refcnt));

	/* We must return immediately, so LINGER option is meaningless. */
	WARN_ON(sock_flag(sk, SOCK_LINGER));
	/* We don't support virtual containers, so TCP_REPAIR is prohibited. */
	WARN_ON(tcp_sk(sk)->repair);
	/* The socket must have atomic allocation mask. */
	WARN_ON(!(sk->sk_allocation & GFP_ATOMIC));

	/* The below is mostly copy-paste from tcp_close(). */
	sk->sk_shutdown = SHUTDOWN_MASK;

	while ((skb = __skb_dequeue(&sk->sk_receive_queue)) != NULL) {
		u32 len = TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq -
			  tcp_hdr(skb)->fin;
		data_was_unread += len;
		SS_DBG("free rcv skb %p\n", skb);
		__kfree_skb(skb);
	}

	sk_mem_reclaim(sk);

	if (sk->sk_state == TCP_CLOSE)
		goto adjudge_to_death;

	if (data_was_unread) {
		NET_INC_STATS_USER(sock_net(sk), LINUX_MIB_TCPABORTONCLOSE);
		tcp_set_state(sk, TCP_CLOSE);
		tcp_send_active_reset(sk, sk->sk_allocation);
	}
	else if (tcp_close_state(sk)) {
		/* The code below is taken from tcp_send_fin(). */
		struct tcp_sock *tp = tcp_sk(sk);
		int mss_now = tcp_current_mss(sk);

		skb = tcp_write_queue_tail(sk);

		if (tcp_send_head(sk) != NULL) {
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
				SS_WARN("can't send FIN due to bad alloc");
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
	state = sk->sk_state;
	sock_hold(sk);
	sock_orphan(sk);

	/*
	 * TODO the check looks very dirty...
	 * Move it to user space ss_close()?
	 */
	if (likely(!in_softirq()))
		bh_lock_sock(sk);

	/*
	 * SS sockets are processed in softirq only,
	 * so backlog queue should be empty.
	 */
	WARN_ON(sk->sk_backlog.tail);

	percpu_counter_inc(sk->sk_prot->orphan_count);

	if (state != TCP_CLOSE && sk->sk_state == TCP_CLOSE)
		goto out;

	if (sk->sk_state == TCP_FIN_WAIT2) {
		const int tmo = tcp_fin_time(sk);
		if (tmo > TCP_TIMEWAIT_LEN) {
			inet_csk_reset_keepalive_timer(sk,
						tmo - TCP_TIMEWAIT_LEN);
		} else {
			tcp_time_wait(sk, TCP_FIN_WAIT2, tmo);
			goto out;
		}
	}
	if (sk->sk_state != TCP_CLOSE) {
		sk_mem_reclaim(sk);
		if (tcp_check_oom(sk, 0)) {
			tcp_set_state(sk, TCP_CLOSE);
			tcp_send_active_reset(sk, GFP_ATOMIC);
			NET_INC_STATS_BH(sock_net(sk),
					 LINUX_MIB_TCPABORTONMEMORY);
		}
	}
	if (sk->sk_state == TCP_CLOSE) {
		struct request_sock *req = tcp_sk(sk)->fastopen_rsk;
		if (req != NULL)
			reqsk_fastopen_remove(sk, req, false);
		inet_csk_destroy_sock(sk);
	}
out:
	if (unlikely(!in_softirq()))
		bh_unlock_sock(sk);
}

int
ss_close(struct sock *sk)
{
	SsWork sw = {
		.sk	= sk,
		.action	= SS_CLOSE,
	};

	if (ss_wq_push(&sw)) {
		SS_WARN("Cannot schedule socket %p for closing\n", sk);
		return SS_ERR;
	}
	return SS_OK;
}
EXPORT_SYMBOL(ss_close);

/*
 * Close the socket first. We're done with it anyway. Then release
 * all Tempesta resources linked with the socket, start failover
 * procedure if necessary, and cut all ties with Tempesta. That
 * stops all traffic from coming to Tempesta.
 *
 * The order in which these actions are executed is important.
 * The failover procedure expects that the socket is inactive.
 *
 * This function is for internal Sync Sockets use only. It's called
 * under the socket lock taken by the kernel, and in the context of
 * the socket that is being closed.
 *
 * Called with locked socket.
 */
static void
ss_droplink(struct sock *sk)
{
	/*
	 * sk->sk_user_data may come NULLed. That's a valid
	 * case that may occur when there's an error during
	 * the allocation of resources for a client connection.
	 */
	BUG_ON(!ss_sock_active(sk));

	ss_do_close(sk);
	SS_CALL(connection_drop, sk);
	sock_put(sk);
}

/**
 * Receive data on TCP socket. Very similar to standard tcp_recvmsg().
 *
 * We can't use standard tcp_read_sock() with our actor callback, because
 * tcp_read_sock() calls __kfree_skb() through sk_eat_skb() which is good
 * for copying data from skb, but we need to manage skb's ourselves.
 *
 * TODO:
 * -- process URG
 */
static bool
ss_tcp_process_data(struct sock *sk)
{
	bool tcp_fin, droplink = true;
	int processed = 0;
	unsigned int off;
	struct sk_buff *skb, *tmp;
	struct tcp_sock *tp = tcp_sk(sk);

	skb_queue_walk_safe(&sk->sk_receive_queue, skb, tmp) {
		if (unlikely(before(tp->copied_seq, TCP_SKB_CB(skb)->seq))) {
			SS_WARN("recvmsg bug: TCP sequence gap at seq %X"
				" recvnxt %X\n",
				tp->copied_seq, TCP_SKB_CB(skb)->seq);
			goto out;
		}

		__skb_unlink(skb, &sk->sk_receive_queue);
		skb_orphan(skb);

		/* Shared SKBs shouldn't be seen here. */
		if (skb_shared(skb))
			BUG();
		/*
		 * Cloned SKBs come here if a client or a back end are
		 * on the same host as Tempesta. Cloning is happen in
		 * tcp_transmit_skb() as it is for all egress packets,
		 * but packets on loopback go to us as is, i.e. cloned.
		 *
		 * Tempesta adjusts skb pointers, but leaves original
		 * data untouched (this is also required in order to
		 * keep pointers to our parsed HTTP data structures
		 * unchanged). So skb uncloning is sufficient here.
		 */
		if (skb_unclone(skb, GFP_ATOMIC)) {
			SS_WARN("Error uncloning ingress skb: sk %p\n", sk);
			goto out;
		}

		/* SKB may be freed in processing. Save the flag. */
		tcp_fin = tcp_hdr(skb)->fin;
		off = tp->copied_seq - TCP_SKB_CB(skb)->seq;
		if (tcp_hdr(skb)->syn)
			off--;
		if (likely(off < skb->len)) {
			int r, count = skb->len - off;
			void *conn = rcu_dereference_sk_user_data(sk);

			/*
			 * If @sk_user_data is unset, then this connection
			 * had been dropped in a parallel thread. Dropping
			 * a connection is serialized with the socket lock.
			 * The receive queue must be empty in that case,
			 * and the execution path should never reach here.
			 */
			BUG_ON(conn == NULL);

			r = SS_CALL(connection_recv, conn, skb, off);

			/*
			 * The socket @sk may have been closed as a result
			 * of data processing in this or in parallel thread.
			 * However the socket is not destroyed until control
			 * is returned back to the Linux kernel.
			 */
			if (r < 0) {
				SS_WARN("Error processing data: sk %p\n", sk);
				goto out; /* connection dropped */
			}
			tp->copied_seq += count;
			processed += count;

			if (tcp_fin) {
				SS_DBG("Data FIN received: sk %p\n", sk);
				++tp->copied_seq;
				goto out;
			}

			if (r == SS_STOP) {
				SS_DBG("Stop processing data: sk %p\n", sk);
				break;
			}
		} else if (tcp_fin) {
			__kfree_skb(skb);
			SS_DBG("Link FIN received: sk %p\n", sk);
			++tp->copied_seq;
			goto out;
		} else {
			SS_WARN("recvmsg bug: overlapping TCP segment at %X"
				" seq %X rcvnxt %X len %x\n",
				tp->copied_seq, TCP_SKB_CB(skb)->seq,
				tp->rcv_nxt, skb->len);
			__kfree_skb(skb);
		}
	}
	droplink = false;
out:
	/*
	 * Recalculate an appropriate TCP receive buffer space
	 * and send ACK to a client with the new window.
	 */
	tcp_rcv_space_adjust(sk);
	if (processed)
		tcp_cleanup_rbuf(sk, processed);

	return droplink;
}

/**
 * Just drain accept queue of listening socket &lsk.
 * See implementation of standard inet_csk_accept().
 */
static void
ss_drain_accept_queue(struct sock *lsk, struct sock *nsk)
{
	struct inet_connection_sock *icsk = inet_csk(lsk);
	struct request_sock_queue *queue = &icsk->icsk_accept_queue;
#if 0
	struct request_sock *prev_r, *req;
#else
	struct request_sock *req;
#endif
	SS_DBG("%s: sk %p, sk->sk_socket %p, state (%s)\n",
		__func__, lsk, lsk->sk_socket, ss_statename[lsk->sk_state]);

	/* Currently we process TCP only. */
	BUG_ON(lsk->sk_protocol != IPPROTO_TCP);

	WARN(reqsk_queue_empty(queue),
	     "drain empty accept queue for socket %p", lsk);

#if 0
	/* TODO it works to slowly, need to patch Linux kernel to make it faster. */
	for (prev_r = NULL, req = queue->rskq_accept_head; req;
	     prev_r = req, req = req->dl_next)
	{
		if (req->sk != nsk)
			continue;
		/* We found the socket, remove it. */
		if (prev_r) {
			/* There are some items before @req in the queue. */
			prev_r->dl_next = req->dl_next;
			if (queue->rskq_accept_tail == req)
				/* @req is the last item. */
				queue->rskq_accept_tail = prev_r;
		} else {
			/* @req is the first item in the queue. */
			queue->rskq_accept_head = req->dl_next;
			if (queue->rskq_accept_head == NULL)
				/* The queue contained only this one item. */
				queue->rskq_accept_tail = NULL;
		}
		break;
	}
#else
	/*
	 * FIXME push any request from the queue,
	 * doesn't matter which exactly.
	 */
	req = reqsk_queue_remove(queue);
#endif
	BUG_ON(!req);
	sk_acceptq_removed(lsk);

	/*
	 * @nsk is in ESTABLISHED state, so 3WHS has completed and
	 * we can safely remove the request socket from accept queue of @lsk.
	 */
	reqsk_put(req);
}

/*
 * ------------------------------------------------------------------------
 *  	Socket callbacks
 * ------------------------------------------------------------------------
 */
static void ss_tcp_state_change(struct sock *sk);

/*
 * Called when a new data received on the socket.
 * Called under bh_lock_sock_nested(sk) (see tcp_v4_rcv()).
 */
static void
ss_tcp_data_ready(struct sock *sk)
{
	SS_DBG("%s: sk %p, sk->sk_socket %p, state (%s)\n",
		__func__, sk, sk->sk_socket, ss_statename[sk->sk_state]);

	WARN_ON(!spin_is_locked(&sk->sk_lock.slock));

	if (!skb_queue_empty(&sk->sk_error_queue)) {
		/*
		 * Error packet received.
		 * See sock_queue_err_skb() in linux/net/core/skbuff.c.
		 */
		SS_ERR("error data in socket %p\n", sk);
	}
	else if (!skb_queue_empty(&sk->sk_receive_queue)) {
		if (ss_tcp_process_data(sk)) {
			/*
			 * Drop connection in case of internal errors,
			 * or banned packets.
			 *
			 * ss_droplink() is responsible for calling
			 * application layer connection closing callback.
			 * The callback will free all SKBs linked with
			 * the message that is currently being processed.
			 */
			ss_droplink(sk);
		}
	}
	else {
		/*
		 * Check for URG data.
		 * TODO shouldn't we do it in th_tcp_process_data()?
		 */
		struct tcp_sock *tp = tcp_sk(sk);
		if (tp->urg_data & TCP_URG_VALID) {
			tp->urg_data = 0;
			SS_DBG("urgent data in socket %p\n", sk);
		}
	}
}

/**
 * Socket state change callback.
 */
static void
ss_tcp_state_change(struct sock *sk)
{
	SS_DBG("%s: sk %p, sk->sk_socket %p, state (%s)\n",
		__func__, sk, sk->sk_socket, ss_statename[sk->sk_state]);

	WARN_ON(!spin_is_locked(&sk->sk_lock.slock));

	if (sk->sk_state == TCP_ESTABLISHED) {
		/* Process the new TCP connection. */
		SsProto *proto = rcu_dereference_sk_user_data(sk);
		struct sock *lsk = proto->listener;
		int r;

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
			SS_DBG("New connection hook failed, r=%d\n", r);
			ss_droplink(sk);
			return;
		}
		if (lsk) {
			/*
			 * This is a new socket for an accepted connect
			 * request that the kernel has allocated itself.
			 * Kernel initializes this field to GFP_KERNEL.
			 * Tempesta works with sockets in SoftIRQ context,
			 * so set it to atomic allocation.
			 */
			sk->sk_allocation = GFP_ATOMIC;

			/*
			 * We know which socket is just accepted.
			 * Just drain listening socket accept queue,
			 * and don't care about the returned socket.
			 */
			assert_spin_locked(&lsk->sk_lock.slock);
			ss_drain_accept_queue(lsk, sk);
		}
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
		SS_DBG("Peer connection closing\n");
		ss_droplink(sk);
	}
	else if (sk->sk_state == TCP_CLOSE) {
		/*
		 * In current implementation we never reach TCP_CLOSE state
		 * in regular course of action. When a socket is moved from
		 * TCP_ESTABLISHED state to a closing state, we forcefully
		 * close the socket before it can reach the final state.
		 *
		 * We get here when an error has occured in the connection.
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
		ss_do_close(sk);
		SS_CALL(connection_error, sk);
		sock_put(sk);
	}
}

void
ss_proto_init(SsProto *proto, const SsHooks *hooks, int type)
{
	proto->hooks = hooks;
	proto->type = type;

	/* The memory allocated for @proto should be already zero'ed, so don't
	 * initialize this field to NULL, but instead check the invariant. */
	BUG_ON(proto->listener);
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
	BUG_ON(!sk->sk_user_data);

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
	BUG_ON(type != SOCK_STREAM || protocol != IPPROTO_TCP);

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

	if (!(sk = sk_alloc(net, pfinet, GFP_ATOMIC, answer_prot)))
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

	rcu_read_lock();
	if ((pf = get_proto_family(family)) == NULL)
		goto out_rcu_unlock;
	if (!try_module_get(pf->owner))
		goto out_rcu_unlock;
	rcu_read_unlock();

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
	rcu_read_unlock();
	goto out_ret_error;
}
EXPORT_SYMBOL(ss_sock_create);

/*
 * The original functions are inet_release() and inet6_release().
 * NOTE: Rework this function if/when Tempesta needs multicast support.
 */
void
ss_release(struct sock *sk)
{
	BUG_ON(sock_flag(sk, SOCK_LINGER));

	sk->sk_prot->close(sk, 0);
}
EXPORT_SYMBOL(ss_release);

/**
 * The original function is inet_stream_connect() that is common
 * to IPv4 and IPv6.
 */
int
ss_connect(struct sock *sk, struct sockaddr *uaddr, int uaddr_len, int flags)
{
	BUG_ON((sk->sk_family != AF_INET) && (sk->sk_family != AF_INET6));
	BUG_ON((uaddr->sa_family != AF_INET) && (uaddr->sa_family != AF_INET6));

	if (uaddr_len < sizeof(uaddr->sa_family))
		return -EINVAL;
	if (sk->sk_state != TCP_CLOSE)
		return -EISCONN;

	return sk->sk_prot->connect(sk, uaddr, uaddr_len);
}
EXPORT_SYMBOL(ss_connect);

/*
 * The original functions are inet_bind() and inet6_bind().
 * These two can be made a bit shorter should that become necessary.
 */
int
ss_bind(struct sock *sk, struct sockaddr *uaddr, int uaddr_len)
{
	struct socket sock = {
		.sk = sk,
		.type = sk->sk_type
	};
	BUG_ON((sk->sk_family != AF_INET) && (sk->sk_family != AF_INET6));
	BUG_ON(sk->sk_type != SOCK_STREAM);
	if (sk->sk_family == AF_INET)
		return inet_bind(&sock, uaddr, uaddr_len);
	else
		return inet6_bind(&sock, uaddr, uaddr_len);
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
	BUG_ON(sk->sk_type != SOCK_STREAM);
	return inet_listen(&sock, backlog);
}
EXPORT_SYMBOL(ss_listen);

/*
 * The original functions are inet_getname() and inet6_getname().
 * There isn't much to make shorter there, so just invoke them directly.
 */
int
ss_getpeername(struct sock *sk, struct sockaddr *uaddr, int *uaddr_len)
{
	struct socket sock = { .sk = sk };

	BUG_ON((sk->sk_family != AF_INET) && (sk->sk_family != AF_INET6));
	if (sk->sk_family == AF_INET)
		return inet_getname(&sock, uaddr, uaddr_len, 1);
	else
		return inet6_getname(&sock, uaddr, uaddr_len, 1);
}
EXPORT_SYMBOL(ss_getpeername);

static void
ss_tx_action(void)
{
	SsWork sw;

	while (!tfw_wq_pop(this_cpu_ptr(&si_wq), &sw)) {
		/* The socket should be accessed by one CPU only. */
		WARN_ON(spin_is_locked(&sw.sk->sk_lock.slock));
		spin_lock_bh(&sw.sk->sk_lock.slock);

		switch (sw.action) {
		case SS_SEND:
			ss_do_send(sw.sk, &sw.skb_list);
			break;
		case SS_CLOSE:
			ss_do_close(sw.sk);
			sock_put(sw.sk);
			break;
		}

		spin_unlock_bh(&sw.sk->sk_lock.slock);
	}
}

int __init
tfw_sync_socket_init(void)
{
	int r, cpu;

	TFW_WQ_CHECKSZ(SsWork);
	for_each_possible_cpu(cpu) {
		TfwRBQueue *wq = &per_cpu(si_wq, cpu);
		if ((r = tfw_wq_init(wq, cpu_to_node(cpu)))) {
			SS_ERR("Cannot initialize softirq tx work queue\n");
			return r;
		}
		init_irq_work(&per_cpu(ipi_work, cpu), ss_ipi);
	}
	tempesta_set_tx_action(ss_tx_action);

	return 0;
}

void
tfw_sync_socket_exit(void)
{
	int cpu;

	tempesta_del_tx_action();
	for_each_possible_cpu(cpu)
		tfw_wq_destroy(&per_cpu(si_wq, cpu));
}
