/**
 *		Tempesta FW
 *
 * Synchronous Sockets API for Linux socket buffers manipulation.
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
#ifndef __TFW_SS_SKB_H__
#define __TFW_SS_SKB_H__

#include <linux/skbuff.h>

#include "str.h"

/**
 * Responses from socket hook functions.
 */
enum {
	/* The packet must be dropped. */
	SS_DROP		= -2,

	/* The packet should be stashed (made by callback). */
	SS_POSTPONE	= -1,

	/* The packet looks good and we can safely pass it. */
	SS_OK		= 0,

	/* Stop passing data to the upper layer for processing. */
	SS_STOP		= 1,
};

typedef struct {
	struct sk_buff	*first;
	struct sk_buff	*last;
} SsSkbList;

typedef int (*ss_skb_actor_t)(void *conn, unsigned char *data, size_t len);

/**
 * The functions below are full analogs of standard Linux functions
 * w/o "ss_" prefix.
 */

static inline void
ss_skb_queue_head_init(SsSkbList *list)
{
	list->first = list->last = (struct sk_buff *)list;
}

static inline int
ss_skb_queue_empty(const SsSkbList *list)
{
	return list->first == (struct sk_buff *)list;
}

/**
 * Add new @skb to the @list in FIFO order.
 */
static inline void
ss_skb_queue_tail(SsSkbList *list, struct sk_buff *skb)
{
	SsSkbCb *scb = TFW_SKB_CB(skb);

	/* Don't link the skb twice. */
	if (unlikely(ss_skb_passed(skb)))
		return;

	scb->next = (struct sk_buff *)list;
	scb->prev = list->last;
	if (ss_skb_queue_empty(list))
		list->first = skb;
	else
		TFW_SKB_CB(list->last)->next = skb;
	list->last = skb;
}

static inline void
ss_skb_unlink(SsSkbList *list, struct sk_buff *skb)
{
	SsSkbCb *scb = TFW_SKB_CB(skb);

	if (scb->next == (struct sk_buff *)list) {
		list->last = scb->prev;
	} else {
		TFW_SKB_CB(scb->next)->prev = scb->prev;
	}
	if (scb->prev == (struct sk_buff *)list) {
		list->first = scb->next;
	} else {
		TFW_SKB_CB(scb->prev)->next = scb->next;
	}
	scb->next = scb->prev = NULL;
}

static inline struct sk_buff *
ss_skb_next(const SsSkbList *list, struct sk_buff *skb)
{
	skb = TFW_SKB_CB(skb)->next;

	if (skb == (struct sk_buff *)list)
		return NULL;
	return skb;

}

static inline struct sk_buff *
ss_skb_peek(const SsSkbList *list)
{
	struct sk_buff *skb = list->first;

	if (skb == (struct sk_buff *)list)
		return NULL;
	return skb;
}

static inline struct sk_buff *
ss_skb_peek_tail(const SsSkbList *list)
{
	struct sk_buff *skb = list->last;

	if (skb == (struct sk_buff *)list)
		return NULL;
	return skb;

}

static inline struct sk_buff *
ss_skb_dequeue(SsSkbList *list)
{
	struct sk_buff *skb = ss_skb_peek(list);
	if (skb)
		ss_skb_unlink(list, skb);
	return skb;
}

static inline skb_frag_t *
ss_skb_frag_next(const SsSkbList *list, struct sk_buff **skb, int *f)
{
	if (skb_shinfo(*skb)->nr_frags > *f + 1) {
		++*f;
		return &skb_shinfo(*skb)->frags[*f];
	}

	*skb = ss_skb_next(list, *skb);
	if (!*skb || !skb_shinfo(*skb)->nr_frags)
		return NULL;
	*f = 0;
	return &skb_shinfo(*skb)->frags[0];
}

static inline void
ss_skb_adjust_data_len(struct sk_buff *skb, int delta)
{
	skb->len += delta;
	skb->data_len += delta;
	skb->truesize += delta;
}

/*
 * skb_tailroom - number of bytes at buffer end
 *
 * This function is nearly a copy of the original that is defined
 * in include/linux/skbuff.h. The difference is that the original
 * only works on a linear skb, while this one works on any skb.
 */
static inline int
ss_skb_tailroom(const struct sk_buff *skb)
{
	return skb->end - skb->tail;
}

/*
 * skb_put - add data to a buffer
 *
 * This function is nearly a copy of the original that is defined
 * in net/core/skbuff.c. The difference is that the original only
 * works on a linear skb, while this one works on any skb.
 */
static inline unsigned char *
ss_skb_put(struct sk_buff *skb, unsigned int len)
{
	unsigned char *tmp = skb_tail_pointer(skb);
	skb->tail += len;
	skb->len  += len;
	if (unlikely(skb->tail > skb->end))
		BUG();
	return tmp;
}

static inline struct sk_buff *
ss_skb_alloc(void)
{
	struct sk_buff *skb = alloc_skb(MAX_TCP_HEADER, GFP_ATOMIC);

	if (!skb)
		return NULL;
	skb_reserve(skb, MAX_TCP_HEADER);

	return skb;
}

#define SS_SKB_MAX_DATA_LEN	(MAX_SKB_FRAGS * PAGE_SIZE)

char *ss_skb_fmt_src_addr(const struct sk_buff *skb, char *out_buf);

struct sk_buff *ss_skb_alloc_pages(size_t len);

struct sk_buff *ss_skb_split(struct sk_buff *skb, int len);

int ss_skb_get_room(struct sk_buff *skb, char *pspt, unsigned int len,
		    TfwStr *it);
int ss_skb_cutoff_data(SsSkbList *head, const TfwStr *it, int skip, int tail);

int ss_skb_process(struct sk_buff *skb, unsigned int *off,
		   ss_skb_actor_t actor, void *objdata);

#endif /* __TFW_SS_SKB_H__ */
