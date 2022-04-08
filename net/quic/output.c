// SPDX-License-Identifier: GPL-2.0-or-later
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2021
 *
 * This file is part of the QUIC kernel implementation
 *
 * Initialization/cleanup for QUIC protocol support.
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#include <net/quic/quic.h>

int quic_v4_flow_route(struct quic_sock *qs)
{
	struct sock *sk = &qs->inet.sk;
	struct flowi4 *fl4;
	struct rtable *rt;
	struct flowi _fl;

	if (__sk_dst_get(sk))
		return 0;

	fl4 = &_fl.u.ip4;
	memset(&_fl, 0x00, sizeof(_fl));
	fl4->saddr = qs->src.v4.sin_addr.s_addr;
	fl4->daddr = qs->dest.v4.sin_addr.s_addr;
	fl4->fl4_sport = qs->src.v4.sin_port;
	fl4->fl4_dport = qs->dest.v4.sin_port;

	rt = ip_route_output_key(sock_net(sk), fl4);
	if (IS_ERR(rt))
		return PTR_ERR(rt);

	sk_dst_set(sk, &rt->dst);
	return 0;
}

int quic_v6_flow_route(struct quic_sock *qs)
{
	struct sock *sk = &qs->inet.sk;
	struct dst_entry *dst;
	struct flowi6 *fl6;
	struct flowi _fl;

	if (__sk_dst_get(sk))
		return 0;

	fl6 = &_fl.u.ip6;
	memset(&_fl, 0x0, sizeof(_fl));
	fl6->daddr = qs->dest.v6.sin6_addr;
	fl6->fl6_dport = qs->dest.v6.sin6_port;
	fl6->saddr = qs->src.v6.sin6_addr;
	fl6->fl6_sport = qs->src.v6.sin6_port;

	dst = ip6_dst_lookup_flow(sock_net(sk), sk, fl6, NULL);
	if (IS_ERR(dst))
		return PTR_ERR(dst);

	sk_dst_set(sk, dst);
	return 0;
}

void quic_v4_lower_xmit(struct quic_sock *qs, struct sk_buff *skb)
{
	struct sock *sk = &qs->inet.sk;
	struct inet_sock *inet = inet_sk(sk);
	struct dst_entry *dst = sk_dst_get(sk);
	__u8 dscp = inet->tos;
	__be16 df = 0;

	pr_info("%s: skb: %p len: %d | path: %pI4:%d -> %pI4:%d\n",
		__func__, skb, skb->len,
		&qs->src.v4.sin_addr.s_addr, ntohs(qs->src.v4.sin_port),
		&qs->dest.v4.sin_addr.s_addr, ntohs(qs->dest.v4.sin_port));

	if (ip_dont_fragment(sk, dst) && !skb->ignore_df)
		df = htons(IP_DF);

	skb->encapsulation = 1;
	skb_reset_inner_mac_header(skb);
	skb_reset_inner_transport_header(skb);
	skb_set_inner_ipproto(skb, IPPROTO_QUIC);
	udp_tunnel_xmit_skb((struct rtable *)dst, sk, skb, qs->src.v4.sin_addr.s_addr,
			    qs->dest.v4.sin_addr.s_addr, dscp, ip4_dst_hoplimit(dst), df,
			    qs->src.v4.sin_port, qs->dest.v4.sin_port, false, false);
}

void quic_v6_lower_xmit(struct quic_sock *qs, struct sk_buff *skb)
{
	struct sock *sk = &qs->inet.sk;
	struct dst_entry *dst = sk_dst_get(sk);

	pr_info("%s: skb: %p len: %d | path: %pI6:%d -> %pI6:%d\n",
		__func__, skb, skb->len,
		&qs->src.v6.sin6_addr, ntohs(qs->src.v6.sin6_port),
		&qs->dest.v6.sin6_addr, ntohs(qs->dest.v6.sin6_port));

	skb->encapsulation = 1;
	skb_reset_inner_mac_header(skb);
	skb_reset_inner_transport_header(skb);
	skb_set_inner_ipproto(skb, IPPROTO_QUIC);
	skb_reset_transport_header(skb);
	udp_tunnel6_xmit_skb(dst, sk, skb, NULL, &qs->src.v6.sin6_addr,
			     &qs->dest.v6.sin6_addr, inet6_sk(sk)->tclass, ip6_dst_hoplimit(dst),
			     0, qs->src.v6.sin6_port, qs->dest.v6.sin6_port, false);
}

static int quic_frag_list_bundle(struct sk_buff *p, struct sk_buff *skb, u32 mss)
{
	if (unlikely(p->len + skb->len > mss))
		return -E2BIG;

	if (QUIC_SND_CB(p)->last == p)
		skb_shinfo(p)->frag_list = skb;
	else
		QUIC_SND_CB(p)->last->next = skb;

	QUIC_SND_CB(p)->last = skb;
	QUIC_SND_CB(p)->count++;
	p->data_len += skb->len;
	p->truesize += skb->truesize;
	p->len += skb->len;

	return 0;
}

int quic_write_queue_flush(struct quic_sock *qs)
{
	struct sk_buff *skb, *n, *head = NULL;
	struct sock *sk = &qs->inet.sk;
	u8 start_timer = 0;
	int err;

	if (qs->packet.cork)
		return 0;

	err = quic_dst_mss_check(qs, 0);
	if (err < 0)
		return err;

	while ((skb = __skb_dequeue(&sk->sk_write_queue)) != NULL) {
		if (QUIC_SND_CB(skb)->has_strm) {
			n = skb_clone(skb, GFP_ATOMIC);
			if (!n)
				return -ENOMEM;
			quic_send_queue_add(qs, skb);
			skb = n; /* send the cloned skb */
			start_timer = 1;
		}
		if (!head) {
			head = skb;
			QUIC_SND_CB(head)->last = skb;
		} else {
			if (quic_frag_list_bundle(head, skb, err)) {
				skb_set_owner_w(head, sk);
				qs->af->lower_xmit(qs, head);
				head = skb;
				QUIC_SND_CB(head)->last = skb;
			}
		}

		if (QUIC_SND_CB(skb)->type == QUIC_PKT_SHORT) {
			skb_set_owner_w(head, sk);
			qs->af->lower_xmit(qs, head);
			head = NULL;
		}
	}

	if (head) {
		skb_set_owner_w(head, sk);
		qs->af->lower_xmit(qs, head);
	}
	if (start_timer)
		quic_start_rtx_timer(qs, 0);
	return 0;
}

void quic_write_queue_enqueue(struct quic_sock *qs, struct sk_buff *skb)
{
	__skb_queue_tail(&qs->inet.sk.sk_write_queue, skb);
}

void quic_send_queue_add(struct quic_sock *qs, struct sk_buff *skb)
{
	struct sk_buff *n = qs->inet.sk.sk_send_head;

	if (!n) {
		qs->inet.sk.sk_send_head = skb;
		return;
	}

	while (n) {
		if (!n->next) {
			n->next = skb;
			break;
		}
		n = n->next;
	}
}

void quic_send_queue_check(struct quic_sock *qs, u32 v)
{
	struct sk_buff *skb = qs->inet.sk.sk_send_head;
	struct sk_buff *prev = skb, *next;

	while (skb) {
		if (QUIC_SND_CB(skb)->pn > v) {
			prev = skb;
			skb = skb->next;
			break;
		}
		if (skb == prev) {
			qs->inet.sk.sk_send_head = skb->next;
			prev = skb->next;
			next = prev;
		} else {
			prev->next = skb->next;
			next = skb->next;
		}
		pr_debug("ACKed by peer %u %u\n", QUIC_SND_CB(skb)->pn, v);
		quic_wmem_free_skb(&qs->inet.sk, skb);
		skb = next;
	}

	if (qs->inet.sk.sk_send_head) {
		quic_start_rtx_timer(qs, 1);
		return;
	}
	quic_stop_rtx_timer(qs);
}

int quic_send_queue_rtx(struct quic_sock *qs)
{
	struct sock *sk = &qs->inet.sk;
	struct sk_buff *skb, *n;
	u8 start_timer = 0;

	for (skb = qs->inet.sk.sk_send_head; skb; skb = skb->next) {
		if (QUIC_SND_CB(skb)->cnt++ >= 3)
			return -ETIMEDOUT;
		n = skb_clone(skb, GFP_ATOMIC);
		if (!n)
			return -ENOMEM;
		skb_set_owner_w(n, sk);
		qs->af->lower_xmit(qs, n);
		start_timer = 1;
	}
	if (start_timer)
		quic_start_rtx_timer(qs, 0);
	return 0;
}
