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
	union quic_addr *a;
	struct flowi4 *fl4;
	struct rtable *rt;
	struct flowi _fl;

	if (__sk_dst_get(sk))
		return 0;

	fl4 = &_fl.u.ip4;
	memset(&_fl, 0x00, sizeof(_fl));
	a = quic_saddr_cur(qs);
	fl4->saddr = a->v4.sin_addr.s_addr;
	fl4->fl4_sport = a->v4.sin_port;
	a = quic_daddr_cur(qs);
	fl4->daddr = a->v4.sin_addr.s_addr;
	fl4->fl4_dport = a->v4.sin_port;

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
	union quic_addr *a;
	struct flowi6 *fl6;
	struct flowi _fl;

	if (__sk_dst_get(sk))
		return 0;

	fl6 = &_fl.u.ip6;
	memset(&_fl, 0x0, sizeof(_fl));
	a = quic_daddr_cur(qs);
	fl6->daddr = a->v6.sin6_addr;
	fl6->fl6_dport = a->v6.sin6_port;
	a = quic_saddr_cur(qs);
	fl6->saddr = a->v6.sin6_addr;
	fl6->fl6_sport = a->v6.sin6_port;

	dst = ip6_dst_lookup_flow(sock_net(sk), sk, fl6, NULL);
	if (IS_ERR(dst))
		return PTR_ERR(dst);

	sk_dst_set(sk, dst);
	return 0;
}

void quic_v4_lower_xmit(struct quic_sock *qs, struct sk_buff *skb)
{
	union quic_addr *s = quic_saddr_cur(qs);
	union quic_addr *d = quic_daddr_cur(qs);
	struct sock *sk = &qs->inet.sk;
	struct inet_sock *inet = inet_sk(sk);
	struct dst_entry *dst = sk_dst_get(sk);
	__u8 dscp = inet->tos;
	__be16 df = 0;

	pr_debug("%s: skb: %p len: %d | path: %pI4:%d -> %pI4:%d\n",
		 __func__, skb, skb->len,
		 &s->v4.sin_addr.s_addr, ntohs(s->v4.sin_port),
		 &d->v4.sin_addr.s_addr, ntohs(d->v4.sin_port));

	if (ip_dont_fragment(sk, dst) && !skb->ignore_df)
		df = htons(IP_DF);

	skb->encapsulation = 1;
	skb_reset_inner_mac_header(skb);
	skb_reset_inner_transport_header(skb);
	skb_set_inner_ipproto(skb, IPPROTO_QUIC);
	udp_tunnel_xmit_skb((struct rtable *)dst, sk, skb, s->v4.sin_addr.s_addr,
			    d->v4.sin_addr.s_addr, dscp, ip4_dst_hoplimit(dst), df,
			    s->v4.sin_port, d->v4.sin_port, false, false);
}

void quic_v6_lower_xmit(struct quic_sock *qs, struct sk_buff *skb)
{
	union quic_addr *s = quic_saddr_cur(qs);
	union quic_addr *d = quic_daddr_cur(qs);
	struct sock *sk = &qs->inet.sk;
	struct dst_entry *dst = sk_dst_get(sk);

	pr_debug("%s: skb: %p len: %d | path: %pI6:%d -> %pI6:%d\n",
		 __func__, skb, skb->len,
		 &s->v6.sin6_addr, ntohs(s->v6.sin6_port),
		 &d->v6.sin6_addr, ntohs(d->v6.sin6_port));

	skb->encapsulation = 1;
	skb_reset_inner_mac_header(skb);
	skb_reset_inner_transport_header(skb);
	skb_set_inner_ipproto(skb, IPPROTO_QUIC);
	skb_reset_transport_header(skb);
	udp_tunnel6_xmit_skb(dst, sk, skb, NULL, &s->v6.sin6_addr,
			     &d->v6.sin6_addr, inet6_sk(sk)->tclass, ip6_dst_hoplimit(dst),
			     0, s->v6.sin6_port, d->v6.sin6_port, false);
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

static int quic_write_flow_control(struct quic_sock *qs, struct sk_buff *skb)
{
	struct quic_strm *strm = quic_strm_snd_get(qs, QUIC_SND_CB(skb)->strm_id);
	u32 mlen = QUIC_SND_CB(skb)->mlen;
	struct sock *sk = &qs->inet.sk;
	u64 strm_max = strm->snd_max;
	u64 max = qs->packet.snd_max;
	u8 start_timer = 0;

	if (qs->packet.snd_len + mlen <= max && strm->snd_len + mlen <= strm_max) {
		qs->packet.snd_len += mlen;
		strm->snd_len += mlen;
		return 0;
	}
	__skb_queue_head(&sk->sk_write_queue, skb); /* put it back to the queue */

	if (strm->snd_len + mlen > strm_max && !qs->packet.fc_msd) {
		qs->frame.stream.sid = QUIC_SND_CB(skb)->strm_id;
		qs->frame.max.limit = strm_max;
		qs->packet.fc_msd = quic_packet_create(qs, QUIC_PKT_SHORT,
						       QUIC_FRAME_STREAM_DATA_BLOCKED);
		if (qs->packet.fc_msd) {
			skb = skb_clone(qs->packet.fc_msd, GFP_ATOMIC);
			if (skb) {
				skb_set_owner_w(skb, sk);
				qs->af->lower_xmit(qs, skb);
			}
			start_timer = 1;
		}
	}

	if (qs->packet.snd_len + mlen > max && !qs->packet.fc_md) {
		qs->frame.max.limit = max;
		qs->packet.fc_md = quic_packet_create(qs, QUIC_PKT_SHORT, QUIC_FRAME_DATA_BLOCKED);
		if (qs->packet.fc_md) {
			skb = skb_clone(qs->packet.fc_md, GFP_ATOMIC);
			if (skb) {
				skb_set_owner_w(skb, sk);
				qs->af->lower_xmit(qs, skb);
			}
			start_timer = 1;
		}
	}

	if (start_timer)
		quic_start_rtx_timer(qs, 0);
	return 1;
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
		if (QUIC_SND_CB(skb)->type == QUIC_PKT_SHORT &&
		    QUIC_SND_CB(skb)->has_strm) {
			if (quic_write_flow_control(qs, skb))
				break;
			n = skb_clone(skb, GFP_ATOMIC);
			if (!n)
				return -ENOMEM;
			if (!qs->cong.rto_pending) {
				qs->cong.rto_pending = 1;
				QUIC_SND_CB(skb)->rtt_probe = 1;
				QUIC_SND_CB(skb)->sent_at = jiffies;
			}
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

void quic_send_list_free(struct quic_sock *qs)
{
	struct sock *sk = &qs->inet.sk;
	struct sk_buff *skb, *tmp;

	skb = qs->inet.sk.sk_send_head;
	while (skb) {
		pr_warn("rtx queue free %u\n", QUIC_SND_CB(skb)->pn);
		tmp = skb;
		skb = skb->next;
		kfree_skb(tmp);
	}
	qs->inet.sk.sk_send_head = NULL;

	skb = __skb_dequeue(&sk->sk_write_queue);
	while (skb) {
		pr_warn("write queue free %u\n", QUIC_SND_CB(skb)->pn);
		kfree_skb(skb);
		skb = __skb_dequeue(&sk->sk_write_queue);
	}

	kfree_skb(qs->packet.fc_md);
	kfree_skb(qs->packet.fc_msd);
	kfree_skb(qs->packet.ticket);
	kfree_skb(qs->packet.token);
	kfree_skb(qs->packet.ku);
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

static void quic_cong_update_rto(struct quic_sock *qs, __u32 rtt)
{
	struct quic_cong *c = &qs->cong;

	if (c->rttvar || c->srtt) {
		/* When a new RTT measurement R' is made, set
		 * RTTVAR <- (1 - RTO.Beta) * RTTVAR + RTO.Beta * |SRTT - R'|
		 * SRTT <- (1 - RTO.Alpha) * SRTT + RTO.Alpha * R'
		 */
		c->rttvar = c->rttvar - (c->rttvar >> QUIC_RTO_BETA)
			+ (((__u32)abs((__s64)c->srtt - (__s64)rtt)) >> QUIC_RTO_BETA);
		c->srtt = c->srtt - (c->srtt >> QUIC_RTO_ALPHA)
			+ (rtt >> QUIC_RTO_ALPHA);
	} else {
		/* When the first RTT measurement R is made, set
		 * SRTT <- R, RTTVAR <- R/2.
		 */
		c->srtt = rtt;
		c->rttvar = rtt >> 1;
	}

	/* Whenever RTTVAR is computed, if RTTVAR = 0, then
	 * adjust RTTVAR <- G, where G is the CLOCK GRANULARITY.
	 */
	if (c->rttvar == 0)
		c->rttvar = 1;

	/* After the computation, update RTO <- SRTT + 4 * RTTVAR. */
	c->rto = c->srtt + (c->rttvar << 2);
	c->rtt = rtt;
	c->rto_pending = 0;

	if (c->rto > msecs_to_jiffies(QUIC_RTO_MAX))
		c->rto = msecs_to_jiffies(QUIC_RTO_MAX);
	else if (c->rto < msecs_to_jiffies(QUIC_RTO_MIN))
		c->rto = msecs_to_jiffies(QUIC_RTO_MIN);

	pr_debug("updata rtt:%u, srtt:%u rttvar:%u, rto:%u\n",
		 rtt, c->srtt, c->rttvar, c->rto);
}

void quic_send_queue_check(struct quic_sock *qs, u32 v)
{
	struct sk_buff *skb = qs->inet.sk.sk_send_head;
	struct sk_buff *prev = skb, *next;
	struct quic_strm *strm;
	u32 rtt;
	int err;

	while (skb) {
		if (QUIC_SND_CB(skb)->pn > v)
			break;

		if (QUIC_SND_CB(skb)->pn < v) {
			prev = skb;
			skb = skb->next;
			continue;
		}

		strm = quic_strm_snd_get(qs, QUIC_SND_CB(skb)->strm_id);
		strm->in_flight--;
		if (strm->snd_state == QUIC_STRM_L_SENT && !strm->in_flight)
			strm->snd_state = QUIC_STRM_L_RECVD;

		if (skb == prev) {
			qs->inet.sk.sk_send_head = skb->next;
			prev = skb->next;
			next = prev;
		} else {
			prev->next = skb->next;
			next = skb->next;
		}
		if (!QUIC_SND_CB(skb)->cnt && QUIC_SND_CB(skb)->rtt_probe) {
			rtt = jiffies - QUIC_SND_CB(skb)->sent_at;
			QUIC_SND_CB(skb)->rtt_probe = 0;
			quic_cong_update_rto(qs, rtt);
		}
		pr_debug("ACKed by peer %u %u\n", QUIC_SND_CB(skb)->pn, v);
		kfree_skb(skb);
		break;
	}

	if (qs->packet.ticket && QUIC_SND_CB(qs->packet.ticket)->pn == v) {
		kfree_skb(qs->packet.ticket);
		qs->packet.ticket = NULL;
		err = quic_evt_notify_ticket(qs);
		if (err) {
			qs->inet.sk.sk_err = err;
			pr_warn("notify ticket fails %d\n", err);
		}
		if (qs->lsk && qs->crypt.psks) {
			struct quic_psk *psk = qs->lsk->crypt.psks;

			if (psk) {
				while (psk->next)
					psk = psk->next;
				psk->next = qs->crypt.psks;
				qs->crypt.psks = NULL;
			} else {
				qs->lsk->crypt.psks = qs->crypt.psks;
				qs->crypt.psks = NULL;
			}
		}
	}

	if (qs->packet.token && QUIC_SND_CB(qs->packet.token)->pn == v) {
		kfree(qs->lsk->token.token);
		qs->lsk->token.token = quic_mem_dup(qs->token.token, qs->token.len);
		if (qs->lsk->token.token) {
			kfree_skb(qs->packet.token);
			qs->packet.token = NULL;
			qs->lsk->token.len = qs->token.len;
			err = quic_evt_notify_token(qs);
			if (err) {
				qs->inet.sk.sk_err = err;
				pr_warn("notify token fails %d\n", err);
			}
		}
	}

	if (qs->inet.sk.sk_send_head || qs->packet.fc_md || qs->packet.fc_msd ||
	    qs->packet.ticket) {
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

	if (qs->packet.fc_msd) {
		n = skb_clone(qs->packet.fc_msd, GFP_ATOMIC);
		if (!n)
			return -ENOMEM;
		skb_set_owner_w(n, sk);
		qs->af->lower_xmit(qs, n);
		start_timer = 1;
	}

	if (qs->packet.fc_md) {
		n = skb_clone(qs->packet.fc_md, GFP_ATOMIC);
		if (!n)
			return -ENOMEM;
		skb_set_owner_w(n, sk);
		qs->af->lower_xmit(qs, n);
		start_timer = 1;
	}

	if (qs->packet.token) {
		n = skb_clone(qs->packet.token, GFP_ATOMIC);
		if (!n)
			return -ENOMEM;
		skb_set_owner_w(n, sk);
		qs->af->lower_xmit(qs, n);
		start_timer = 1;
	}

	for (skb = qs->inet.sk.sk_send_head; skb; skb = skb->next) {
		if (QUIC_SND_CB(skb)->cnt++ >= QUIC_RTX_MAX) {
			pr_warn("snd queue rtx %u\n", QUIC_SND_CB(skb)->pn);
			return -ETIMEDOUT;
		}
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
