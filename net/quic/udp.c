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

static int quic_udp_rcv(struct sock *sk, struct sk_buff *skb)
{
	if (skb_linearize(skb))
		return 0;

	QUIC_RCV_CB(skb)->udp_hdr = skb->transport_header;
	skb_set_transport_header(skb, sizeof(struct udphdr));
	quic_rcv(skb);
	return 0;
}

static int quic_udp_err_lookup(struct sock *sk, struct sk_buff *skb)
{
	return -ENOENT;
}

static struct quic_usock *quic_udp_sock_create(struct quic_sock *qs, union quic_addr *a)
{
	struct udp_tunnel_sock_cfg tuncfg = {NULL};
	struct net *net = sock_net(&qs->inet.sk);
	struct udp_port_cfg udp_conf = {0};
	struct quic_hash_head *head;
	struct quic_usock *usk;
	struct socket *sock;

	usk = kzalloc(sizeof(*usk), GFP_ATOMIC);
	if (!usk)
		return NULL;

	qs->af->udp_conf_init(&udp_conf, a);
	if (udp_sock_create(net, &udp_conf, &sock)) {
		pr_err("[QUIC] Failed to create UDP sock for QUIC\n");
		kfree(usk);
		return NULL;
	}

	tuncfg.encap_type = 1;
	tuncfg.encap_rcv = quic_udp_rcv;
	tuncfg.encap_err_lookup = quic_udp_err_lookup;
	setup_udp_tunnel_sock(net, sock, &tuncfg);

	refcount_set(&usk->refcnt, 1);
	usk->sk = sock->sk;
	memcpy(&usk->a, a, sizeof(*a));

	head = quic_usk_head(net, a);
	spin_lock(&head->lock);
	hlist_add_head(&usk->node, &head->head);
	spin_unlock(&head->lock);

	return usk;
}

struct quic_usock *quic_udp_sock_lookup(struct quic_sock *qs, union quic_addr *a)
{
	struct net *net = sock_net(&qs->inet.sk);
	struct quic_usock *usk, *us = NULL;
	struct quic_hash_head *head;

	head = quic_usk_head(net, a);
	spin_lock(&head->lock);
	hlist_for_each_entry(usk, &head->head, node) {
		if (net == sock_net(usk->sk) && !memcmp(&usk->a, a, qs->af->addr_len)) {
			us = quic_us_get(usk);
			break;
		}
	}
	spin_unlock(&head->lock);

	if (!us)
		us = quic_udp_sock_create(qs, a);

	return us;
}
