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

int quic_do_rcv(struct sock *sk, struct sk_buff *skb)
{
	struct quic_sock *qs = quic_sk(sk);
	int err;

	err = quic_packet_process(qs, skb);
	if (err) {
		kfree_skb(skb);
		return err;
	}

	return quic_write_queue_flush(qs);
}

static void quic_cids_parse(struct sk_buff *skb)
{
	u8 *p = skb_transport_header(skb);

	if (quic_lhdr(skb)->form) {
		p += 5;
		QUIC_RCV_CB(skb)->dcid_len = *p++;
		QUIC_RCV_CB(skb)->dcid = p;
		p += QUIC_RCV_CB(skb)->dcid_len;
		QUIC_RCV_CB(skb)->scid_len = *p++;
		QUIC_RCV_CB(skb)->scid = p;
	} else {
		p++;
		QUIC_RCV_CB(skb)->dcid = p;
		QUIC_RCV_CB(skb)->dcid_len = 0;
	}
}

int quic_rcv(struct sk_buff *skb)
{
	struct quic_rcv_cb *cb = QUIC_RCV_CB(skb);
	struct quic_lhdr *hdr = quic_lhdr(skb);
	union quic_addr dest;
	struct quic_sock *qs;
	int err = -EINVAL;
	struct sock *sk;

	skb_pull(skb, skb_transport_offset(skb));
	cb->af = quic_af_get(ip_hdr(skb)->version == 4 ? AF_INET : AF_INET6);
	cb->af->get_addr(&dest, skb, 0);
	quic_cids_parse(skb);

	qs = quic_ssk_lookup(skb, cb->dcid, cb->dcid_len);
	if (!qs) {
		if (!hdr->form || hdr->type != QUIC_PKT_INITIAL)
			goto err;
		qs = quic_lsk_lookup(skb, &dest); /* lookup listening socket */
		if (!qs)
			goto err;
		qs = quic_lsk_process(qs, skb);
		if (!qs)
			goto err;
	}
	sk = &qs->inet.sk;
	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		if (sk_add_backlog(sk, skb, READ_ONCE(sk->sk_rcvbuf))) {
			bh_unlock_sock(sk);
			goto err;
		}
	} else {
		quic_do_rcv(sk, skb);
	}
	bh_unlock_sock(sk);
	return 0;
err:
	kfree_skb(skb);
	return err;
}

int quic_pnmap_init(struct quic_sock *qs, gfp_t gfp)
{
	struct quic_pnmap *map = &qs->pnmap;
	u16 len = BITS_PER_LONG;

	if (!map->pn_map) {
		map->pn_map = kzalloc((len >> 3), gfp);
		if (!map->pn_map)
			return -ENOMEM;
		map->len = len;
	} else {
		bitmap_zero(map->pn_map, map->len);
	}

	map->base_pn = 1;
	map->cum_pn_ack_point = map->base_pn - 1;
	map->max_pn_seen = map->cum_pn_ack_point;

	return 0;
}

void quic_pnmap_free(struct quic_sock *qs)
{
	struct quic_pnmap *map = &qs->pnmap;

	map->len = 0;
	kfree(map->pn_map);
}

static void quic_pnmap_update(struct quic_sock *qs)
{
	struct quic_pnmap *map = &qs->pnmap;
	unsigned long zero_bit;
	u16 len;

	len = map->max_pn_seen - map->cum_pn_ack_point;
	zero_bit = find_first_zero_bit(map->pn_map, len);
	if (!zero_bit)
		return;

	map->base_pn += zero_bit;
	map->cum_pn_ack_point += zero_bit;

	bitmap_shift_right(map->pn_map, map->pn_map, zero_bit, map->len);
}

int quic_pnmap_mark(struct quic_sock *qs, u32 pn)
{
	struct quic_pnmap *map = &qs->pnmap;
	u16 gap;

	pn += 1;
	if (pn < map->base_pn)
		return 0;
	gap = pn - map->base_pn;
	if (gap >= map->len)
		return -ENOMEM;

	if (map->cum_pn_ack_point == map->max_pn_seen && gap == 0) {
		map->max_pn_seen++;
		map->cum_pn_ack_point++;
		map->base_pn++;
	} else {
		if (map->max_pn_seen < pn)
			map->max_pn_seen = pn;
		set_bit(gap, map->pn_map);
		quic_pnmap_update(qs);
	}

	return 0;
}

int quic_receive_list_add(struct quic_sock *qs, struct sk_buff *skb)
{
	u32 noff, off = QUIC_RCV_CB(skb)->strm_off;
	u32 nid, id = QUIC_RCV_CB(skb)->strm_id;
	struct sock *sk = &qs->inet.sk;
	struct quic_istrm *is;
	struct sk_buff *n, *p;

	is = quic_istrm_get(qs, id);
	if (is->offset > off)
		return -EINVAL;

	if (is->offset < off) {
		for (n = qs->packet.recv_list; n; n = n->next) {
			noff = QUIC_RCV_CB(n)->strm_off;
			nid = QUIC_RCV_CB(n)->strm_id;
			if (id < nid) {
				p = n;
				continue;
			}
			if (id == nid && off < noff) {
				p = n;
				continue;
			}
			if (!p) {
				skb->next = n->next;
				qs->packet.recv_list = skb;
			} else {
				skb->next = n->next;
				p->next = skb;
			}
			is->cnt++;
			break;
		}
		return 0;
	}

	__skb_queue_tail(&sk->sk_receive_queue, skb);
	pr_debug("recv stream id: %u, off: %u, len: %u, fin: %u\n", id, off,
		 skb->len, QUIC_RCV_CB(skb)->strm_fin);
	if (QUIC_RCV_CB(skb)->strm_fin) {
		is->offset = 0;
		return 0;
	}
	is->offset += skb->len;
	if (!is->cnt)
		return 0;

	n = qs->packet.recv_list;
	while (n) {
		noff = QUIC_RCV_CB(n)->strm_off;
		nid = QUIC_RCV_CB(n)->strm_id;
		if (id < nid) {
			p = n;
			n = n->next;
			continue;
		}
		if (id > nid)
			break;
		if (is->offset > noff)
			return -EINVAL;
		if (is->offset < noff)
			break;
		if (!p)
			qs->packet.recv_list = n->next;
		else
			p->next = n->next;
		is->cnt--;
		skb = n;
		n = n->next;

		__skb_queue_tail(&sk->sk_receive_queue, skb);
		if (QUIC_RCV_CB(skb)->strm_fin) {
			is->offset = 0;
			return 0;
		}
		is->offset += skb->len;
		if (!is->cnt)
			return 0;
	}
	return 0;
}
