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

	if (qs->state == QUIC_CS_CLOSING) {
		err = -EPIPE;
		goto err;
	}
	err = quic_packet_process(qs, skb);
	if (err)
		goto err;

	return quic_write_queue_flush(qs);

err:
	kfree_skb(skb);
	return err;
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

	qs = quic_ssk_lookup(skb, cb->dcid, &cb->dcid_len);
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

void quic_receive_list_del(struct quic_sock *qs, u32 sid)
{
	struct sk_buff *n, *p = NULL;
	struct quic_strm *strm;
	u32 nid;

	strm = quic_strm_rcv_get(qs, sid);
	for (n = qs->packet.recv_list; n; n = n->next) {
		nid = QUIC_RCV_CB(n)->strm_id;
		if (sid > nid)
			break;
		if (sid < nid) {
			p = n;
			continue;
		}
		if (!p)
			qs->packet.recv_list = n->next;
		else
			p->next = n->next;
		strm->cnt--;
	}
}

static int quic_receive_known_size_update(struct quic_sock *qs, struct sk_buff *skb)
{
	u32 sid = QUIC_RCV_CB(skb)->strm_id, strm_rwnd;
	struct quic_packet *pkt = &qs->packet;
	struct quic_strm *strm;
	u64 known_size;

	strm = quic_strm_rcv_get(qs, sid);
	strm_rwnd = quic_strm_max_get(qs, sid);
	known_size = strm->known_size;

	if (QUIC_RCV_CB(skb)->strm_fin)
		strm->known_size = QUIC_RCV_CB(skb)->strm_off + skb->len;
	else if (strm->rcv_state < QUIC_STRM_P_SIZE_KNOWN)
		strm->known_size = strm->rcv_off;

	pkt->known_size += (strm->known_size - known_size);
	if (pkt->known_size > pkt->rcv_max || strm->known_size > strm->rcv_max) {
		pr_warn("recv msg err %llu %llu %llu %llu (%u)\n", pkt->known_size, pkt->rcv_max,
			strm->known_size, strm->rcv_max, QUIC_RCV_CB(skb)->pn);
		qs->frame.close.err = QUIC_ERROR_FLOW_CONTROL_ERROR;
		return quic_frame_create(qs, QUIC_FRAME_CONNECTION_CLOSE);
	}

	skb_set_owner_r(skb, &qs->inet.sk);
	return 0;
}

int quic_receive_list_add(struct quic_sock *qs, struct sk_buff *skb)
{
	u32 noff, off = QUIC_RCV_CB(skb)->strm_off;
	u32 nid, id = QUIC_RCV_CB(skb)->strm_id;
	struct sk_buff *n, *p = NULL, *tmp;
	struct sock *sk = &qs->inet.sk;
	struct quic_strm *strm;

	strm = quic_strm_rcv_get(qs, id);
	strm = quic_strm_rcv_get(qs, id);
	if (strm->rcv_off > off)
		return -EINVAL;

	if (off - strm->rcv_len > sk->sk_rcvbuf)
		return -ENOBUFS;
	if (QUIC_RCV_CB(skb)->strm_fin) {
		if (strm->rcv_state == QUIC_STRM_P_RECV)
			strm->rcv_state = QUIC_STRM_P_SIZE_KNOWN;
		else if (strm->rcv_state >= QUIC_STRM_P_RECVD)
			return -EINVAL;
	}

	if (strm->rcv_off < off) {
		n = qs->packet.recv_list;
		if (!n) {
			qs->packet.recv_list = skb;
			strm->cnt++;
			goto out;
		}
		for (; n; n = n->next) {
			noff = QUIC_RCV_CB(n)->strm_off;
			nid = QUIC_RCV_CB(n)->strm_id;
			if (nid < id) {
				p = n;
				continue;
			}
			if (id == nid) {
				if (noff < off) {
					p = n;
					continue;
				} else if (noff == off) {
					pr_debug("dup offset\n");
					return -EINVAL; /* dup */
				}
			}
			if (!p) {
				skb->next = n;
				qs->packet.recv_list = skb;
			} else {
				skb->next = n;
				p->next = skb;
			}
			strm->cnt++;
			goto out;
		}
		p->next = skb;
		strm->cnt++;
		goto out;
	}

	__skb_queue_tail(&sk->sk_receive_queue, skb);
	sk->sk_data_ready(sk);
	pr_debug("recv stream id: %u, off: %u, len: %u, fin: %u\n", id, off,
		 skb->len, QUIC_RCV_CB(skb)->strm_fin);
	if (QUIC_RCV_CB(skb)->strm_fin) {
		strm->rcv_state = QUIC_STRM_P_RECVD;
		goto out;
	}
	strm->rcv_off += skb->len;
	if (!strm->cnt)
		goto out;

	n = qs->packet.recv_list;
	p = NULL;
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
		if (strm->rcv_off > noff)
			return -EINVAL;
		if (strm->rcv_off < noff)
			break;
		if (!p)
			qs->packet.recv_list = n->next;
		else
			p->next = n->next;
		strm->cnt--;

		tmp = n->next;
		__skb_queue_tail(&sk->sk_receive_queue, n);
		sk->sk_data_ready(sk);
		if (QUIC_RCV_CB(n)->strm_fin) {
			strm->rcv_state = QUIC_STRM_P_RECVD;
			break;
		}
		strm->rcv_off += n->len;
		if (!strm->cnt)
			break;
		n = tmp;
	}

out:
	return quic_receive_known_size_update(qs, skb);
}

void quic_receive_list_free(struct quic_sock *qs)
{
	struct sock *sk = &qs->inet.sk;
	struct sk_buff *skb, *tmp;

	skb = qs->packet.recv_list;
	while (skb) {
		pr_warn("recv list free %u\n", QUIC_RCV_CB(skb)->pn);
		tmp = skb;
		skb = skb->next;
		kfree_skb(tmp);
	}
	qs->packet.recv_list = NULL;

	skb = __skb_dequeue(&sk->sk_receive_queue);
	while (skb) {
		pr_warn("receive queue free %u\n", QUIC_RCV_CB(skb)->pn);
		kfree_skb(skb);
		skb = __skb_dequeue(&sk->sk_receive_queue);
	}
	kfree_skb(qs->packet.fc_md);
	kfree_skb(qs->packet.fc_msd);
	kfree_skb(qs->packet.ticket);
	kfree_skb(qs->packet.ku);
	kfree_skb(qs->packet.token);
}

int quic_evt_notify(struct quic_sock *qs, u8 evt_type, u8 sub_type, u32 v[])
{
	struct sock *sk = &qs->inet.sk;
	struct quic_evt_msg *em;
	struct sk_buff *skb;

	if (!(qs->packet.events & (1 << evt_type)))
		return 0;

	skb = alloc_skb(sizeof(*em), GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;

	QUIC_RCV_CB(skb)->is_evt = 1;
	em = skb_put(skb, sizeof(*em));
	em->evt_type = evt_type;
	em->sub_type = sub_type;
	em->value[0] = v[0];
	em->value[1] = v[1];
	em->value[2] = v[2];

	pr_debug("event created %u %u\n", evt_type, sub_type);
	__skb_queue_tail(&sk->sk_receive_queue, skb);
	sk->sk_data_ready(sk);
	return 0;
}

int quic_evt_notify_ticket(struct quic_sock *qs)
{
	struct sock *sk = &qs->inet.sk;
	struct quic_evt_msg *em;
	struct quic_psk *psk;
	struct sk_buff *skb;
	u32 len;

	if (!(qs->packet.events & (1 << QUIC_EVT_TICKET)))
		return 0;

	psk = qs->crypt.psks;
	len = 8 + psk->mskey.len + psk->nonce.len + psk->pskid.len;
	skb = alloc_skb(sizeof(*em) + len, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;

	QUIC_RCV_CB(skb)->is_evt = 1;
	em = skb_put(skb, sizeof(*em) + len);
	em->evt_type = QUIC_EVT_TICKET;
	em->sub_type = QUIC_EVT_TICKET_NEW;
	em->value[0] = psk->pskid.len;
	em->value[1] = psk->nonce.len;
	em->value[2] = psk->mskey.len;
	memcpy(em->data, &psk->psk_sent_at, 4);
	memcpy(em->data + 4, &psk->psk_expire, 4);
	memcpy(em->data + 8, psk->pskid.v, psk->pskid.len);
	memcpy(em->data + 8 + psk->pskid.len, psk->nonce.v, psk->nonce.len);
	memcpy(em->data + 8 + psk->pskid.len + psk->nonce.len, psk->mskey.v, psk->mskey.len);

	pr_debug("event created %u %u\n", QUIC_EVT_TICKET, QUIC_EVT_TICKET_NEW);
	__skb_queue_tail(&sk->sk_receive_queue, skb);
	sk->sk_data_ready(sk);
	return 0;
}

int quic_evt_notify_token(struct quic_sock *qs)
{
	struct sock *sk = &qs->inet.sk;
	struct quic_evt_msg *em;
	struct sk_buff *skb;

	if (!(qs->packet.events & (1 << QUIC_EVT_TOKEN)))
		return 0;

	skb = alloc_skb(sizeof(*em) + qs->token.len, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;

	QUIC_RCV_CB(skb)->is_evt = 1;
	em = skb_put(skb, sizeof(*em) + qs->token.len);
	em->evt_type = QUIC_EVT_TOKEN;
	em->sub_type = QUIC_EVT_TOKEN_NEW;
	em->value[0] = qs->token.len;
	memcpy(em->data, qs->token.token, qs->token.len);

	pr_debug("event created %u %u\n", QUIC_EVT_TOKEN, QUIC_EVT_TOKEN_NEW);
	__skb_queue_tail(&sk->sk_receive_queue, skb);
	sk->sk_data_ready(sk);
	return 0;
}
