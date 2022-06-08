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

static struct sk_buff *quic_packet_long_create(struct quic_sock *qs, u8 type)
{
	int len, hlen, plen, rlen, padlen = 0, dlen, minlen = 16, early_len = 0;
	struct quic_vlen *f = qs->packet.f;
	struct quic_lhdr *hdr;
	struct sk_buff *skb;
	__u8 *p;

	hlen = sizeof(struct udphdr) + qs->af->iphdr_len + MAX_HEADER;
	len = sizeof(*hdr) + 4 + 2 + qs->cids.dcid.cur->len + qs->cids.scid.cur->len;

	if (type == QUIC_PKT_INITIAL) {
		if (qs->frame.stream.msg)
			early_len = len + 1 + 1 + iov_iter_count(qs->frame.stream.msg);
		len += quic_put_varint_len(qs->token.len) + qs->token.len;
		qs->packet.pn = qs->packet.in_tx_pn++;
		if (!qs->packet.pn)
			minlen = (early_len >= 1178) ? 0 : (1178 - early_len);
	} else if (type == QUIC_PKT_0RTT) {
		qs->packet.pn = qs->packet.ad_tx_pn++;
		minlen = 0;
	} else {
		qs->packet.pn = qs->packet.hs_tx_pn++;
	}
	plen = quic_put_pkt_numlen(qs->packet.pn) - 1;
	qs->packet.pn_len = plen + 1;
	dlen = qs->packet.pn_len + f->len;
	if (dlen < minlen) {
		dlen = minlen;
		padlen = dlen - (qs->packet.pn_len + f->len);
	}
	rlen = dlen + QUIC_TAGLEN;
	len += quic_put_varint_len(rlen);
	qs->packet.pn_off = len;
	len += dlen;
	pr_debug("remain len: %d, pn_offset: %d, pn_len: %d, len: %d\n",
		 rlen, qs->packet.pn_off, qs->packet.pn_len, len);

	skb = alloc_skb(len + QUIC_TAGLEN + hlen, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_reserve(skb, len + hlen);
	hdr = skb_push(skb, len);

	/* Fixed Header */
	hdr->form = 1;
	hdr->fixed = 1;
	hdr->type = type;
	hdr->reserved = 0;
	hdr->pnl = plen;
	p = (u8 *)hdr;
	p++;

	/* Version */
	p = quic_put_pkt_num(p, QUIC_VERSION_V1, 4);

	/* Various Length Header: dcid and scid */
	p = quic_put_varint(p, qs->cids.dcid.cur->len);
	p = quic_put_pkt_data(p, qs->cids.dcid.cur->id, qs->cids.dcid.cur->len);
	p = quic_put_varint(p, qs->cids.scid.cur->len);
	p = quic_put_pkt_data(p, qs->cids.scid.cur->id, qs->cids.scid.cur->len);

	/* Various Length Header: token */
	if (type == QUIC_PKT_INITIAL) {
		p = quic_put_varint(p, qs->token.len);
		p = quic_put_pkt_data(p, qs->token.v, qs->token.len);
	}

	/* Various Length Header: length */
	p = quic_put_varint(p, rlen);

	/* Various Length Header: packet number */
	p = quic_put_pkt_num(p, qs->packet.pn, qs->packet.pn_len);
	QUIC_SND_CB(skb)->pn = qs->packet.pn;
	QUIC_SND_CB(skb)->type = type;
	QUIC_SND_CB(skb)->has_strm = qs->frame.has_strm;

	/* CRYPTO Frame */
	p = quic_put_pkt_data(p, f->v, f->len);
	f->len = 0;
	if (padlen)
		memset(p, 0, padlen); /* padding frame */
	pr_debug("packet type: %d, len %d, pad len %d\n", type, skb->len, padlen);

	return skb;
}

static struct sk_buff *quic_packet_short_create(struct quic_sock *qs)
{
	int len, hlen, plen, rlen, padlen = 0, dlen, minlen = 16;
	struct quic_vlen *f = qs->packet.f;
	struct quic_shdr *hdr;
	struct sk_buff *skb;
	__u8 *p;

	hlen = sizeof(struct udphdr) + qs->af->iphdr_len + MAX_HEADER;
	len = 1 + qs->cids.dcid.cur->len;

	qs->packet.pn = qs->packet.ad_tx_pn++;
	plen = quic_put_pkt_numlen(qs->packet.pn) - 1;
	qs->packet.pn_len = plen + 1;
	dlen = qs->packet.pn_len + f->len;
	if (dlen < minlen) {
		dlen = minlen;
		padlen = dlen - (qs->packet.pn_len + f->len);
	}
	rlen = dlen + QUIC_TAGLEN;
	qs->packet.pn_off = len;
	len += dlen;

	skb = alloc_skb(len + QUIC_TAGLEN + hlen, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_reserve(skb, len + hlen);
	hdr = skb_push(skb, len);

	/* Fixed Header */
	hdr->form = 0;
	hdr->fixed = 1;
	hdr->spin = 0;
	hdr->reserved = 0;
	hdr->key = qs->crypt.key_phase;
	hdr->pnl = plen;
	p = (u8 *)hdr;
	p++;

	/* Various Length Header: dcid */
	p = quic_put_pkt_data(p, qs->cids.dcid.cur->id, qs->cids.dcid.cur->len);

	/* Various Length Header: packet number */
	p = quic_put_pkt_num(p, qs->packet.pn, qs->packet.pn_len);
	QUIC_SND_CB(skb)->pn = qs->packet.pn;
	QUIC_SND_CB(skb)->type = QUIC_PKT_SHORT;
	QUIC_SND_CB(skb)->has_strm = qs->frame.has_strm;
	QUIC_SND_CB(skb)->strm_off = qs->frame.stream.off;

	/* Frame */
	p = quic_put_pkt_data(p, f->v, f->len);
	f->len = 0;
	if (padlen)
		memset(p, 0, padlen); /* padding frame */
	pr_debug("packet type: %d, len %d, pad len %d\n", QUIC_PKT_SHORT, skb->len, padlen);

	return skb;
}

static struct sk_buff *quic_packet_do_create(struct quic_sock *qs, u8 type)
{
	if (type == QUIC_PKT_SHORT)
		return quic_packet_short_create(qs);

	return  quic_packet_long_create(qs, type);
}

static int quic_packet_long_process(struct quic_sock *qs, struct sk_buff *skb, u8 **ptr)
{
	struct quic_lhdr *hdr = quic_lhdr(skb);
	u32 pd_len, pn_len, pn_off, pn, len;
	u8 *p = *ptr;
	int err;

	p += 1 + 4 + 1 + QUIC_RCV_CB(skb)->scid_len +
		1 + QUIC_RCV_CB(skb)->dcid_len;
	if (hdr->type == QUIC_PKT_INITIAL) {
		len = *p++;
		p += len;
	}

	pd_len = quic_get_varint_next(&p, &len);
	qs->packet.pn_off = p - (u8 *)hdr;
	qs->packet.pd_len = pd_len;
	err = quic_crypto_decrypt(qs, skb, hdr->type);
	if (err)
		goto out;
	pn_len = qs->packet.pn_len;
	pn_off = qs->packet.pn_off;
	pn = qs->packet.pn;
	p = (u8 *)hdr + pn_off + pn_len;
	err = quic_frame_process(qs, p, pd_len - QUIC_TAGLEN - pn_len);
	if (err)
		goto out;
	if (qs->frame.need_ack) {
		err = quic_frame_create(qs, QUIC_FRAME_ACK);
		if (err)
			goto out;
	}
	p += (pd_len - pn_len);
out:
	*ptr = p;
	return err;
}

static int quic_packet_short_process(struct quic_sock *qs, struct sk_buff *skb, u8 **ptr)
{
	struct quic_shdr *hdr = quic_shdr(skb);
	u32 pd_len, pn_len, pn_off, pn;
	union quic_addr src;
	u8 *p = *ptr;
	int err;

	p += 1 + QUIC_RCV_CB(skb)->dcid_len;
	qs->packet.pn_off = p - (u8 *)hdr;
	pd_len = skb->len - qs->packet.pn_off;
	qs->packet.pd_len = pd_len;
	err = quic_crypto_decrypt(qs, skb, QUIC_PKT_SHORT);
	if (err) {
		pr_warn("pkt decrypt err %d\n", err);
		goto out;
	}
	pn_len = qs->packet.pn_len;
	pn_off = qs->packet.pn_off;
	pn = qs->packet.pn;
	p = (u8 *)hdr + pn_off + pn_len;
	err = quic_frame_process(qs, p, pd_len - QUIC_TAGLEN - pn_len);
	if (err)
		goto out;
	if (qs->frame.non_probe) {
		qs->af->get_addr(&src, skb, 1);
		if (memcmp(&src, quic_daddr_cur(qs), qs->af->addr_len)) {
			err = quic_cid_path_change(qs, &src);
			if (err)
				goto out;
		}
	}
	if (qs->frame.need_ack) {
		qs->packet.pn = pn;
		err = quic_frame_create(qs, QUIC_FRAME_ACK);
		if (err)
			goto out;
	}
	p += (pd_len - pn_len);
out:
	*ptr = p;
	return err;
}

/* exported */
int quic_packet_process(struct quic_sock *qs, struct sk_buff *skb)
{
	struct quic_lhdr *hdr = quic_lhdr(skb);
	u8 *p = (u8 *)hdr, type;
	struct quic_vlen *f;
	int err, i;

	while (1) {
		skb_pull(skb, (u32)(p - (u8 *)hdr));
		skb_reset_transport_header(skb);
		hdr = quic_lhdr(skb);
		qs->packet.skb = skb;
		if (hdr->form) {
			qs->packet.type = hdr->type;
			err = quic_packet_long_process(qs, skb, &p);
		} else {
			qs->packet.type = QUIC_PKT_SHORT;
			err = quic_packet_short_process(qs, skb, &p);
		}
		if (err) {
			pr_warn("pkt process err %d %u\n", err, qs->packet.pn);
			return err;
		}

		if ((u32)(p - skb->data) >= skb->len)
			break;
	}

	consume_skb(skb);
	quic_start_ping_timer(qs, 1);

	for (i = 0; i < QUIC_FR_NR; i++) {
		f = &qs->frame.f[i];
		if (!f->len)
			continue;
		type = (i >= QUIC_PKT_SHORT + 1) ? QUIC_PKT_HANDSHAKE : i;
		qs->packet.f = f;
		skb = quic_packet_do_create(qs, type);
		if (!skb)
			return -ENOMEM;
		err = quic_crypto_encrypt(qs, skb, type);
		if (err) {
			kfree_skb(skb);
			return err;
		}
		quic_write_queue_enqueue(qs, skb);
	}

	return 0;
}

/* exported */
struct sk_buff *quic_packet_create(struct quic_sock *qs, u8 type, u8 ftype)
{
	struct sk_buff *skb;
	int err;

	qs->packet.type = type;
	qs->frame.has_strm = 0;
	err = quic_frame_create(qs, ftype);
	if (err)
		return NULL;
	qs->packet.f = &qs->frame.f[type];
	skb = quic_packet_do_create(qs, type);
	if (!skb)
		return NULL;
	err = quic_crypto_encrypt(qs, skb, type);
	if (err) {
		kfree_skb(skb);
		return NULL;
	}

	return skb;
}
