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

int quic_strm_max_get(struct quic_sock *qs, u32 sid)
{
	int len;

	if (sid & QUIC_STRM_UNI_MASK)
		len = qs->params.local.initial_max_stream_data_uni;
	else if (quic_is_serv(qs) ^ !(sid & QUIC_STRM_SERV_MASK))
		len = qs->params.local.initial_max_stream_data_bidi_local;
	else
		len = qs->params.local.initial_max_stream_data_bidi_remote;

	return len;
}

struct quic_strm *quic_strm_snd_get(struct quic_sock *qs, u32 sid)
{
	struct quic_strms *strms = &qs->strms;
	u32 i, id = sid >> QUIC_STRM_MASK_BITS;
	u64 snd_max, rcv_max;
	struct sk_buff *skb;

	if (sid & QUIC_STRM_UNI_MASK) {
		if (quic_is_serv(qs) ^ (sid & QUIC_STRM_SERV_MASK))
			return NULL;
		if (id >= strms->l_uni_cnt) {
			if (id >= qs->params.local.initial_max_streams_uni) {
				qs->frame.max.limit = id + 1;
				skb = quic_packet_create(qs, QUIC_PKT_SHORT,
							 QUIC_FRAME_STREAMS_BLOCKED_UNI);
				if (skb) {
					quic_write_queue_enqueue(qs, skb);
					quic_write_queue_flush(qs);
				}
				return NULL;
			}
			if (genradix_prealloc(&strms->l_uni, id + 1, GFP_ATOMIC))
				return NULL;
			snd_max = qs->params.peer.initial_max_stream_data_uni;
			for (i = 0; i <= id - strms->l_uni_cnt; i++)
				quic_strm(&strms->l_uni, i + strms->l_uni_cnt)->snd_max = snd_max;
			strms->l_uni_cnt = id + 1;
		}
		return genradix_ptr(&strms->l_uni, id);
	}

	if (quic_is_serv(qs) ^ (sid & QUIC_STRM_SERV_MASK)) {
		if (id >= strms->p_bi_cnt)
			return NULL;
		return genradix_ptr(&strms->p_bi, id);
	}

	if (id >= strms->l_bi_cnt) {
		if (id >= qs->params.local.initial_max_streams_bidi) {
			qs->frame.max.limit = id + 1;
			skb = quic_packet_create(qs, QUIC_PKT_SHORT,
						 QUIC_FRAME_STREAMS_BLOCKED_BIDI);
			if (skb) {
				quic_write_queue_enqueue(qs, skb);
				quic_write_queue_flush(qs);
			}
			return NULL;
		}
		if (genradix_prealloc(&strms->l_bi, id + 1, GFP_ATOMIC))
			return NULL;
		snd_max = qs->params.peer.initial_max_stream_data_bidi_remote;
		rcv_max = qs->params.local.initial_max_stream_data_bidi_local;
		for (i = 0; i <= id - strms->l_bi_cnt; i++) {
			quic_strm(&strms->l_bi, i + strms->l_bi_cnt)->snd_max = snd_max;
			quic_strm(&strms->l_bi, i + strms->l_bi_cnt)->rcv_max = rcv_max;
		}
		strms->l_bi_cnt = id + 1;
	}
	return genradix_ptr(&strms->l_bi, id);
}

struct quic_strm *quic_strm_rcv_get(struct quic_sock *qs, u32 sid)
{
	struct quic_strms *strms = &qs->strms;
	u32 i, id = sid >> QUIC_STRM_MASK_BITS;
	u64 snd_max, rcv_max;

	if (sid & QUIC_STRM_UNI_MASK) {
		if (quic_is_serv(qs) ^ !(sid & QUIC_STRM_SERV_MASK))
			return NULL;
		if (id >= strms->p_uni_cnt) {
			if (id >= qs->params.peer.initial_max_streams_uni)
				return NULL;
			if (genradix_prealloc(&strms->p_uni, id + 1, GFP_ATOMIC))
				return NULL;
			rcv_max = qs->params.local.initial_max_stream_data_uni;
			for (i = 0; i <= id - strms->p_uni_cnt; i++)
				quic_strm(&strms->p_uni, i + strms->p_uni_cnt)->rcv_max = rcv_max;
			strms->p_uni_cnt = id + 1;
		}
		return genradix_ptr(&strms->p_uni, id);
	}

	if (quic_is_serv(qs) ^ !(sid & QUIC_STRM_SERV_MASK)) {
		if (id >= strms->l_bi_cnt)
			return NULL;
		return genradix_ptr(&strms->l_bi, id);
	}

	if (id >= strms->p_bi_cnt) {
		if (id >= qs->params.peer.initial_max_streams_bidi)
			return NULL;
		if (genradix_prealloc(&strms->p_bi, id + 1, GFP_ATOMIC))
			return NULL;
		snd_max = qs->params.peer.initial_max_stream_data_bidi_local;
		rcv_max = qs->params.local.initial_max_stream_data_bidi_remote;
		for (i = 0; i <= id - strms->p_bi_cnt; i++) {
			quic_strm(&strms->p_bi, i + strms->p_bi_cnt)->snd_max = snd_max;
			quic_strm(&strms->p_bi, i + strms->p_bi_cnt)->rcv_max = rcv_max;
		}
		strms->p_bi_cnt = id + 1;
	}
	return genradix_ptr(&strms->p_bi, id);
}

struct quic_strm *quic_strm_get(struct quic_sock *qs, u32 sid)
{
	struct quic_strms *strms = &qs->strms;
	u32 id = sid >> QUIC_STRM_MASK_BITS;

	if (quic_is_serv(qs) ^ (id & QUIC_STRM_SERV_MASK)) {
		if (sid & QUIC_STRM_UNI_MASK)
			return genradix_ptr(&strms->p_uni, id);
		return genradix_ptr(&strms->p_bi, id);
	}
	if (sid & QUIC_STRM_UNI_MASK)
		return genradix_ptr(&strms->l_uni, id);
	return genradix_ptr(&strms->l_bi, id);
}

int quic_strm_init(struct quic_sock *qs, u32 uni_cnt, u32 bi_cnt)
{
	struct quic_strms *strms = &qs->strms;
	u64 snd_max, rcv_max;
	int err, i;

	strms->l_uni_cnt = uni_cnt;
	err = genradix_prealloc(&strms->l_uni, strms->l_uni_cnt, GFP_ATOMIC);
	if (err)
		return err;

	snd_max = qs->params.peer.initial_max_stream_data_uni;
	for (i = 0; i < strms->l_uni_cnt; i++)
		quic_strm(&strms->l_uni, i)->snd_max = snd_max;

	strms->l_bi_cnt = bi_cnt;
	err = genradix_prealloc(&strms->l_bi, strms->l_bi_cnt, GFP_ATOMIC);
	if (err) {
		genradix_free(&strms->l_uni);
		return err;
	}

	snd_max = qs->params.peer.initial_max_stream_data_bidi_remote;
	rcv_max = qs->params.local.initial_max_stream_data_bidi_local;
	for (i = 0; i < strms->l_bi_cnt; i++) {
		quic_strm(&strms->l_bi, i)->snd_max = snd_max;
		quic_strm(&strms->l_bi, i)->rcv_max = rcv_max;
	}

	return 0;
}

void quic_strm_free(struct quic_sock *qs)
{
	genradix_free(&qs->strms.l_uni);
	genradix_free(&qs->strms.l_bi);
	genradix_free(&qs->strms.p_uni);
	genradix_free(&qs->strms.p_bi);
}
