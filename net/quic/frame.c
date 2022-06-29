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

static int quic_frame_params_len_get(struct quic_sock *qs)
{
	struct quic_param *p = &qs->params.local;
	u32 len;

	len = (1 + quic_varint_len(qs->cids.scid.cur->len) + qs->cids.scid.cur->len) +
		quic_varint_lens(p->max_udp_payload_size) + 1 +
		quic_varint_lens(p->initial_max_data) + 1 +
		quic_varint_lens(p->initial_max_stream_data_bidi_local) + 1 +
		quic_varint_lens(p->initial_max_stream_data_bidi_remote) + 1 +
		quic_varint_lens(p->initial_max_stream_data_uni) + 1 +
		quic_varint_lens(p->initial_max_streams_bidi) + 1 +
		quic_varint_lens(p->initial_max_streams_uni) + 1;

	if (qs->crypt.is_serv)
		len += (1 + quic_varint_len(qs->cids.scid.cur->len) + qs->cids.scid.cur->len);

	return len;
}

#define QUIC_EXT_quic_transport_parameters	0x0039
static int quic_ext_transport_init(struct quic_sock *qs, struct quic_vlen *f)
{
	struct quic_param *pm = &qs->params.local;
	u8 *p = f->v;

	f->len = 0;
	p = quic_put_fixint(p, QUIC_EXT_quic_transport_parameters, 2);
	p = quic_put_fixint(p, quic_frame_params_len_get(qs), 2);
	if (qs->crypt.is_serv) {
		p = quic_put_varint(p, QUIC_PARAM_original_destination_connection_id);
		p = quic_put_varint(p, qs->cids.scid.cur->len);
		p = quic_put_data(p, qs->cids.scid.cur->id, qs->cids.scid.cur->len);
	}
	p = quic_put_varint(p, QUIC_PARAM_max_udp_payload_size);
	p = quic_put_varint(p, quic_varint_len(pm->max_udp_payload_size));
	p = quic_put_varint(p, pm->max_udp_payload_size);
	p = quic_put_varint(p, QUIC_PARAM_initial_max_data);
	p = quic_put_varint(p, quic_varint_len(pm->initial_max_data));
	p = quic_put_varint(p, pm->initial_max_data);
	p = quic_put_varint(p, QUIC_PARAM_initial_max_stream_data_bidi_local);
	p = quic_put_varint(p, quic_varint_len(pm->initial_max_stream_data_bidi_local));
	p = quic_put_varint(p, pm->initial_max_stream_data_bidi_local);
	p = quic_put_varint(p, QUIC_PARAM_initial_max_stream_data_bidi_remote);
	p = quic_put_varint(p, quic_varint_len(pm->initial_max_stream_data_bidi_remote));
	p = quic_put_varint(p, pm->initial_max_stream_data_bidi_remote);
	p = quic_put_varint(p, QUIC_PARAM_initial_max_stream_data_uni);
	p = quic_put_varint(p, quic_varint_len(pm->initial_max_stream_data_uni));
	p = quic_put_varint(p, pm->initial_max_stream_data_uni);
	p = quic_put_varint(p, QUIC_PARAM_initial_max_streams_bidi);
	p = quic_put_varint(p, quic_varint_len(pm->initial_max_streams_bidi));
	p = quic_put_varint(p, pm->initial_max_streams_bidi);
	p = quic_put_varint(p, QUIC_PARAM_initial_max_streams_uni);
	p = quic_put_varint(p, quic_varint_len(pm->initial_max_streams_uni));
	p = quic_put_varint(p, pm->initial_max_streams_uni);
	p = quic_put_varint(p, QUIC_PARAM_initial_source_connection_id);
	p = quic_put_varint(p, qs->cids.scid.cur->len);
	p = quic_put_data(p, qs->cids.scid.cur->id, qs->cids.scid.cur->len);
	f->len = (u32)(p - f->v);

	return 0;
}

static int quic_frame_ch_crypto_create(struct quic_sock *qs)
{
	struct quic_vlen *f = &qs->frame.f[QUIC_PKT_INITIAL];
	struct tls_vec vec;
	int err = -EINVAL;
	u8 *p;

        quic_ext_transport_init(qs, f);

        tls_vec(&vec, f->v, f->len); /* reuse initial frame */
        err = tls_handshake_set(qs->tls, TLS_T_EXT, &vec);
        if (err)
                return err;
	f->len = 0;

        err = tls_handshake(qs->tls, NULL, &vec);
        if (err < 0)
                return err;

	p = f->v + f->len;
	p = quic_put_varint(p, QUIC_FRAME_CRYPTO);
	p = quic_put_varint(p, 0);
	p = quic_put_varint(p, vec.len);
	p = quic_put_data(p, vec.data, vec.len);
	f->len = (u32)(p - f->v);

	return 0;
}

static int quic_frame_sh_crypto_create(struct quic_sock *qs)
{
	struct quic_vlen *f = &qs->frame.f[QUIC_PKT_INITIAL];
	struct tls_vec vec = {NULL, 0};
	int err;
	u8 *p;

	err = tls_handshake_get(qs->tls, TLS_T_MSG, &vec);
	if (err)
		return err;

	f->len = 0;
	p = f->v + f->len;
	p = quic_put_varint(p, QUIC_FRAME_CRYPTO);
	p = quic_put_varint(p, 0);
	p = quic_put_varint(p, vec.len);
	p = quic_put_data(p, vec.data, vec.len);
	f->len = (u32)(p - f->v);

	f = &qs->frame.f[QUIC_PKT_HANDSHAKE];
	quic_ext_transport_init(qs, f); /* for ee msg */
	tls_vec(&vec, f->v, f->len); /* reuse initial frame */
	err = tls_handshake_set(qs->tls, TLS_T_EXT, &vec);
	if (err)
		return err;
	f->len = 0;

	return 0;
}

static int quic_frame_ack_create(struct quic_sock *qs)
{
	struct quic_vlen *f = &qs->frame.f[qs->packet.type];
	u8 *p, *tmp;
	u32 f_len;

	p = f->v + f->len;
	tmp = p;
	p = quic_put_varint(p, QUIC_FRAME_ACK);
	p = quic_put_varint(p, qs->packet.pn); /* Largest Acknowledged */
	p = quic_put_varint(p, 0); /* ACK Delay */
	p = quic_put_varint(p, 0); /* ACK Count */
	p = quic_put_varint(p, 0); /* First ACK Range */
	f_len = (u32)(p - tmp);
	f->len += f_len;

	return 0;
}

static int quic_frame_ping_create(struct quic_sock *qs)
{
	struct quic_vlen *f = &qs->frame.f[qs->packet.type];
	u8 *p, *tmp;
	u32 f_len;

	p = f->v + f->len;
	tmp = p;
	p = quic_put_varint(p, QUIC_FRAME_PING);
	f_len = (u32)(p - tmp);
	f->len += f_len;

	return 0;
}

static int quic_frame_padding_create(struct quic_sock *qs)
{
	return 0;
}

static int quic_frame_new_token_create(struct quic_sock *qs)
{
	struct quic_vlen *f = &qs->frame.f[qs->packet.type];
	u8 *p, *tmp;
	u32 f_len;

	p = f->v + f->len;
	tmp = p;
	p = quic_put_varint(p, QUIC_FRAME_NEW_TOKEN);
	p = quic_put_varint(p, qs->token.len);
	p = quic_put_data(p, qs->token.token, qs->token.len);
	f_len = (u32)(p - tmp);
	f->len += f_len;

	return 0;
}

static int quic_frame_stream_create(struct quic_sock *qs)
{
	struct quic_vlen *f = &qs->frame.f[qs->packet.type];
	struct iov_iter *msg = qs->frame.stream.msg;
	u32 mlen = iov_iter_count(msg), hlen, off;
	u32 mss = qs->frame.stream.mss;
	u32 sid = qs->frame.stream.sid;
	struct quic_strm *strm;
	u8 *p, *tmp, flag;

	strm = quic_strm_snd_get(qs, sid);
	if (!strm)
		return -EINVAL;

	off = strm->snd_off;
	mss -= quic_fixint_len(qs->packet.ad_tx_pn + 1);
	flag = QUIC_FRAME_STREAM;
	if (mlen < 16 - 2)
		flag |= 0x02;
	if (off)
		flag |= 0x04;

	qs->frame.has_strm = 1;
	qs->frame.stream.off = off;
	p = f->v + f->len;
	tmp = p++;
	p = quic_put_varint(p, sid);
	if (flag & 0x04)
		p = quic_put_varint(p, off);
	if (flag & 0x02) {
		p = quic_put_varint(p, mlen);
		hlen = (u32)(p - tmp);
	} else {
		hlen = (u32)(p - tmp);
		if (mss - hlen < mlen)
			mlen = mss - hlen;
		else if (qs->frame.stream.fin)
			flag |= 0x01;
	}
	quic_put_varint(tmp, flag);

	if (!copy_from_iter_full(p, mlen, msg))
		return -EFAULT;
	pr_debug("[QUIC] create stream hlen: %u, mlen: %u, mss: %u, off: %u\n",
		 hlen, mlen, mss, off);

	if (flag & 0x01)
		strm->snd_state = QUIC_STRM_L_SENT;
	qs->frame.stream.len = mlen;
	strm->in_flight++;
	strm->snd_off += mlen;
	f->len += hlen + mlen;
	return 0;
}

static int quic_frame_handshake_done_create(struct quic_sock *qs)
{
	struct quic_vlen *f = &qs->frame.f[QUIC_PKT_SHORT];
	u8 *p = f->v + f->len;

	p = quic_put_varint(p, 0x1e);

	return 0;
}

static int quic_frame_fin_crypto_create(struct quic_sock *qs)
{
	struct quic_vlen *f = &qs->frame.f[QUIC_PKT_HANDSHAKE];
	struct tls_vec vec = {NULL, 0};
	int err;
	u8 *p;

        err = tls_handshake_get(qs->tls, TLS_T_MSG, &vec);
        if (err)
                return err;

	f->len = 0;
	p = f->v + f->len;
	p = quic_put_varint(p, QUIC_FRAME_CRYPTO);
	p = quic_put_varint(p, 0);
	p = quic_put_varint(p, vec.len);
	p = quic_put_data(p, vec.data, vec.len);
	f->len = (u32)(p - f->v);
	return 0;
}

static int quic_frame_hs_crypto_create(struct quic_sock *qs)
{
	struct quic_vlen *f = &qs->frame.f[QUIC_PKT_HANDSHAKE];
	struct quic_vlen *fr = &qs->frame.f[QUIC_PKT_INITIAL];
	int mss, hmss, hlen, m_len, t_len, d_len;
	struct tls_vec vec = {NULL, 0};
	int err, i = 1;
	u8 *p, *tmp;

        err = tls_handshake_get(qs->tls, TLS_T_MSG, &vec);
        if (err)
                return err;

	mss = quic_dst_mss_check(qs, 0);
	if (mss < 0)
		return mss;
	hmss = quic_dst_mss_check(qs, 2);
	if (hmss < 0)
		return hmss;
	hlen = mss - hmss;
	m_len = hmss - 4;
	if ((fr->len + hlen) < m_len)
		m_len -= (fr->len + hlen); /* try to bundle with sh crypto */
	tmp = vec.data;
	t_len = vec.len;

	while (t_len > 0) {
		d_len = m_len < t_len ? m_len : t_len;
		f->len = 0;
		p = f->v + f->len;
		p = quic_put_varint(p, QUIC_FRAME_CRYPTO);
		p = quic_put_varint(p, vec.len - t_len);
		p = quic_put_varint(p, d_len);
		p = quic_put_data(p, tmp, d_len);
		f->len = (u32)(p - f->v);
		pr_debug("[QUIC] hs_crypto t_len: %u,  m_len: %u, f_len: %u\n", t_len, m_len, f->len);

		t_len -= d_len;
		tmp += d_len;
		m_len = hmss - 4;
		f = &qs->frame.f[QUIC_PKT_VERSION_NEGOTIATION + i++];
	}

	return 0;
}

static int quic_frame_ticket_crypto_create(struct quic_sock *qs)
{
	struct quic_vlen *f = &qs->frame.f[QUIC_PKT_SHORT];
	struct tls_vec vec;
	int err;
	u8 *p;

        err = tls_handshake_get(qs->tls, TLS_T_MSG, &vec);
        if (err)
                return err;

	f->len = 0;
	p = f->v + f->len;
	p = quic_put_varint(p, QUIC_FRAME_CRYPTO);
	p = quic_put_varint(p, 0);
	p = quic_put_varint(p, vec.len);
	p = quic_put_data(p, vec.data, vec.len);
	f->len = (u32)(p - f->v);

	return 0;
}

static int quic_frame_crypto_create(struct quic_sock *qs)
{
	if (qs->state == QUIC_CS_CLIENT_INITIAL)
		return quic_frame_ch_crypto_create(qs);
	if (qs->state == QUIC_CS_CLIENT_WAIT_HANDSHAKE)
		return quic_frame_fin_crypto_create(qs);
	if (qs->state == QUIC_CS_SERVER_INITIAL)
		return quic_frame_sh_crypto_create(qs);
	if (qs->state == QUIC_CS_SERVER_WAIT_HANDSHAKE)
		return quic_frame_hs_crypto_create(qs);
	if (qs->state == QUIC_CS_SERVER_POST_HANDSHAKE)
		return quic_frame_ticket_crypto_create(qs);
	return -EINVAL;
}

static int quic_frame_retire_connection_id_create(struct quic_sock *qs)
{
	struct quic_vlen *f = &qs->frame.f[QUIC_PKT_SHORT];
	u8 *p, *tmp;
	u32 f_len;

	p = f->v + f->len;
	tmp = p;
	p = quic_put_varint(p, QUIC_FRAME_RETIRE_CONNECTION_ID);
	p = quic_put_varint(p, qs->frame.cid.no);
	f_len = (u32)(p - tmp);
	f->len += f_len;

	return 0;
}

static int quic_frame_new_connection_id_create(struct quic_sock *qs)
{
	struct quic_vlen *f = &qs->frame.f[QUIC_PKT_SHORT];
	struct net *net = sock_net(&qs->inet.sk);
	struct quic_hash_head *head;
	struct quic_cid *cid, *n;
	u8 *p, *tmp, scid[8];
	u32 f_len, num;

	cid = kzalloc(sizeof(*cid), GFP_ATOMIC);
	if (!cid)
		return -ENOMEM;

	get_random_bytes(scid, 8);
	cid->id = quic_mem_dup(scid, 8);
	if (!cid->id) {
		kfree(cid);
		return -ENOMEM;
	}
	cid->len = 8;
	cid->qs = qs;
	num = qs->cids.scid.first + qs->cids.scid.cnt;
	cid->no = num;

	head = quic_cid_head(net, cid->id);
	spin_lock(&head->lock);
	hlist_add_head(&cid->node, &head->head);
	spin_unlock(&head->lock);

	for (n = qs->cids.scid.list; n; n = n->next) {
		if (!n->next) {
			n->next = cid;
			qs->cids.scid.cnt++;
			break;
		}
	}

	p = f->v + f->len;
	tmp = p;
	p = quic_put_varint(p, QUIC_FRAME_NEW_CONNECTION_ID);
	p = quic_put_varint(p, num);
	p = quic_put_varint(p, qs->frame.cid.no);
	p = quic_put_fixint(p, cid->len, 1);
	p = quic_put_data(p, cid->id, cid->len);
	p += 16; /* Stateless Reset Token */
	f_len = (u32)(p - tmp);
	f->len += f_len;

	return 0;
}

static int quic_frame_path_response_create(struct quic_sock *qs)
{
	struct quic_vlen *f = &qs->frame.f[QUIC_PKT_SHORT];
	u8 *p, *tmp;
	u32 f_len;

	p = f->v + f->len;
	tmp = p;
	p = quic_put_varint(p, QUIC_FRAME_PATH_RESPONSE);
	p = quic_put_data(p, qs->frame.path.data, 8);
	f_len = (u32)(p - tmp);
	f->len += f_len;

	return 0;
}

static int quic_frame_path_challenge_create(struct quic_sock *qs)
{
	struct quic_vlen *f = &qs->frame.f[QUIC_PKT_SHORT];
	u8 *p, *tmp;
	u32 f_len;

	p = f->v + f->len;
	tmp = p;
	get_random_bytes(qs->frame.path.data, 8);
	p = quic_put_varint(p, QUIC_FRAME_PATH_CHALLENGE);
	p = quic_put_data(p, qs->frame.path.data, 8);
	f_len = (u32)(p - tmp);
	f->len += f_len;

	return 0;
}

static int quic_frame_reset_stream_create(struct quic_sock *qs)
{
	struct quic_vlen *f = &qs->frame.f[QUIC_PKT_SHORT];
	struct quic_strm *strm;
	u8 *p, *tmp;
	u32 f_len;

	p = f->v + f->len;
	tmp = p;
	strm = quic_strm_snd_get(qs, qs->frame.stream.sid);
	if (!strm)
		return -EINVAL;
	p = quic_put_varint(p, QUIC_FRAME_RESET_STREAM);
	p = quic_put_varint(p, qs->frame.stream.sid);
	p = quic_put_varint(p, 1);
	p = quic_put_varint(p, strm->snd_off);
	f_len = (u32)(p - tmp);
	f->len += f_len;

	return 0;
}

static int quic_frame_stop_sending_create(struct quic_sock *qs)
{
	struct quic_vlen *f = &qs->frame.f[QUIC_PKT_SHORT];
	struct quic_strm *strm;
	u8 *p, *tmp;
	u32 f_len;

	p = f->v + f->len;
	tmp = p;
	strm = quic_strm_rcv_get(qs, qs->frame.stream.sid);
	if (!strm)
		return -EINVAL;
	p = quic_put_varint(p, QUIC_FRAME_STOP_SENDING);
	p = quic_put_varint(p, qs->frame.stream.sid);
	p = quic_put_varint(p, 2);
	f_len = (u32)(p - tmp);
	f->len += f_len;

	return 0;
}

static int quic_frame_max_data_create(struct quic_sock *qs)
{
	struct quic_vlen *f = &qs->frame.f[QUIC_PKT_SHORT];
	u8 *p, *tmp;
	u32 f_len;

	p = f->v + f->len;
	tmp = p;
	p = quic_put_varint(p, QUIC_FRAME_MAX_DATA);
	p = quic_put_varint(p, qs->frame.max.limit);
	f_len = (u32)(p - tmp);
	f->len += f_len;

	return 0;
}

static int quic_frame_max_stream_data_create(struct quic_sock *qs)
{
	struct quic_vlen *f = &qs->frame.f[QUIC_PKT_SHORT];
	u8 *p, *tmp;
	u32 f_len;

	p = f->v + f->len;
	tmp = p;
	p = quic_put_varint(p, QUIC_FRAME_MAX_STREAM_DATA);
	p = quic_put_varint(p, qs->frame.stream.sid);
	p = quic_put_varint(p, qs->frame.max.limit);
	f_len = (u32)(p - tmp);
	f->len += f_len;

	return 0;
}

static int quic_frame_max_streams_uni_create(struct quic_sock *qs)
{
	struct quic_vlen *f = &qs->frame.f[QUIC_PKT_SHORT];
	u8 *p, *tmp;
	u32 f_len;

	p = f->v + f->len;
	tmp = p;
	p = quic_put_varint(p, QUIC_FRAME_MAX_STREAMS_UNI);
	p = quic_put_varint(p, qs->frame.max.limit);
	f_len = (u32)(p - tmp);
	f->len += f_len;

	return 0;
}

static int quic_frame_max_streams_bidi_create(struct quic_sock *qs)
{
	struct quic_vlen *f = &qs->frame.f[QUIC_PKT_SHORT];
	u8 *p, *tmp;
	u32 f_len;

	p = f->v + f->len;
	tmp = p;
	p = quic_put_varint(p, QUIC_FRAME_MAX_STREAMS_BIDI);
	p = quic_put_varint(p, qs->frame.max.limit);
	f_len = (u32)(p - tmp);
	f->len += f_len;

	return 0;
}

static int quic_frame_connection_close_create(struct quic_sock *qs)
{
	struct quic_vlen *f = &qs->frame.f[QUIC_PKT_SHORT];
	u8 *p, *tmp;
	u32 f_len;

	p = f->v + f->len;
	tmp = p;
	p = quic_put_varint(p, QUIC_FRAME_CONNECTION_CLOSE);
	p = quic_put_varint(p, qs->frame.close.err);
	p = quic_put_varint(p, 0);
	p = quic_put_varint(p, 0);
	f_len = (u32)(p - tmp);
	f->len += f_len;
	qs->state = QUIC_CS_CLOSING;

	return 0;
}

static int quic_frame_data_blocked_create(struct quic_sock *qs)
{
	struct quic_vlen *f = &qs->frame.f[QUIC_PKT_SHORT];
	u8 *p, *tmp;
	u32 f_len;

	p = f->v + f->len;
	tmp = p;
	p = quic_put_varint(p, QUIC_FRAME_DATA_BLOCKED);
	p = quic_put_varint(p, qs->frame.max.limit);
	f_len = (u32)(p - tmp);
	f->len += f_len;

	return 0;
}

static int quic_frame_stream_data_blocked_create(struct quic_sock *qs)
{
	struct quic_vlen *f = &qs->frame.f[QUIC_PKT_SHORT];
	u8 *p, *tmp;
	u32 f_len;

	p = f->v + f->len;
	tmp = p;
	p = quic_put_varint(p, QUIC_FRAME_STREAM_DATA_BLOCKED);
	p = quic_put_varint(p, qs->frame.stream.sid);
	p = quic_put_varint(p, qs->frame.max.limit);
	f_len = (u32)(p - tmp);
	f->len += f_len;

	return 0;
}

static int quic_frame_streams_blocked_uni_create(struct quic_sock *qs)
{
	struct quic_vlen *f = &qs->frame.f[QUIC_PKT_SHORT];
	u8 *p, *tmp;
	u32 f_len;

	p = f->v + f->len;
	tmp = p;
	p = quic_put_varint(p, QUIC_FRAME_STREAMS_BLOCKED_UNI);
	p = quic_put_varint(p, qs->frame.max.limit);
	f_len = (u32)(p - tmp);
	f->len += f_len;

	return 0;
}

static int quic_frame_streams_blocked_bidi_create(struct quic_sock *qs)
{
	struct quic_vlen *f = &qs->frame.f[QUIC_PKT_SHORT];
	u8 *p, *tmp;
	u32 f_len;

	p = f->v + f->len;
	tmp = p;
	p = quic_put_varint(p, QUIC_FRAME_STREAMS_BLOCKED_BIDI);
	p = quic_put_varint(p, qs->frame.max.limit);
	f_len = (u32)(p - tmp);
	f->len += f_len;

	return 0;
}

static int quic_frame_crypto_process(struct quic_sock *qs, u8 **ptr, u8 type, u32 left)
{
	u32 len, hs_offset, hs_len, dlen;
	struct sock *sk = &qs->inet.sk;
	struct tls_vec in, vec;
	struct quic_cid *cid;
	u8 *p = *ptr, *dcid;
	int err = 0, ret;

	hs_offset = quic_get_varint(&p, &len);
	left -= len;
	hs_len = quic_get_varint(&p, &len);
	left -= len;

	if (qs->state == QUIC_CS_CLIENT_POST_HANDSHAKE ||
	    qs->state == QUIC_CS_SERVER_POST_HANDSHAKE) {
		ret = tls_handshake_post(qs->tls, TLS_P_NONE, tls_vec(&in, p, hs_len), &vec);
		switch (ret) {
		case TLS_P_NONE:
			break;
		case TLS_P_TICKET:
			err = quic_evt_notify_ticket(qs);
			break;
		default:
			return -EINVAL;
		}
		*ptr = p + hs_len;
		return err;
	}

	/* process */
	ret = tls_handshake(qs->tls, tls_vec(&in, p, hs_len), &vec);
	switch (ret) {
	case TLS_ST_START:
		break;
	case TLS_ST_RCVD:
		if (qs->crypt.is_serv) {
			quic_crypto_early_keys_install(qs);
			err = quic_frame_create(qs, QUIC_FRAME_CRYPTO);
			if (err)
				return err;

			qs->state = QUIC_CS_SERVER_WAIT_HANDSHAKE;
			quic_crypto_handshake_keys_install(qs);
			err = tls_handshake(qs->tls, NULL, &vec);
			if (err < 0)
				return err;
			err = quic_frame_create(qs, QUIC_FRAME_CRYPTO);
			if (err)
				return err;

			quic_crypto_application_keys_install(qs);
			list_add_tail(&qs->list, &qs->lsk->list);
			sk = &qs->lsk->inet.sk;
			sk_acceptq_added(sk);
			sk->sk_state_change(sk);
		} else {
			qs->state = QUIC_CS_CLIENT_WAIT_HANDSHAKE;
			quic_crypto_handshake_keys_install(qs);

			dcid = QUIC_RCV_CB(qs->packet.skb)->scid;
			dlen = QUIC_RCV_CB(qs->packet.skb)->scid_len;
			dcid = quic_mem_dup(dcid, dlen);
			if (!dcid)
				return -ENOMEM;
			cid = qs->cids.dcid.list;
			kfree(cid->id);
			cid->id = dcid;
			cid->len = dlen;

			quic_stop_hs_timer(qs);
		}
		break;
	case TLS_ST_WAIT:
		break;
	case TLS_ST_CONNECTED:
		if (qs->crypt.is_serv) {
			qs->state = QUIC_CS_SERVER_POST_HANDSHAKE;
		} else {
			err = quic_frame_create(qs, QUIC_FRAME_CRYPTO);
			if (err)
				return err;
			quic_crypto_application_keys_install(qs);
			qs->state = QUIC_CS_CLIENT_POST_HANDSHAKE;
		}
		inet_sk_set_state(sk, QUIC_SS_ESTABLISHED);
		sk->sk_state_change(sk);
		break;
	default:
		err = ret;
	}

	*ptr = p + hs_len;
	return err;
}

static int quic_frame_stream_process(struct quic_sock *qs, u8 **ptr, u8 type, u32 left)
{
	u32 v, len, id, off = 0;
	u8 *p = *ptr, fin = 0;
	struct sk_buff *skb;
	int err = 0;

	id = quic_get_varint(&p, &len);
	left -= len;
	pr_debug("[QUIC] stream id: %u, left: %u\n", id, left);
	if (type & 0x04) {
		off = quic_get_varint(&p, &len);
		left -= len;
	}
	if (type & 0x02) {
		len = quic_get_varint(&p, &v);
		p += len;
	} else {
		len = left;
		p += left;
	}
	if (type & 0x01)
		fin = 1;
	skb = skb_clone(qs->packet.skb, GFP_ATOMIC);
	if (!skb)
		goto out;
	QUIC_RCV_CB(skb)->strm_id = id;
	QUIC_RCV_CB(skb)->strm_off = off;
	QUIC_RCV_CB(skb)->strm_fin = fin;
	QUIC_RCV_CB(skb)->pn = qs->packet.pn;
	skb_pull(skb, (p - len) - skb->data);
	skb_trim(skb, len);

	err = quic_receive_list_add(qs, skb);
	if (err && err != -ENOBUFS) {
		kfree_skb(skb);
		err = 0;
	}

out:
	*ptr = p;
	return err;
}

static int quic_frame_ack_process(struct quic_sock *qs, u8 **ptr, u8 type, u32 left)
{
	u32 v, len, count, i;
	u8 *p = *ptr;

	v = quic_get_varint(&p, &len);
	if (qs->packet.type == QUIC_PKT_SHORT)
		quic_send_queue_check(qs, v);
	v = quic_get_varint(&p, &len);
	count = quic_get_varint(&p, &len);
	v = quic_get_varint(&p, &len);

	for (i = 0; i < count; i++) {
		v = quic_get_varint(&p, &len);
		v = quic_get_varint(&p, &len);
	}

	if (v == QUIC_FRAME_ACK_ECN) {
		v = quic_get_varint(&p, &len);
		v = quic_get_varint(&p, &len);
		v = quic_get_varint(&p, &len);
	}

	*ptr = p;
	return 0;
}

static int quic_frame_new_connection_id_process(struct quic_sock *qs, u8 **ptr, u8 type, u32 left)
{
	u32 v, len, prior_to, no, value[3] = {0};
	u8 *p = *ptr, cur = 0, cnt = 0;
	struct quic_cid *cid, *tmp;
	int err;

	v = quic_get_varint(&p, &len);
	no = v;
	v = quic_get_varint(&p, &len);
	prior_to = v;
	len = quic_get_fixint(&p, 1);

	if (no != qs->cids.dcid.first + qs->cids.dcid.cnt)
		return -EINVAL;

	cid = kzalloc(sizeof(*cid), GFP_ATOMIC);
	if (!cid)
		return -ENOMEM;

	cid->no = no;
	cid->len = len;

	cid->id = quic_mem_dup(p, len);
	if (!cid->id) {
		kfree(cid);
		return -ENOMEM;
	}
	p += len;

	for (tmp = qs->cids.dcid.list; tmp; tmp = tmp->next) {
		if (tmp->len == cid->len && !memcmp(cid->id, tmp->id, tmp->len)) {
			kfree(cid->id);
			kfree(cid);
			return -EINVAL;
		}
		if (!tmp->next) {
			tmp->next = cid;
			qs->cids.dcid.cnt++;
			cnt = 1;
			break;
		}
	}
	v = 0;
	tmp = qs->cids.dcid.list;
	while (tmp->next) {
		if (tmp->no >= prior_to)
			break;
		qs->cids.dcid.list = tmp->next;
		if (tmp == qs->cids.dcid.cur) {
			qs->cids.dcid.cur = qs->cids.dcid.list;
			cur = 1;
		}
		qs->cids.dcid.cnt--;
		quic_cid_destroy(tmp);
		tmp = qs->cids.dcid.list;
		v = 1;
	}

	if (prior_to > qs->cids.dcid.first)
		qs->cids.dcid.first = prior_to;

	if (v) {
		qs->frame.cid.no = prior_to - 1;
		err = quic_frame_create(qs, QUIC_FRAME_RETIRE_CONNECTION_ID);
		if (err)
			return err;
	}

	if (cur) {
		value[0] = 1;
		value[1] = qs->cids.dcid.cur->no;
		err = quic_evt_notify(qs, QUIC_EVT_CIDS, QUIC_EVT_CIDS_CUR, value);
		if (err)
			return err;
	}
	if (cnt) {
		value[0] = 1;
		value[1] = no;
		value[2] = prior_to;
		err = quic_evt_notify(qs, QUIC_EVT_CIDS, QUIC_EVT_CIDS_NEW, value);
		if (err)
			return err;
	}

	pr_debug("[QUIC] Tell Userspace Stateless Reset Token: %16phN\n", p);
	p += 16;

	*ptr = p;
	return 0;
}

static int quic_frame_retire_connection_id_process(struct quic_sock *qs, u8 **ptr,
						   u8 type, u32 left)
{
	u32 v, len, retire_no, value[3] = {0};
	u8 *p = *ptr, cur = 0;
	struct quic_cid *tmp;
	int err;

	retire_no = quic_get_varint(&p, &len);
	pr_debug("[QUIC] Tell Userspace Retire Sequence Number: %u\n", retire_no);

	v = 0;
	tmp = qs->cids.scid.list;
	while (tmp->next) {
		if (tmp->no > retire_no)
			break;
		qs->cids.scid.list = tmp->next;
		if (tmp == qs->cids.scid.cur) {
			qs->cids.scid.cur = qs->cids.scid.list;
			cur = 1;
		}
		qs->cids.scid.cnt--;
		quic_cid_destroy(tmp);
		tmp = qs->cids.scid.list;
		v = 1;
	}
	if (v) {
		value[0] = 0;
		value[1] = retire_no;
		err = quic_evt_notify(qs, QUIC_EVT_CIDS, QUIC_EVT_CIDS_DEL, value);
		if (err)
			return err;

		qs->frame.cid.no = retire_no + 1;
		qs->cids.scid.first = retire_no + 1;
		err = quic_frame_create(qs, QUIC_FRAME_NEW_CONNECTION_ID);
		if (err)
			return err;
	}

	if (cur) {
		value[0] = 0;
		value[1] = qs->cids.scid.cur->no;
		err = quic_evt_notify(qs, QUIC_EVT_CIDS, QUIC_EVT_CIDS_CUR, value);
		if (err)
			return err;
	}

	*ptr = p;
	return 0;
}

static int quic_frame_new_token_process(struct quic_sock *qs, u8 **ptr, u8 type, u32 left)
{
	u8 *p = *ptr;
	u32 v, len;
	int err;

	len = quic_get_varint(&p, &v);
	kfree(qs->token.token);
	qs->token.len = len;
	qs->token.token = quic_mem_dup(p, len);
	p += len;

	err = quic_evt_notify_token(qs);
	if (err)
		return err;

	*ptr = p;
	return 0;
}

static int quic_frame_handshake_done_process(struct quic_sock *qs, u8 **ptr, u8 type, u32 left)
{
	u8 *p = *ptr;

	*ptr = p;
	return 0;
}

static int quic_frame_padding_process(struct quic_sock *qs, u8 **ptr, u8 type, u32 left)
{
	u8 *p = *ptr;

	p += left;
	*ptr = p;
	return 0;
}

static int quic_frame_ping_process(struct quic_sock *qs, u8 **ptr, u8 type, u32 left)
{
	u8 *p = *ptr;

	p++;
	*ptr = p;
	return 0;
}

static int quic_frame_path_challenge_process(struct quic_sock *qs, u8 **ptr, u8 type, u32 left)
{
	u8 *p = *ptr;
	int err;

	qs->frame.path.data = p;
	err = quic_frame_create(qs, QUIC_FRAME_PATH_RESPONSE);
	if (err)
		return err;
	p += 8;
	*ptr = p;
	return 0;
}

static int quic_frame_reset_stream_process(struct quic_sock *qs, u8 **ptr, u8 type, u32 left)
{
	u32 v, len, sid, value[3] = {0};
	struct quic_strm *strm;
	u8 *p = *ptr;
	int err;

	sid = quic_get_varint(&p, &len);
	if (quic_is_serv(qs) ^ !(sid & 0x01))
		return -EINVAL;
	strm = quic_strm_rcv_get(qs, sid);
	if (!strm)
		return -EINVAL;

	value[0] = sid;
	v = quic_get_varint(&p, &len);
	value[1] = v;
	v = quic_get_varint(&p, &len);
	value[2] = v;
	quic_receive_list_del(qs, sid);
	strm->rcv_state = QUIC_STRM_P_RESET_RECVD;

	err = quic_evt_notify(qs, QUIC_EVT_STREAMS, QUIC_EVT_STREAMS_RESET, value);
	if (err)
		return err;

	*ptr = p;
	return 0;
}

static int quic_frame_stop_sending_process(struct quic_sock *qs, u8 **ptr, u8 type, u32 left)
{
	u32 v, len, value[3] = {0};
	struct quic_strm *strm;
	u8 *p = *ptr;
	int err;

	v = quic_get_varint(&p, &len);
	strm = quic_strm_snd_get(qs, v);
	if (!strm)
		return -EINVAL;
	qs->frame.stream.sid = v;
	err = quic_frame_create(qs, QUIC_FRAME_RESET_STREAM);
	if (err)
		return err;
	value[0] = v;
	v = quic_get_varint(&p, &len);
	value[1] = v;
	strm->snd_state = QUIC_STRM_L_RESET_SENT;
	err = quic_evt_notify(qs, QUIC_EVT_STREAMS, QUIC_EVT_STREAMS_STOP, value);
	if (err)
		return err;

	*ptr = p;
	return 0;
}

static int quic_frame_max_data_process(struct quic_sock *qs, u8 **ptr, u8 type, u32 left)
{
	u8 *p = *ptr;
	u32 len;
	u64 max;

	max = quic_get_varint(&p, &len);

	if (max > qs->packet.snd_max)
		qs->packet.snd_max = max;
	if (qs->packet.fc_md) {
		kfree_skb(qs->packet.fc_md);
		qs->packet.fc_md = NULL;
	}
	quic_write_queue_flush(qs);

	*ptr = p;
	return 0;
}

static int quic_frame_max_stream_data_process(struct quic_sock *qs, u8 **ptr, u8 type, u32 left)
{
	struct quic_strm *strm;
	u32 sid, len;
	u8 *p = *ptr;
	u64 max;

	sid = quic_get_varint(&p, &len);
	strm = quic_strm_get(qs, sid);
	if (!strm)
		return -EINVAL;
	max = quic_get_varint(&p, &len);

	if (max > strm->snd_max)
		strm->snd_max = max;
	if (qs->packet.fc_msd) {
		kfree_skb(qs->packet.fc_msd);
		qs->packet.fc_msd = NULL;
	}
	quic_write_queue_flush(qs);

	*ptr = p;
	return 0;
}

static int quic_frame_max_streams_uni_process(struct quic_sock *qs, u8 **ptr, u8 type, u32 left)
{
	u32 v, len, value[3] = {0};
	u8 *p = *ptr;
	int err;

	v = quic_get_varint(&p, &len);
	value[1] = v;
	err = quic_evt_notify(qs, QUIC_EVT_STREAMS, QUIC_EVT_STREAMS_MAX, value);
	if (err)
		return err;
	if (qs->params.local.initial_max_streams_uni < v)
		qs->params.local.initial_max_streams_uni = v;

	pr_debug("[QUIC] Tell Userspace uni streams %u allowed\n", v);

	*ptr = p;
	return 0;
}

static int quic_frame_max_streams_bidi_process(struct quic_sock *qs, u8 **ptr, u8 type, u32 left)
{
	u32 v, len, value[3] = {0};
	u8 *p = *ptr;
	int err;

	v = quic_get_varint(&p, &len);
	value[0] = 1;
	value[1] = v;
	err = quic_evt_notify(qs, QUIC_EVT_STREAMS, QUIC_EVT_STREAMS_MAX, value);
	if (err)
		return err;

	if (qs->params.local.initial_max_streams_bidi < v)
		qs->params.local.initial_max_streams_bidi = v;

	pr_debug("[QUIC] Tell Userspace bidi streams %u allowed\n", v);

	*ptr = p;
	return 0;
}

static int quic_frame_connection_close_process(struct quic_sock *qs, u8 **ptr, u8 type, u32 left)
{
	struct sock *sk = &qs->inet.sk;
	u8 *p = *ptr;
	u32 v, len;

	v = quic_get_varint(&p, &len);
	pr_debug("[QUIC] Connection Close error: %u\n", v);
	v = quic_get_varint(&p, &len);
	if (type == QUIC_FRAME_CONNECTION_CLOSE)
		v = quic_get_varint(&p, &len);
	len = quic_get_varint(&p, &v);
	p += len;
	qs->state = QUIC_CS_CLOSING;
	sk->sk_data_ready(sk);

	*ptr = p;
	return 0;
}

static int quic_frame_data_blocked_process(struct quic_sock *qs, u8 **ptr, u8 type, u32 left)
{
	u32 pkt_rwnd = qs->params.local.initial_max_data, len;
	u8 *p = *ptr;
	u64 max;
	int err;

	max = quic_get_varint(&p, &len);
	max = (max != qs->packet.rcv_max) ? qs->packet.rcv_max
					  : qs->packet.rcv_len + pkt_rwnd;

	qs->frame.max.limit = max;
	qs->packet.rcv_max = max;
	err = quic_frame_create(qs, QUIC_FRAME_MAX_DATA);
	if (err)
		return err;

	*ptr = p;
	return 0;
}

static int quic_frame_stream_data_blocked_process(struct quic_sock *qs, u8 **ptr, u8 type, u32 left)
{
	struct quic_strm *strm;
	u32 sid, len, strm_rwnd;
	u8 *p = *ptr;
	u64 max;
	int err;

	sid = quic_get_varint(&p, &len);
	max = quic_get_varint(&p, &len);
	strm = quic_strm_get(qs, sid);
	if (!strm)
		return -EINVAL;

	strm_rwnd = quic_strm_max_get(qs, sid);
	max = (max != strm->rcv_max) ? strm->rcv_max
				     : strm->rcv_len + strm_rwnd;

	qs->frame.stream.sid = sid;
	qs->frame.max.limit = max;
	strm->rcv_max = max;
	err = quic_frame_create(qs, QUIC_FRAME_MAX_STREAM_DATA);
	if (err)
		return err;

	*ptr = p;
	return 0;
}

static int quic_frame_streams_blocked_uni_process(struct quic_sock *qs, u8 **ptr, u8 type, u32 left)
{
	u32 v, len, value[3] = {0};
	u8 *p = *ptr;
	int err;

	v = quic_get_varint(&p, &len);
	value[1] = v;
	err = quic_evt_notify(qs, QUIC_EVT_STREAMS, QUIC_EVT_STREAMS_BLOCKED, value);
	if (err)
		return err;

	pr_debug("[QUIC] Tell Userspace the peer needs %u uni streams\n", v);

	*ptr = p;
	return 0;
}

static int quic_frame_streams_blocked_bidi_process(struct quic_sock *qs, u8 **ptr,
						   u8 type, u32 left)
{
	u32 v, len, value[3] = {0};
	u8 *p = *ptr;
	int err;

	v = quic_get_varint(&p, &len);
	value[0] = 1;
	value[1] = v;
	err = quic_evt_notify(qs, QUIC_EVT_STREAMS, QUIC_EVT_STREAMS_BLOCKED, value);
	if (err)
		return err;

	pr_debug("[QUIC] Tell Userspace the peer needs %u bidi streams\n", v);

	*ptr = p;
	return 0;
}

static int quic_frame_path_response_process(struct quic_sock *qs, u8 **ptr, u8 type, u32 left)
{
	u8 *p = *ptr;

	if (!memcmp(qs->frame.path.data, p, 8))
		quic_stop_path_timer(qs);

	p += 8;
	*ptr = p;
	return 0;
}

#define quic_frame_create_and_process(type) \
	{quic_frame_##type##_create, quic_frame_##type##_process}

static struct quic_frame_ops quic_frames[QUIC_FRAME_BASE_MAX + 1] = {
	quic_frame_create_and_process(padding), /* 0x00 */
	quic_frame_create_and_process(ping),
	quic_frame_create_and_process(ack),
	quic_frame_create_and_process(ack), /* ack_ecn */
	quic_frame_create_and_process(reset_stream),
	quic_frame_create_and_process(stop_sending),
	quic_frame_create_and_process(crypto),
	quic_frame_create_and_process(new_token),
	quic_frame_create_and_process(stream),
	quic_frame_create_and_process(stream),
	quic_frame_create_and_process(stream),
	quic_frame_create_and_process(stream),
	quic_frame_create_and_process(stream),
	quic_frame_create_and_process(stream),
	quic_frame_create_and_process(stream),
	quic_frame_create_and_process(stream),
	quic_frame_create_and_process(max_data), /* 0x10 */
	quic_frame_create_and_process(max_stream_data),
	quic_frame_create_and_process(max_streams_bidi),
	quic_frame_create_and_process(max_streams_uni),
	quic_frame_create_and_process(data_blocked),
	quic_frame_create_and_process(stream_data_blocked),
	quic_frame_create_and_process(streams_blocked_bidi),
	quic_frame_create_and_process(streams_blocked_uni),
	quic_frame_create_and_process(new_connection_id),
	quic_frame_create_and_process(retire_connection_id),
	quic_frame_create_and_process(path_challenge),
	quic_frame_create_and_process(path_response),
	quic_frame_create_and_process(connection_close),
	quic_frame_create_and_process(connection_close), /* close_app */
	quic_frame_create_and_process(handshake_done),
};

int quic_frame_process(struct quic_sock *qs, u8 *p, u32 len)
{
	u32 frames_len = len, v;
	int err, left = len;
	u8 *frames_p = p;

	qs->frame.need_ack = 0;
	qs->frame.has_strm = 0;
	qs->frame.non_probe = 0;
	while (1) {
		v = quic_get_varint(&p, &len);
		left -= len;

		if (v != QUIC_FRAME_ACK && v != QUIC_FRAME_PADDING)
			qs->frame.need_ack = 1;
		if (v != QUIC_FRAME_NEW_CONNECTION_ID && v != QUIC_FRAME_PADDING &&
		    v != QUIC_FRAME_PATH_RESPONSE && v != QUIC_FRAME_PATH_CHALLENGE)
			qs->frame.non_probe = 1;

		if (v > QUIC_FRAME_BASE_MAX) {
			pr_err_once("[QUIC] frame err: unsupported frame %u\n", v);
			err = -EPROTONOSUPPORT;
			break;
		}
		pr_debug("[QUIC] frame process %u %u %d\n", v, len, left);
		err = quic_frames[v].frame_process(qs, &p, v, left);
		if (err) {
			pr_warn("[QUIC] frame err %u %d\n", v, err);
			break;
		}

		left = frames_len - (u32)(p - frames_p);
		if (left <= 0)
			break;
	}

	return err;
}

int quic_frame_create(struct quic_sock *qs, u8 type)
{
	int err;

	if (type > QUIC_FRAME_BASE_MAX)
		return -EINVAL;
	pr_debug("[QUIC] frame create %u\n", type);
	err = quic_frames[type].frame_create(qs);
	if (err)
		pr_err("[QUIC] frame create failed %u\n", type);
	return err;
}

int quic_frame_init(struct quic_sock *qs)
{
	int i, err;

	for (i = 0; i < QUIC_FR_NR; i++) {
		qs->frame.f[i].v = (u8 *)__get_free_page(GFP_ATOMIC);
		if (!qs->frame.f[i].v)
			goto err;
	}

	qs->frame.crypto.msg = (u8 *)__get_free_page(GFP_ATOMIC);
	if (!qs->frame.crypto.msg)
		goto err;

	return 0;

err:
	quic_frame_free(qs);
	return err;
}

void quic_frame_free(struct quic_sock *qs)
{
	int i;

	for (i = 0; i < QUIC_FR_NR; i++)
		free_page((unsigned long)qs->frame.f[i].v);

	free_page((unsigned long)qs->frame.crypto.msg);
}
