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

	len = (1 + quic_put_varint_len(qs->cids.scid.cur->len) + qs->cids.scid.cur->len) +
		quic_put_varint_lens(p->max_udp_payload_size) + 1 +
		quic_put_varint_lens(p->initial_max_data) + 1 +
		quic_put_varint_lens(p->initial_max_stream_data_bidi_local) + 1 +
		quic_put_varint_lens(p->initial_max_stream_data_bidi_remote) + 1 +
		quic_put_varint_lens(p->initial_max_stream_data_uni) + 1 +
		quic_put_varint_lens(p->initial_max_streams_bidi) + 1 +
		quic_put_varint_lens(p->initial_max_streams_uni) + 1;

	if (qs->state > QUIC_CS_CLOSING)
		len += (1 + quic_put_varint_len(qs->cids.scid.cur->len) + qs->cids.scid.cur->len);

	return len;
}

static int quic_frame_ch_crypto_init(struct quic_sock *qs)
{
	struct quic_initial_param *ch = &qs->crypt.hello;
	u16 cipher_suites = htons(QUIC_AES_128_GCM_SHA256);

	ch->type = QUIC_MT_CLIENT_HELLO;
	ch->version = QUIC_MSG_legacy_version;
	memset(ch->random, 0x1, sizeof(ch->random));

	ch->cipher_suites_len = 2;
	ch->cipher_suites = kzalloc(ch->cipher_suites_len, GFP_KERNEL);
	if (!ch->cipher_suites)
		return -ENOMEM;
	memcpy(ch->cipher_suites, &cipher_suites, ch->cipher_suites_len);

	ch->compression_methods_len = 1;
	ch->compression_methods = kzalloc(ch->compression_methods_len, GFP_KERNEL);
	if (!ch->compression_methods)
		return -ENOMEM;

	ch->extensions_len = 8 + 8 + 7 + 75 + (4 + quic_frame_params_len_get(qs));
	if (qs->crypt.psks) {
		ch->extensions_len += 4; /* early data indication */
		ch->extensions_len += 4 + 1 + 1; /* psk mode */
		ch->extensions_len += 4 + 2 + 2 + qs->crypt.psks->pskid.len + 4; /* pskid */
		ch->extensions_len += 3 + 32; /* binder */
	}
	ch->length = 2 + 32 + 1 + ch->session_id_len + 2 + ch->cipher_suites_len +
			1 + ch->compression_methods_len + 2 + ch->extensions_len;

	return 0;
}

static int quic_frame_ch_crypto_create(struct quic_sock *qs)
{
	struct quic_vlen *f = &qs->frame.f[QUIC_PKT_INITIAL];
	struct quic_param *pm = &qs->params.local;
	struct quic_initial_param *ch;
	u32 f_len, h_len;
	u8 *p, *tmp;
	int err;

	err = quic_frame_ch_crypto_init(qs);
	if (err)
		return err;

	ch = &qs->crypt.hello;
	h_len = ch->length + 4;
	p = f->v + f->len;
	p = quic_put_varint(p, QUIC_FRAME_CRYPTO);
	p = quic_put_varint(p, 0);
	p = quic_put_varint(p, h_len);
	tmp = p;
	p = quic_put_pkt_num(p, ch->type, 1);
	p = quic_put_pkt_num(p, ch->length, 3);
	p = quic_put_pkt_num(p, ch->version, 2);
	p = quic_put_pkt_data(p, ch->random, 32);
	p = quic_put_pkt_num(p, ch->session_id_len, 1);
	p = quic_put_pkt_data(p, ch->session_id, ch->session_id_len);
	p = quic_put_pkt_num(p, ch->cipher_suites_len, 2);
	p = quic_put_pkt_data(p, ch->cipher_suites, ch->cipher_suites_len);
	p = quic_put_pkt_num(p, ch->compression_methods_len, 1);
	p = quic_put_pkt_data(p, ch->compression_methods, ch->compression_methods_len);
	p = quic_put_pkt_num(p, ch->extensions_len, 2);

	p = quic_put_pkt_num(p, QUIC_EXT_supported_groups, 2);
	p = quic_put_pkt_num(p, 4, 2);
	p = quic_put_pkt_num(p, 2, 2);
	p = quic_put_pkt_num(p, QUIC_ECDHE_secp256r1, 2);

	p = quic_put_pkt_num(p, QUIC_EXT_signature_algorithms, 2);
	p = quic_put_pkt_num(p, 4, 2);
	p = quic_put_pkt_num(p, 2, 2);
	p = quic_put_pkt_num(p, QUIC_SAE_rsa_pss_rsae_sha256, 2);

	p = quic_put_pkt_num(p, QUIC_EXT_supported_versions, 2);
	p = quic_put_pkt_num(p, 3, 2);
	p = quic_put_pkt_num(p, 2, 1);
	p = quic_put_pkt_num(p, QUIC_MSG_version, 2);

	p = quic_put_pkt_num(p, QUIC_EXT_key_share, 2);
	p = quic_put_pkt_num(p, 75 - 4, 2);
	p = quic_put_pkt_num(p, 75 - 4 - 2, 2);
	p = quic_put_pkt_num(p, QUIC_ECDHE_secp256r1, 2);
	p = quic_put_pkt_num(p, 75 - 4 - 2 - 2 - 2, 2);
	p = quic_put_pkt_num(p, 4, 1);
	p = quic_put_pkt_data(p, qs->crypt.ecdh_x, QUIC_ECDHLEN);
	p = quic_put_pkt_data(p, qs->crypt.ecdh_y, QUIC_ECDHLEN);

	p = quic_put_pkt_num(p, QUIC_EXT_quic_transport_parameters, 2);
	p = quic_put_pkt_num(p, quic_frame_params_len_get(qs), 2);
	p = quic_put_varint(p, QUIC_PARAM_max_udp_payload_size);
	p = quic_put_varint(p, quic_put_varint_len(pm->max_udp_payload_size));
	p = quic_put_varint(p, pm->max_udp_payload_size);
	p = quic_put_varint(p, QUIC_PARAM_initial_max_data);
	p = quic_put_varint(p, quic_put_varint_len(pm->initial_max_data));
	p = quic_put_varint(p, pm->initial_max_data);
	p = quic_put_varint(p, QUIC_PARAM_initial_max_stream_data_bidi_local);
	p = quic_put_varint(p, quic_put_varint_len(pm->initial_max_stream_data_bidi_local));
	p = quic_put_varint(p, pm->initial_max_stream_data_bidi_local);
	p = quic_put_varint(p, QUIC_PARAM_initial_max_stream_data_bidi_remote);
	p = quic_put_varint(p, quic_put_varint_len(pm->initial_max_stream_data_bidi_remote));
	p = quic_put_varint(p, pm->initial_max_stream_data_bidi_remote);
	p = quic_put_varint(p, QUIC_PARAM_initial_max_stream_data_uni);
	p = quic_put_varint(p, quic_put_varint_len(pm->initial_max_stream_data_uni));
	p = quic_put_varint(p, pm->initial_max_stream_data_uni);
	p = quic_put_varint(p, QUIC_PARAM_initial_max_streams_bidi);
	p = quic_put_varint(p, quic_put_varint_len(pm->initial_max_streams_bidi));
	p = quic_put_varint(p, pm->initial_max_streams_bidi);
	p = quic_put_varint(p, QUIC_PARAM_initial_max_streams_uni);
	p = quic_put_varint(p, quic_put_varint_len(pm->initial_max_streams_uni));
	p = quic_put_varint(p, pm->initial_max_streams_uni);
	p = quic_put_varint(p, QUIC_PARAM_initial_source_connection_id);
	p = quic_put_varint(p, qs->cids.scid.cur->len);
	p = quic_put_pkt_data(p, qs->cids.scid.cur->id, qs->cids.scid.cur->len);
	if (qs->crypt.psks) {
		p = quic_put_pkt_num(p, QUIC_EXT_early_data, 2);
		p = quic_put_pkt_num(p, 0, 2);

		p = quic_put_pkt_num(p, QUIC_EXT_psk_kex_modes, 2);
		p = quic_put_pkt_num(p, 2, 2);
		p = quic_put_pkt_num(p, 1, 1);
		p = quic_put_pkt_num(p, 1, 1); /* psk_dhe_ke */

		p = quic_put_pkt_num(p, QUIC_EXT_psk, 2);
		p = quic_put_pkt_num(p, 2 + 2 + qs->crypt.psks->pskid.len + 4 + 3 + 32, 2);

		p = quic_put_pkt_num(p, 2 + qs->crypt.psks->pskid.len + 4, 2);
		p = quic_put_pkt_num(p, qs->crypt.psks->pskid.len, 2);
		p = quic_put_pkt_data(p, qs->crypt.psks->pskid.v, qs->crypt.psks->pskid.len);
		p = quic_put_pkt_num(p, qs->crypt.psks->psk_sent_at, 4);
		err = quic_crypto_early_binder_create(qs, tmp, (u32)(p - tmp));
		if (err)
			return err;

		p = quic_put_pkt_num(p, 33, 2);
		p = quic_put_pkt_num(p, 32, 1);
		p = quic_put_pkt_data(p, qs->crypt.binder_secret, 32);
	}

	f_len = 2 + quic_put_varint_len(h_len) + h_len;
	f->len += f_len;
	qs->crypt.hs_buf[QUIC_H_CH].v = quic_mem_dup(tmp, h_len);
	if (!qs->crypt.hs_buf[QUIC_H_CH].v)
		return -ENOMEM;
	qs->crypt.hs_buf[QUIC_H_CH].len = h_len;
	pr_debug("client hello len: %u, frame len: %u\n", h_len, f_len);

	return 0;
}

static int quic_frame_sh_crypto_init(struct quic_sock *qs)
{
	struct quic_initial_param *sh = &qs->crypt.hello;
	u16 cipher_suites = htons(QUIC_AES_128_GCM_SHA256);

	sh->type = QUIC_MT_SERVER_HELLO;
	sh->version = QUIC_MSG_legacy_version;
	memset(sh->random, 0x1, sizeof(sh->random));

	sh->cipher_suites_len = 2;
	sh->cipher_suites = kzalloc(sh->cipher_suites_len, GFP_ATOMIC);
	if (!sh->cipher_suites)
		return -ENOMEM;
	memcpy(sh->cipher_suites, &cipher_suites, sh->cipher_suites_len);

	sh->extensions_len = 6 + 73;
	if (qs->crypt.psks) {
		sh->extensions_len += 4; /* early data indication */
		sh->extensions_len += 4 + 1 + 1; /* psk mode */
		sh->extensions_len += 4 + 2; /* pskid selected_identity */
	}
	sh->length = 2 + 32 + 1 + sh->session_id_len + sh->cipher_suites_len +
			1 + sh->compression_methods_len + 2 + sh->extensions_len;

	return 0;
}

static int quic_frame_sh_crypto_create(struct quic_sock *qs)
{
	struct quic_vlen *f = &qs->frame.f[QUIC_PKT_INITIAL];
	struct quic_initial_param *sh;
	u32 f_len, h_len;
	struct sock *sk;
	u8 *p, *tmp;
	int err;

	err = quic_frame_sh_crypto_init(qs);
	if (err)
		return err;

	sh = &qs->crypt.hello;
	h_len = sh->length + 4;
	p = f->v + f->len;
	p = quic_put_varint(p, QUIC_FRAME_CRYPTO);
	p = quic_put_varint(p, 0);
	p = quic_put_varint(p, h_len);
	tmp = p;
	p = quic_put_pkt_num(p, sh->type, 1);
	p = quic_put_pkt_num(p, sh->length, 3);
	p = quic_put_pkt_num(p, sh->version, 2);
	p = quic_put_pkt_data(p, sh->random, 32);
	p = quic_put_pkt_num(p, sh->session_id_len, 1);
	p = quic_put_pkt_data(p, sh->session_id, sh->session_id_len);
	p = quic_put_pkt_data(p, sh->cipher_suites, sh->cipher_suites_len); /* len = 2 */
	p = quic_put_pkt_num(p, sh->compression_methods_len, 1); /* len = 0 */
	p = quic_put_pkt_num(p, sh->extensions_len, 2);

	p = quic_put_pkt_num(p, QUIC_EXT_supported_versions, 2);
	p = quic_put_pkt_num(p, 2, 2);
	p = quic_put_pkt_num(p, QUIC_MSG_version, 2);

	p = quic_put_pkt_num(p, QUIC_EXT_key_share, 2);
	p = quic_put_pkt_num(p, 73 - 4, 2);
	p = quic_put_pkt_num(p, QUIC_ECDHE_secp256r1, 2);
	p = quic_put_pkt_num(p, 73 - 4 - 2 - 2, 2);
	p = quic_put_pkt_num(p, 4, 1);
	p = quic_put_pkt_data(p, qs->crypt.ecdh_x, QUIC_ECDHLEN);
	p = quic_put_pkt_data(p, qs->crypt.ecdh_y, QUIC_ECDHLEN);
	if (qs->crypt.psks) {
		p = quic_put_pkt_num(p, QUIC_EXT_early_data, 2);
		p = quic_put_pkt_num(p, 0, 2);

		p = quic_put_pkt_num(p, QUIC_EXT_psk_kex_modes, 2);
		p = quic_put_pkt_num(p, 2, 2);
		p = quic_put_pkt_num(p, 1, 1);
		p = quic_put_pkt_num(p, 1, 1); /* psk_dhe_ke */

		p = quic_put_pkt_num(p, QUIC_EXT_psk, 2);
		p = quic_put_pkt_num(p, 2, 2);
		p = quic_put_pkt_num(p, 0, 2);
	}

	f_len = 2 + quic_put_varint_len(h_len) + h_len;
	f->len += f_len;
	qs->crypt.hs_buf[QUIC_H_SH].v = quic_mem_dup(tmp, h_len);
	if (!qs->crypt.hs_buf[QUIC_H_SH].v)
		return -ENOMEM;
	qs->crypt.hs_buf[QUIC_H_SH].len = h_len;
	pr_debug("server hello len: %u, frame len: %u\n", h_len, f_len);

	err = quic_crypto_handshake_keys_install(qs);
	if (err)
		return err;

	list_add_tail(&qs->list, &qs->lsk->list);
	sk = &qs->lsk->inet.sk;
	sk_acceptq_added(sk);
	sk->sk_state_change(sk);
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
	pr_debug("create ack frame len: %u\n", f_len);

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
	pr_debug("create ping frame len: %u\n", f_len);

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
	p = quic_put_pkt_data(p, qs->token.token, qs->token.len);
	f_len = (u32)(p - tmp);
	f->len += f_len;
	pr_debug("create new token frame len: %u\n", f_len);

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
	mss -= quic_put_pkt_numlen(qs->packet.ad_tx_pn + 1);
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
	pr_debug("create stream hlen: %u, mlen: %u, mss: %u, off: %u\n",
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

static int quic_frame_hs_fin_crypto_create(struct quic_sock *qs)
{
	struct quic_vlen *f = &qs->frame.f[QUIC_PKT_HANDSHAKE];
	u32 f_len, clen = 0, c_len, v_len, t_len;
	u8 cf[QUIC_HKDF_HASHLEN], *p, *tmp;
	struct quic_cert *c;
	int err;

	t_len = 36;
	p = f->v + f->len;
	p = quic_put_varint(p, QUIC_FRAME_CRYPTO);
	p = quic_put_varint(p, 0x00);

	if (!qs->crypt.hs_buf[QUIC_H_CREQ].v) {
		p = quic_put_varint(p, t_len);
		goto fin;
	}

	for (c = qs->crypt.certs; c; c = c->next)
		clen += (2 + c->raw.len + 3);

	c_len = 4 + clen + 4;
	v_len = 4 + (2 + 2 + 256);
	t_len += c_len + v_len;
	p = quic_put_varint(p, t_len);

	tmp = p;
	p = quic_put_pkt_num(p, QUIC_MT_CERTIFICATE, 1);
	p = quic_put_pkt_num(p, clen + 4, 3);
	p = quic_put_pkt_num(p, 0, 1);
	p = quic_put_pkt_num(p, clen, 3);

	for (c = qs->crypt.certs; c; c = c->next) {
		p = quic_put_pkt_num(p, c->raw.len, 3);
		p = quic_put_pkt_data(p, c->raw.v, c->raw.len);
		p = quic_put_pkt_num(p, 0, 2);
	}

	qs->crypt.hs_buf[QUIC_H_CCERT].len = (u32)(p - tmp);
	qs->crypt.hs_buf[QUIC_H_CCERT].v = quic_mem_dup(tmp, qs->crypt.hs_buf[QUIC_H_CCERT].len);
	if (!qs->crypt.hs_buf[QUIC_H_CCERT].v)
		return -ENOMEM;

	err = quic_crypto_certvfy_sign(qs);
	if (err)
		return err;
	tmp = p;
	p = quic_put_pkt_num(p, QUIC_MT_CERTIFICATE_VERIFY, 1);
	p = quic_put_pkt_num(p, 2 + 2 + qs->crypt.sig.len, 3);
	p = quic_put_pkt_num(p, QUIC_SAE_rsa_pss_rsae_sha256, 2);
	p = quic_put_pkt_num(p, qs->crypt.sig.len, 2);
	p = quic_put_pkt_data(p, qs->crypt.sig.v, qs->crypt.sig.len);
	qs->crypt.hs_buf[QUIC_H_CCVFY].len = (u32)(p - tmp);
	qs->crypt.hs_buf[QUIC_H_CCVFY].v = quic_mem_dup(tmp, qs->crypt.hs_buf[QUIC_H_CCVFY].len);
	if (!qs->crypt.hs_buf[QUIC_H_CCVFY].v)
		return -ENOMEM;

fin:
	err = quic_crypto_client_finished_create(qs, cf);
	if (err)
		return err;
	tmp = p;
	p = quic_put_pkt_num(p, QUIC_MT_FINISHED, 1);
	p = quic_put_pkt_num(p, 32, 3);
	p = quic_put_pkt_data(p, cf, QUIC_HKDF_HASHLEN);
	qs->crypt.hs_buf[QUIC_H_CFIN].len = (u32)(p - tmp);
	qs->crypt.hs_buf[QUIC_H_CFIN].v = quic_mem_dup(tmp, qs->crypt.hs_buf[QUIC_H_CFIN].len);
	if (!qs->crypt.hs_buf[QUIC_H_CFIN].v)
		return -ENOMEM;
	err = quic_crypto_rms_key_install(qs);
	if (err)
		return err;
	f_len = t_len + 2 + quic_put_varint_len(t_len);
	f->len += f_len;
	pr_debug("client crypto finished frame len: %u\n", f_len);

	return 0;
}

static int quic_frame_hs_crypto_create(struct quic_sock *qs)
{
	struct quic_vlen *f = &qs->frame.f[QUIC_PKT_HANDSHAKE];
	u32 f_len, m_len, p_len, clen = 0, cr_len = 0, t_len;
	struct quic_param *pm = &qs->params.local;
	u32 e_len, c_len, v_len, fin_len, i = 1;
	u8 *p, *tmp, sf[QUIC_HKDF_HASHLEN];
	struct quic_cert *c;
	int err, mss;

	mss = quic_dst_mss_check(qs, 2);
	if (mss < 0)
		return mss;

	p_len = quic_frame_params_len_get(qs);

	e_len = 4 + (2 + 8 + (4 + p_len));
	fin_len = 4 + QUIC_HKDF_HASHLEN;
	t_len = e_len + fin_len;
	if (!qs->crypt.psks) {
		if (qs->crypt.cert_req)
			cr_len = 4 + 11;

		for (c = qs->crypt.certs; c; c = c->next)
			clen += (2 + c->raw.len + 3);

		c_len = 4 + clen + 4;
		v_len = 4 + (2 + 2 + 256);
		t_len += c_len + v_len + cr_len;
	}

	m_len = t_len;
	if (m_len > mss - 4)
		m_len = mss - 4;
	pr_debug("hs_crypto mss: %u, t_len: %u, m_len: %u\n",
		 mss, t_len, m_len);

	p = f->v + f->len;
	p = quic_put_varint(p, QUIC_FRAME_CRYPTO);
	p = quic_put_varint(p, 0x00);
	p = quic_put_varint(p, m_len);

	tmp = p;
	p = quic_put_pkt_num(p, QUIC_MT_ENCRYPTED_EXTENSIONS, 1);
	p = quic_put_pkt_num(p, p_len + 4 + 8 + 2, 3);
	p = quic_put_pkt_num(p, p_len + 4 + 8, 2);

	p = quic_put_pkt_num(p, QUIC_EXT_supported_groups, 2);
	p = quic_put_pkt_num(p, 4, 2);
	p = quic_put_pkt_num(p, 2, 2);
	p = quic_put_pkt_num(p, QUIC_ECDHE_secp256r1, 2);

	p = quic_put_pkt_num(p, QUIC_EXT_quic_transport_parameters, 2);
	p = quic_put_pkt_num(p, p_len, 2);
	p = quic_put_varint(p, QUIC_PARAM_original_destination_connection_id);
	p = quic_put_varint(p, qs->cids.scid.cur->len);
	p = quic_put_pkt_data(p, qs->cids.scid.cur->id, qs->cids.scid.cur->len);
	p = quic_put_varint(p, QUIC_PARAM_max_udp_payload_size);
	p = quic_put_varint(p, quic_put_varint_len(pm->max_udp_payload_size));
	p = quic_put_varint(p, pm->max_udp_payload_size);
	p = quic_put_varint(p, QUIC_PARAM_initial_max_data);
	p = quic_put_varint(p, quic_put_varint_len(pm->initial_max_data));
	p = quic_put_varint(p, pm->initial_max_data);
	p = quic_put_varint(p, QUIC_PARAM_initial_max_stream_data_bidi_local);
	p = quic_put_varint(p, quic_put_varint_len(pm->initial_max_stream_data_bidi_local));
	p = quic_put_varint(p, pm->initial_max_stream_data_bidi_local);
	p = quic_put_varint(p, QUIC_PARAM_initial_max_stream_data_bidi_remote);
	p = quic_put_varint(p, quic_put_varint_len(pm->initial_max_stream_data_bidi_remote));
	p = quic_put_varint(p, pm->initial_max_stream_data_bidi_remote);
	p = quic_put_varint(p, QUIC_PARAM_initial_max_stream_data_uni);
	p = quic_put_varint(p, quic_put_varint_len(pm->initial_max_stream_data_uni));
	p = quic_put_varint(p, pm->initial_max_stream_data_uni);
	p = quic_put_varint(p, QUIC_PARAM_initial_max_streams_bidi);
	p = quic_put_varint(p, quic_put_varint_len(pm->initial_max_streams_bidi));
	p = quic_put_varint(p, pm->initial_max_streams_bidi);
	p = quic_put_varint(p, QUIC_PARAM_initial_max_streams_uni);
	p = quic_put_varint(p, quic_put_varint_len(pm->initial_max_streams_uni));
	p = quic_put_varint(p, pm->initial_max_streams_uni);
	p = quic_put_varint(p, QUIC_PARAM_initial_source_connection_id);
	p = quic_put_varint(p, qs->cids.scid.cur->len);
	p = quic_put_pkt_data(p, qs->cids.scid.cur->id, qs->cids.scid.cur->len);
	qs->crypt.hs_buf[QUIC_H_EE].len = (u32)(p - tmp);
	qs->crypt.hs_buf[QUIC_H_EE].v = quic_mem_dup(tmp, qs->crypt.hs_buf[QUIC_H_EE].len);
	if (!qs->crypt.hs_buf[QUIC_H_EE].v)
		return -ENOMEM;

	if (qs->crypt.psks)
		goto fin;

	if (qs->crypt.cert_req) {
		tmp = p;
		p = quic_put_pkt_num(p, QUIC_MT_CERTIFICATE_REQUEST, 1);
		p = quic_put_pkt_num(p, 11, 3);
		p = quic_put_pkt_num(p, 0, 1);
		p = quic_put_pkt_num(p, 8, 2);

		p = quic_put_pkt_num(p, QUIC_EXT_signature_algorithms, 2);
		p = quic_put_pkt_num(p, 4, 2);
		p = quic_put_pkt_num(p, 2, 2);
		p = quic_put_pkt_num(p, QUIC_SAE_rsa_pss_rsae_sha256, 2);

		qs->crypt.hs_buf[QUIC_H_CREQ].len = (u32)(p - tmp);
		qs->crypt.hs_buf[QUIC_H_CREQ].v =
			quic_mem_dup(tmp, qs->crypt.hs_buf[QUIC_H_CREQ].len);
		if (!qs->crypt.hs_buf[QUIC_H_CREQ].v)
			return -ENOMEM;
	}

	tmp = p;
	p = quic_put_pkt_num(p, QUIC_MT_CERTIFICATE, 1);
	p = quic_put_pkt_num(p, clen + 4, 3);
	p = quic_put_pkt_num(p, 0, 1);
	p = quic_put_pkt_num(p, clen, 3);

	for (c = qs->crypt.certs; c; c = c->next) {
		p = quic_put_pkt_num(p, c->raw.len, 3);
		p = quic_put_pkt_data(p, c->raw.v, c->raw.len);
		p = quic_put_pkt_num(p, 0, 2);
	}

	qs->crypt.hs_buf[QUIC_H_SCERT].len = (u32)(p - tmp);
	qs->crypt.hs_buf[QUIC_H_SCERT].v = quic_mem_dup(tmp, qs->crypt.hs_buf[QUIC_H_SCERT].len);
	if (!qs->crypt.hs_buf[QUIC_H_SCERT].v)
		return -ENOMEM;

	err = quic_crypto_certvfy_sign(qs);
	if (err)
		return err;
	tmp = p;
	p = quic_put_pkt_num(p, QUIC_MT_CERTIFICATE_VERIFY, 1);
	p = quic_put_pkt_num(p, 2 + 2 + qs->crypt.sig.len, 3);
	p = quic_put_pkt_num(p, QUIC_SAE_rsa_pss_rsae_sha256, 2);
	p = quic_put_pkt_num(p, qs->crypt.sig.len, 2);
	p = quic_put_pkt_data(p, qs->crypt.sig.v, qs->crypt.sig.len);
	qs->crypt.hs_buf[QUIC_H_SCVFY].len = (u32)(p - tmp);
	qs->crypt.hs_buf[QUIC_H_SCVFY].v = quic_mem_dup(tmp, qs->crypt.hs_buf[QUIC_H_SCVFY].len);
	if (!qs->crypt.hs_buf[QUIC_H_SCVFY].v)
		return -ENOMEM;

fin:
	err = quic_crypto_server_finished_create(qs, sf);
	if (err)
		return err;

	tmp = p;
	p = quic_put_pkt_num(p, QUIC_MT_FINISHED, 1);
	p = quic_put_pkt_num(p, QUIC_HKDF_HASHLEN, 3);
	p = quic_put_pkt_data(p, sf, QUIC_HKDF_HASHLEN);
	qs->crypt.hs_buf[QUIC_H_SFIN].len = (u32)(p - tmp);
	qs->crypt.hs_buf[QUIC_H_SFIN].v = quic_mem_dup(tmp, qs->crypt.hs_buf[QUIC_H_SFIN].len);
	if (!qs->crypt.hs_buf[QUIC_H_SFIN].v)
		return -ENOMEM;

	tmp = f->v + f->len + 4;
	f_len = 4 + m_len;
	f->len += f_len;
	pr_debug("hs_crypto p_len: %u, e_len: %u, f_len: %u\n", p_len, e_len, f_len);
	while (m_len < t_len) {
		f = &qs->frame.f[QUIC_PKT_VERSION_NEGOTIATION + i];

		t_len = t_len - m_len;
		v_len = m_len < t_len ? m_len : t_len;
		p = f->v + f->len;
		p = quic_put_varint(p, QUIC_FRAME_CRYPTO);
		p = quic_put_varint(p, m_len * i);
		p = quic_put_varint(p, v_len);
		p = quic_put_pkt_data(p, tmp + m_len, v_len);
		f->len = (u32)(p - f->v);
		pr_debug("hs_crypto t_len: %u,  m_len: %u, f_len: %u\n",
				t_len, m_len, f->len);
		tmp += m_len;
		i++;
	}

	return quic_crypto_application_keys_install(qs);
}

static int quic_frame_ticket_crypto_create(struct quic_sock *qs)
{
	struct quic_vlen *f = &qs->frame.f[QUIC_PKT_SHORT];
	struct quic_psk *psk = qs->crypt.psks;
	u32 f_len, len;
	u8 *p;

	pr_debug("send ticket %u %u: %8phN(%u), %8phN(%u), %8phN(%u)\n",
		 psk->psk_sent_at, psk->psk_expire,
		 psk->pskid.v, psk->pskid.len, psk->nonce.v,
		 psk->nonce.len, psk->mskey.v, psk->mskey.len);

	p = f->v + f->len;
	len = 4 + 4 + 4 + 1 + psk->nonce.len + 2 + psk->pskid.len + 10;
	p = quic_put_varint(p, QUIC_FRAME_CRYPTO);
	p = quic_put_varint(p, 0x00);
	p = quic_put_varint(p, len);
	p = quic_put_pkt_num(p, QUIC_MT_NEWSESSION_TICKET, 1);
	p = quic_put_pkt_num(p, len - 4, 3);
	p = quic_put_pkt_num(p, psk->psk_expire, 4);
	p = quic_put_pkt_num(p, psk->psk_sent_at, 4);
	p = quic_put_pkt_num(p, psk->nonce.len, 1);
	p = quic_put_pkt_data(p, psk->nonce.v, psk->nonce.len);
	p = quic_put_pkt_num(p, psk->pskid.len, 2);
	p = quic_put_pkt_data(p, psk->pskid.v, psk->pskid.len);
	p = quic_put_pkt_num(p, 2 + 2 + 4, 2);
	p = quic_put_pkt_num(p, QUIC_EXT_early_data, 2);
	p = quic_put_pkt_num(p, 4, 2);
	p = quic_put_pkt_num(p, 0xffffffff, 4);

	f_len = len + 3;
	f->len += f_len;
	pr_debug("new ticket crypto frame len: %u\n", f_len);

	return 0;
}

static int quic_frame_crypto_create(struct quic_sock *qs)
{
	if (qs->state == QUIC_CS_CLIENT_INITIAL)
		return quic_frame_ch_crypto_create(qs);
	if (qs->state == QUIC_CS_CLIENT_WAIT_HANDSHAKE)
		return quic_frame_hs_fin_crypto_create(qs);
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

	pr_debug("create retire_connection_id frame len: %u\n", f_len);
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
	p = quic_put_pkt_num(p, cid->len, 1);
	p = quic_put_pkt_data(p, cid->id, cid->len);
	p += 16; /* Stateless Reset Token */
	f_len = (u32)(p - tmp);
	f->len += f_len;

	pr_debug("create retire_connection_id frame len: %u\n", f_len);
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
	p = quic_put_pkt_data(p, qs->frame.path.data, 8);
	f_len = (u32)(p - tmp);
	f->len += f_len;

	pr_debug("create path response frame len: %u %8phN\n",
		 f_len, qs->frame.path.data);
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
	p = quic_put_pkt_data(p, qs->frame.path.data, 8);
	f_len = (u32)(p - tmp);
	f->len += f_len;

	pr_debug("create path challenge frame len: %u %8phN\n",
		 f_len, qs->frame.path.data);
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

	pr_debug("create reset stream frame len: %u\n", f_len);
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

	pr_debug("create stop sending frame len: %u\n", f_len);
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

	pr_debug("create max data frame len: %u\n", f_len);
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

	pr_debug("create max stream data frame len: %u %llu\n", f_len, qs->frame.max.limit);
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

	pr_debug("create max streams uni frame len: %u\n", f_len);
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

	pr_debug("create max streams uni frame len: %u\n", f_len);
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

	pr_debug("create connection close frame len: %u\n", f_len);
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

	pr_debug("create data blocked frame len: %u\n", f_len);
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

	pr_debug("create data blocked frame len: %u\n", f_len);
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

	pr_debug("create streams blocked uni frame len: %u\n", f_len);
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

	pr_debug("create streams blocked uni frame len: %u\n", f_len);
	return 0;
}

static int quic_frame_crypto_process(struct quic_sock *qs, u8 **ptr, u8 type, u32 left)
{
	u32 len, hs_offset, hs_len;
	u8 *p = *ptr;
	int err;

	hs_offset = quic_get_varint_next(&p, &len);
	left -= len;
	hs_len = quic_get_varint_next(&p, &len);
	left -= len;

	err = quic_msg_process(qs, p, hs_len, hs_offset, left);
	if (err)
		return err;

	*ptr = p + hs_len;
	return 0;
}

static int quic_frame_stream_process(struct quic_sock *qs, u8 **ptr, u8 type, u32 left)
{
	u32 v, len, id, off = 0;
	u8 *p = *ptr, fin = 0;
	struct sk_buff *skb;
	int err = 0;

	id = quic_get_varint_next(&p, &len);
	left -= len;
	pr_debug("Stream ID: %u, Left: %u\n", id, left);
	if (type & 0x04) {
		off = quic_get_varint_next(&p, &len);
		left -= len;
		pr_debug("Stream Offset: %u\n", off);
	}
	if (type & 0x02) {
		len = quic_get_varint_next(&p, &v);
		p += len;
		pr_debug("Stream Len: %u\n", v);
	} else {
		len = left;
		p += left;
	}
	if (type & 0x01) {
		pr_debug("Stream End\n");
		fin = 1;
	}
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

	v = quic_get_varint_next(&p, &len);
	pr_debug("ack Largest Acknowledged: %u\n", v);
	if (qs->packet.type == QUIC_PKT_SHORT)
		quic_send_queue_check(qs, v);
	v = quic_get_varint_next(&p, &len);
	pr_debug("ack ACK Delay: %u\n", v);
	count = quic_get_varint_next(&p, &len);
	pr_debug("ack ACK Count: %u\n", count);
	v = quic_get_varint_next(&p, &len);
	pr_debug("ack First ACK Range: %u\n", v);

	for (i = 0; i < count; i++) {
		v = quic_get_varint_next(&p, &len);
		pr_debug("ack Gap: %u, %u\n", i, v);
		v = quic_get_varint_next(&p, &len);
		pr_debug("ack ACK Range Length: %u, %u\n", i, v);
	}

	if (v == QUIC_FRAME_ACK_ECN) {
		v = quic_get_varint_next(&p, &len);
		pr_debug("ack ECT0 Count: %u\n", v);
		v = quic_get_varint_next(&p, &len);
		pr_debug("ack ECT1 Count: %u\n", v);
		v = quic_get_varint_next(&p, &len);
		pr_debug("ack ECN-CE Count: %u\n", v);
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

	v = quic_get_varint_next(&p, &len);
	pr_debug("Sequence Number: %u\n", v);
	no = v;
	v = quic_get_varint_next(&p, &len);
	pr_debug("Retire Prior To: %u\n", v);
	prior_to = v;
	len = quic_get_fixint_next(&p, 1);
	pr_debug("Length: %u\n", len);

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
	pr_debug("CID: %8phN\n", cid->id);
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

	pr_debug("Tell Userspace Stateless Reset Token: %16phN\n", p);
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

	retire_no = quic_get_varint_next(&p, &len);
	pr_debug("Tell Userspace Retire Sequence Number: %u\n", retire_no);

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

	len = quic_get_varint_next(&p, &v);
	pr_debug("Token Length: %u\n", len);
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

	pr_debug("Handshake Done\n");
	*ptr = p;
	return 0;
}

static int quic_frame_padding_process(struct quic_sock *qs, u8 **ptr, u8 type, u32 left)
{
	u8 *p = *ptr;

	pr_debug("Padding Process %u\n", left);
	p += left;
	*ptr = p;
	return 0;
}

static int quic_frame_ping_process(struct quic_sock *qs, u8 **ptr, u8 type, u32 left)
{
	u8 *p = *ptr;

	pr_debug("Ping Received\n");
	p++;
	*ptr = p;
	return 0;
}

static int quic_frame_path_challenge_process(struct quic_sock *qs, u8 **ptr, u8 type, u32 left)
{
	u8 *p = *ptr;
	int err;

	pr_debug("Path Challenge: %8phN\n", p);
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

	sid = quic_get_varint_next(&p, &len);
	pr_debug("Reset Stream sid: %u\n", sid);
	if (quic_is_serv(qs) ^ !(sid & 0x01))
		return -EINVAL;
	strm = quic_strm_rcv_get(qs, sid);
	if (!strm)
		return -EINVAL;

	value[0] = sid;
	v = quic_get_varint_next(&p, &len);
	pr_debug("Reset Stream error code: %u\n", v);
	value[1] = v;
	v = quic_get_varint_next(&p, &len);
	pr_debug("Tell Userspace Reset Stream final size: %u\n", v);
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

	v = quic_get_varint_next(&p, &len);
	pr_debug("Stop Sending sid: %u\n", v);
	strm = quic_strm_snd_get(qs, v);
	if (!strm)
		return -EINVAL;
	qs->frame.stream.sid = v;
	err = quic_frame_create(qs, QUIC_FRAME_RESET_STREAM);
	if (err)
		return err;
	value[0] = v;
	v = quic_get_varint_next(&p, &len);
	value[1] = v;
	pr_debug("Tell Userspace Reset Stream error code: %u\n", v);
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

	max = quic_get_varint_next(&p, &len);
	pr_debug("Max Data len: %llu %llu\n", max, qs->packet.snd_max);

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

	sid = quic_get_varint_next(&p, &len);
	pr_debug("Max Stream Data sid: %u\n", sid);
	strm = quic_strm_get(qs, sid);
	if (!strm)
		return -EINVAL;
	max = quic_get_varint_next(&p, &len);
	pr_debug("Max Stream Data max: %llu %llu\n", max, strm->snd_max);

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

	v = quic_get_varint_next(&p, &len);
	value[1] = v;
	err = quic_evt_notify(qs, QUIC_EVT_STREAMS, QUIC_EVT_STREAMS_MAX, value);
	if (err)
		return err;
	if (qs->params.local.initial_max_streams_uni < v)
		qs->params.local.initial_max_streams_uni = v;

	pr_debug("Tell Userspace uni streams %u allowed\n", v);

	*ptr = p;
	return 0;
}

static int quic_frame_max_streams_bidi_process(struct quic_sock *qs, u8 **ptr, u8 type, u32 left)
{
	u32 v, len, value[3] = {0};
	u8 *p = *ptr;
	int err;

	v = quic_get_varint_next(&p, &len);
	value[0] = 1;
	value[1] = v;
	err = quic_evt_notify(qs, QUIC_EVT_STREAMS, QUIC_EVT_STREAMS_MAX, value);
	if (err)
		return err;

	if (qs->params.local.initial_max_streams_bidi < v)
		qs->params.local.initial_max_streams_bidi = v;

	pr_debug("Tell Userspace bidi streams %u allowed\n", v);

	*ptr = p;
	return 0;
}

static int quic_frame_connection_close_process(struct quic_sock *qs, u8 **ptr, u8 type, u32 left)
{
	struct sock *sk = &qs->inet.sk;
	u8 *p = *ptr;
	u32 v, len;

	v = quic_get_varint_next(&p, &len);
	pr_debug("Connection Close error: %u\n", v);
	v = quic_get_varint_next(&p, &len);
	pr_debug("Connection Close type: %u\n", v);
	if (type == QUIC_FRAME_CONNECTION_CLOSE) {
		v = quic_get_varint_next(&p, &len);
		pr_debug("Connection Close Frame type: %u\n", v);
	}
	len = quic_get_varint_next(&p, &v);
	pr_debug("Connection Close Reason Phrase Length %u\n", len);
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

	max = quic_get_varint_next(&p, &len);
	pr_debug("Data Blocked max data: %llu\n", max);

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

	sid = quic_get_varint_next(&p, &len);
	pr_debug("Stream Data Blocked sid: %u\n", sid);
	max = quic_get_varint_next(&p, &len);
	pr_debug("Stream Data Blocked max data: %llu\n", max);

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

	v = quic_get_varint_next(&p, &len);
	value[1] = v;
	err = quic_evt_notify(qs, QUIC_EVT_STREAMS, QUIC_EVT_STREAMS_BLOCKED, value);
	if (err)
		return err;

	pr_debug("Tell Userspace the peer needs %u uni streams\n", v);

	*ptr = p;
	return 0;
}

static int quic_frame_streams_blocked_bidi_process(struct quic_sock *qs, u8 **ptr,
						   u8 type, u32 left)
{
	u32 v, len, value[3] = {0};
	u8 *p = *ptr;
	int err;

	v = quic_get_varint_next(&p, &len);
	value[0] = 1;
	value[1] = v;
	err = quic_evt_notify(qs, QUIC_EVT_STREAMS, QUIC_EVT_STREAMS_BLOCKED, value);
	if (err)
		return err;

	pr_debug("Tell Userspace the peer needs %u bidi streams\n", v);

	*ptr = p;
	return 0;
}

static int quic_frame_path_response_process(struct quic_sock *qs, u8 **ptr, u8 type, u32 left)
{
	u8 *p = *ptr;

	pr_debug("Path Response: %8phN\n", p);
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

/* exported */
int quic_frame_process(struct quic_sock *qs, u8 *p, u32 len)
{
	u32 frames_len = len, v;
	int err, left = len;
	u8 *frames_p = p;

	pr_debug("frames_len %u\n", frames_len);
	qs->frame.need_ack = 0;
	qs->frame.has_strm = 0;
	qs->frame.non_probe = 0;
	while (1) {
		v = quic_get_varint_next(&p, &len);
		left -= len;
		pr_debug("frame type: %x\n", v);

		if (v != QUIC_FRAME_ACK && v != QUIC_FRAME_PADDING)
			qs->frame.need_ack = 1;
		if (v != QUIC_FRAME_NEW_CONNECTION_ID && v != QUIC_FRAME_PADDING &&
		    v != QUIC_FRAME_PATH_RESPONSE && v != QUIC_FRAME_PATH_CHALLENGE)
			qs->frame.non_probe = 1;

		if (v > QUIC_FRAME_BASE_MAX) {
			pr_err_once("frame err: unsupported frame %u\n", v);
			err = -EPROTONOSUPPORT;
			break;
		}
		err = quic_frames[v].frame_process(qs, &p, v, left);
		if (err) {
			pr_warn("frame err %u %d\n", v, err);
			break;
		}

		left = frames_len - (u32)(p - frames_p);
		pr_debug("left frame len %u\n", left);
		if (left <= 0)
			break;
	}

	return err;
}

/* exported */
int quic_frame_create(struct quic_sock *qs, u8 type)
{
	if (type > QUIC_FRAME_BASE_MAX)
		return -EINVAL;
	return quic_frames[type].frame_create(qs);
}

/* exported */
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

/* exported */
void quic_frame_free(struct quic_sock *qs)
{
	int i;

	for (i = 0; i < QUIC_FR_NR; i++)
		free_page((unsigned long)qs->frame.f[i].v);

	free_page((unsigned long)qs->frame.crypto.msg);
}
