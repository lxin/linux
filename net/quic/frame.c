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
	struct quic_params *p = &qs->params;
	u32 len;

	len = (1 + quic_put_varint_len(qs->scid.len) + qs->scid.len) +
		quic_put_varint_lens(p->max_udp_payload_size) + 1 +
		quic_put_varint_lens(p->initial_max_data) + 1 +
		quic_put_varint_lens(p->initial_max_stream_data_bidi_local) + 1 +
		quic_put_varint_lens(p->initial_max_stream_data_bidi_remote) + 1 +
		quic_put_varint_lens(p->initial_max_stream_data_uni) + 1 +
		quic_put_varint_lens(p->initial_max_streams_bidi) + 1 +
		quic_put_varint_lens(p->initial_max_streams_uni) + 1;

	if (qs->state > QUIC_CS_CLOSING)
		len += (1 + quic_put_varint_len(qs->scid.len) + qs->scid.len);

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
	ch->length = 2 + 32 + 1 + ch->session_id_len + 2 + ch->cipher_suites_len +
			1 + ch->compression_methods_len + 2 + ch->extensions_len;

	return 0;
}

static int quic_frame_ch_crypto_create(struct quic_sock *qs)
{
	struct quic_vlen *f = &qs->frame.f[0];
	struct quic_params *pm = &qs->params;
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
	p = quic_put_varint(p, 0x03);
	p = quic_put_varint(p, quic_put_varint_len(pm->max_udp_payload_size));
	p = quic_put_varint(p, pm->max_udp_payload_size);
	p = quic_put_varint(p, 0x04);
	p = quic_put_varint(p, quic_put_varint_len(pm->initial_max_data));
	p = quic_put_varint(p, pm->initial_max_data);
	p = quic_put_varint(p, 0x05);
	p = quic_put_varint(p, quic_put_varint_len(pm->initial_max_stream_data_bidi_local));
	p = quic_put_varint(p, pm->initial_max_stream_data_bidi_local);
	p = quic_put_varint(p, 0x06);
	p = quic_put_varint(p, quic_put_varint_len(pm->initial_max_stream_data_bidi_remote));
	p = quic_put_varint(p, pm->initial_max_stream_data_bidi_remote);
	p = quic_put_varint(p, 0x07);
	p = quic_put_varint(p, quic_put_varint_len(pm->initial_max_stream_data_uni));
	p = quic_put_varint(p, pm->initial_max_stream_data_uni);
	p = quic_put_varint(p, 0x08);
	p = quic_put_varint(p, quic_put_varint_len(pm->initial_max_streams_bidi));
	p = quic_put_varint(p, pm->initial_max_streams_bidi);
	p = quic_put_varint(p, 0x09);
	p = quic_put_varint(p, quic_put_varint_len(pm->initial_max_streams_uni));
	p = quic_put_varint(p, pm->initial_max_streams_uni);
	p = quic_put_varint(p, 0x0f);
	p = quic_put_varint(p, qs->scid.len);
	p = quic_put_pkt_data(p, qs->scid.id, qs->scid.len);

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
	sh->length = 2 + 32 + 1 + sh->session_id_len + sh->cipher_suites_len +
			1 + sh->compression_methods_len + 2 + sh->extensions_len;

	return 0;
}

static int quic_frame_sh_crypto_create(struct quic_sock *qs)
{
	struct quic_vlen *f = &qs->frame.f[0];
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
	struct quic_vlen *f = &qs->frame.f[qs->packet.type / 2];
	u32 f_len;
	u8 *p;

	p = f->v + f->len;
	p = quic_put_varint(p, QUIC_FRAME_ACK);
	p = quic_put_varint(p, qs->packet.pn); /* Largest Acknowledged */
	p = quic_put_varint(p, 0); /* ACK Delay */
	p = quic_put_varint(p, 0); /* ACK Count */
	p = quic_put_varint(p, 0); /* First ACK Range */
	f_len = 5;
	f->len += f_len;
	pr_debug("client ack frame len: %u\n", f_len);

	return 0;
}

static int quic_frame_stream_create(struct quic_sock *qs)
{
	struct quic_vlen *f = &qs->frame.f[QUIC_PKT_SHORT / 2];
	struct iov_iter *msg = qs->frame.stream.msg;
	u32 mlen = iov_iter_count(msg), hlen;
	u32 mss = qs->frame.stream.mss;
	u32 sid = qs->frame.stream.sid;
	u32 off = qs->frame.stream.off;
	u8 *p, *tmp, flag;

	mss -= quic_put_pkt_numlen(qs->packet.ad_tx_pn + 1);
	flag = QUIC_FRAME_STREAM;
	if (mlen < 16 - 2)
		flag |= 0x02;
	if (off)
		flag |= 0x04;

	qs->frame.has_strm = 1;
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

	pr_debug("create stream hlen: %u, mlen: %u, mss: %u, off: %u\n",
		 hlen, mlen, mss, off);
	if (!copy_from_iter_full(p, mlen, msg))
		return -EFAULT;

	qs->frame.stream.off += mlen;
	f->len += hlen + mlen;
	return 0;
}

static int quic_frame_handshake_done_create(struct quic_sock *qs)
{
	struct quic_vlen *f = &qs->frame.f[2];
	u8 *p = f->v + f->len;

	p = quic_put_varint(p, 0x1e);

	return 0;
}

static int quic_frame_hs_fin_crypto_create(struct quic_sock *qs)
{
	struct quic_vlen *f = &qs->frame.f[1];
	u32 f_len;
	u8 *p;

	p = f->v + f->len;
	p = quic_put_varint(p, QUIC_FRAME_CRYPTO);
	p = quic_put_varint(p, 0x00);
	p = quic_put_varint(p, 36);
	p = quic_put_pkt_num(p, QUIC_MT_FINISHED, 1);
	p = quic_put_pkt_num(p, 32, 3);
	p = quic_put_pkt_data(p, qs->crypt.hs_buf[QUIC_H_CFIN].v,
			      qs->crypt.hs_buf[QUIC_H_CFIN].len);
	f_len = 39;
	f->len += f_len;
	pr_debug("client crypto finished frame len: %u\n", f_len);

	return 0;
}

static int quic_frame_hs_crypto_create(struct quic_sock *qs)
{
	struct quic_vlen *f = &qs->frame.f[1];
	struct quic_params *pm = &qs->params;
	u32 f_len, m_len, p_len, clen, t_len;
	u8 *p, *tmp, sf[QUIC_HKDF_HASHLEN];
	u32 e_len, c_len, v_len, fin_len;
	int err, mss;

	mss = quic_dst_mss_check(qs, 2);
	if (mss < 0)
		return mss;

	clen = qs->crypt.crt.len;
	p_len = quic_frame_params_len_get(qs);

	e_len = 4 + (2 + 8 + (4 + p_len));
	c_len = 4 + (2 + clen + 3) + 4;
	v_len = 4 + (2 + 2 + 256);
	fin_len = 4 + QUIC_HKDF_HASHLEN;
	t_len = e_len + c_len + v_len + fin_len;

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
	p = quic_put_varint(p, 0x00);
	p = quic_put_varint(p, qs->scid.len);
	p = quic_put_pkt_data(p, qs->scid.id, qs->scid.len);
	p = quic_put_varint(p, 0x03);
	p = quic_put_varint(p, quic_put_varint_len(pm->max_udp_payload_size));
	p = quic_put_varint(p, pm->max_udp_payload_size);
	p = quic_put_varint(p, 0x04);
	p = quic_put_varint(p, quic_put_varint_len(pm->initial_max_data));
	p = quic_put_varint(p, pm->initial_max_data);
	p = quic_put_varint(p, 0x05);
	p = quic_put_varint(p, quic_put_varint_len(pm->initial_max_stream_data_bidi_local));
	p = quic_put_varint(p, pm->initial_max_stream_data_bidi_local);
	p = quic_put_varint(p, 0x06);
	p = quic_put_varint(p, quic_put_varint_len(pm->initial_max_stream_data_bidi_remote));
	p = quic_put_varint(p, pm->initial_max_stream_data_bidi_remote);
	p = quic_put_varint(p, 0x07);
	p = quic_put_varint(p, quic_put_varint_len(pm->initial_max_stream_data_uni));
	p = quic_put_varint(p, pm->initial_max_stream_data_uni);
	p = quic_put_varint(p, 0x08);
	p = quic_put_varint(p, quic_put_varint_len(pm->initial_max_streams_bidi));
	p = quic_put_varint(p, pm->initial_max_streams_bidi);
	p = quic_put_varint(p, 0x09);
	p = quic_put_varint(p, quic_put_varint_len(pm->initial_max_streams_uni));
	p = quic_put_varint(p, pm->initial_max_streams_uni);
	p = quic_put_varint(p, 0x0f);
	p = quic_put_varint(p, qs->scid.len);
	p = quic_put_pkt_data(p, qs->scid.id, qs->scid.len);
	qs->crypt.hs_buf[QUIC_H_EE].len = (u32)(p - tmp);
	qs->crypt.hs_buf[QUIC_H_EE].v = quic_mem_dup(tmp, qs->crypt.hs_buf[QUIC_H_EE].len);
	if (!qs->crypt.hs_buf[QUIC_H_EE].v)
		return -ENOMEM;

	tmp = p;
	p = quic_put_pkt_num(p, QUIC_MT_CERTIFICATE, 1);
	p = quic_put_pkt_num(p, 2 + clen + 3 + 4, 3);
	p = quic_put_pkt_num(p, 0, 1);
	p = quic_put_pkt_num(p, 2 + clen + 3, 3);
	p = quic_put_pkt_num(p, clen, 3);
	p = quic_put_pkt_data(p, qs->crypt.crt.v, clen);
	p = quic_put_pkt_num(p, 0, 2);
	qs->crypt.hs_buf[QUIC_H_CERT].len = (u32)(p - tmp);
	qs->crypt.hs_buf[QUIC_H_CERT].v = quic_mem_dup(tmp, qs->crypt.hs_buf[QUIC_H_CERT].len);
	if (!qs->crypt.hs_buf[QUIC_H_CERT].v)
		return -ENOMEM;

	err = quic_crypto_server_certvfy_sign(qs);
	if (err)
		return err;
	/* self-check */
	err = quic_crypto_server_certvfy_verify(qs);
	if (err)
		return err;
	tmp = p;
	p = quic_put_pkt_num(p, QUIC_MT_CERTIFICATE_VERIFY, 1);
	p = quic_put_pkt_num(p, 2 + 2 + qs->crypt.sig.len, 3);
	p = quic_put_pkt_num(p, QUIC_SAE_rsa_pss_rsae_sha256, 2);
	p = quic_put_pkt_num(p, qs->crypt.sig.len, 2);
	p = quic_put_pkt_data(p, qs->crypt.sig.v, qs->crypt.sig.len);
	qs->crypt.hs_buf[QUIC_H_CVFY].len = (u32)(p - tmp);
	qs->crypt.hs_buf[QUIC_H_CVFY].v = quic_mem_dup(tmp, qs->crypt.hs_buf[QUIC_H_CVFY].len);
	if (!qs->crypt.hs_buf[QUIC_H_CVFY].v)
		return -ENOMEM;

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
	pr_debug("hs_crypto p_len: %u, e_len: %u, f_len: %u, c_len: %u\n",
		 p_len, e_len, f_len, c_len);
	if (m_len < t_len) {
		f = &qs->frame.f[3];

		t_len = t_len - m_len;
		p = f->v + f->len;
		p = quic_put_varint(p, QUIC_FRAME_CRYPTO);
		p = quic_put_varint(p, m_len);
		p = quic_put_varint(p, t_len);
		p = quic_put_pkt_data(p, tmp + m_len, t_len);
		f->len = (u32)(p - f->v);
		pr_debug("hs_crypto t_len: %u,  m_len: %u, f_len: %u\n",
			 t_len, m_len, f->len);
	}

	return quic_crypto_application_keys_install(qs);
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
	return -EINVAL;
}

static int quic_frame_crypto_process(struct quic_sock *qs, u8 **ptr, u32 left)
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
	skb_pull(skb, (p - len) - skb->data);
	skb_trim(skb, len);

	err = quic_receive_list_add(qs, skb);

out:
	*ptr = p;
	return err;
}

static int quic_frame_ack_process(struct quic_sock *qs, u8 **ptr)
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

	*ptr = p;
	return 0;
}

static int quic_frame_new_connection_id_process(struct quic_sock *qs, u8 **ptr)
{
	struct quic_cid *cid, *tmp;
	u8 *p = *ptr;
	u32 v, len;

	v = quic_get_varint_next(&p, &len);
	pr_debug("Sequence Number: %u\n", v);
	v = quic_get_varint_next(&p, &len);
	pr_debug("Retire Prior To: %u\n", v);
	len = quic_get_fixint_next(&p, 1);
	pr_debug("Length: %u\n", len);
	cid = kzalloc(sizeof(*cid), GFP_ATOMIC);
	if (!cid)
		return -ENOMEM;

	cid->len = len;
	cid->id = quic_mem_dup(p, len);
	for (tmp = &qs->dcid; tmp; tmp = tmp->next) {
		if (tmp->len == cid->len && !memcmp(cid->id, tmp->id, tmp->len))
			return -EINVAL;
		if (!tmp->next) {
			tmp->next = cid;
			break;
		}
	}
	p += len;

	pr_debug("Stateless Reset Token: %16phN\n", p);
	p += 16;

	*ptr = p;
	return 0;
}

static int quic_frame_new_token_process(struct quic_sock *qs, u8 **ptr)
{
	u8 *p = *ptr;
	u32 v, len;

	len = quic_get_varint_next(&p, &v);
	pr_debug("Token Length: %u\n", len);
	kfree(qs->token.v);
	qs->token.len = len;
	qs->token.v = quic_mem_dup(p, len);
	p += len;

	*ptr = p;
	return 0;
}

static int quic_frame_handshake_done_process(struct quic_sock *qs, u8 **ptr)
{
	return 0;
}

/* exported */
int quic_frame_process(struct quic_sock *qs, u8 *p, u32 len)
{
	u32 frames_len = len, v;
	int err, left = len;
	u8 *frames_p = p;

	pr_debug("frames_len %u\n", frames_len);
	qs->frame.need_ack = 0;
	qs->frame.has_strm = 0;
	while (1) {
		v = quic_get_varint_next(&p, &len);
		left -= len;
		pr_debug("ch type: %x\n", v);
		if (v != QUIC_FRAME_ACK && v != QUIC_FRAME_PADDING)
			qs->frame.need_ack = 1;
		if (v == QUIC_FRAME_ACK) {
			err = quic_frame_ack_process(qs, &p);
		} else if (v == QUIC_FRAME_CRYPTO) {
			err = quic_frame_crypto_process(qs, &p, left);
		} else if (v == QUIC_FRAME_NEW_CONNECTION_ID) {
			err = quic_frame_new_connection_id_process(qs, &p);
		} else if (v == QUIC_FRAME_NEW_TOKEN) {
			err = quic_frame_new_token_process(qs, &p);
		} else if (v == QUIC_FRAME_HANDSHAKE_DONE) {
			err = quic_frame_handshake_done_process(qs, &p);
		} else if (v == QUIC_FRAME_PADDING) {
			p = frames_p + frames_len;
		} else if (v < QUIC_FRAME_MAX_DATA && v >= QUIC_FRAME_STREAM) {
			err = quic_frame_stream_process(qs, &p, v, left);
		} else {
			pr_err_once("ch packet: unsupported frame %u\n", v);
			err = -EPROTONOSUPPORT;
		}
		if (err)
			break;

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
	if (type == QUIC_FRAME_ACK)
		return quic_frame_ack_create(qs);
	if (type == QUIC_FRAME_CRYPTO)
		return quic_frame_crypto_create(qs);
	if (type < QUIC_FRAME_MAX_DATA && type >= QUIC_FRAME_STREAM)
		return quic_frame_stream_create(qs);
	if (type == QUIC_FRAME_HANDSHAKE_DONE)
		return quic_frame_handshake_done_create(qs);
	return -EINVAL;
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
