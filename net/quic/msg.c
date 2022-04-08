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

static int quic_msg_encrypted_extension_process(struct quic_sock *qs, u8 *p, u32 len)
{
	qs->crypt.hs_buf[QUIC_H_EE].len = len + 4;
	qs->crypt.hs_buf[QUIC_H_EE].v = quic_mem_dup(p - 4, qs->crypt.hs_buf[QUIC_H_EE].len);
	if (!qs->crypt.hs_buf[QUIC_H_EE].v)
		return -ENOMEM;

	return quic_exts_process(qs, p);
}

static int quic_msg_certificate_process(struct quic_sock *qs, u8 *p, u32 len)
{
	struct x509_certificate *x, *cert = NULL;
	u8 *cert_p;
	u32 clen;

	qs->crypt.hs_buf[QUIC_H_CERT].len = len + 4;
	qs->crypt.hs_buf[QUIC_H_CERT].v = quic_mem_dup(p - 4, qs->crypt.hs_buf[QUIC_H_CERT].len);
	if (!qs->crypt.hs_buf[QUIC_H_CERT].v)
		return -ENOMEM;

	pr_debug("cert context %x\n", *p);
	p++;
	clen = quic_get_fixint_next(&p, 3);
	cert_p = p;
	pr_debug("cert total len %u\n", clen);
	while (1) {
		len = quic_get_fixint_next(&p, 3);
		pr_debug("cert one len %u\n", len);
		x = x509_cert_parse(p, len);
		if (IS_ERR(x))
			return PTR_ERR(x);
		if (!cert) {
			cert = x;
		} else {
			x->next = cert;
			cert = x;
		}
		p += len;

		len = quic_get_fixint_next(&p, 2);
		pr_debug("cert ext len %u\n", len);
		p += len;

		if ((u32)(p - cert_p) >= clen)
			break;
	}
	qs->crypt.cert = cert;

	return quic_crypto_server_cert_verify(qs);
}

static int quic_msg_certificate_verify_process(struct quic_sock *qs, u8 *p, u32 len)
{
	u32 v;

	qs->crypt.hs_buf[QUIC_H_CVFY].len = len + 4;
	qs->crypt.hs_buf[QUIC_H_CVFY].v = quic_mem_dup(p - 4, qs->crypt.hs_buf[QUIC_H_CVFY].len);
	if (!qs->crypt.hs_buf[QUIC_H_CVFY].v)
		return -ENOMEM;

	v = quic_get_fixint_next(&p, 2);
	pr_debug("certvfy alg: %x\n", v);

	qs->crypt.sig.len = quic_get_fixint_next(&p, 2);
	qs->crypt.sig.v = quic_mem_dup(p, qs->crypt.sig.len);
	if (!qs->crypt.sig.v)
		return -ENOMEM;

	return quic_crypto_server_certvfy_verify(qs);
}

static int quic_msg_server_finished_process(struct quic_sock *qs, u8 *p, u32 len)
{
	struct sock *sk = &qs->inet.sk;
	int err;

	qs->crypt.hs_buf[QUIC_H_SFIN].len = len + 4;
	qs->crypt.hs_buf[QUIC_H_SFIN].v = quic_mem_dup(p - 4, qs->crypt.hs_buf[QUIC_H_SFIN].len);
	if (!qs->crypt.hs_buf[QUIC_H_SFIN].v)
		return -ENOMEM;

	err = quic_crypto_server_finished_verify(qs);
	if (err)
		return err;

	err = quic_crypto_application_keys_install(qs);
	if (err)
		return err;

	err = quic_frame_create(qs, QUIC_FRAME_CRYPTO);
	if (err)
		return err;
	qs->packet.cork = 0;

	qs->state = QUIC_CS_CLIENT_POST_HANDSHAKE;
	inet_sk_set_state(sk, QUIC_SS_ESTABLISHED);
	sk->sk_state_change(sk);
	return 0;
}

static int quic_msg_client_finished_process(struct quic_sock *qs, u8 *p, u32 len)
{
	struct sock *sk = &qs->inet.sk;
	int err;

	err = (len != qs->crypt.hs_buf[QUIC_H_CFIN].len ||
	       memcmp(p, qs->crypt.hs_buf[QUIC_H_CFIN].v, len));
	pr_debug("client finished verified %d\n", err);
	if (err)
		return err;
	err = quic_frame_create(qs, QUIC_FRAME_HANDSHAKE_DONE);
	if (err)
		return err;

	qs->state = QUIC_CS_SERVER_POST_HANDSHAKE;
	inet_sk_set_state(sk, QUIC_SS_ESTABLISHED);
	sk->sk_state_change(sk);
	return 0;
}

static int quic_msg_finished_process(struct quic_sock *qs, u8 *p, u32 len)
{
	if (qs->state < QUIC_CS_CLOSING)
		return quic_msg_server_finished_process(qs, p, len);

	return quic_msg_client_finished_process(qs, p, len);
}

static int quic_msg_newsession_ticket_process(struct quic_sock *qs, u8 *p, u32 len)
{
	int err;
	u32 v;

	v = quic_get_fixint_next(&p, 4);
	pr_debug("ticket_lifetime: %u\n", v);
	v = quic_get_fixint_next(&p, 4);
	pr_debug("ticket_age_add: %u\n", v);
	len = quic_get_fixint_next(&p, 1);
	pr_debug("ticket_nonce len: %u\n", len);
	p += len;
	len = quic_get_fixint_next(&p, 2);
	pr_debug("ticket len: %u\n", len);
	p += len;

	err = quic_exts_process(qs, p);
	if (err)
		return err;

	return 0;
}

static int quic_msg_client_hello_process(struct quic_sock *qs, u8 *p, u32 len)
{
	int err, i;
	u32 v;

	qs->crypt.hs_buf[QUIC_H_CH].v = quic_mem_dup(p - 4, len + 4);
	if (!qs->crypt.hs_buf[QUIC_H_CH].v)
		return -ENOMEM;
	qs->crypt.hs_buf[QUIC_H_CH].len = len + 4;

	v = quic_get_fixint_next(&p, 2);
	pr_debug("sh version: %x\n", v);
	p += 32; /* random */
	len = quic_get_fixint_next(&p, 1);
	pr_debug("sh session_len: %u\n", len);
	p += len;
	len = quic_get_fixint_next(&p, 2);
	for (i = 0; i < len; i += 2)
		pr_debug("sh cepher %d: %x\n", i, *((u16 *)(p + i)));
	p += len;
	len = quic_get_fixint_next(&p, 1);
	pr_debug("sh compression_len: %u\n", len);
	p += len; /* compression = 0 */

	err = quic_exts_process(qs, p);
	if (err)
		return err;
	err = quic_frame_create(qs, QUIC_FRAME_CRYPTO);
	if (err)
		return err;
	qs->state = QUIC_CS_SERVER_WAIT_HANDSHAKE;
	err = quic_frame_create(qs, QUIC_FRAME_CRYPTO);
	if (err)
		return err;
	return 0;
}

static int quic_msg_server_hello_process(struct quic_sock *qs, u8 *p, u32 len)
{
	struct sk_buff *skb = qs->packet.skb;
	u8 *dcid;
	int err;
	u32 v;

	qs->crypt.hs_buf[QUIC_H_SH].v = quic_mem_dup(p - 4, len + 4);
	if (!qs->crypt.hs_buf[QUIC_H_SH].v)
		return -ENOMEM;
	qs->crypt.hs_buf[QUIC_H_SH].len = len + 4;

	v = quic_get_fixint_next(&p, 2);
	pr_debug("sh version: %x\n", v);
	p += 32; /* random */
	len = quic_get_fixint_next(&p, 1);
	pr_debug("sh session_len: %u\n", len);
	p += len;
	v = quic_get_fixint_next(&p, 2);
	pr_debug("sh cepher: %x\n", v);
	p++; /* compression = 0 */

	err = quic_exts_process(qs, p);
	if (err)
		return err;

	dcid = QUIC_RCV_CB(skb)->scid;
	len = QUIC_RCV_CB(skb)->scid_len;
	dcid = quic_mem_dup(dcid, len);
	if (!dcid)
		return -ENOMEM;

	kfree(qs->dcid.id);
	qs->dcid.id = quic_mem_dup(dcid, len);
	qs->dcid.len = len;
	qs->packet.cork = 1;
	quic_stop_hs_timer(qs);
	return 0;
}

int quic_msg_process(struct quic_sock *qs, u8 *p, u32 hs_len, u32 hs_offset, u32 left)
{
	u32 offset = qs->frame.crypto.msg_off;
	u8 *msg = qs->frame.crypto.msg;
	u8 type = qs->frame.crypto.type;
	u32 v, len, last = 0;
	u8 *hs_v;
	int err;

	/* process the incomplete crypto */
	if (offset && type == qs->packet.type) {
		if (hs_offset != qs->frame.crypto.off)
			return -EINVAL;
		memcpy(msg + offset, p, hs_len);
		p = msg;
		last = offset;
		left += offset;
	}

	hs_v = p;
	while (1) {
		v = quic_get_fixint_next(&p, 1);
		len = quic_get_fixint_next(&p, 3);
		pr_debug("crypto msg: %u %u, left: %u\n", v, len, left);

		left -= 4;
		if (len > left) {
			if (offset && type != qs->packet.type)
				return -EINVAL;
			qs->frame.crypto.type = qs->packet.type;
			qs->frame.crypto.msg_off = left + 4;
			memcpy(msg, p - 4, qs->frame.crypto.msg_off);
			qs->frame.crypto.off = hs_offset + hs_len;
			return 0;
		}
		if (offset && type == qs->packet.type)
			qs->frame.crypto.msg_off = 0;

		if (v == QUIC_MT_CLIENT_HELLO) {
			err = quic_msg_client_hello_process(qs, p, len);
		} else if (v == QUIC_MT_SERVER_HELLO) {
			err = quic_msg_server_hello_process(qs, p, len);
		} else if (v == QUIC_MT_ENCRYPTED_EXTENSIONS) {
			err = quic_msg_encrypted_extension_process(qs, p, len);
		} else if (v == QUIC_MT_CERTIFICATE) {
			err = quic_msg_certificate_process(qs, p, len);
		} else if (v == QUIC_MT_CERTIFICATE_VERIFY) {
			err = quic_msg_certificate_verify_process(qs, p, len);
		} else if (v == QUIC_MT_FINISHED) {
			err = quic_msg_finished_process(qs, p, len);
		} else if (v == QUIC_MT_NEWSESSION_TICKET) {
			err = quic_msg_newsession_ticket_process(qs, p, len);
		} else {
			pr_err_once("crypto frame: unsupported msg %u\n", v);
			err = -EPROTONOSUPPORT;
		}
		if (err)
			return err;
		p += len;
		left -= len;
		if ((u32)(p - hs_v) >= hs_len + last)
			break;
	}
	return 0;
}
