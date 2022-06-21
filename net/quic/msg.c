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
	struct quic_cert *c, *certs = NULL, *tmp = NULL;
	u8 *cert_p, ctype;
	u32 clen;

	ctype = quic_is_serv(qs) ? QUIC_H_CCERT : QUIC_H_SCERT;
	qs->crypt.hs_buf[ctype].len = len + 4;
	qs->crypt.hs_buf[ctype].v = quic_mem_dup(p - 4, qs->crypt.hs_buf[ctype].len);
	if (!qs->crypt.hs_buf[ctype].v)
		return -ENOMEM;

	pr_debug("cert context %x\n", *p);
	p++;
	clen = quic_get_fixint_next(&p, 3);
	cert_p = p;
	pr_debug("cert total len %u\n", clen);
	while (1) {
		len = quic_get_fixint_next(&p, 3);
		pr_debug("cert one len %u\n", len);
		c = quic_cert_create(p, len);
		if (!c) {
			qs->crypt.rcerts = certs;
			return -ENOMEM;
		}
		if (!certs)
			certs = c;
		else
			tmp->next = c;
		tmp = c;
		p += len;

		len = quic_get_fixint_next(&p, 2);
		pr_debug("cert ext len %u\n", len);
		p += len;

		if ((u32)(p - cert_p) >= clen)
			break;
	}

	qs->crypt.rcerts = certs;

	return quic_crypto_cert_verify(qs);
}

static int quic_msg_certificate_request_process(struct quic_sock *qs, u8 *p, u32 len)
{
	qs->crypt.hs_buf[QUIC_H_CREQ].len = len + 4;
	qs->crypt.hs_buf[QUIC_H_CREQ].v = quic_mem_dup(p - 4, qs->crypt.hs_buf[QUIC_H_CREQ].len);
	if (!qs->crypt.hs_buf[QUIC_H_CREQ].v)
		return -ENOMEM;

	len = quic_get_fixint_next(&p, 1);
	pr_debug("cert request len: %d\n", len);
	p += len;

	return quic_exts_process(qs, p);
}

static int quic_msg_certificate_verify_process(struct quic_sock *qs, u8 *p, u32 len)
{
	u32 v, vtype;

	vtype = quic_is_serv(qs) ? QUIC_H_CCVFY : QUIC_H_SCVFY;
	qs->crypt.hs_buf[vtype].len = len + 4;
	qs->crypt.hs_buf[vtype].v = quic_mem_dup(p - 4, qs->crypt.hs_buf[vtype].len);
	if (!qs->crypt.hs_buf[vtype].v)
		return -ENOMEM;

	v = quic_get_fixint_next(&p, 2);
	pr_debug("certvfy alg: %x\n", v);

	qs->crypt.sig.len = quic_get_fixint_next(&p, 2);
	qs->crypt.sig.v = quic_mem_dup(p, qs->crypt.sig.len);
	if (!qs->crypt.sig.v)
		return -ENOMEM;

	return quic_crypto_certvfy_verify(qs);
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

	qs->crypt.hs_buf[QUIC_H_CFIN].len = len + 4;
	qs->crypt.hs_buf[QUIC_H_CFIN].v = quic_mem_dup(p - 4, qs->crypt.hs_buf[QUIC_H_CFIN].len);
	err = quic_crypto_client_finished_verify(qs);
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
	u32 v, expire, nonce_len, pskid_len, age_add;
	struct quic_psk *psks;
	u8 *nonce, *pskid;
	int err;

	v = quic_get_fixint_next(&p, 4);
	expire = v;
	pr_debug("ticket_lifetime: %u\n", v);
	v = quic_get_fixint_next(&p, 4);
	pr_debug("ticket_age_add: %u\n", v);
	age_add = v;

	len = quic_get_fixint_next(&p, 1);
	pr_debug("ticket_nonce len: %u\n", len);
	nonce_len = len;
	nonce = p;
	p += len;
	len = quic_get_fixint_next(&p, 2);
	pr_debug("ticket len: %u\n", len);
	pskid_len = len;
	pskid = p;
	p += len;

	err = quic_crypto_psk_create(qs, pskid, pskid_len, nonce, nonce_len,
				     qs->crypt.rms_secret, QUIC_HKDF_HASHLEN);
	if (err)
		return err;
	psks = qs->crypt.psks;
	psks->psk_expire = expire;
	psks->psk_sent_at = age_add;
	pr_debug("recv ticket %u %u: %8phN(%u), %8phN(%u), %8phN(%u)\n",
		 psks->psk_sent_at, psks->psk_expire,
		 psks->pskid.v, psks->pskid.len, psks->nonce.v,
		 psks->nonce.len, psks->mskey.v, psks->mskey.len);

	err = quic_exts_process(qs, p);
	if (err)
		goto out;
	pr_debug("ticket done\n");
	err = quic_evt_notify_ticket(qs);
out:
	quic_crypto_psk_free(qs);
	return err;
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
	err = quic_crypto_early_keys_install(qs);
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
	struct quic_cid *cid;
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

	cid = qs->cids.dcid.list;
	kfree(cid->id);
	cid->id = quic_mem_dup(dcid, len);
	cid->len = len;
	qs->packet.cork = 1;
	quic_stop_hs_timer(qs);
	return 0;
}

static int quic_msg_unsupported_process(struct quic_sock *qs, u8 *p, u32 len)
{
	pr_err_once("crypto frame: unsupported msg %u\n", *(p - 4));
	return -EPROTONOSUPPORT;
}

static struct quic_msg_ops quic_msgs[QUIC_MT_MAX + 1] = {
	{quic_msg_unsupported_process}, /* 0 */
	{quic_msg_client_hello_process},
	{quic_msg_server_hello_process},
	{quic_msg_unsupported_process},
	{quic_msg_newsession_ticket_process},
	{quic_msg_unsupported_process},
	{quic_msg_unsupported_process},
	{quic_msg_unsupported_process},
	{quic_msg_encrypted_extension_process},
	{quic_msg_unsupported_process},
	{quic_msg_unsupported_process},
	{quic_msg_certificate_process},
	{quic_msg_unsupported_process},
	{quic_msg_certificate_request_process},
	{quic_msg_unsupported_process},
	{quic_msg_certificate_verify_process},
	{quic_msg_unsupported_process}, /* 16 */
	{quic_msg_unsupported_process},
	{quic_msg_unsupported_process},
	{quic_msg_unsupported_process},
	{quic_msg_finished_process},
	{quic_msg_unsupported_process},
	{quic_msg_unsupported_process},
	{quic_msg_unsupported_process},
	{quic_msg_unsupported_process},
};

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

		if (v > QUIC_MT_MAX) {
			pr_err_once("crypto frame: unsupported msg %u\n", v);
			return -EPROTONOSUPPORT;
		}
		err = quic_msgs[v].msg_process(qs, p, len);
		if (err) {
			pr_err("crypto msg err %u %d\n", v, err);
			return err;
		}

		p += len;
		left -= len;
		if ((u32)(p - hs_v) >= hs_len + last)
			break;
	}
	return 0;
}
