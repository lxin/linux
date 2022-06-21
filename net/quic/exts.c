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

static int quic_exts_transport_parameters_process(struct quic_sock *qs, u8 *p, u32 len)
{
	struct quic_param *pm = &qs->params.peer;
	u32 ext_len = len, v, type;
	u8 *ext_p = p;

	while (1) {
		type = quic_get_varint_next(&p, &len);
		pr_debug("transport param type: %x\n", type);
		len = quic_get_varint_next(&p, &v);
		pr_debug("transport param len: %u\n", len);
		if (type == QUIC_PARAM_max_udp_payload_size) {
			pm->max_udp_payload_size = quic_get_varint(&len, p);
		} else if (type == QUIC_PARAM_initial_max_data) {
			pm->initial_max_data = quic_get_varint(&len, p);
			qs->packet.snd_max = qs->params.peer.initial_max_data;
		} else if (type == QUIC_PARAM_initial_max_stream_data_bidi_local) {
			pm->initial_max_stream_data_bidi_local = quic_get_varint(&len, p);
		} else if (type == QUIC_PARAM_initial_max_stream_data_bidi_remote) {
			pm->initial_max_stream_data_bidi_remote = quic_get_varint(&len, p);
		} else if (type == QUIC_PARAM_initial_max_stream_data_uni) {
			pm->initial_max_stream_data_uni = quic_get_varint(&len, p);
		} else if (type == QUIC_PARAM_initial_max_streams_bidi) {
			pm->initial_max_streams_bidi = quic_get_varint(&len, p);
		} else if (type == QUIC_PARAM_initial_max_streams_uni) {
			pm->initial_max_streams_uni = quic_get_varint(&len, p);
		}
		p += len;
		if ((u32)(p - ext_p) >= ext_len)
			break;
	}

	return 0;
}

static int quic_exts_supported_groups_process(struct quic_sock *qs, u8 *p, u32 len)
{
	int i;

	for (i = 0; i < len; i += 2, p += 2)
		if (*((u16 *)p) == htons(QUIC_ECDHE_secp256r1))
			return 0;

	return -ENOENT;
}

static int quic_exts_key_share_process(struct quic_sock *qs, u8 *p, u32 len)
{
	u8 *x, *y;
	int err;
	u32 v;

	if (qs->state > QUIC_CS_CLOSING) {
		len = quic_get_fixint_next(&p, 2);
		pr_debug("key_share len: %x\n", v);
	}
	v = quic_get_fixint_next(&p, 2);
	pr_debug("key_share sgrp: %x\n", v);
	len = quic_get_fixint_next(&p, 2);
	pr_debug("key_share sgrp len %u\n", len);
	p++; /* legacy_form = 4 */
	x = p;
	pr_debug("key_share ecdh X: %32phN\n", x);
	p += QUIC_ECDHLEN;
	y = p;
	pr_debug("key_share ecdh Y: %32phN\n", y);

	err = quic_crypto_compute_ecdh_secret(qs, x, y);
	if (err)
		return err;

	if (qs->state > QUIC_CS_CLOSING)
		return 0;

	return quic_crypto_handshake_keys_install(qs);
}

static int quic_exts_supported_versions_process(struct quic_sock *qs, u8 *p, u32 len)
{
	int i;
	u32 v;

	if (qs->state > QUIC_CS_CLOSING)
		v = quic_get_fixint_next(&p, 1);

	for (i = 0; i < len; i += 2, p += 2)
		if (*((u16 *)p) == htons(QUIC_MSG_version))
			return 0;

	return -ENOENT;
}

static int quic_exts_psk(struct quic_sock *qs, u8 *p, u32 len)
{
	u32 pskid_len, binder_len, v, age_add;
	struct quic_psk *psk;
	u8 *pskid, *binder;
	int err = -EINVAL;

	if (!(qs->state > QUIC_CS_CLOSING)) {
		v = quic_get_fixint_next(&p, 2);

		pr_debug("psk selected_identity %u\n", v);
		return 0;
	}

	len = quic_get_fixint_next(&p, 2);
	pskid_len = quic_get_fixint_next(&p, 2);
	pskid = p;
	p += pskid_len;
	age_add = quic_get_fixint_next(&p, 4);

	for (psk = qs->lsk->crypt.psks; psk; psk = psk->next) {
		if (pskid_len == psk->pskid.len &&
		    !memcmp(pskid, psk->pskid.v, pskid_len))
			break;
	}
	if (!psk)
		return err;

	err = quic_crypto_psk_create(qs, psk->pskid.v, psk->pskid.len, psk->nonce.v,
				     psk->nonce.len, psk->mskey.v, psk->mskey.len);
	if (err)
		return err;
	err = quic_crypto_early_keys_prepare(qs);
	if (err)
		return err;

	len = quic_get_fixint_next(&p, 2);
	binder_len = quic_get_fixint_next(&p, 1);
	binder = p;
	err = quic_crypto_early_binder_create(qs, qs->crypt.hs_buf[QUIC_H_CH].v,
					      qs->crypt.hs_buf[QUIC_H_CH].len - len - 2);
	if (err)
		return err;
	pr_debug("psk binder %32phN, %32phN\n", binder, qs->crypt.binder_secret);

	return memcmp(binder, qs->crypt.binder_secret, binder_len);
}

static int quic_exts_early_data_process(struct quic_sock *qs, u8 *p, u32 len)
{
	u32 v;

	if (qs->packet.type != QUIC_PKT_SHORT) {
		pr_debug("max_early_data_size recvd\n");
		return 0;
	}

	v = quic_get_fixint_next(&p, 4);
	pr_debug("max_early_data_size %u\n", v);
	if (v != 0xffffffff)
		return 1;

	return 0;
}

static int quic_exts_unsupported(struct quic_sock *qs, u8 *p, u32 len)
{
	pr_err_once("crypto frame: unsupported extension %u\n", *((u16 *)(p - 4)));
	return -EPROTONOSUPPORT;
}

static int quic_exts_server_name(struct quic_sock *qs, u8 *p, u32 len)
{
	char name[20] = {'\0'};

	memcpy(name, p, len);
	pr_debug("server_name %s\n", name);

	return 0;
}

static int quic_exts_ec_point_formats(struct quic_sock *qs, u8 *p, u32 len)
{
	pr_debug("ec point: %x\n", *((u16 *)p));
	return 0;
}

static int quic_exts_session_ticket(struct quic_sock *qs, u8 *p, u32 len)
{
	pr_debug("session_ticket\n");
	return 0;
}

static int quic_exts_application_layer_protocol_negotiation(struct quic_sock *qs, u8 *p, u32 len)
{
	pr_debug("application_layer_protocol_negotiation\n");
	return 0;
}

static int quic_exts_encrypt_then_mac(struct quic_sock *qs, u8 *p, u32 len)
{
	pr_debug("encrypt_then_mac\n");
	return 0;
}

static int quic_exts_extended_master_secret(struct quic_sock *qs, u8 *p, u32 len)
{
	pr_debug("extended_master_secret\n");
	return 0;
}

static int quic_exts_signature_algorithms(struct quic_sock *qs, u8 *p, u32 len)
{
	int i;

	len = quic_get_fixint_next(&p, 2);

	for (i = 0; i < len; i += 2)
		pr_debug("signature_algorithms %d: %x", i, *((u16 *)(p + i)));

	return 0;
}

static int quic_exts_psk_kex_modes(struct quic_sock *qs, u8 *p, u32 len)
{
	int i;
	u32 v;

	len = quic_get_fixint_next(&p, 1);
	for (i = 0; i < len; i++) {
		v = quic_get_fixint_next(&p, 1);
		if (v == 1) {
			pr_debug("psk_kex_modes psk_dhe_ke\n");
			return 0;
		}
	}
	pr_debug("psk_kex_modes not supported\n");
	return 1;
}

static int quic_exts_transport_parameters_draft_process(struct quic_sock *qs, u8 *p, u32 len)
{
	pr_debug("transport_parameters_draft\n");
	return 0;
}

static struct quic_ext_ops quic_exts[QUIC_EXT_MAX + 1] = {
	{quic_exts_server_name}, /* 0 */
	{quic_exts_unsupported},
	{quic_exts_unsupported},
	{quic_exts_unsupported},
	{quic_exts_unsupported},
	{quic_exts_unsupported},
	{quic_exts_unsupported},
	{quic_exts_unsupported},
	{quic_exts_unsupported},
	{quic_exts_unsupported},
	{quic_exts_supported_groups_process},
	{quic_exts_ec_point_formats},
	{quic_exts_unsupported},
	{quic_exts_signature_algorithms},
	{quic_exts_unsupported},
	{quic_exts_unsupported},
	{quic_exts_application_layer_protocol_negotiation}, /* 16 */
	{quic_exts_unsupported},
	{quic_exts_unsupported},
	{quic_exts_unsupported},
	{quic_exts_unsupported},
	{quic_exts_unsupported},
	{quic_exts_encrypt_then_mac},
	{quic_exts_extended_master_secret},
	{quic_exts_unsupported},
	{quic_exts_unsupported},
	{quic_exts_unsupported},
	{quic_exts_unsupported},
	{quic_exts_unsupported},
	{quic_exts_unsupported},
	{quic_exts_unsupported},
	{quic_exts_unsupported},
	{quic_exts_unsupported}, /* 32 */
	{quic_exts_unsupported},
	{quic_exts_unsupported},
	{quic_exts_session_ticket},
	{quic_exts_unsupported},
	{quic_exts_unsupported},
	{quic_exts_unsupported},
	{quic_exts_unsupported},
	{quic_exts_unsupported},
	{quic_exts_psk},
	{quic_exts_early_data_process},
	{quic_exts_supported_versions_process},
	{quic_exts_unsupported},
	{quic_exts_psk_kex_modes},
	{quic_exts_unsupported},
	{quic_exts_unsupported},
	{quic_exts_unsupported}, /* 48 */
	{quic_exts_unsupported},
	{quic_exts_unsupported},
	{quic_exts_key_share_process},
};

/* exported */
int quic_exts_process(struct quic_sock *qs, u8 *p)
{
	u32 exts_len, v, len;
	u8 *exts_p;
	int err;

	exts_len = quic_get_fixint_next(&p, 2);
	exts_p = p;
	while (1) {
		v = quic_get_fixint_next(&p, 2);
		pr_debug("ext_subtype: %x\n", v);
		len = quic_get_fixint_next(&p, 2);
		pr_debug("ext_sublen: %u\n", len);

		if (v > QUIC_EXT_MAX) {
			if (v == QUIC_EXT_quic_transport_parameters) {
				err = quic_exts_transport_parameters_process(qs, p, len);
			} else if (v == QUIC_EXT_quic_transport_parameters_draft) {
				err = quic_exts_transport_parameters_draft_process(qs, p, len);
			} else {
				pr_err_once("crypto frame: unsupported extension %u\n", v);
				err = -EPROTONOSUPPORT;
			}
		} else {
			err = quic_exts[v].ext_process(qs, p, len);
		}
		if (err) {
			pr_err("ext err: %u %d\n", v, err);
			return err;
		}

		p += len;
		if ((u32)(p - exts_p) >= exts_len)
			break;
	}

	return 0;
}
