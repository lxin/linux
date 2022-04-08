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
	struct sock *sk = &qs->inet.sk;
	u32 ext_len = len, v, type;
	u8 *ext_p = p;

	while (1) {
		type = quic_get_varint_next(&p, &len);
		pr_debug("transport param type: %x\n", type);
		len = quic_get_varint_next(&p, &v);
		pr_debug("transport param len: %u\n", len);
		if (type == 0x04) {
			sk->sk_sndbuf = quic_get_varint(&len, p);
			pr_debug("transport param v: %u\n", sk->sk_sndbuf);
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

static int quic_exts_early_data_process(struct quic_sock *qs, u8 *p, u32 len)
{
	u32 v;

	v = quic_get_fixint_next(&p, 4);
	pr_debug("max_early_data_size %u\n", v);

	return 0;
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

	for (i = 0; i < len; i += 4)
		pr_debug("signature_algorithms %d: %x", i, *((u16 *)(p + i + 2)));

	return 0;
}

static int quic_exts_psk_kex_modes(struct quic_sock *qs, u8 *p, u32 len)
{
	pr_debug("psk_kex_modes\n");
	return 0;
}

static int quic_exts_transport_parameters_draft_process(struct quic_sock *qs, u8 *p, u32 len)
{
	pr_debug("transport_parameters_draft\n");
	return 0;
}

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

		if (v == QUIC_EXT_server_name) {
			err = quic_exts_server_name(qs, p, len);
		} else if (v == QUIC_EXT_supported_groups) {
			err = quic_exts_supported_groups_process(qs, p, len);
		} else if (v == QUIC_EXT_supported_versions) {
			err = quic_exts_supported_versions_process(qs, p, len);
		} else if (v == QUIC_EXT_ec_point_formats) {
			err = quic_exts_ec_point_formats(qs, p, len);
		} else if (v == QUIC_EXT_session_ticket) {
			err = quic_exts_session_ticket(qs, p, len);
		} else if (v == QUIC_EXT_application_layer_protocol_negotiation) {
			err = quic_exts_application_layer_protocol_negotiation(qs, p, len);
		} else if (v == QUIC_EXT_encrypt_then_mac) {
			err = quic_exts_encrypt_then_mac(qs, p, len);
		} else if (v == QUIC_EXT_extended_master_secret) {
			err = quic_exts_extended_master_secret(qs, p, len);
		} else if (v == QUIC_EXT_signature_algorithms) {
			err = quic_exts_signature_algorithms(qs, p, len);
		} else if (v == QUIC_EXT_psk_kex_modes) {
			err = quic_exts_psk_kex_modes(qs, p, len);
		} else if (v == QUIC_EXT_key_share) {
			err = quic_exts_key_share_process(qs, p, len);
		} else if (v == QUIC_EXT_quic_transport_parameters) {
			err = quic_exts_transport_parameters_process(qs, p, len);
		} else if (v == QUIC_EXT_quic_transport_parameters_draft) {
			err = quic_exts_transport_parameters_draft_process(qs, p, len);
		} else if (v == QUIC_EXT_early_data) {
			err = quic_exts_early_data_process(qs, p, len);
		} else {
			pr_err_once("crypto frame: unsupported extension %u\n", v);
			err = -EPROTONOSUPPORT;
		}
		if (err)
			return err;
		p += len;
		if ((u32)(p - exts_p) >= exts_len)
			break;
	}

	return 0;
}
