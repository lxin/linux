/* SPDX-License-Identifier: GPL-2.0-or-later */
/* TLS 1.3 Handshake kernel implementation
 * (C) Copyright Red Hat Corp. 2021
 *
 * This file is the TLS 1.3 Handshake kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#ifndef __net_tls_hs_h__
#define __net_tls_hs_h__

#include <linux/types.h>

enum {
	TLS_T_PKEY,
	TLS_T_PSK,
	TLS_T_CA,
	TLS_T_CRT_REQ,
	TLS_T_CRTS,
	TLS_T_CRT,
	TLS_T_MSG,
	TLS_T_EXT,
	TLS_T_TEA,
	TLS_T_REA,
	TLS_T_THS,
	TLS_T_RHS,
	TLS_T_TAP,
	TLS_T_RAP,
}; /* hs opt type */

enum {
	TLS_P_NONE,
	TLS_P_TICKET,
	TLS_P_KEY_UPDATE,
}; /* post hs opt type */

enum {
	TLS_ST_START,
	TLS_ST_RCVD,
	TLS_ST_WAIT,
	TLS_ST_CONNECTED,
}; /* state hs returns */

struct tls_vec {
	u8 *data;
	u32  len;
};

static inline struct tls_vec *tls_vec(struct tls_vec *vec, u8 *data, u32 len)
{
	vec->data = data;
	vec->len  = len;
	return vec;
}

struct tls_hs;

int tls_handshake_create(struct tls_hs **tlsp, bool is_serv, gfp_t gfp);
void tls_handshake_destroy(struct tls_hs *tls);

int tls_handshake(struct tls_hs *tls, struct tls_vec *imsg, struct tls_vec *omsg);
int tls_handshake_set(struct tls_hs *tls, u8 type, struct tls_vec *vec);
int tls_handshake_get(struct tls_hs *tls, u8 type, struct tls_vec *vec);
int tls_handshake_post(struct tls_hs *tls, u8 type, struct tls_vec *imsg, struct tls_vec *omsg);

int tls_hkdf_expand(struct tls_hs *tls, struct tls_vec *s, struct tls_vec *l, struct tls_vec *k);
int tls_hkdf_extract(struct tls_hs *tls, struct tls_vec *s, struct tls_vec *l, struct tls_vec *k);

#endif /* __net_tls_hs_h__ */
