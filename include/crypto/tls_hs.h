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
	TLS_T_CMSG,
	TLS_T_EARLY,
}; /* hs opt type */

enum {
	TLS_SE_DHE,
	TLS_SE_RMS,

	/* early data keys */
	TLS_SE_EA,
	TLS_SE_TEA,
	TLS_SE_TEA_KEY,
	TLS_SE_TEA_IV,
	TLS_SE_REA,
	TLS_SE_REA_KEY,
	TLS_SE_REA_IV,

	/* handshake keys */
	TLS_SE_HS,
	TLS_SE_THS,
	TLS_SE_THS_KEY,
	TLS_SE_THS_IV,
	TLS_SE_RHS,
	TLS_SE_RHS_KEY,
	TLS_SE_RHS_IV,

	/* application keys */
	TLS_SE_AP,
	TLS_SE_TAP,
	TLS_SE_TAP_KEY,
	TLS_SE_TAP_IV,
	TLS_SE_RAP,
	TLS_SE_RAP_KEY,
	TLS_SE_RAP_IV,
	TLS_SE_MAX,
}; /* hs key type */

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
struct socket;

/* Low Level TLS 1.3 Handshake APIs */
int tls_handshake_create(struct tls_hs **tlsp, bool is_serv, gfp_t gfp);
void tls_handshake_destroy(struct tls_hs *tls);

int tls_handshake(struct tls_hs *tls, struct tls_vec *msg);
int tls_handshake_set(struct tls_hs *tls, u8 type, struct tls_vec *vec);
int tls_handshake_get(struct tls_hs *tls, u8 type, struct tls_vec *vec);
int tls_handshake_post(struct tls_hs *tls, u8 type, struct tls_vec *msg);

int tls_hkdf_expand(struct tls_hs *tls, struct tls_vec *s, struct tls_vec *l, struct tls_vec *k);
int tls_hkdf_extract(struct tls_hs *tls, struct tls_vec *s, struct tls_vec *l, struct tls_vec *k);
int tls_secret_get(struct tls_hs *tls, u8 type, struct tls_vec *vec);

#define TLS_F_SERV		0x1
#define TLS_F_PSK		0x2
#define TLS_F_CRT		0x4
#define TLS_F_CRT_REQ		0x8
#define TLS_F_NO_KTLS		0x10

/* General TCP TLS 1.3 Handshake APIs */
struct tls_hs *tls_sk_handshake(struct socket *sock, struct tls_vec *msg, char *subsys, u8 flag);
int tls_sk_handshake_post(struct socket *sock, struct tls_hs *tls, u8 type, struct tls_vec *msg);

/* En/Decrypt msg when tls_sk is used without KTLS. */
int tls_ap_encrypt(struct tls_hs *tls, struct tls_vec *msg, u32 seq);
int tls_ap_decrypt(struct tls_hs *tls, struct tls_vec *msg, u32 seq);
#endif /* __net_tls_hs_h__ */
