// SPDX-License-Identifier: GPL-2.0-or-later
/* TLS Handshake 1.3 kernel implementation
 * (C) Copyright Red Hat Corp. 2021
 *
 * This file is the TLS 1.3 Handshake kernel implementation
 *
 * Provides APIs for TLS 1.3 Handshake.
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/key-type.h>
#include <linux/net.h>
#include <linux/tls.h>
#include <crypto/hash.h>
#include <crypto/sha2.h>
#include <crypto/aead.h>
#include <crypto/skcipher.h>
#include <crypto/akcipher.h>
#include <crypto/kpp.h>
#include <crypto/ecdh.h>
#include <crypto/tls_hs.h>
#include <keys/user-type.h>
#include "asymmetric_keys/x509_parser.h"

struct tls_crt {
	struct tls_crt *next;
	struct x509_certificate *x509;
	struct tls_vec raw;
};

struct tls_psk {
	struct tls_psk *next;
	struct tls_vec id;
	struct tls_vec key;
	struct tls_vec nonce;
	u32 age_add;
	u32 lifetime;
};

enum {
	TLS_B_MH,
	TLS_B_CH,
	TLS_B_HRR,
	TLS_B_NEG,
	TLS_B_SH,
	TLS_B_EE,
	TLS_B_CRT_REQ,
	TLS_B_S_CRT,
	TLS_B_S_CRT_VFY,
	TLS_B_S_FIN,
	TLS_B_END_EARLY,
	TLS_B_C_CRT,
	TLS_B_C_CRT_VFY,
	TLS_B_C_FIN,
	TLS_B_MAX,
};

struct tls_hello {
	struct tls_vec random;
	struct tls_vec session;
	struct tls_vec cipher;
	struct tls_vec compress;
	struct tls_vec cookie;
};

struct tls_hs {
	struct tls_hello h;
	struct tls_vec ext;
	struct tls_vec imsg;
	struct tls_vec cmsg;
	struct tls_vec omsg;

	struct crypto_kpp *kpp_tfm;
	struct crypto_aead *aead_tfm;
	struct crypto_shash *srt_tfm;
	struct crypto_shash *hash_tfm;
	struct crypto_akcipher *akc_tfm;

	struct tls_vec buf[TLS_B_MAX];
	struct tls_vec srt[TLS_SE_MAX];

	struct tls_crt *tcrts;
	struct tls_crt *rcrts;
	struct tls_vec pkey;
	struct tls_crt *ca;
	struct tls_psk *psks;

	u8 state:2,
	   early:1,
	   is_serv:1,
	   crt_req:1;
};

static inline int tls_vec_new(struct tls_vec *vec, u32 len)
{
	if (vec->data)
		return 0;

	vec->data = kzalloc(len, GFP_ATOMIC);
	if (!vec->data)
		return -ENOMEM;

	vec->len = len;
	return 0;
}

static inline int tls_vec_set(struct tls_vec *vec, u8 *data, u32 len)
{
	if (vec->data) {
		memcpy(vec->data, data, len);
		vec->len = len;
		return 0;
	}

	vec->data = kmemdup(data, len, GFP_ATOMIC);
	if (!vec->data)
		return -ENOMEM;

	vec->len = len;
	return 0;
}

static inline int tls_vec_cpy(struct tls_vec *dst, struct tls_vec *src)
{
	if (!src->len)
		return 0;

	if (dst->data) {
		memcpy(dst->data, src->data, src->len);
		dst->len = src->len;
		return 0;
	}
	dst->data = kmemdup(src->data, src->len, GFP_ATOMIC);
	if (!dst->data)
		return -ENOMEM;

	dst->len = src->len;
	return 0;
}

static inline struct tls_vec *tls_vec_add(struct tls_vec *dst, struct tls_vec *src)
{
	memcpy(dst->data + dst->len, src->data, src->len);
	dst->len += src->len;
	return dst;
}

static inline int tls_vec_cmp(struct tls_vec *dst, struct tls_vec *src)
{
	int len = dst->len - src->len;

	return len ?: memcmp(dst->data, src->data, src->len);
}

static inline int tls_buf_set(struct tls_vec *dst, struct tls_vec *src)
{
	kfree(dst->data);
	dst->len = 0;

	dst->data = kmemdup(src->data, src->len, GFP_ATOMIC);
	if (!dst->data)
		return -ENOMEM;
	dst->len = src->len;
	return 0;
}

union tls_num {
	u8	n8;
	u16	n16;
	u32	n32;
	u64	n64;
	u8	n[8];
};

static inline u8 *tls_put_num(u8 *p, u64 num, u8 len)
{
	union tls_num n;

	n.n64 = num;
	switch (len) {
	case 1:
		*p++ = n.n8;
		return p;
	case 2:
		n.n16 = htons(n.n16);
		memcpy(p, &n.n16, 2);
		return p + 2;
	case 3:
		n.n32 = htonl(n.n32);
		memcpy(p, ((u8 *)&n.n32) + 1, 3);
		return p + 3;
	case 4:
		n.n32 = htonl(n.n32);
		memcpy(p, &n.n32, 4);
		return p + 4;
	default:
		return NULL;
	}
}

static inline u8 *tls_put_data(u8 *p, struct tls_vec *vec)
{
	if (!vec->len)
		return p;

	memcpy(p, vec->data, vec->len);
	return p + vec->len;
}

static inline int tls_get_num(struct tls_vec *m, u32 len, u32 *n)
{
	union tls_num tn;
	u8 *p = m->data;
	u32 num;

	if (len > m->len)
		return -EINVAL;

	tn.n32 = 0;
	switch (len) {
	case 1:
		num = *p;
		break;
	case 2:
		memcpy(&tn.n16, p, 2);
		num = ntohs(tn.n16);
		break;
	case 3:
		memcpy(((u8 *)&tn.n32) + 1, p, 3);
		num = ntohl(tn.n32);
		break;
	case 4:
		memcpy(&tn.n32, p, 4);
		num = ntohl(tn.n32);
		break;
	}

	*n = num;
	m->len -= len;
	m->data += len;
	return 0;
}

static inline int tls_get_data(struct tls_vec *m, u32 len, struct tls_vec *v)
{
	if (len > m->len)
		return -EINVAL;
	v->data = m->data;
	v->len = len;
	m->data += len;
	m->len -= len;
	return 0;
}

static inline int tls_get_sub(struct tls_vec *m, u32 len, struct tls_vec *s)
{
	u32 n;

	if (tls_get_num(m, len, &n))
		return -EINVAL;

	return tls_get_data(m, n, s);
}

static inline void tls_pr_hex(char *str, u8 data[], u32 len)
{
	pr_debug("[TLS_HS] %s: %d\n", str, len);
	print_hex_dump(KERN_INFO, "", DUMP_PREFIX_NONE, 32, 1, data, len, false);
}

#define TLS_MT_HELLO_RETRY_REQUEST	0
#define TLS_MT_CLIENT_HELLO		1
#define TLS_MT_SERVER_HELLO		2
#define TLS_MT_NEWSESSION_TICKET	4
#define TLS_MT_END_OF_EARLY_DATA	5
#define TLS_MT_ENCRYPTED_EXTENSIONS	8
#define TLS_MT_CERTIFICATE		11
#define TLS_MT_CERTIFICATE_REQUEST	13
#define TLS_MT_CERTIFICATE_VERIFY	15
#define TLS_MT_FINISHED			20
#define TLS_MT_KEY_UPDATE		24

#define TLS_EXT_server_name		0
#define TLS_EXT_max_fragment_length	1  /* todo */
#define TLS_EXT_supported_groups	10
#define TLS_EXT_ec_point_formats	11
#define TLS_EXT_signature_algorithms	13
#define TLS_EXT_heartbeat		15
#define TLS_EXT_alpn			16
#define TLS_EXT_signed_cert_timestamp	18
#define TLS_EXT_padding			21
#define TLS_EXT_encrypt_then_mac	22
#define TLS_EXT_extended_master_srt	23
#define TLS_EXT_session_ticket		35
#define TLS_EXT_psk			41
#define TLS_EXT_early_data		42
#define TLS_EXT_supported_versions	43
#define TLS_EXT_cookie			44
#define TLS_EXT_psk_kex_modes		45
#define TLS_EXT_certificate_authorities	47
#define TLS_EXT_post_handshake_auth	49
#define TLS_EXT_signature_algs_cert	50
#define TLS_EXT_key_share		51

#define TLS_MSG_legacy_version		0x0303
#define TLS_AES_128_GCM_SHA256		0x1301
#define TLS_ECDHE_secp256r1		0x0017
#define TLS_SAE_rsa_pss_rsae_sha256	0x0804
#define TLS_MSG_version			0x0304
#define TLS_PSK_dhe_ke			0x01

static int tls_crypto_ecdh_compute(struct crypto_kpp *tfm, struct tls_vec *srt,
				   struct tls_vec *x, struct tls_vec *y)
{
	struct scatterlist src, dst;
	struct kpp_request *req;
	u8 *tmp;
	int err;

	tmp = kmalloc(64, GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;
	req = kpp_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		err = -ENOMEM;
		goto free_tmp;
	}
	err = tls_vec_new(srt, 32);
	if (err)
		goto free_req;
	memcpy(tmp, x->data, 32);
	memcpy(&tmp[32], y->data, 32);
	sg_init_one(&src, tmp, 64);
	sg_init_one(&dst, srt->data, 32);
	kpp_request_set_input(req, &src, 64);
	kpp_request_set_output(req, &dst, 32);
	err = crypto_kpp_compute_shared_secret(req);
	if (err < 0)
		pr_err("[TLS_HS] compute secret failed %d\n", err);
free_req:
	kpp_request_free(req);
free_tmp:
	kfree_sensitive(tmp);
	return err;
}

static int tls_crypto_ecdh_set_privkey(struct crypto_kpp *tfm)
{
	unsigned int buf_len;
	struct ecdh p = {0};
	u8 *buf;
	int err;

	buf_len = crypto_ecdh_key_len(&p);
	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	err = crypto_ecdh_encode_key(buf, buf_len, &p);
	if (err)
		goto free;
	err = crypto_kpp_set_secret(tfm, buf, buf_len);
free:
	kfree_sensitive(buf);
	return err;
}

static int tls_crypto_ecdh_generate(struct crypto_kpp *tfm, struct tls_vec *x, struct tls_vec *y)
{
	struct kpp_request *req;
	struct scatterlist dst;
	u8 *tmp;
	int err;

	err = tls_crypto_ecdh_set_privkey(tfm);
	if (err)
		return err;
	tmp = kmalloc(64, GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;
	req = kpp_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		err = -ENOMEM;
		goto free_tmp;
	}
	sg_init_one(&dst, tmp, 64);
	kpp_request_set_input(req, NULL, 0);
	kpp_request_set_output(req, &dst, 64);
	err = crypto_kpp_generate_public_key(req);
	if (err < 0)
		goto free_all;
	err = tls_vec_set(x, tmp, 32);
	if (err)
		goto free_all;
	err = tls_vec_set(y, &tmp[32], 32);
free_all:
	kpp_request_free(req);
free_tmp:
	kfree(tmp);
	return err;
}

static int tls_crypto_hash(struct crypto_shash *tfm, struct tls_vec buf[], int n,
			   struct tls_vec *hash)
{
	SHASH_DESC_ON_STACK(desc, tfm);
	int err, i;

	desc->tfm = tfm;
	crypto_shash_init(desc);
	for (i = 0; i < n; i++) {
		if (!buf[i].len)
			continue;
		err = crypto_shash_update(desc, buf[i].data, buf[i].len);
		if (err)
			goto out;
	}
	err = tls_vec_new(hash, 32);
	if (err)
		goto out;
	err = crypto_shash_final(desc, hash->data);
out:
	shash_desc_zero(desc);
	return err;
}

static int tls_crypto_hkdf_expand(struct crypto_shash *tfm, struct tls_vec *srt,
				  struct tls_vec *label, struct tls_vec *hash, struct tls_vec *key)
{
	u8 cnt = 1, info[256], *p = info, *prev = NULL;
	u8 LABEL[] = "tls13 ", tmp[32];
	SHASH_DESC_ON_STACK(desc, tfm);
	int err, i, infolen;

	err = tls_vec_new(key, 32);
	if (err)
		return err;
	*p++ = (u8)(key->len / 256);
	*p++ = (u8)(key->len % 256);
	*p++ = (u8)(sizeof(LABEL) - 1 + label->len);
	memcpy(p, LABEL, sizeof(LABEL) - 1);
	p += sizeof(LABEL) - 1;
	memcpy(p, label->data, label->len);
	p += label->len;
	if (hash) {
		*p++ = hash->len;
		memcpy(p, hash->data, hash->len);
		p += hash->len;
	} else {
		*p++ = 0;
	}
	infolen = (int)(p - info);

	desc->tfm = tfm;
	err = crypto_shash_setkey(tfm, srt->data, srt->len);
	if (err)
		return err;
	for (i = 0; i < key->len; i += 32) {
		err = crypto_shash_init(desc);
		if (err)
			goto out;
		if (prev) {
			err = crypto_shash_update(desc, prev, 32);
			if (err)
				goto out;
		}
		err = crypto_shash_update(desc, info, infolen);
		if (err)
			goto out;
		BUILD_BUG_ON(sizeof(cnt) != 1);
		if (key->len - i < 32) {
			err = crypto_shash_finup(desc, &cnt, 1, tmp);
			if (err)
				goto out;
			memcpy(&key->data[i], tmp, key->len - i);
			memzero_explicit(tmp, sizeof(tmp));
		} else {
			err = crypto_shash_finup(desc, &cnt, 1, &key->data[i]);
			if (err)
				goto out;
		}
		cnt++;
		prev = &key->data[i];
	}
out:
	shash_desc_zero(desc);
	return err;
}

static int tls_crypto_hkdf_extract(struct crypto_shash *tfm, struct tls_vec *srt,
				   struct tls_vec *hash, struct tls_vec *key)
{
	int err;

	err = crypto_shash_setkey(tfm, srt->data, srt->len);
	if (err)
		return err;
	err = tls_vec_new(key, 32);
	if (err)
		return err;

	return crypto_shash_tfm_digest(tfm, hash->data, hash->len, key->data);
}

static int tls_crypto_signature_sign(struct crypto_akcipher *tfm, struct public_key *pkey,
				     struct public_key_signature *sig)
{
	struct scatterlist src_sg[1], dst_sg[1];
	struct akcipher_request *req;
	char *key, *ptr;
	int ret;

	req = akcipher_request_alloc(tfm, GFP_ATOMIC);
	if (!req)
		return -ENOMEM;
	key = kmalloc(pkey->keylen + sizeof(u32) * 2 + pkey->paramlen, GFP_ATOMIC);
	if (!key)
		goto free_req;
	memcpy(key, pkey->key, pkey->keylen);
	ptr = key + pkey->keylen;
	memcpy(ptr, &pkey->algo, 4);
	ptr += 4;
	memcpy(ptr, &pkey->paramlen, 4);
	ptr += 4;
	memcpy(ptr, pkey->params, pkey->paramlen);
	ret = crypto_akcipher_set_priv_key(tfm, key, pkey->keylen);
	if (ret)
		goto free_key;
	ret = crypto_akcipher_set_sig_params(tfm, sig, sizeof(*sig));
	if (ret)
		goto free_key;
	sg_init_table(src_sg, 1);
	sg_init_table(dst_sg, 1);
	sg_set_buf(&src_sg[0], sig->digest, sig->digest_size);
	sg_set_buf(&dst_sg[0], sig->s, sig->s_size);
	akcipher_request_set_crypt(req, src_sg, dst_sg, sig->digest_size, sig->s_size);
	ret = crypto_akcipher_sign(req);
free_key:
	kfree(key);
free_req:
	akcipher_request_free(req);
	return ret;
}

static int tls_crypto_crt_verify(struct tls_hs *tls, struct tls_crt *crts)
{
	struct public_key_signature *sig;
	struct asymmetric_key_id *auth;
	struct tls_crt *p, *x, *ca;
	int err = 0;

	for (p = crts; p; p = p->next)
		p->x509->seen = false;
	x = crts;
	ca = tls->ca;
	while (1) {
		x->x509->seen = true;
		sig = x->x509->sig;
		if (x->x509->self_signed) {
			if (!ca) {
				x->x509->signer = x->x509;
				break;
			}
			if (ca->raw.len != x->raw.len ||
			    memcmp(ca->raw.data, x->raw.data, x->raw.len))
				err = -EINVAL;
			break;
		}
		auth = sig->auth_ids[0];
		if (auth) {
			for (p = crts; p; p = p->next) {
				if (asymmetric_key_id_same(p->x509->id, auth))
					goto check_skid;
			}
		} else if (sig->auth_ids[1]) {
			auth = sig->auth_ids[1];
			for (p = crts; p; p = p->next) {
				if (!p->x509->skid)
					continue;
				if (asymmetric_key_id_same(p->x509->skid, auth))
					goto found;
			}
		}
		err = -EKEYREJECTED;
		break;

check_skid:
		if (sig->auth_ids[1] && !asymmetric_key_id_same(p->x509->skid, sig->auth_ids[1])) {
			err = -EKEYREJECTED;
			break;
		}
found:
		if (p->x509->seen)
			break;
		err = public_key_verify_signature(p->x509->pub, x->x509->sig);
		if (err < 0)
			break;
		x->x509->signer = p->x509;
		if (x == p)
			break;
		x = p;
	}

	pr_debug("[TLS_HS] cert verified %d\n", err);
	return err;
}

static int tls_crypto_signature_verify(struct crypto_akcipher *tfm, struct public_key *pkey,
				       struct public_key_signature *sig)
{
	struct akcipher_request *req;
	struct scatterlist src_sg[2];
	char *key, *ptr;
	int ret;

	req = akcipher_request_alloc(tfm, GFP_ATOMIC);
	if (!req)
		return -ENOMEM;
	key = kmalloc(pkey->keylen + sizeof(u32) * 2 + pkey->paramlen, GFP_ATOMIC);
	if (!key)
		goto free_req;
	memcpy(key, pkey->key, pkey->keylen);
	ptr = key + pkey->keylen;
	memcpy(ptr, &pkey->algo, 4);
	ptr += 4;
	memcpy(ptr, &pkey->paramlen, 4);
	ptr += 4;
	memcpy(ptr, pkey->params, pkey->paramlen);
	ret = crypto_akcipher_set_pub_key(tfm, key, pkey->keylen);
	if (ret)
		goto free_key;
	ret = crypto_akcipher_set_sig_params(tfm, sig, sizeof(*sig));
	if (ret)
		goto free_key;
	sg_init_table(src_sg, 2);
	sg_set_buf(&src_sg[0], sig->s, sig->s_size);
	sg_set_buf(&src_sg[1], sig->digest, sig->digest_size);
	akcipher_request_set_crypt(req, src_sg, NULL, sig->s_size, sig->digest_size);
	ret = crypto_akcipher_verify(req);
free_key:
	kfree(key);
free_req:
	akcipher_request_free(req);
	return ret;
}

static int tls_keys_derive(struct tls_hs *tls, struct tls_vec *s, struct tls_vec *k,
			   struct tls_vec *i)
{
	struct tls_vec k_l = {"key", 3}, i_l = {"iv", 2};
	int err;

	err = tls_vec_new(k, 16);
	if (err)
		return err;
	err = tls_hkdf_expand(tls, s, &k_l, k);
	if (err)
		return err;
	err = tls_vec_new(i, 12);
	if (err)
		return err;

	return tls_hkdf_expand(tls, s, &i_l, i);
}

static int tls_keys_setup(struct tls_hs *tls, u8 t, struct tls_vec *tl,
			  struct tls_vec *rl, struct tls_vec *h, char *str)
{
	struct crypto_shash *tfm = tls->srt_tfm;
	int err;

	err = tls_crypto_hkdf_expand(tfm, &tls->srt[t], tl, h, &tls->srt[t + 1]);
	if (err)
		return err;
	err = tls_crypto_hkdf_expand(tfm, &tls->srt[t], rl, h, &tls->srt[t + 4]);
	if (err)
		return err;
	pr_debug("[TLS_HS] %s secrets: %32phN, %32phN\n",
		 str, tls->srt[t + 1].data, tls->srt[t + 4].data);
	if (tls->ext.len)
		return 0;

	err = tls_keys_derive(tls, &tls->srt[t + 1], &tls->srt[t + 2], &tls->srt[t + 3]);
	if (err)
		return err;
	err = tls_keys_derive(tls, &tls->srt[t + 4], &tls->srt[t + 5], &tls->srt[t + 6]);
	if (err)
		return err;

	pr_debug("[TLS_HS] %s keys: %16phN, %16phN\n",
		 str, tls->srt[t + 2].data, tls->srt[t + 5].data);
	pr_debug("[TLS_HS] %s ivs: %12phN, %12phN\n",
		 str, tls->srt[t + 3].data, tls->srt[t + 6].data);
	return 0;
}

static int tls_keys_ea_setup(struct tls_hs *tls)
{
	struct tls_vec h_v, rl, tl;
	u8 h[32];
	int err;

	if (tls->is_serv) {
		tls_vec(&rl, "c e traffic", 11);
		tls_vec(&tl, "s e traffic", 11);
	} else {
		tls_vec(&rl, "s e traffic", 11);
		tls_vec(&tl, "c e traffic", 11);
	}
	err = tls_crypto_hash(tls->hash_tfm, tls->buf, TLS_B_CH + 1, tls_vec(&h_v, h, 32)); /* h1 */
	if (err)
		return err;

	return tls_keys_setup(tls, TLS_SE_EA, &tl, &rl, &h_v, "ea");
}

static int tls_keys_hs_setup(struct tls_hs *tls)
{
	struct tls_vec des_v, h_v, l = {"derived", 7}, tl, rl;
	struct crypto_shash *tfm = tls->srt_tfm;
	u8 des[32], h[32];
	int err;

	err = tls_crypto_hash(tls->hash_tfm, NULL, 0, tls_vec(&h_v, h, 32)); /* h0 */
	if (err)
		return err;
	err = tls_crypto_hkdf_expand(tfm, &tls->srt[TLS_SE_EA], &l,
				     &h_v, tls_vec(&des_v, des, 32));
	if (err)
		return err;
	err = tls_crypto_hkdf_extract(tfm, &des_v, &tls->srt[TLS_SE_DHE],
				      &tls->srt[TLS_SE_HS]);
	if (err)
		return err;
	if (tls->is_serv) {
		tls_vec(&rl, "c hs traffic", 12);
		tls_vec(&tl, "s hs traffic", 12);
	} else {
		tls_vec(&rl, "s hs traffic", 12);
		tls_vec(&tl, "c hs traffic", 12);
	}
	err = tls_crypto_hash(tls->hash_tfm, tls->buf, TLS_B_SH + 1, &h_v); /* h2 */
	if (err)
		return err;

	return tls_keys_setup(tls, TLS_SE_HS, &tl, &rl, &h_v, "hs");
}

static int tls_keys_ap_setup(struct tls_hs *tls)
{
	struct tls_vec dhs_v, z0_v, h_v, l = {"derived", 7}, rl, tl;
	struct crypto_shash *tfm = tls->srt_tfm;
	u8 zeros[32] = {0}, dhs[32], h[32];
	int err;

	err = tls_crypto_hash(tls->hash_tfm, NULL, 0, tls_vec(&h_v, h, 32)); /* h0 */
	if (err)
		return err;
	err = tls_crypto_hkdf_expand(tfm, &tls->srt[TLS_SE_HS], &l,
				     &h_v, tls_vec(&dhs_v, dhs, 32));
	if (err)
		return err;
	err = tls_crypto_hkdf_extract(tfm, &dhs_v, tls_vec(&z0_v, zeros, 32),
				      &tls->srt[TLS_SE_AP]);
	if (err)
		return err;
	if (tls->is_serv) {
		tls_vec(&rl, "c ap traffic", 12);
		tls_vec(&tl, "s ap traffic", 12);
	} else {
		tls_vec(&rl, "s ap traffic", 12);
		tls_vec(&tl, "c ap traffic", 12);
	}
	err = tls_crypto_hash(tls->hash_tfm, tls->buf, TLS_B_S_FIN + 1, &h_v); /* h3 */
	if (err)
		return err;

	return tls_keys_setup(tls, TLS_SE_AP, &tl, &rl, &h_v, "ap");
}

static int tls_keys_rm_setup(struct tls_hs *tls)
{
	struct tls_vec h_v, l_v = {"res master", 10};
	u8 h[32];
	int err;

	tls_vec(&h_v, h, 32);
	err = tls_crypto_hash(tls->hash_tfm, tls->buf, TLS_B_C_FIN + 1, &h_v); /* h4 */
	if (err)
		return err;

	return tls_crypto_hkdf_expand(tls->srt_tfm, &tls->srt[TLS_SE_AP], &l_v, &h_v,
				      &tls->srt[TLS_SE_RMS]);
}

static void tls_crt_free(struct tls_crt *crts)
{
	struct tls_crt *n, *p = crts;

	while (p) {
		n = p->next;
		kfree(p->x509);
		kfree(p->raw.data);
		kfree(p);
		p = n;
	}
}

static struct tls_crt *tls_crt_new(struct tls_vec *vec)
{
	struct x509_certificate *x;
	struct tls_crt *c;

	c = kzalloc(sizeof(*c), GFP_ATOMIC);
	if (!c)
		return NULL;
	if (tls_vec_cpy(&c->raw, vec)) {
		kfree(c);
		return NULL;
	}
	x = x509_cert_parse(c->raw.data, c->raw.len);
	if (IS_ERR(x)) {
		tls_crt_free(c);
		return NULL;
	}

	c->x509 = x;
	return c;
}

static void tls_psk_free(struct tls_psk *psks)
{
	struct tls_psk *n, *p = psks;

	while (p) {
		n = p->next;
		kfree(p->id.data);
		kfree(p->key.data);
		kfree(p->nonce.data);
		kfree(p);
		p = n;
	}
}

static struct tls_psk *tls_psk_new(struct tls_vec *id, struct tls_vec *key,
				   struct tls_vec *nonce, u32 age, u32 life)
{
	struct tls_psk *p;

	p = kzalloc(sizeof(*p), GFP_ATOMIC);
	if (!p)
		return NULL;
	if (tls_vec_cpy(&p->id, id))
		goto err;
	if (tls_vec_cpy(&p->key, key))
		goto err;
	if (tls_vec_cpy(&p->nonce, nonce))
		goto err;

	p->age_add  = age;
	p->lifetime = life;
	return p;
err:
	tls_psk_free(p);
	return NULL;
}

static int tls_hello_init(struct tls_hs *tls, struct tls_vec *x, struct tls_vec *y,
			  struct tls_vec *s)
{
	u8 compress = 0, random[32] = {0x1}, zeros[32] = {0};
	u16 cipher = htons(TLS_AES_128_GCM_SHA256);
	struct tls_vec z0_v, z32_v;
	int err;

	err = tls_crypto_hkdf_extract(tls->srt_tfm, tls_vec(&z0_v, zeros, 0),
				      tls_vec(&z32_v, zeros, 32),
				      &tls->srt[TLS_SE_EA]);
	if (err)
		return err;
	err = tls_crypto_ecdh_generate(tls->kpp_tfm, x, y);
	if (err)
		return err;
	pr_debug("[TLS_HS] hello init ecdh X: %32phN, Y: %32phN\n", x->data, y->data);

	memset(random, 0x1, 32);
	if (tls_vec_set(&tls->h.random, random, 32))
		return -ENOMEM;
	if (tls_vec_set(&tls->h.cipher, (u8 *)&cipher, 2))
		return -ENOMEM;
	if (tls_vec_cpy(&tls->h.session, s))
		return -ENOMEM;
	if (!tls->is_serv && tls_vec_set(&tls->h.compress, (u8 *)&compress, 1))
		return -ENOMEM;

	return 0;
}

static void tls_hello_free(struct tls_hello *h)
{
	kfree(h->random.data);
	kfree(h->session.data);
	kfree(h->cipher.data);
	kfree(h->compress.data);
	kfree(h->cookie.data);
}

static int tls_crtvfy_sign(struct tls_hs *tls, struct tls_vec *sig)
{
	u8 tlstbs[98 + 64], *p = tlstbs, *label, dig[32], h[32];
	struct crypto_shash *tfm = tls->hash_tfm;
	struct public_key_signature _s, *s = &_s;
	struct public_key _pkey, *pkey = &_pkey;
	struct tls_vec h_v, vec, dig_v;
	int err;

	tls_vec(&h_v, h, 32);
	if (tls->is_serv) {
		label = "TLS 1.3, server CertificateVerify";
		err = tls_crypto_hash(tfm, tls->buf, TLS_B_S_CRT + 1, &h_v); /* h6 */
		if (err)
			return err;
	} else {
		label = "TLS 1.3, client CertificateVerify";
		err = tls_crypto_hash(tfm, tls->buf, TLS_B_C_CRT + 1, &h_v); /* h8 */
		if (err)
			return err;
	}
	memset(pkey, 0, sizeof(_pkey));
	pkey->key = tls->pkey.data;
	pkey->keylen = tls->pkey.len;
	pkey->key_is_private = true;
	memset(p, 32, 64);
	memcpy(p + 64, label, strlen(label) + 1);
	memcpy(p + 98, h_v.data, 32);
	err = tls_crypto_hash(tfm, tls_vec(&vec, p, 130), 1,
			      tls_vec(&dig_v, dig, 32));
	if (err)
		return err;
	memset(s, 0, sizeof(_s));
	s->s = sig->data;
	s->s_size = sig->len;
	s->digest = dig_v.data;
	s->digest_size = dig_v.len;
	s->data = p;
	s->data_size = 130;
	s->encoding = "pss";
	s->pkey_algo = "rsa";
	s->hash_algo = "sha256";
	s->mgf = "mgf1";
	s->mgf_hash_algo = "sha256";
	s->salt_length = 32;
	s->trailer_field = 0xbc;

	return tls_crypto_signature_sign(tls->akc_tfm, pkey, s);
}

static int tls_crtvfy_verify(struct tls_hs *tls, struct tls_vec *sig)
{
	u8 tlstbs[98 + 64], *p = tlstbs, *label, dig[32], h[32];
	struct x509_certificate *x = tls->rcrts->x509;
	struct crypto_shash *tfm = tls->hash_tfm;
	struct public_key_signature _s, *s = &_s;
	struct tls_vec h_v, vec, dig_v;
	int err;

	tls_vec(&h_v, h, 32);
	if (tls->is_serv) {
		label = "TLS 1.3, client CertificateVerify";
		err = tls_crypto_hash(tfm, tls->buf, TLS_B_C_CRT + 1, &h_v); /* h8 */
		if (err)
			return err;
	} else {
		label = "TLS 1.3, server CertificateVerify";
		err = tls_crypto_hash(tfm, tls->buf, TLS_B_S_CRT + 1, &h_v); /* h6 */
		if (err)
			return err;
	}
	memset(p, 32, 64);
	memcpy(p + 64, label, strlen(label) + 1);
	memcpy(p + 98, h_v.data, 32);
	err = tls_crypto_hash(tfm, tls_vec(&vec, p, 130), 1,
			      tls_vec(&dig_v, dig, 32));
	if (err)
		return err;
	memset(s, 0, sizeof(_s));
	s->s = sig->data;
	s->s_size = sig->len;
	s->digest = dig_v.data;
	s->digest_size = dig_v.len;
	s->data = p;
	s->data_size = 130;
	s->encoding = "pss";
	s->pkey_algo = "rsa";
	s->hash_algo = "sha256";
	s->mgf = "mgf1";
	s->mgf_hash_algo = "sha256";
	s->salt_length = 32;
	s->trailer_field = 0xbc;

	err = tls_crypto_signature_verify(tls->akc_tfm, x->pub, s);
	pr_debug("[TLS_HS] crtvfy verified %d\n", err);
	return err;
}

static int tls_sf_generate(struct tls_hs *tls, struct tls_vec *sf)
{
	struct tls_vec fks_v, h_v, l_v = {"finished", 8};
	u8 fks[32], h[32], t;
	int err;

	t = tls->is_serv ? TLS_SE_THS : TLS_SE_RHS;
	err = tls_hkdf_expand(tls, &tls->srt[t], &l_v, tls_vec(&fks_v, fks, 32));
	if (err)
		return err;
	tls_vec(&h_v, h, 32);
	err = tls_crypto_hash(tls->hash_tfm, tls->buf, TLS_B_S_CRT_VFY + 1, &h_v); /* h7 */
	if (err)
		return err;

	return tls_crypto_hkdf_extract(tls->srt_tfm, &fks_v, &h_v, sf);
}

static int tls_cf_generate(struct tls_hs *tls, struct tls_vec *cf)
{
	struct tls_vec fks_v, h_v, l_v = {"finished", 8};
	u8 fks[32], h[32], t;
	int err;

	t = tls->is_serv ? TLS_SE_RHS : TLS_SE_THS;
	err = tls_hkdf_expand(tls, &tls->srt[t], &l_v, tls_vec(&fks_v, fks, 32));
	if (err)
		return err;
	tls_vec(&h_v, h, 32);
	err = tls_crypto_hash(tls->hash_tfm, tls->buf, TLS_B_C_CRT_VFY + 1, &h_v); /* h9 */
	if (err)
		return err;

	return tls_crypto_hkdf_extract(tls->srt_tfm, &fks_v, &h_v, cf);
}

static int tls_bin_generate(struct tls_hs *tls, struct tls_psk *p,
			    struct tls_vec *vec, struct tls_vec *bin)
{
	u8 psk[32], bk[32], fbk[32], zeros[32] = {0}, h[32];
	struct tls_vec psk_v, bk_v, fbk_v, z0_v, h_v;
	struct tls_vec fbk_l = {"finished", 8}, bk_l;
	struct crypto_shash *tfm = tls->srt_tfm;
	int err;

	psk_v = p->key;
	tls_vec(&bk_l, "ext binder", 10);
	if (p->lifetime) { /* this is a ticket */
		struct tls_vec psk_l = {"resumption", 10};

		err = tls_crypto_hkdf_expand(tfm, &p->key, &psk_l,
					     &p->nonce, tls_vec(&psk_v, psk, 32));
		if (err)
			return err;
		tls_vec(&bk_l, "res binder", 10);
	}
	err = tls_crypto_hkdf_extract(tfm, tls_vec(&z0_v, zeros, 0), &psk_v,
				      &tls->srt[TLS_SE_EA]);
	if (err)
		return err;
	err = tls_crypto_hash(tls->hash_tfm, NULL, 0, tls_vec(&h_v, h, 32));
	if (err)
		return err;
	err = tls_crypto_hkdf_expand(tfm, &tls->srt[TLS_SE_EA], &bk_l, &h_v,
				     tls_vec(&bk_v, bk, 32));
	if (err)
		return err;
	err = tls_hkdf_expand(tls, &bk_v, &fbk_l, tls_vec(&fbk_v, fbk, 32));
	if (err)
		return err;
	err = tls_crypto_hash(tls->hash_tfm, vec, 4, tls_vec(&h_v, h, 32)); /* h5 */
	if (err)
		return err;

	return tls_crypto_hkdf_extract(tfm, &fbk_v, &h_v, bin);
}

static int tls_msg_ch_build(struct tls_hs *tls)
{
	u8 *p, *len_p, *extlen_p, *psklen_p, *bin_p, bin[32], x[32], y[32];
	struct tls_vec bin_v, x_v, y_v, s = {NULL, 0};
	struct tls_vec vec[4] = {s, s, s};
	struct tls_psk *psk;
	int err, len;

	err = tls_hello_init(tls, tls_vec(&x_v, x, 32), tls_vec(&y_v, y, 32), &s);
	if (err)
		return err;
	p = tls->omsg.data;
	p = tls_put_num(p, TLS_MT_CLIENT_HELLO, 1);
	len_p = p;
	p += 3; /* set length later */
	p = tls_put_num(p, TLS_MSG_legacy_version, 2);
	p = tls_put_data(p, &tls->h.random);
	p = tls_put_num(p, tls->h.session.len, 1);
	p = tls_put_data(p, &tls->h.session);
	p = tls_put_num(p, tls->h.cipher.len, 2);
	p = tls_put_data(p, &tls->h.cipher);
	p = tls_put_num(p, tls->h.compress.len, 1);
	p = tls_put_data(p, &tls->h.compress);
	extlen_p = p;
	p += 2; /* set extension length later */

	p = tls_put_num(p, TLS_EXT_supported_groups, 2);
	p = tls_put_num(p, 4, 2);
	p = tls_put_num(p, 2, 2);
	p = tls_put_num(p, TLS_ECDHE_secp256r1, 2);

	p = tls_put_num(p, TLS_EXT_signature_algorithms, 2);
	p = tls_put_num(p, 4, 2);
	p = tls_put_num(p, 2, 2);
	p = tls_put_num(p, TLS_SAE_rsa_pss_rsae_sha256, 2);

	p = tls_put_num(p, TLS_EXT_supported_versions, 2);
	p = tls_put_num(p, 3, 2);
	p = tls_put_num(p, 2, 1);
	p = tls_put_num(p, TLS_MSG_version, 2);

	len = x_v.len + y_v.len;
	p = tls_put_num(p, TLS_EXT_key_share, 2);
	p = tls_put_num(p, len + 7, 2);
	p = tls_put_num(p, len + 5, 2);
	p = tls_put_num(p, TLS_ECDHE_secp256r1, 2);
	p = tls_put_num(p, len + 1, 2);
	p = tls_put_num(p, 4, 1);
	p = tls_put_data(p, &x_v);
	p = tls_put_data(p, &y_v);

	if (tls->ext.len)
		p = tls_put_data(p, &tls->ext);

	if (!tls->psks) {
		tls_put_num(len_p, (u32)(p - len_p) - 3, 3);
		tls_put_num(extlen_p, (u32)(p - extlen_p) - 2, 2);
		tls->omsg.len = (u32)(p - tls->omsg.data);

		if (tls_buf_set(&tls->buf[TLS_B_CH], &tls->omsg))
			return -ENOMEM;
		pr_debug("[TLS_HS] client hello crt len: %u\n", tls->omsg.len);
		return 0;
	}

	if (tls->early) {
		p = tls_put_num(p, TLS_EXT_early_data, 2);
		p = tls_put_num(p, 0, 2);
	}

	p = tls_put_num(p, TLS_EXT_psk_kex_modes, 2);
	p = tls_put_num(p, 2, 2);
	p = tls_put_num(p, 1, 1);
	p = tls_put_num(p, TLS_PSK_dhe_ke, 1);

	p = tls_put_num(p, TLS_EXT_psk, 2);
	psklen_p = p;
	p += 2;
	psk = tls->psks; /* use the 1st one */
	p = tls_put_num(p, 2 + psk->id.len + 4, 2);
	p = tls_put_num(p, psk->id.len, 2);
	p = tls_put_data(p, &psk->id);
	p = tls_put_num(p, 0, 4);
	p = tls_put_num(p, 33, 2);
	p = tls_put_num(p, 32, 1);
	bin_p = p;
	p += 32; /* set up bin later */
	tls_put_num(psklen_p, (u32)(p - psklen_p) - 2, 2);
	tls_put_num(len_p, (u32)(p - len_p) - 3, 3);
	tls_put_num(extlen_p, (u32)(p - extlen_p) - 2, 2);

	tls_vec(&vec[3], tls->omsg.data, (u32)(bin_p - 3 - tls->omsg.data));
	tls_vec(&bin_v, bin, 32);
	err = tls_bin_generate(tls, psk, vec, &bin_v);
	if (err)
		return err;
	tls_put_data(bin_p, &bin_v);
	tls->omsg.len = (u32)(p - tls->omsg.data);

	if (tls_buf_set(&tls->buf[TLS_B_CH], &tls->omsg))
		return -ENOMEM;

	err = tls_keys_ea_setup(tls);
	if (err)
		return err;
	pr_debug("[TLS_HS] client hello len: %u\n", tls->omsg.len);
	return 0;
}

static int tls_msg_sh_build(struct tls_hs *tls, struct tls_vec *x, struct tls_vec *y, u8 req)
{
	u8 *p, *len_p, *extlen_p, t, hrr_random[] = {
		0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02,
		0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
		0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c
	};
	struct tls_vec hrr;
	u32 len;

	p = tls->omsg.data;
	p = tls_put_num(p, TLS_MT_SERVER_HELLO, 1);
	len_p = p;
	p += 3; /* set length later */
	p = tls_put_num(p, TLS_MSG_legacy_version, 2);
	p = tls_put_data(p, req ? tls_vec(&hrr, hrr_random, 32) : &tls->h.random);
	p = tls_put_num(p, tls->h.session.len, 1);
	p = tls_put_data(p, &tls->h.session);
	p = tls_put_data(p, &tls->h.cipher);
	p = tls_put_num(p, tls->h.compress.len, 1);
	extlen_p = p;
	p += 2; /* set extension length later */

	p = tls_put_num(p, TLS_EXT_supported_versions, 2);
	p = tls_put_num(p, 2, 2);
	p = tls_put_num(p, TLS_MSG_version, 2);

	if (req) {
		if (tls->h.cookie.len) {
			p = tls_put_num(p, TLS_EXT_cookie, 2);
			p = tls_put_num(p, tls->h.cookie.len, 2);
			p = tls_put_data(p, &tls->h.cookie);
		}
		p = tls_put_num(p, TLS_EXT_key_share, 2);
		p = tls_put_num(p, 2, 2);
		p = tls_put_num(p, TLS_ECDHE_secp256r1, 2);
		t = TLS_B_HRR;
	} else {
		len = x->len + y->len;
		p = tls_put_num(p, TLS_EXT_key_share, 2);
		p = tls_put_num(p, len + 5, 2);
		p = tls_put_num(p, TLS_ECDHE_secp256r1, 2);
		p = tls_put_num(p, len + 1, 2);
		p = tls_put_num(p, 4, 1);
		p = tls_put_data(p, x);
		p = tls_put_data(p, y);
		if (tls->psks) {
			p = tls_put_num(p, TLS_EXT_psk, 2);
			p = tls_put_num(p, 2, 2);
			p = tls_put_num(p, 0, 2);
		}
		t = TLS_B_SH;
	}

	tls_put_num(len_p, (u32)(p - len_p) - 3, 3);
	tls_put_num(extlen_p, (u32)(p - extlen_p) - 2, 2);
	tls->omsg.len = (u32)(p - tls->omsg.data);

	if (tls_buf_set(&tls->buf[t], &tls->omsg))
		return -ENOMEM;

	pr_debug("[TLS_HS] server hello len: %u\n", tls->omsg.len);
	return 0;
}

static int tls_msg_hs_build(struct tls_hs *tls)
{
	u8 *p = tls->omsg.data, *len_p, *extlen_p, *crtlen_p, sf[32];
	struct tls_vec msg, sf_v, sig = {NULL, 0};
	struct tls_crt *c;
	int err;

	msg.data = p;
	p = tls_put_num(p, TLS_MT_ENCRYPTED_EXTENSIONS, 1);
	len_p = p;
	p += 3;
	extlen_p = p;
	p += 2;

	p = tls_put_num(p, TLS_EXT_supported_groups, 2);
	p = tls_put_num(p, 4, 2);
	p = tls_put_num(p, 2, 2);
	p = tls_put_num(p, TLS_ECDHE_secp256r1, 2);

	if (tls->early) {
		p = tls_put_num(p, TLS_EXT_early_data, 2);
		p = tls_put_num(p, 0, 2);
	}

	if (tls->ext.len)
		p = tls_put_data(p, &tls->ext);

	tls_put_num(len_p, (u32)(p - len_p) - 3, 3);
	tls_put_num(extlen_p, (u32)(p - extlen_p) - 2, 2);
	msg.len = (u32)(p - msg.data);
	if (tls_buf_set(&tls->buf[TLS_B_EE], &msg))
		return -ENOMEM;

	if (tls->psks)
		goto fin;

	if (tls->crt_req) {
		msg.data = p;
		p = tls_put_num(p, TLS_MT_CERTIFICATE_REQUEST, 1);
		p = tls_put_num(p, 11, 3);
		p = tls_put_num(p, 0, 1);
		p = tls_put_num(p, 8, 2);

		p = tls_put_num(p, TLS_EXT_signature_algorithms, 2);
		p = tls_put_num(p, 4, 2);
		p = tls_put_num(p, 2, 2);
		p = tls_put_num(p, TLS_SAE_rsa_pss_rsae_sha256, 2);

		msg.len = (u32)(p - msg.data);
		if (tls_buf_set(&tls->buf[TLS_B_CRT_REQ], &msg))
			return -ENOMEM;
	}

	msg.data = p;
	p = tls_put_num(p, TLS_MT_CERTIFICATE, 1);
	len_p = p;
	p += 3;
	p = tls_put_num(p, 0, 1);
	crtlen_p = p;
	p += 3;
	for (c = tls->tcrts; c; c = c->next) {
		p = tls_put_num(p, c->raw.len, 3);
		p = tls_put_data(p, &c->raw);
		p = tls_put_num(p, 0, 2);
	}
	tls_put_num(len_p, (u32)(p - len_p) - 3, 3);
	tls_put_num(crtlen_p, (u32)(p - crtlen_p) - 3, 3);
	msg.len = (u32)(p - msg.data);
	if (tls_buf_set(&tls->buf[TLS_B_S_CRT], &msg))
		return -ENOMEM;

	err = tls_vec_new(&sig, 256);
	if (err)
		return err;
	err = tls_crtvfy_sign(tls, &sig);
	if (err)
		goto err;
	msg.data = p;
	p = tls_put_num(p, TLS_MT_CERTIFICATE_VERIFY, 1);
	p = tls_put_num(p, 4 + sig.len, 3);
	p = tls_put_num(p, TLS_SAE_rsa_pss_rsae_sha256, 2);
	p = tls_put_num(p, sig.len, 2);
	p = tls_put_data(p, &sig);
	msg.len = (u32)(p - msg.data);
	err = tls_buf_set(&tls->buf[TLS_B_S_CRT_VFY], &msg);
	if (err)
		goto err;
fin:
	err = tls_sf_generate(tls, tls_vec(&sf_v, sf, 32));
	if (err)
		goto err;
	msg.data = p;
	p = tls_put_num(p, TLS_MT_FINISHED, 1);
	p = tls_put_num(p, 32, 3);
	p = tls_put_data(p, &sf_v);
	msg.len = (u32)(p - msg.data);
	err = tls_buf_set(&tls->buf[TLS_B_S_FIN], &msg);
	if (err)
		goto err;

	err = tls_keys_ap_setup(tls);
	if (err)
		return err;

	tls->omsg.len = (u32)(p - tls->omsg.data);
	tls->state = TLS_ST_WAIT;
	pr_debug("[TLS_HS] server finish len: %u\n", tls->omsg.len);
err:
	kfree(sig.data);
	return err;
}

static int tls_msg_cfin_build(struct tls_hs *tls)
{
	u8 *p = tls->omsg.data, *len_p, *crtlen_p, cf[32];
	struct tls_vec msg, cf_v, sig = {NULL, 0};
	struct tls_crt *c;
	int err;

	if (!tls->crt_req)
		goto fin;

	if (!tls->tcrts)
		return -EINVAL;

	msg.data = p;
	p = tls_put_num(p, TLS_MT_CERTIFICATE, 1);
	len_p = p;
	p += 3;
	p = tls_put_num(p, 0, 1);
	crtlen_p = p;
	p += 3;
	for (c = tls->tcrts; c; c = c->next) {
		p = tls_put_num(p, c->raw.len, 3);
		p = tls_put_data(p, &c->raw);
		p = tls_put_num(p, 0, 2);
	}
	tls_put_num(len_p, (u32)(p - len_p) - 3, 3);
	tls_put_num(crtlen_p, (u32)(p - crtlen_p) - 3, 3);
	msg.len = (u32)(p - msg.data);
	if (tls_buf_set(&tls->buf[TLS_B_C_CRT], &msg))
		return -ENOMEM;

	err = tls_vec_new(&sig, 256);
	if (err)
		return err;
	err = tls_crtvfy_sign(tls, &sig);
	if (err)
		goto err;
	msg.data = p;
	p = tls_put_num(p, TLS_MT_CERTIFICATE_VERIFY, 1);
	p = tls_put_num(p, 4 + sig.len, 3);
	p = tls_put_num(p, TLS_SAE_rsa_pss_rsae_sha256, 2);
	p = tls_put_num(p, sig.len, 2);
	p = tls_put_data(p, &sig);
	msg.len = (u32)(p - msg.data);
	err = tls_buf_set(&tls->buf[TLS_B_C_CRT_VFY], &msg);
	if (err)
		goto err;
fin:
	err = tls_cf_generate(tls, tls_vec(&cf_v, cf, 32));
	if (err)
		goto err;

	p = tls_put_num(p, TLS_MT_FINISHED, 1);
	p = tls_put_num(p, 32, 3);
	p = tls_put_data(p, &cf_v);
	tls->omsg.len = (u32)(p - tls->omsg.data);
	err = tls_buf_set(&tls->buf[TLS_B_C_FIN], &tls->omsg);
	if (err)
		goto err;

	err = tls_keys_ap_setup(tls);
	if (err)
		goto err;

	err = tls_keys_rm_setup(tls);
	if (err)
		goto err;
	tls->state = TLS_ST_CONNECTED;
	pr_debug("[TLS_HS] client finish len: %u\n", tls->omsg.len);
	return 0;
err:
	kfree(sig.data);
	return err;
}

static int tls_msg_ticket_build(struct tls_hs *tls, struct tls_vec *id)
{
	struct tls_vec nonce;
	struct tls_psk *psk;
	u8 *p, *len_p, n[8];

	psk = tls_psk_new(id, &tls->srt[TLS_SE_RMS], tls_vec(&nonce, n, 8), 0, 5000);
	if (!psk)
		return -ENOMEM;
	if (tls->psks)
		psk->next = tls->psks;
	tls->psks = psk;

	p = tls->omsg.data;
	p = tls_put_num(p, TLS_MT_NEWSESSION_TICKET, 1);
	len_p = p;
	p += 3;
	p = tls_put_num(p, psk->lifetime, 4);
	p = tls_put_num(p, psk->age_add, 4);
	p = tls_put_num(p, psk->nonce.len, 1);
	p = tls_put_data(p, &psk->nonce);
	p = tls_put_num(p, psk->id.len, 2);
	p = tls_put_data(p, &psk->id);
	p = tls_put_num(p, 8, 2);

	p = tls_put_num(p, TLS_EXT_early_data, 2);
	p = tls_put_num(p, 4, 2);
	p = tls_put_num(p, 0xffffffff, 4);
	tls_put_num(len_p, (u32)(p - len_p) - 3, 3);
	tls->omsg.len = (u32)(p - tls->omsg.data);

	pr_debug("[TLS_HS] new session ticket len: %u\n", tls->omsg.len);
	return 0;
}

static int tls_msg_ku_build(struct tls_hs *tls, struct tls_vec *l, u8 req)
{
	struct tls_vec l_v = {"traffic upd", 11}, srt = {NULL, 0};
	int err;
	u8 *p;

	if (!l)
		l = &l_v;
	if (tls_vec_cpy(&srt, &tls->srt[TLS_SE_TAP]))
		return -ENOMEM;
	err = tls_hkdf_expand(tls, &srt, l, &tls->srt[TLS_SE_TAP]);
	if (err)
		return err;
	if (tls_vec_cpy(&srt, &tls->srt[TLS_SE_RAP]))
		return -ENOMEM;
	err = tls_hkdf_expand(tls, &srt, l, &tls->srt[TLS_SE_RAP]);
	if (err)
		return err;

	p = tls->omsg.data;
	p = tls_put_num(p, TLS_MT_KEY_UPDATE, 1);
	p = tls_put_num(p, 1, 3);
	p = tls_put_num(p, req, 1);
	tls->omsg.len = (u32)(p - tls->omsg.data);

	pr_debug("[TLS_HS] key update len: %u\n", tls->omsg.len);
	return 0;
}

static int tls_ext_supported_groups_handle(struct tls_hs *tls, u8 mt, struct tls_vec *e)
{
	u32 n;

	if (mt != TLS_MT_CLIENT_HELLO && mt != TLS_MT_ENCRYPTED_EXTENSIONS)
		return -EINVAL;

	while (e->len > 0) {
		if (tls_get_num(e, 2, &n))
			return -EINVAL;
		pr_debug("[TLS_HS] ext supported groups %x\n", n);
		if (n == TLS_ECDHE_secp256r1)
			return 0;
	}

	return -ENOENT;
}

static int tls_ext_key_share_handle(struct tls_hs *tls, u8 mt, struct tls_vec *e)
{
	struct tls_vec x, y, s;
	u32 n;

	if (mt != TLS_MT_CLIENT_HELLO && mt != TLS_MT_SERVER_HELLO)
		return -EINVAL;

	if (tls->is_serv) {
		if (tls_get_num(e, 2, &n))
			return -EINVAL;
		while (e->len > 0) {
			if (tls_get_num(e, 2, &n))
				return -EINVAL;
			pr_debug("[TLS_HS] ext group %x\n", n);
			if (n == TLS_ECDHE_secp256r1)
				break;
			if (tls_get_sub(e, 2, &s))
				return -EINVAL;
		}
		if ((int)e->len <= 0)
			return -EAGAIN;
	} else {
		if (tls_get_num(e, 2, &n))
			return -EINVAL;
		if (n != TLS_ECDHE_secp256r1)
			return -ENOENT;
	}
	if (tls_get_num(e, 2, &n) || tls_get_num(e, 1, &n) ||
	    tls_get_data(e, 32, &x) || tls_get_data(e, 32, &y))
		return -EINVAL;

	return tls_crypto_ecdh_compute(tls->kpp_tfm, &tls->srt[TLS_SE_DHE], &x, &y);
}

static int tls_ext_supported_versions_handle(struct tls_hs *tls, u8 mt, struct tls_vec *e)
{
	struct tls_vec s = *e;
	u32 n;

	if (mt != TLS_MT_CLIENT_HELLO && mt != TLS_MT_SERVER_HELLO)
		return -EINVAL;

	if (tls->is_serv)
		if (tls_get_sub(e, 1, &s))
			return -EINVAL;
	while (s.len > 0) {
		if (tls_get_num(&s, 2, &n))
			return -EINVAL;
		pr_debug("[TLS_HS] ext supported versions %x\n", n);
		if (n == TLS_MSG_version)
			return 0;
	}

	return -ENOENT;
}

static int tls_ext_psk_handle(struct tls_hs *tls, u8 mt, struct tls_vec *e)
{
	struct tls_vec pskid, b = {NULL, 0}, bin_v;
	struct tls_vec vec[4] = {b, b, b};
	int err, age_add, len;
	struct tls_psk *psk;
	u8 bin[32];

	if (mt != TLS_MT_CLIENT_HELLO && mt != TLS_MT_SERVER_HELLO)
		return -EINVAL;

	if (!tls->is_serv) {
		if (tls_get_sub(e, 2, &pskid))
			return -EINVAL;
		pr_debug("[TLS_HS] ext psk %u\n", pskid.len);
		return 0;
	}
	if (tls_get_num(e, 2, &len) || tls_get_sub(e, 2, &pskid) || tls_get_num(e, 4, &age_add))
		return -EINVAL;
	for (psk = tls->psks; psk; psk = psk->next)
		if (!tls_vec_cmp(&psk->id, &pskid))
			break;
	if (!psk)
		return -EINVAL;
	if (tls->buf[TLS_B_HRR].len) {
		vec[0] = tls->buf[TLS_B_MH];
		vec[1] = tls->buf[TLS_B_CH];
		vec[2] = tls->buf[TLS_B_HRR];
	}
	tls_vec(&vec[3], tls->imsg.data, (u32)(e->data - tls->imsg.data));
	if (tls_get_num(e, 2, &len) || tls_get_sub(e, 1, &b))
		return -EINVAL;
	err = tls_bin_generate(tls, psk, vec, tls_vec(&bin_v, bin, 32));
	if (err)
		return err;
	if (tls_vec_cmp(&b, &bin_v))
		return -EINVAL;

	return tls_keys_ea_setup(tls);
}

static int tls_ext_early_data_handle(struct tls_hs *tls, u8 mt, struct tls_vec *e)
{
	u32 len;

	if (mt != TLS_MT_CLIENT_HELLO && mt != TLS_MT_ENCRYPTED_EXTENSIONS &&
	    mt != TLS_MT_NEWSESSION_TICKET)
		return -EINVAL;

	tls->early = 1;
	if (mt != TLS_MT_NEWSESSION_TICKET)
		return 0;
	if (tls_get_num(e, 4, &len))
		return -EINVAL;
	pr_debug("[TLS_HS] ext max_early_data_size %u\n", len);

	return 0;
}

static int tls_ext_skip_handle(struct tls_hs *tls, u8 mt, struct tls_vec *e)
{
	return 0;
}

static int tls_ext_signature_algorithms_handle(struct tls_hs *tls, u8 mt, struct tls_vec *e)
{
	struct tls_vec s;
	u32 n;

	if (mt != TLS_MT_CLIENT_HELLO && mt != TLS_MT_CERTIFICATE_REQUEST)
		return -EINVAL;

	if (tls_get_sub(e, 2, &s))
		return -EINVAL;
	while (s.len > 0) {
		if (tls_get_num(&s, 2, &n))
			return -EINVAL;
		pr_debug("[TLS_HS] ext signature_algorithms %x", n);
		if (n == TLS_SAE_rsa_pss_rsae_sha256)
			return 0;
	}

	return -ENOENT;
}

static int tls_ext_psk_kex_modes_handle(struct tls_hs *tls, u8 mt, struct tls_vec *e)
{
	struct tls_vec s;
	u32 n;

	if (mt != TLS_MT_CLIENT_HELLO)
		return -EINVAL;

	if (tls_get_sub(e, 1, &s))
		return -EINVAL;
	while (s.len > 0) {
		if (tls_get_num(&s, 1, &n))
			return -EINVAL;
		pr_debug("[TLS_HS] ext psk_kex_modes %x", n);
		if (n == TLS_PSK_dhe_ke)
			return 0;
	}

	return -ENOENT;
}

static int tls_ext_cookie(struct tls_hs *tls, u8 mt, struct tls_vec *e)
{
	if (mt != TLS_MT_CLIENT_HELLO)
		return -EINVAL;

	return tls_vec_cpy(&tls->h.cookie, e);
}

static int tls_ext_default_handle(struct tls_hs *tls, u8 mt, struct tls_vec *e)
{
	if (e->len + 4 > PAGE_SIZE)
		return -ENOMEM;
	return tls_vec_set(&tls->ext, e->data - 4, e->len + 4);
}

static int tls_ext_handle(struct tls_hs *tls, struct tls_vec *ext, u8 mt, u64 *exts)
{
	struct tls_vec e;
	int ret, type;

	while ((int)ext->len > 0) {
		if (tls_get_num(ext, 2, &type) || tls_get_sub(ext, 2, &e))
			return -EINVAL;
		pr_debug("[TLS_HS] ext handle type %d len %d\n", type, e.len);
		switch (type) {
		case TLS_EXT_supported_groups:
			ret = tls_ext_supported_groups_handle(tls, mt, &e);
			break;
		case TLS_EXT_supported_versions:
			ret = tls_ext_supported_versions_handle(tls, mt, &e);
			break;
		case TLS_EXT_signature_algs_cert:
		case TLS_EXT_signature_algorithms:
			ret = tls_ext_signature_algorithms_handle(tls, mt, &e);
			break;
		case TLS_EXT_psk_kex_modes:
			ret = tls_ext_psk_kex_modes_handle(tls, mt, &e);
			break;
		case TLS_EXT_psk:
			ret = tls_ext_psk_handle(tls, mt, &e);
			break;
		case TLS_EXT_early_data:
			ret = tls_ext_early_data_handle(tls, mt, &e);
			break;
		case TLS_EXT_key_share:
			ret = tls_ext_key_share_handle(tls, mt, &e);
			break;
		case TLS_EXT_cookie:
			ret = tls_ext_cookie(tls, mt, &e);
			break;
		case TLS_EXT_padding:
		case TLS_EXT_heartbeat:
		case TLS_EXT_server_name:
		case TLS_EXT_alpn:
		case TLS_EXT_signed_cert_timestamp:
		case TLS_EXT_ec_point_formats:
		case TLS_EXT_encrypt_then_mac:
		case TLS_EXT_extended_master_srt:
		case TLS_EXT_session_ticket:
		case TLS_EXT_certificate_authorities:
			ret = tls_ext_skip_handle(tls, mt, &e);
			break;
		default:
			ret = tls_ext_default_handle(tls, mt, &e);
			break;
		}
		if (ret) {
			if (ret == -EAGAIN)
				(*exts) |= ((u64)1 << type);
			pr_err("[TLS_HS] ext handle err %d\n", ret);
			return ret;
		}
		(*exts) |= ((u64)1 << type);
	}

	return 0;
}

static int tls_msg_ch_handle(struct tls_hs *tls, struct tls_vec *m)
{
	struct tls_vec x_v, y_v, s, ss, msg = {m->data - 4, m->len + 4};
	u8 mh[4] = {0xfe, 0x0, 0x0, 0x20}, h[32];
	u8 x[32], y[32], req = 0;
	u64 exts = 0;
	int err;
	u32 n;

	if (!tls->is_serv || tls->state != TLS_ST_START)
		return -EINVAL;

	if (tls_get_num(m, 2, &n) || tls_get_data(m, 32, &s) ||
	    tls_get_sub(m, 1, &ss) || tls_get_sub(m, 2, &s))
		return -EINVAL;
	while (s.len > 0) {
		if (tls_get_num(&s, 2, &n))
			return -EINVAL;
		pr_debug("[TLS_HS] msg ch cipher %x\n", n);
		if (n == TLS_AES_128_GCM_SHA256)
			break;
	}
	if (n != TLS_AES_128_GCM_SHA256)
		return -ENOENT;
	if (tls_get_sub(m, 1, &s))
		return -EINVAL;
	err = tls_hello_init(tls, tls_vec(&x_v, x, 32), tls_vec(&y_v, y, 32), &ss);
	if (err)
		return err;
	if (tls_get_sub(m, 2, &s) || !s.len)
		return -EINVAL;
	if (tls->buf[TLS_B_CH].len) {
		err = tls_crypto_hash(tls->hash_tfm, tls->buf, TLS_B_CH + 1, tls_vec(&ss, h, 32));
		if (err)
			return err;
		if (tls_buf_set(&tls->buf[TLS_B_CH], &ss) ||
		    tls_buf_set(&tls->buf[TLS_B_NEG], &msg) ||
		    tls_buf_set(&tls->buf[TLS_B_MH], tls_vec(&ss, mh, 4)))
			return -ENOMEM;
	} else {
		if (tls_buf_set(&tls->buf[TLS_B_CH], &msg))
			return -ENOMEM;
	}
	err = tls_ext_handle(tls, &s, TLS_MT_CLIENT_HELLO, &exts);
	if (err) {
		if (err != -EAGAIN)
			return err;
		req = 1;
	}
	if (!(exts & ((u64)1 << TLS_EXT_key_share)) ||
	    (!req && tls->psks && !(exts & ((u64)1 << TLS_EXT_psk))))
		return -EINVAL;
	err = tls_msg_sh_build(tls, &x_v, &y_v, req);
	if (req || err)
		return err;
	err = tls_keys_hs_setup(tls);
	if (err)
		return err;

	tls->state = TLS_ST_RCVD;
	return 0;
}

static int tls_msg_sh_handle(struct tls_hs *tls, struct tls_vec *m)
{
	struct tls_vec s, msg = {m->data - 4, m->len + 4};
	u64 exts = 0;
	int err;
	u32 n;

	if (tls->is_serv || tls->state != TLS_ST_START)
		return -EINVAL;

	if (tls_get_num(m, 2, &n) || tls_get_data(m, 32, &s) ||
	    tls_get_sub(m, 1, &s) || tls_get_num(m, 2, &n))
		return -EINVAL;
	if (n != TLS_AES_128_GCM_SHA256)
		return -ENOENT;
	if (tls_get_sub(m, 1, &s) || tls_get_sub(m, 2, &s) || !s.len)
		return -EINVAL;
	if (tls_buf_set(&tls->buf[TLS_B_SH], &msg))
		return -ENOMEM;
	err = tls_ext_handle(tls, &s, TLS_MT_SERVER_HELLO, &exts);
	if (err)
		return err;
	if (!(exts & ((u64)1 << TLS_EXT_key_share)) ||
	    (tls->psks && !(exts & ((u64)1 << TLS_EXT_psk))))
		return -EINVAL;
	err = tls_keys_hs_setup(tls);
	if (err)
		return err;

	tls->state = TLS_ST_RCVD;
	return 0;
}

static int tls_msg_ee_handle(struct tls_hs *tls, struct tls_vec *m)
{
	struct tls_vec s, msg = {m->data - 4, m->len + 4};
	u64 exts = 0;
	int err;

	if (tls->is_serv || tls->state != TLS_ST_RCVD)
		return -EINVAL;

	if (tls_get_sub(m, 2, &s) || !s.len)
		return -EINVAL;
	if (tls_buf_set(&tls->buf[TLS_B_EE], &msg))
		return -ENOMEM;
	err = tls_ext_handle(tls, &s, TLS_MT_ENCRYPTED_EXTENSIONS, &exts);
	if (err)
		return err;

	tls->state = TLS_ST_WAIT;
	return 0;
}

static int tls_msg_crt_handle(struct tls_hs *tls, struct tls_vec *m)
{
	struct tls_vec v, s, msg = {m->data - 4, m->len + 4};
	struct tls_crt *c, *crts = NULL, *prev;
	u32 len, t;
	int err;

	if (tls->state != TLS_ST_WAIT || tls->psks)
		return -EINVAL;

	if (tls_get_num(m, 1, &t) || tls_get_sub(m, 3, &s))
		return -EINVAL;
	pr_debug("[TLS_HS] crt total len %u\n", s.len);
	while (1) {
		if (tls_get_sub(&s, 3, &v))
			return -EINVAL;
		pr_debug("[TLS_HS] crt one len %u\n", len);
		c = tls_crt_new(&v);
		if (!c) {
			tls_crt_free(crts);
			return -ENOMEM;
		}
		if (!crts)
			crts = c;
		else
			prev->next = c;
		prev = c;
		if (tls_get_sub(&s, 2, &v))
			return -EINVAL;

		if ((int)s.len <= 0)
			break;
	}
	err = tls_crypto_crt_verify(tls, crts);
	if (err) {
		tls_crt_free(crts);
		return err;
	}

	tls->rcrts = crts;
	t = tls->is_serv ? TLS_B_C_CRT : TLS_B_S_CRT;
	return tls_buf_set(&tls->buf[t], &msg);
}

static int tls_msg_crtvfy_handle(struct tls_hs *tls, struct tls_vec *m)
{
	struct tls_vec sig, msg = {m->data - 4, m->len + 4};
	u32 n, t;
	int err;

	if (tls->state != TLS_ST_WAIT || !tls->rcrts)
		return -EINVAL;

	if (tls_get_num(m, 2, &n) || tls_get_sub(m, 2, &sig))
		return -EINVAL;
	err = tls_crtvfy_verify(tls, &sig);
	if (err)
		return err;

	t = tls->is_serv ? TLS_B_C_CRT_VFY : TLS_B_S_CRT_VFY;
	return tls_buf_set(&tls->buf[t], &msg);
}

static int tls_msg_crtreq_handle(struct tls_hs *tls, struct tls_vec *m)
{
	struct tls_vec s, msg = {m->data - 4, m->len + 4};
	u64 exts = 0;
	int err;

	if (tls->state != TLS_ST_WAIT || tls->psks)
		return -EINVAL;

	if (tls_get_sub(m, 1, &s) || tls_get_sub(m, 2, &s))
		return -EINVAL;
	tls->crt_req = 1;
	if (tls_buf_set(&tls->buf[TLS_B_CRT_REQ], &msg))
		return -ENOMEM;
	err = tls_ext_handle(tls, &s, TLS_MT_CERTIFICATE_REQUEST, &exts);
	if (err)
		return err;

	return 0;
}

static int tls_msg_sfin_handle(struct tls_hs *tls, struct tls_vec *m)
{
	struct tls_vec sf_v, msg = {m->data - 4, m->len + 4};
	u8 sf[32];
	int err;

	if (tls->state != TLS_ST_WAIT ||
	    (!tls->psks && !tls->buf[TLS_B_S_CRT_VFY].len))
		return -EINVAL;

	err = tls_sf_generate(tls, tls_vec(&sf_v, sf, 32));
	if (err)
		return err;
	if (tls_vec_cmp(&sf_v, m))
		return -EINVAL;
	if (tls_buf_set(&tls->buf[TLS_B_S_FIN], &msg))
		return -ENOMEM;

	return tls_msg_cfin_build(tls);
}

static int tls_msg_cfin_handle(struct tls_hs *tls, struct tls_vec *m)
{
	struct tls_vec cf_v, msg = {m->data - 4, m->len + 4};
	u8 cf[32];
	int err;

	if (tls->state != TLS_ST_WAIT ||
	    (tls->crt_req && !tls->buf[TLS_B_C_CRT_VFY].len))
		return -EINVAL;

	err = tls_cf_generate(tls, tls_vec(&cf_v, cf, 32));
	if (err)
		return err;
	if (tls_vec_cmp(&cf_v, m))
		return -EINVAL;
	if (tls_buf_set(&tls->buf[TLS_B_C_FIN], &msg))
		return -ENOMEM;
	err = tls_keys_rm_setup(tls);
	if (err)
		return err;

	tls->state = TLS_ST_CONNECTED;
	return 0;
}

static int tls_msg_fin_handle(struct tls_hs *tls, struct tls_vec *m)
{
	if (!tls->is_serv)
		return tls_msg_sfin_handle(tls, m);

	return tls_msg_cfin_handle(tls, m);
}

static int tls_msg_ticket_handle(struct tls_hs *tls, struct tls_vec *m)
{
	struct tls_vec id, nonce, s;
	u32 lifetime, age_add, len;
	struct tls_psk *psk;
	u64 exts = 0;
	int err;

	if (tls->state != TLS_ST_CONNECTED)
		return -EINVAL;

	if (tls_get_num(m, 4, &lifetime) || tls_get_num(m, 4, &age_add))
		return -EINVAL;
	pr_debug("[TLS_HS] new session %u %u\n", age_add, lifetime);

	if (tls_get_sub(m, 1, &nonce))
		return -EINVAL;

	if (tls_get_sub(m, 2, &id))
		return -EINVAL;

	psk = tls_psk_new(&id, &tls->srt[TLS_SE_RMS], &nonce, age_add, lifetime);
	if (!psk)
		return -ENOMEM;

	if (tls->psks)
		psk->next = tls->psks;
	tls->psks = psk;

	if (tls_get_sub(m, 2, &s))
		return -EINVAL;
	if (!len)
		return TLS_P_TICKET;
	err = tls_ext_handle(tls, &s, TLS_MT_NEWSESSION_TICKET, &exts);
	if (err)
		return err;

	return TLS_P_TICKET;
}

static int tls_msg_ku_handle(struct tls_hs *tls, struct tls_vec *m)
{
	int err;
	u32 req;

	if (tls->state != TLS_ST_CONNECTED)
		return -EINVAL;

	if (tls_get_num(m, 1, &req))
		return -EINVAL;
	if (req) {
		err = tls_msg_ku_build(tls, NULL, 0);
		if (err)
			return err;
	}

	return TLS_P_KEY_UPDATE;
}

static int tls_msg_handle(struct tls_hs *tls, struct tls_vec *imsg)
{
	int ret = 0, len, type;
	struct tls_vec m;

	if (tls->cmsg.len) {
		pr_debug("[TLS_HS] msg handle recovered %d %d\n", tls->cmsg.len, imsg->len);
		*imsg = *tls_vec_add(&tls->cmsg, imsg);
	}

	tls->imsg = *imsg;
	while (1) {
		m = *imsg;
		if (tls_get_num(imsg, 1, &type) || tls_get_sub(imsg, 3, &m)) {
			pr_debug("[TLS_HS] msg handle buffered with no hdr %d\n", imsg->len);
			tls_vec_cpy(&tls->cmsg, &m);
			break;
		}
		pr_debug("[TLS_HS] msg handle type %d len %d\n", type, len);
		switch (type) {
		case TLS_MT_CLIENT_HELLO:
			ret = tls_msg_ch_handle(tls, &m);
			break;
		case TLS_MT_SERVER_HELLO:
			ret = tls_msg_sh_handle(tls, &m);
			break;
		case TLS_MT_ENCRYPTED_EXTENSIONS:
			ret = tls_msg_ee_handle(tls, &m);
			break;
		case TLS_MT_CERTIFICATE_REQUEST:
			ret = tls_msg_crtreq_handle(tls, &m);
			break;
		case TLS_MT_CERTIFICATE:
			ret = tls_msg_crt_handle(tls, &m);
			break;
		case TLS_MT_CERTIFICATE_VERIFY:
			ret = tls_msg_crtvfy_handle(tls, &m);
			break;
		case TLS_MT_FINISHED:
			ret = tls_msg_fin_handle(tls, &m);
			break;
		case TLS_MT_NEWSESSION_TICKET:
			ret = tls_msg_ticket_handle(tls, &m);
			break;
		case TLS_MT_KEY_UPDATE:
			ret = tls_msg_ku_handle(tls, &m);
			break;
		default:
			ret = EPROTONOSUPPORT;
			break;
		}
		if (ret < 0) {
			pr_err("[TLS_HS] msg handle err %d\n", ret);
			break;
		}
		if ((int)imsg->len <= 0) {
			tls->cmsg.len = 0;
			break;
		}
	}

	return ret ?: tls->state;
}

static int tls_set_psk(struct tls_hs *tls, struct tls_vec *vec)
{
	struct tls_psk *p, *psk, *psks = NULL;
	struct tls_vec id, key, nonce;
	int err = 0, len = vec->len;
	u32 dlen, age_add, lifetime;
	u8 *data = vec->data;

	while (len > 0) {
		dlen = *((u32 *)data);
		data += 4;
		tls_vec(&id, data, dlen);
		data += dlen;

		dlen = *((u32 *)data);
		data += 4;
		tls_vec(&key, data, dlen);
		data += dlen;

		dlen = *((u32 *)data);
		data += 4;
		tls_vec(&nonce, data, dlen);
		data += dlen;

		age_add = *((u32 *)data);
		data += 4;
		lifetime = *((u32 *)data);
		data += 4;

		psk = tls_psk_new(&id, &key, &nonce, age_add, lifetime);
		if (!psk) {
			err = -ENOMEM;
			goto out;
		}
		len -= (20 + id.len + key.len + nonce.len);

		if (!psks)
			psks = psk;
		else
			p->next = psk;
		p = psk;
	}
out:
	tls_psk_free(tls->psks);
	tls->psks = psks;
	return err;
}

static int tls_set_crt(struct tls_hs *tls, struct tls_vec *vec)
{
	struct tls_crt *c, *p;
	int len = 0;

	if (!vec->len) {
		tls_crt_free(tls->tcrts);
		tls->tcrts = NULL;
		return 0;
	}
	c = tls_crt_new(vec);
	if (!c)
		return -ENOMEM;
	p = tls->tcrts;
	if (!p) {
		tls->tcrts = c;
		return 0;
	}
	while (p->next) {
		len += p->raw.len;
		p = p->next;
	}
	if (len + c->raw.len > PAGE_SIZE - 512) {
		tls_crt_free(c);
		return -ENOMEM;
	}

	p->next = c;
	return 0;
}

static int tls_set_crts(struct tls_hs *tls, struct tls_vec *vec)
{
	struct tls_crt *c, *crts = NULL, *p;
	int clen, len = vec->len, err = 0;
	u8 *data = vec->data;
	struct tls_vec v;

	while (len > 0) {
		clen = *((u32 *)data);
		data += sizeof(u32);
		tls_vec(&v, data, clen);
		c = tls_crt_new(&v);
		if (!c) {
			err = -ENOMEM;
			goto out;
		}
		data += clen;
		len -= (sizeof(u32) + clen);
		if (!crts)
			crts = c;
		else
			p->next = c;
		p = c;
	}
out:
	tls_crt_free(tls->tcrts);
	tls->tcrts = crts;
	return err;
}

static int tls_set_ca(struct tls_hs *tls, struct tls_vec *vec)
{
	struct tls_crt *c;

	if (!vec->len) {
		tls_crt_free(tls->ca);
		tls->ca = NULL;
		return 0;
	}
	c = tls_crt_new(vec);
	if (!c)
		return -ENOMEM;

	tls_crt_free(tls->ca);
	tls->ca = c;
	return 0;
}

static int tls_set_early(struct tls_hs *tls, struct tls_vec *vec)
{
	u8 e[4] = {TLS_MT_END_OF_EARLY_DATA, 0, 0, 0};
	struct tls_vec msg = {e, 4};

	if (tls_buf_set(&tls->buf[TLS_B_END_EARLY], &msg))
		return -ENOMEM;

	tls->early = !!vec->len;
	return 0;
}

static int tls_get_psk(struct tls_hs *tls, struct tls_vec *vec)
{
	struct tls_psk *psk;
	u8 *p;

	if (!tls->psks)
		return 0;

	tls->omsg.len = 0;
	*vec = tls->omsg;
	p = vec->data;
	for (psk = tls->psks; psk; psk = psk->next) {
		*((u32 *)p) = psk->id.len;
		p += 4;
		p = tls_put_data(p, &psk->id);
		*((u32 *)p) = psk->key.len;
		p += 4;
		p = tls_put_data(p, &psk->key);
		*((u32 *)p) = psk->nonce.len;
		p += 4;
		p = tls_put_data(p, &psk->nonce);
		*((u32 *)p) = psk->age_add;
		p += 4;
		*((u32 *)p) = psk->lifetime;
		p += 4;
		vec->len += (20 + psk->id.len + psk->key.len + psk->nonce.len);
	}

	return 0;
}

static int tls_get_crts(struct tls_hs *tls, struct tls_vec *vec)
{
	struct tls_crt *c;
	u8 *p;

	if (!tls->tcrts)
		return 0;

	tls->omsg.len = 0;
	*vec = tls->omsg;
	p = vec->data;
	for (c = tls->tcrts; c; c = c->next) {
		*((u32 *)p) = c->raw.len;
		p += 4;
		p = tls_put_data(p, &c->raw);
		vec->len += (4 + c->raw.len);
	}

	return 0;
}

static int tls_do_encrypt(struct tls_hs *tls, u8 type, struct tls_vec *msg, u32 seq)
{
	struct crypto_aead *tfm = tls->aead_tfm;
	struct tls_vec *key, *iv;
	struct aead_request *req;
	struct scatterlist sg;
	u8 nonce[12], i;
	__be64 n;
	int err;

	if (type != TLS_SE_EA && type != TLS_SE_HS && type != TLS_SE_AP)
		return -EINVAL;

	type += 1;
	key = &tls->srt[type + 1];
	iv = &tls->srt[type + 2];
	memcpy(nonce, iv->data, iv->len);
	n = cpu_to_be64(seq);
	for (i = 0; i < 8; i++)
		nonce[4 + i] ^= ((u8 *)&n)[i];
	err = crypto_aead_setauthsize(tfm, 16);
	if (err)
		return err;
	err = crypto_aead_setkey(tfm, key->data, key->len);
	if (err)
		return err;
	req = aead_request_alloc(tfm, GFP_ATOMIC);
	if (!req)
		return -ENOMEM;
	sg_init_one(&sg, msg->data, msg->len + 16);
	aead_request_set_ad(req, 5);
	aead_request_set_crypt(req, &sg, &sg, msg->len - 5, nonce);
	err = crypto_aead_encrypt(req);
	if (!err)
		msg->len += 16;

	kfree(req);
	return err;
}

static int tls_do_decrypt(struct tls_hs *tls, u8 type, struct tls_vec *msg, u64 seq)
{
	struct crypto_aead *tfm = tls->aead_tfm;
	struct tls_vec *key, *iv;
	struct aead_request *req;
	struct scatterlist sg;
	u8 nonce[12], i;
	__be64 n;
	int err;

	if (type != TLS_SE_EA && type != TLS_SE_HS && type != TLS_SE_AP)
		return -EINVAL;

	type += 4;
	key = &tls->srt[type + 1];
	iv = &tls->srt[type + 2];
	memcpy(nonce, iv->data, iv->len);
	n = cpu_to_be64(seq);
	for (i = 0; i < 8; i++)
		nonce[4 + i] ^= ((u8 *)&n)[i];
	err = crypto_aead_setauthsize(tfm, 16);
	if (err)
		return err;
	err = crypto_aead_setkey(tfm, key->data, key->len);
	if (err)
		return err;
	req = aead_request_alloc(tfm, GFP_ATOMIC);
	if (!req)
		return -ENOMEM;
	sg_init_one(&sg, msg->data, msg->len);
	aead_request_set_ad(req, 5);
	aead_request_set_crypt(req, &sg, &sg, msg->len - 5, nonce);
	err = crypto_aead_decrypt(req);
	if (!err)
		msg->len -= 16;

	kfree(req);
	return err;
}

int tls_secret_get(struct tls_hs *tls, u8 type, struct tls_vec *vec)
{
	if (type >= TLS_SE_MAX)
		return -EINVAL;

	*vec = tls->srt[type];
	return 0;
}
EXPORT_SYMBOL_GPL(tls_secret_get);

int tls_hkdf_expand(struct tls_hs *tls, struct tls_vec *s, struct tls_vec *l, struct tls_vec *k)
{
	struct tls_vec z = {NULL, 0};

	return tls_crypto_hkdf_expand(tls->srt_tfm, s, l, &z, k);
}
EXPORT_SYMBOL_GPL(tls_hkdf_expand);

int tls_hkdf_extract(struct tls_hs *tls, struct tls_vec *s, struct tls_vec *h, struct tls_vec *k)
{
	return tls_crypto_hkdf_extract(tls->srt_tfm, s, h, k);
}
EXPORT_SYMBOL_GPL(tls_hkdf_extract);

int tls_handshake(struct tls_hs *tls, struct tls_vec *msg)
{
	int ret = -EINVAL;

	tls->omsg.len = 0;
	if (msg->len) {
		ret = tls_msg_handle(tls, msg);
		goto out;
	}
	if (tls->is_serv) {
		if (tls->state != TLS_ST_RCVD)
			goto out;
		ret = tls_msg_hs_build(tls);
		goto out;
	}
	if (tls->state != TLS_ST_START)
		goto out;
	ret = tls_msg_ch_build(tls);
out:
	*msg = tls->omsg;
	return ret;
}
EXPORT_SYMBOL_GPL(tls_handshake);

int tls_handshake_post(struct tls_hs *tls, u8 type, struct tls_vec *msg)
{
	int ret = -EINVAL;

	tls->omsg.len = 0;
	if (type == TLS_P_NONE)
		ret = tls_msg_handle(tls, msg);
	else if (type == TLS_P_TICKET)
		ret = tls_msg_ticket_build(tls, msg);
	else if (type == TLS_P_KEY_UPDATE)
		ret = tls_msg_ku_build(tls, msg, 1);

	*msg = tls->omsg;
	return ret;
}
EXPORT_SYMBOL_GPL(tls_handshake_post);

int tls_handshake_set(struct tls_hs *tls, u8 type, struct tls_vec *vec)
{
	int ret = 0;

	if (vec->len > PAGE_SIZE - 512)
		return -ENOMEM;

	switch (type) {
	case TLS_T_CA:
		ret = tls_set_ca(tls, vec);
		break;
	case TLS_T_CRTS:
		ret = tls_set_crts(tls, vec);
		break;
	case TLS_T_PKEY:
		ret = tls_vec_cpy(&tls->pkey, vec);
		break;
	case TLS_T_CRT:
		ret = tls_set_crt(tls, vec);
		break;
	case TLS_T_PSK:
		ret = tls_set_psk(tls, vec);
		break;
	case TLS_T_CRT_REQ:
		tls->crt_req = !!vec->len;
		break;
	case TLS_T_EXT:
		ret = tls_vec_cpy(&tls->ext, vec);
		break;
	case TLS_T_EARLY:
		ret = tls_set_early(tls, vec);
		break;
	}

	return ret;
}
EXPORT_SYMBOL_GPL(tls_handshake_set);

int tls_handshake_get(struct tls_hs *tls, u8 type, struct tls_vec *vec)
{
	int ret = 0;

	switch (type) {
	case TLS_T_MSG:
		*vec = tls->omsg;
		break;
	case TLS_T_CMSG:
		*vec = tls->cmsg;
		break;
	case TLS_T_EXT:
		*vec = tls->ext;
		break;
	case TLS_T_PKEY:
		*vec = tls->pkey;
		break;
	case TLS_T_CA:
		if (!tls->ca)
			break;
		*vec = tls->ca->raw;
		break;
	case TLS_T_CRT_REQ:
		vec->len = tls->crt_req;
		break;
	case TLS_T_CRT:
		if (!tls->tcrts)
			break;
		*vec = tls->tcrts->raw;
		break;
	case TLS_T_PSK:
		ret = tls_get_psk(tls, vec);
		break;
	case TLS_T_CRTS:
		ret = tls_get_crts(tls, vec);
		break;
	case TLS_T_EARLY:
		vec->len = tls->early;
		break;
	}

	return ret;
}
EXPORT_SYMBOL_GPL(tls_handshake_get);

int tls_handshake_create(struct tls_hs **tlsp, bool is_serv, gfp_t gfp)
{
	struct tls_hs *tls;
	int err = -ENOMEM;

	tls = kzalloc(sizeof(*tls), gfp);
	if (!tls)
		return err;
	tls->srt_tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
	if (IS_ERR(tls->srt_tfm)) {
		err = PTR_ERR(tls->srt_tfm);
		goto err;
	}
	tls->hash_tfm = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(tls->hash_tfm)) {
		err = PTR_ERR(tls->hash_tfm);
		goto err;
	}
	tls->kpp_tfm = crypto_alloc_kpp("ecdh-nist-p256", 0, 0);
	if (IS_ERR(tls->kpp_tfm)) {
		err = PTR_ERR(tls->kpp_tfm);
		goto err;
	}
	tls->aead_tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(tls->aead_tfm)) {
		err = PTR_ERR(tls->aead_tfm);
		goto err;
	}
	tls->akc_tfm = crypto_alloc_akcipher("psspad(rsa,sha256)", 0, 0);
	if (IS_ERR(tls->akc_tfm)) {
		err = PTR_ERR(tls->akc_tfm);
		goto err;
	}
	tls->omsg.data = (u8 *)__get_free_page(GFP_ATOMIC);
	if (!tls->omsg.data)
		goto err;
	tls->cmsg.data = (u8 *)__get_free_page(GFP_ATOMIC);
	if (!tls->cmsg.data)
		goto err;
	tls->ext.data = (u8 *)__get_free_page(GFP_ATOMIC);
	if (!tls->ext.data)
		goto err;
	tls->state = TLS_ST_START;
	tls->is_serv = is_serv;

	*tlsp = tls;
	return 0;
err:
	tls_handshake_destroy(tls);
	return err;
}
EXPORT_SYMBOL_GPL(tls_handshake_create);

void tls_handshake_destroy(struct tls_hs *tls)
{
	int i;

	free_page((unsigned long)tls->cmsg.data);
	free_page((unsigned long)tls->omsg.data);
	free_page((unsigned long)tls->ext.data);

	for (i = 0; i < TLS_SE_MAX; i++)
		kfree(tls->srt[i].data);

	tls_hello_free(&tls->h);
	tls_psk_free(tls->psks);
	tls_crt_free(tls->tcrts);
	tls_crt_free(tls->rcrts);
	tls_crt_free(tls->ca);
	kfree(tls->pkey.data);

	crypto_free_kpp(tls->kpp_tfm);
	crypto_free_aead(tls->aead_tfm);
	crypto_free_shash(tls->hash_tfm);
	crypto_free_shash(tls->srt_tfm);
	crypto_free_akcipher(tls->akc_tfm);

	kfree(tls);
}
EXPORT_SYMBOL_GPL(tls_handshake_destroy);

/* These APIs below are for general TCP TLS handshake, also an example for
 * how to use tls_* APIs.
 */

static int tls_gen_msg_build(struct tls_hs *tls, struct tls_vec *v, struct tls_vec *o,
			     u8 crypt, u32 seq)
{
	u32 len = v->len;
	u8 *p, type = 22;
	int err = 0;

	if (crypt) {
		type = 23;
		len += 17;
	}
	if (o->len + len + 5 > PAGE_SIZE)
		return -ENOMEM;
	p = o->data + o->len;
	p = tls_put_num(p, type, 1);
	p = tls_put_num(p, 0x0303, 2);
	p = tls_put_num(p, len, 2);
	p = tls_put_data(p, v);
	if (crypt) {
		type = 22;
		if (crypt == TLS_SE_AP || (crypt == TLS_SE_EA && !seq))
			type = 23;
		p = tls_put_num(p, type, 1);
		tls_vec(v, o->data + o->len, v->len + 6);
		err = tls_do_encrypt(tls, crypt, v, seq);
		if (err) {
			pr_err("[TLS_HS_GEN] msg send encrypt err %d\n", err);
			return err;
		}
	}
	o->len += (len + 5);

	return err;
}

static int tls_gen_getopt(struct tls_hs *tls, u8 type)
{
	struct tls_vec v;

	tls_handshake_get(tls, type, &v);
	return v.len;
}

static int tls_gen_setopt(struct tls_hs *tls, u8 type, u32 value)
{
	struct tls_vec v;

	return tls_handshake_set(tls, type, tls_vec(&v, NULL, value));
}

static int tls_gen_post_handle(struct tls_hs *tls, u8 type, struct tls_vec *v)
{
	int ret, err = 0;

	if (type != 22) {
		pr_debug("[TLS_HS_GEN] post handle alert %d %d\n", type, v->len);
		return 0;
	}

	ret = tls_handshake_post(tls, TLS_P_NONE, v);
	switch (ret) {
	case TLS_P_KEY_UPDATE:
		pr_debug("[TLS_HS_GEN] post key_updata %d\n", v->len);
		break;
	case TLS_P_TICKET:
		pr_debug("[TLS_HS_GEN] post ticket %d\n", v->len);
		break;
	default:
		err = ret;
		pr_err("[TLS_HS_GEN] post process err %d\n", ret);
	}

	return err;
}

static int tls_gen_ea_handle(struct tls_hs *tls, u32 type, struct tls_vec *i,
			     struct tls_vec *o, u64 *eseq)
{
	struct tls_vec vec;
	int err;

	tls_vec(&vec, i->data - 5, i->len + 5);
	err = tls_do_decrypt(tls, TLS_SE_EA, &vec, (*eseq)++);
	if (err) {
		pr_err("[TLS_HS_GEN] msg recv ea err %d\n", err);
		return err;
	}
	if (tls_get_data(i, i->len - 17, &vec) || tls_get_num(i, 1, &type))
		return -EINVAL;
	if (type == 22) { /* process end of early data */
		if (tls_get_num(&vec, 1, &type) || type != TLS_MT_END_OF_EARLY_DATA)
			return -EINVAL;
		err = tls_gen_setopt(tls, TLS_T_EARLY, 0);
		if (err)
			return err;
		pr_debug("[TLS_HS_GEN] msg recv ea end of data\n");
	} else if (type == 23) {
		pr_debug("[TLS_HS_GEN] msg recv ea data %d %d\n", o->len, vec.len);
		if (o->len + vec.len > PAGE_SIZE)
			return -ENOMEM;
		tls_vec_add(o, &vec);
	} else {
		pr_debug("[TLS_HS_GEN] msg recv ea skip type %d\n", type);
	}

	return 0;
}

static int tls_gen_ap_handle(struct tls_hs *tls, u32 type, struct tls_vec *i,
			     struct tls_vec *o, u64 *rseq)
{
	struct tls_vec vec;
	int err;

	tls_vec(&vec, i->data - 5, i->len + 5);
	err = tls_do_decrypt(tls, TLS_SE_AP, &vec, (*rseq)++);
	if (err) {
		pr_err("[TLS_HS_GEN] app handle decrypt err %d\n", err);
		return err;
	}
	if (tls_get_data(i, i->len - 17, &vec) || tls_get_num(i, 1, &type))
		return -EINVAL;
	pr_debug("[TLS_HS_GEN] app handle type %d\n", type);
	if (type == 23) {
		pr_debug("[TLS_HS_GEN] app recv data %d %d\n", o->len, vec.len);
		if (o->len + vec.len > PAGE_SIZE)
			return -ENOMEM;
		tls_vec_add(o, &vec);
	} else {
		err = tls_gen_post_handle(tls, type, &vec);
		if (err) {
			pr_err("[TLS_HS_GEN] app post handle err %d\n", err);
			return err;
		}
	}
	return 0;
}

static int tls_gen_hs_handle(struct tls_hs *tls, u32 type, struct tls_vec *i, struct tls_vec *o,
			     struct tls_vec *es, u64 *rseq, u64 *wseq, u8 is_serv)
{
	struct tls_vec vec = *i;
	int ret, err;

	if (type == 23) {
		tls_vec(&vec, i->data - 5, i->len + 5);
		err = tls_do_decrypt(tls, TLS_SE_HS, &vec, (*rseq)++);
		if (err) {
			pr_err("[TLS_HS_GEN] msg recv hs err %d\n", err);
			return err;
		}
		if (tls_get_data(i, i->len - 17, &vec) || tls_get_num(i, 1, &type))
			return -EINVAL;
		pr_debug("[TLS_HS_GEN] msg recv internal type %d\n", type);
	}
	if (type != 22) {
		pr_debug("[TLS_HS_GEN] msg recv skip type %d\n", type);
		return 0;
	}
	ret = tls_handshake(tls, &vec);
	switch (ret) {
	case TLS_ST_START:
		err = tls_gen_msg_build(tls, &vec, o, 0, 0);
		if (err < 0)
			return err;
		return -EAGAIN;
	case TLS_ST_WAIT:
		break;
	case TLS_ST_RCVD:
		if (!is_serv)
			break;
		err = tls_gen_msg_build(tls, &vec, o, 0, 0);
		if (err < 0)
			return err;
		err = tls_handshake(tls, tls_vec(&vec, NULL, 0));
		if (err < 0)
			return err;
		err = tls_gen_msg_build(tls, &vec, o, TLS_SE_HS, 0);
		if (err < 0)
			return err;
		if (!es->len)
			break;
		err = tls_gen_msg_build(tls, es, o, TLS_SE_AP, (*wseq)++);
		if (err < 0)
			return err;
		es->len = 0;
		break;
	case TLS_ST_CONNECTED:
		if (is_serv)
			return 1;
		if (tls_gen_getopt(tls, TLS_T_EARLY)) { /* create end of early data */
			u8 emsg[4] = {TLS_MT_END_OF_EARLY_DATA, 0, 0, 0};
			struct tls_vec s;

			err = tls_gen_msg_build(tls, tls_vec(&s, emsg, 4), o, TLS_SE_EA, 1);
			if (err < 0)
				return err;
			err = tls_gen_setopt(tls, TLS_T_EARLY, 0);
			if (err)
				return err;
		}
		err = tls_gen_msg_build(tls, &vec, o, TLS_SE_HS, 0);
		if (err < 0)
			return err;
		if (es->len) {
			err = tls_gen_msg_build(tls, es, o, TLS_SE_AP, (*wseq)++);
			if (err < 0)
				return err;
			es->len = 0;
		}
		return 1;
	default:
		err = ret;
		return err;
	}
	return 0;
}

static int tls_gen_msg_handle(struct tls_hs *tls, struct tls_vec *i, struct tls_vec *o,
			      struct tls_vec *es, struct tls_vec *er, u8 is_serv,
			      u64 *rseq, u64 *wseq, u64 *eseq)
{
	struct tls_vec vec;
	int err, ret = 0;
	u32 ver, type;

	while (i->len > 0) {
		if (tls_get_num(i, 1, &type) || tls_get_num(i, 2, &ver) || tls_get_sub(i, 2, &vec))
			return -EINVAL;
		pr_debug("[TLS_HS_GEN] msg recv type %d\n", type);
		if (type == 23) { /* encrypted data */
			if (ret > 0) { /* process app data if there is */
				err = tls_gen_ap_handle(tls, type, &vec, er, rseq);
				if (err)
					return err;
				continue;
			}
			if (is_serv && tls_gen_getopt(tls, TLS_T_EARLY)) { /* process early data */
				err = tls_gen_ea_handle(tls, type, &vec, er, eseq);
				if (err)
					return err;
				continue;
			}
		}
		ret = tls_gen_hs_handle(tls, type, &vec, o, es, rseq, wseq, is_serv);
		if (ret < 0)
			return ret == -EAGAIN ? 0 : ret;
		if (!ret)
			continue;
		*rseq = 0;
	}
	return ret;
}

static int tls_gen_key_setup(struct tls_hs *tls, struct key *key, u8 type, char *sub, u8 *data)
{
	key_ref_t kref = NULL;
	struct tls_vec vec;
	int len;

	kref = keyring_search(make_key_ref(key, 1UL), &key_type_user, sub, false);
	if (IS_ERR(kref)) {
		pr_debug("[TLS_HS_GEN] keyring request_key %s %ld\n", sub, PTR_ERR(kref));
		return PTR_ERR(kref);
	}
	len = user_read(key_ref_to_ptr(kref), data, PAGE_SIZE);

	return tls_handshake_set(tls, type, tls_vec(&vec, data, len));
}

static int tls_gen_key_append(struct tls_hs *tls, struct key *key, char *sub,
			      struct tls_vec *v, u8 l)
{
	u8 *p = v->data + v->len;
	key_ref_t kref = NULL;
	int len;

	kref = keyring_search(make_key_ref(key, 1UL), &key_type_user, sub, false);
	if (IS_ERR(kref)) {
		pr_debug("[TLS_HS_GEN] keyring request_key %s %ld\n", sub, PTR_ERR(kref));
		return PTR_ERR(kref);
	}
	if (!l) {
		len = user_read(key_ref_to_ptr(kref), p + 4, PAGE_SIZE - v->len - 4);
		*((u32 *)p) = len;
		len += 4;
	} else {
		len = user_read(key_ref_to_ptr(kref), p, l);
		if (len != l)
			return -EINVAL;
	}

	v->len += len;
	return 0;
}

static int tls_gen_kerying_setup(struct tls_hs *tls, char *subsys, u8 flag, u8 *data)
{
	u8 is_serv = flag & TLS_F_SERV;
	char sub[32] = {'\0'};
	struct tls_vec vec;
	struct key *key;
	int err, i;

	if (flag & (TLS_F_CRT | TLS_F_PSK)) {
		sprintf(sub, "%s-%d", subsys, is_serv);
		key = request_key(&key_type_keyring, sub, NULL);
		if (IS_ERR(key)) {
			pr_err("[TLS_HS_GEN] keyring request_key tls err %ld\n", PTR_ERR(key));
			return PTR_ERR(key);
		}
	}
	if (flag & TLS_F_CRT) {
		err = tls_gen_key_setup(tls, key, TLS_T_PKEY, "pkey", data);
		if (err && is_serv)
			return err;
		for (i = 0; i < 5; i++) { /* certificate chain */
			sprintf(sub, "%s-%d", "crt", i);
			err = tls_gen_key_setup(tls, key, TLS_T_CRT, sub, data);
			if (err == -EAGAIN)
				break;
			if (err)
				return err;
		}
		if (!i && is_serv)
			return -EINVAL;
		err = tls_gen_key_setup(tls, key, TLS_T_CA, "ca", data);
		if (err && err != -EAGAIN)
			return err;
		if (flag & TLS_F_CRT_REQ)
			tls_gen_setopt(tls, TLS_T_CRT_REQ, 1);
		return 0;
	}
	if (!(flag & TLS_F_PSK))
		return 0;
	tls_vec(&vec, data, 0);
	for (i = 0; i < 5; i++) { /* psks */
		sprintf(sub, "psk-%d-id", i);
		err = tls_gen_key_append(tls, key, sub, &vec, 0);
		if (err < 0)
			return err;
		sprintf(sub, "psk-%d-master", i);
		err = tls_gen_key_append(tls, key, sub, &vec, 0);
		if (err < 0)
			return err;
		sprintf(sub, "psk-%d-nonce", i);
		err = tls_gen_key_append(tls, key, sub, &vec, 0);
		if (err < 0) {
			if (err != -EAGAIN)
				return err;
			memset(vec.data + vec.len, 0, 12);
			vec.len += 12;
			break;
		}
		sprintf(sub, "psk-%d-ageadd", i);
		err = tls_gen_key_append(tls, key, sub, &vec, 4);
		if (err < 0)
			return err;
		sprintf(sub, "psk-%d-lifetime", i);
		err = tls_gen_key_append(tls, key, sub, &vec, 4);
		if (err < 0)
			return err;
	}

	return tls_handshake_set(tls, TLS_T_PSK, &vec);
}

#if IS_ENABLED(CONFIG_TLS)

static int tls_sk_ktls_setup(struct socket *sock, struct tls_hs *tls, u64 rseq, u64 wseq)
{
	struct tls12_crypto_info_aes_gcm_128 crypto_info;
	struct tls_vec key, iv;
	int err;

	err = sock->ops->setsockopt(sock, SOL_TCP, 31,
				    KERNEL_SOCKPTR("tls"), sizeof("tls"));
	if (err) {
		pr_err("[TLS_HS_GEN] ktls setup TCP_ULP err %d\n", err);
		return err;
	}

	memset(&crypto_info, 0, sizeof(crypto_info));
	crypto_info.info.version = TLS_1_3_VERSION;
	crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_128;
	err = tls_secret_get(tls, TLS_SE_TAP_KEY, &key);
	if (err)
		return err;
	err = tls_secret_get(tls, TLS_SE_TAP_IV, &iv);
	if (err)
		return err;
	memcpy(crypto_info.key, key.data, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
	memcpy(crypto_info.iv, iv.data + 4, TLS_CIPHER_AES_GCM_128_IV_SIZE);
	memcpy(crypto_info.rec_seq, &wseq, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);
	memcpy(crypto_info.salt, iv.data, TLS_CIPHER_AES_GCM_128_SALT_SIZE);
	err = sock->ops->setsockopt(sock, SOL_TLS, TLS_TX,
				    KERNEL_SOCKPTR(&crypto_info), sizeof(crypto_info));
	if (err) {
		pr_err("[TLS_HS_GEN] ktls setup TCP_TX err %d\n", err);
		return err;
	}

	memset(&crypto_info, 0, sizeof(crypto_info));
	crypto_info.info.version = TLS_1_3_VERSION;
	crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_128;
	err = tls_secret_get(tls, TLS_SE_RAP_KEY, &key);
	if (err)
		return err;
	err = tls_secret_get(tls, TLS_SE_RAP_IV, &iv);
	if (err)
		return err;
	memcpy(crypto_info.key, key.data, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
	memcpy(crypto_info.iv, iv.data + 4, TLS_CIPHER_AES_GCM_128_IV_SIZE);
	memcpy(crypto_info.rec_seq, &rseq, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);
	memcpy(crypto_info.salt, iv.data, TLS_CIPHER_AES_GCM_128_SALT_SIZE);
	err = sock->ops->setsockopt(sock, SOL_TLS, TLS_RX,
				    KERNEL_SOCKPTR(&crypto_info), sizeof(crypto_info));
	if (err) {
		pr_err("[TLS_HS_GEN] ktls setup TCP_RX err %d\n", err);
		return err;
	}

	return 0;
}

#else

static int tls_sk_ktls_setup(struct socket *sock, struct tls_hs *tls, be64 rseq, be64 wseq)
{
	pr_err("[TLS_HS_GEN] please enable CONFIG_TLS or use flag with TLS_F_NO_KTLS.\n");
	return -EPROTONOSUPPORT;
}

#endif /* CONFIG_TLS */

struct tls_hs *tls_sk_handshake(struct socket *sock, struct tls_vec *es, char *subsys, u8 flag)
{
	u8 *data, is_serv = flag & TLS_F_SERV;
	u64 rseq = 0, wseq = 0, eseq = 0;
	struct tls_vec vec, out, er;
	struct tls_hs *tls;
	struct msghdr msg;
	struct kvec iv;
	int err, ret;

	err = tls_handshake_create(&tls, is_serv, GFP_ATOMIC);
	if (err)
		return ERR_PTR(err);
	data = (u8 *)__get_free_page(GFP_ATOMIC);
	if (!data) {
		err = -ENOMEM;
		goto err;
	}
	if (subsys) {
		err = tls_gen_kerying_setup(tls, subsys, flag, data);
		if (err)
			goto err;
	}
	tls_handshake_get(tls, TLS_T_EXT, &out); /* reuse tls->ext */
	tls_handshake_get(tls, TLS_T_CMSG, &er); /* reuse tls->cmsg */
	if (!is_serv) { /* send client hello */
		if ((flag & TLS_F_PSK) && es->len) {
			err = tls_gen_setopt(tls, TLS_T_EARLY, 1);
			if (err)
				goto err;
		}
		err = tls_handshake(tls, tls_vec(&vec, NULL, 0));
		if (err < 0)
			goto err;
		err = tls_gen_msg_build(tls, &vec, &out, 0, 0);
		if (err)
			goto err;
		if ((flag & TLS_F_PSK) && es->len) { /* start early data */
			err = tls_gen_msg_build(tls, es, &out, TLS_SE_EA, 0);
			if (err)
				goto err;
			es->len = 0;
		}
		memset(&msg, 0, sizeof(msg));
		iv.iov_base = out.data;
		iv.iov_len = out.len;
		err = kernel_sendmsg(sock, &msg, &iv, 1, iv.iov_len);
		if (err < 0) {
			pr_err("[TLS_HS_GEN] msg send err %d\n", err);
			goto err;
		}
		out.len = 0;
	}
	while (1) { /* recv hs msg and wait handshake done */
		memset(&msg, 0, sizeof(msg));
		iv.iov_base = data;
		iv.iov_len = PAGE_SIZE;
		ret = kernel_recvmsg(sock, &msg, &iv, 1, iv.iov_len, 0);
		if (ret <= 0) {
			err = ret ?: -EPIPE;
			goto err;
		}
		tls_vec(&vec, data, ret);
		err = tls_gen_msg_handle(tls, &vec, &out, es, &er,
					 is_serv, &rseq, &wseq, &eseq); /* handle hs msg */
		if (err < 0)
			goto err;
		if (out.len > 0) {
			memset(&msg, 0, sizeof(msg));
			iv.iov_base = out.data;
			iv.iov_len = out.len;
			ret = kernel_sendmsg(sock, &msg, &iv, 1, iv.iov_len);
			if (ret <= 0) {
				err = ret ?: -EPIPE;
				pr_err("[TLS_HS_GEN] msg send err %d\n", err);
				goto err;
			}
			out.len = 0;
		}
		if (!err)
			continue;
		if (!(flag & TLS_F_NO_KTLS)) {
			err = tls_sk_ktls_setup(sock, tls, cpu_to_be64(rseq), cpu_to_be64(wseq));
			if (err < 0)
				goto err;
		}
		*es = er; /* pass it back to the caller via es */
		break;
	}

	free_page((unsigned long)data);
	return tls;
err:
	free_page((unsigned long)data);
	tls_handshake_destroy(tls);
	return ERR_PTR(err);
}
EXPORT_SYMBOL_GPL(tls_sk_handshake);

int tls_sk_handshake_post(struct socket *sock, struct tls_hs *tls, u8 type, struct tls_vec *v)
{
	return tls_gen_post_handle(tls, type, v);
}
EXPORT_SYMBOL_GPL(tls_sk_handshake_post);

int tls_ap_encrypt(struct tls_hs *tls, struct tls_vec *msg, u32 seq)
{
	return tls_do_encrypt(tls, TLS_SE_AP, msg, seq);
}
EXPORT_SYMBOL_GPL(tls_ap_encrypt);

int tls_ap_decrypt(struct tls_hs *tls, struct tls_vec *msg, u32 seq)
{
	return tls_do_decrypt(tls, TLS_SE_AP, msg, seq);
}
EXPORT_SYMBOL_GPL(tls_ap_decrypt);

static int __init tls_hs_init(void)
{
	void *tfm;

	/* FIXME: load modules in thread context in a better way */
	tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);
	crypto_free_shash(tfm);
	tfm = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);
	crypto_free_shash(tfm);
	tfm = crypto_alloc_skcipher("ecb(aes)", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);
	crypto_free_skcipher(tfm);
	tfm = crypto_alloc_kpp("ecdh-nist-p256", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);
	crypto_free_kpp(tfm);
	tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);
	crypto_free_aead(tfm);
	tfm = crypto_alloc_akcipher("pkcs1pad(rsa,sha256)", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);
	crypto_free_akcipher(tfm);
	tfm = crypto_alloc_akcipher("psspad(rsa,sha256)", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);
	crypto_free_akcipher(tfm);

	pr_info("tls_hs init\n");
	return 0;
}

static void __exit tls_hs_exit(void)
{
	pr_info("tls_hs exit\n");
}

module_init(tls_hs_init);
module_exit(tls_hs_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Xin Long <lucien.xin@gmail.com>");
MODULE_DESCRIPTION("TLS 1.3 handshake APIs");
