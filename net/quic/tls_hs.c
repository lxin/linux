// SPDX-License-Identifier: GPL-2.0-or-later
/* TLS Handshake kernel implementation
 * (C) Copyright Red Hat Corp. 2021
 *
 * This file is the TLS Handshake kernel implementation
 *
 * Provides APIs for TLS Handshake.
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#include <net/quic/tls_hs.h>
#include <linux/scatterlist.h>
#include <crypto/hash.h>
#include <crypto/sha2.h>
#include <crypto/aead.h>
#include <crypto/skcipher.h>
#include <crypto/akcipher.h>
#include <crypto/kpp.h>
#include <crypto/ecdh.h>
#include <crypto/x509_parser.h>

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
	TLS_SE_DHE,
	TLS_SE_EA,
	TLS_SE_HS,
	TLS_SE_MS,
	TLS_SE_RMS,
	TLS_SE_TEA,
	TLS_SE_REA,
	TLS_SE_THS,
	TLS_SE_RHS,
	TLS_SE_TAP,
	TLS_SE_RAP,
	TLS_SE_MAX,
};

enum {
	TLS_B_CH,
	TLS_B_SH,
	TLS_B_EE,
	TLS_B_CRT_REQ,
	TLS_B_S_CRT,
	TLS_B_S_CRT_VFY,
	TLS_B_S_FIN,
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
};

struct tls_hs {
	struct tls_hello h;
	struct tls_vec ext;
	struct tls_vec imsg;
	struct tls_vec cmsg;
	struct tls_vec omsg;

	struct crypto_kpp *kpp_tfm;
	struct crypto_shash *srt_tfm;
	struct crypto_shash *hash_tfm;
	struct crypto_akcipher *akc_tfm;

	struct tls_vec buf[TLS_B_MAX];
	struct tls_vec srt[TLS_SE_MAX];

	/* TODO: move these keys to keyring */
	struct tls_crt *tcrts;
	struct tls_crt *rcrts;
	struct tls_vec pkey;
	struct tls_crt *ca;
	struct tls_psk *psks;

	u8 state:2,
	   is_serv:1,
	   crt_req:1;
};

static inline int tls_vec_alloc(struct tls_vec *vec, u32 len)
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

static inline u32 tls_get_num(u8 **pp, u32 len)
{
	union tls_num n;
	u8 *p = *pp;
	u32 num;

	n.n32 = 0;
	switch (len) {
	case 1:
		num = *p;
		break;
	case 2:
		memcpy(&n.n16, p, 2);
		num = ntohs(n.n16);
		break;
	case 3:
		memcpy(((u8 *)&n.n32) + 1, p, 3);
		num = ntohl(n.n32);
		break;
	case 4:
		memcpy(&n.n32, p, 4);
		num = ntohl(n.n32);
		break;
	}

	*pp += len;
	return num;
}

static inline u8 *tls_put_data(u8 *p, struct tls_vec *vec)
{
	if (!vec->len)
		return p;

	memcpy(p, vec->data, vec->len);
	return p + vec->len;
}

static inline void tls_pr_hex(char *str, u8 data[], u32 len)
{
	pr_debug("[TLS_HS] %s: %d: \n", str, len);
	print_hex_dump(KERN_INFO, "", DUMP_PREFIX_NONE, 32, 1, data, len, false);
}

#define TLS_MT_HELLO_REQUEST		0
#define TLS_MT_CLIENT_HELLO		1
#define TLS_MT_SERVER_HELLO		2
#define TLS_MT_NEWSESSION_TICKET	4
#define TLS_MT_END_OF_EARLY_DATA	5
#define TLS_MT_ENCRYPTED_EXTENSIONS	8
#define TLS_MT_CERTIFICATE		11
#define TLS_MT_SERVER_KEY_EXCHANGE	12
#define TLS_MT_CERTIFICATE_REQUEST	13
#define TLS_MT_SERVER_DONE		14
#define TLS_MT_CERTIFICATE_VERIFY	15
#define TLS_MT_CLIENT_KEY_EXCHANGE	16
#define TLS_MT_FINISHED			20
#define TLS_MT_CERTIFICATE_URL		21
#define TLS_MT_CERTIFICATE_STATUS	22
#define TLS_MT_SUPPLEMENTAL_DATA	23
#define TLS_MT_KEY_UPDATE		24

#define TLS_EXT_server_name		0
#define TLS_EXT_max_fragment_length	1
#define TLS_EXT_client_certificate_url	2
#define TLS_EXT_trusted_ca_keys		3
#define TLS_EXT_truncated_hmac		4
#define TLS_EXT_status_request		5
#define TLS_EXT_user_mapping		6
#define TLS_EXT_client_authz		7
#define TLS_EXT_server_authz		8
#define TLS_EXT_cert_type		9
#define TLS_EXT_supported_groups	10
#define TLS_EXT_ec_point_formats	11
#define TLS_EXT_srp			12
#define TLS_EXT_signature_algorithms	13
#define TLS_EXT_use_srtp		14
#define TLS_EXT_heartbeat		15
#define TLS_EXT_application_layer_protocol_negotiation	16
#define TLS_EXT_signed_certificate_timestamp		18
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
#define TLS_EXT_post_handshake_auth			49
#define TLS_EXT_signature_algorithms_cert		50
#define TLS_EXT_key_share				51

#define TLS_MSG_legacy_version		0x0303
#define TLS_AES_128_GCM_SHA256		0x1301
#define TLS_ECDHE_secp256r1		0x0017
#define TLS_SAE_rsa_pss_rsae_sha256	0x0804
#define TLS_MSG_version			0x0304

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

	err = tls_vec_alloc(srt, 32);
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

	err = tls_vec_alloc(hash, 32);
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

	err = tls_vec_alloc(key, 32);
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

	err = tls_vec_alloc(key, 32);
	if (err)
		return err;

	err = crypto_shash_tfm_digest(tfm, hash->data, hash->len, key->data);
	if (err)
		return err;

	return 0;
}

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

static int tls_bin_generate(struct tls_hs *tls, struct tls_psk *p,
			    struct tls_vec *vec, struct tls_vec *bin)
{
	u8 psk[32], bk[32], fbk[32], zeros[32] = {0}, h[32];
	struct tls_vec psk_v, bk_v, fbk_v, z0_v, h_v;
	struct tls_vec bk_l = {"res binder", 10};
	struct crypto_shash *tfm = tls->srt_tfm;
	struct tls_vec fbk_l = {"finished", 8};
	int err;

	psk_v = p->key;
	if (p->lifetime) { /* this is a ticket */
		struct tls_vec psk_l = {"resumption", 10};

		err = tls_crypto_hkdf_expand(tfm, &p->key, &psk_l,
					     &p->nonce, tls_vec(&psk_v, psk, 32));
		if (err)
			return err;
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
	err = tls_crypto_hash(tls->hash_tfm, vec, 1, tls_vec(&h_v, h, 32)); /* h5 */
	if (err)
		return err;
	return tls_crypto_hkdf_extract(tfm, &fbk_v, &h_v, bin);
}

static int tls_keys_ea_setup(struct tls_hs *tls)
{
	struct crypto_shash *tfm = tls->srt_tfm;
	struct tls_vec h_v, l_v = {"derived", 7};
	u8 h[32], *rl, *tl;
	int err;

	err = tls_crypto_hash(tls->hash_tfm, tls->buf, TLS_B_CH + 1, tls_vec(&h_v, h, 32));
	if (err)
		return err;

	if (tls->is_serv) {
		rl = "c e traffic";
		tl = "s e traffic";
	} else {
		tl = "c e traffic";
		rl = "s e traffic";
	}

	err = tls_crypto_hkdf_expand(tfm, &tls->srt[TLS_SE_EA], tls_vec(&l_v, tl, 11),
				     &h_v, &tls->srt[TLS_SE_TEA]);
	if (err)
		return err;
	err = tls_crypto_hkdf_expand(tfm, &tls->srt[TLS_SE_EA], tls_vec(&l_v, rl, 11),
				     &h_v, &tls->srt[TLS_SE_REA]);
	if (err)
		return err;

	pr_debug("[TLS_HS] ea keys: %32phN, %32phN\n", tls->srt[TLS_SE_TEA].data,
		 tls->srt[TLS_SE_REA].data);
	return 0;
}

static int tls_hello_init(struct tls_hs *tls, struct tls_vec *x, struct tls_vec *y)
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

	if (!tls->is_serv && tls_vec_set(&tls->h.compress, (u8 *)&compress, 1))
		return -ENOMEM;

	return 0;
}

static int tls_msg_ch_build(struct tls_hs *tls)
{
	u8 *p, *len_p, *extlen_p, *psklen_p, *bin_p, bin[32], x[32], y[32];
	struct tls_vec vec, bin_v, x_v, y_v;
	struct tls_psk *psk;
	int err, len;

	err = tls_hello_init(tls, tls_vec(&x_v, x, 32), tls_vec(&y_v, y, 32));
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

		if (tls_vec_cpy(&tls->buf[TLS_B_CH], &tls->omsg))
			return -ENOMEM;
		pr_debug("[TLS_HS] client hello crt len: %u\n", tls->omsg.len);
		return 0;
	}

	p = tls_put_num(p, TLS_EXT_early_data, 2);
	p = tls_put_num(p, 0, 2);

	p = tls_put_num(p, TLS_EXT_psk_kex_modes, 2);
	p = tls_put_num(p, 2, 2);
	p = tls_put_num(p, 1, 1);
	p = tls_put_num(p, 1, 1); /* psk_dhe_ke */

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

	tls_vec(&vec, tls->omsg.data, (u32)(bin_p - 3 - tls->omsg.data));
	tls_vec(&bin_v, bin, 32);
	err = tls_bin_generate(tls, psk, &vec, &bin_v);
	if (err)
		return err;
	tls_put_data(bin_p, &bin_v);
	tls->omsg.len = (u32)(p - tls->omsg.data);

	if (tls_vec_cpy(&tls->buf[TLS_B_CH], &tls->omsg))
		return -ENOMEM;

	err = tls_keys_ea_setup(tls);
	if (err)
		return err;
	pr_debug("[TLS_HS] client hello len: %u\n", tls->omsg.len);
	return 0;
}

static int tls_msg_sh_build(struct tls_hs *tls, struct tls_vec *x, struct tls_vec *y)
{
	u8 *p, *len_p, *extlen_p;
	u32 len;

	p = tls->omsg.data;
	p = tls_put_num(p, TLS_MT_SERVER_HELLO, 1);
	len_p = p;
	p += 3; /* set length later */
	p = tls_put_num(p, TLS_MSG_legacy_version, 2);
	p = tls_put_data(p, &tls->h.random);
	p = tls_put_num(p, tls->h.session.len, 1);
	p = tls_put_data(p, &tls->h.session);
	p = tls_put_data(p, &tls->h.cipher);
	p = tls_put_num(p, tls->h.compress.len, 1);
	extlen_p = p;
	p += 2; /* set extension length later */

	p = tls_put_num(p, TLS_EXT_supported_versions, 2);
	p = tls_put_num(p, 2, 2);
	p = tls_put_num(p, TLS_MSG_version, 2);

	len = x->len + y->len;
	p = tls_put_num(p, TLS_EXT_key_share, 2);
	p = tls_put_num(p, len + 5, 2);
	p = tls_put_num(p, TLS_ECDHE_secp256r1, 2);
	p = tls_put_num(p, len + 1, 2);
	p = tls_put_num(p, 4, 1);
	p = tls_put_data(p, x);
	p = tls_put_data(p, y);

	if (tls->psks) {
		p = tls_put_num(p, TLS_EXT_early_data, 2);
		p = tls_put_num(p, 0, 2);

		p = tls_put_num(p, TLS_EXT_psk_kex_modes, 2);
		p = tls_put_num(p, 2, 2);
		p = tls_put_num(p, 1, 1);
		p = tls_put_num(p, 1, 1); /* psk_dhe_ke */

		p = tls_put_num(p, TLS_EXT_psk, 2);
		p = tls_put_num(p, 2, 2);
		p = tls_put_num(p, 0, 2);
	}

	tls_put_num(len_p, (u32)(p - len_p) - 3, 3);
	tls_put_num(extlen_p, (u32)(p - extlen_p) - 2, 2);
	tls->omsg.len = (u32)(p - tls->omsg.data);

	if (tls_vec_cpy(&tls->buf[TLS_B_SH], &tls->omsg))
		return -ENOMEM;

	pr_debug("[TLS_HS] server hello len: %u\n", tls->omsg.len);
	return 0;
}

static int tls_crtvfy_sign(struct tls_hs *tls, struct tls_vec *sig)
{
	u8 tlstbs[98 + 64], *p = tlstbs, *label, dig[32], h[32];
	struct crypto_shash *tfm = tls->hash_tfm;
	struct public_key_signature _s, *s = &_s;
	struct public_key _pkey, *pkey = &_pkey;
	struct tls_vec h_v, vec, dig_v;
	int err;

	if (tls->is_serv) {
		label = "TLS 1.3, server CertificateVerify";
		err = tls_crypto_hash(tfm, tls->buf, TLS_B_S_CRT + 1, tls_vec(&h_v, h, 32)); /* h6 */
		if (err)
			return err;
	} else {
		label = "TLS 1.3, client CertificateVerify";
		err = tls_crypto_hash(tfm, tls->buf, TLS_B_C_CRT + 1, tls_vec(&h_v, h, 32)); /* h8 */
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

	err = tls_crypto_signature_sign(tls->akc_tfm, pkey, s);
	return err;
}

static int tls_keys_ap_setup(struct tls_hs *tls)
{
	struct tls_vec dhs_v, z0_v, h_v, l_v = {"derived", 7};
	u8 zeros[32] = {0}, dhs[32], h[32], *rl, *tl;
	struct crypto_shash *tfm = tls->srt_tfm;
	int err;

	err = tls_crypto_hash(tls->hash_tfm, NULL, 0, tls_vec(&h_v, h, 32)); /* h0 */
	if (err)
		return err;
	err = tls_crypto_hkdf_expand(tfm, &tls->srt[TLS_SE_HS], &l_v,
				     &h_v, tls_vec(&dhs_v, dhs, 32));
	if (err)
		return err;

	err = tls_crypto_hkdf_extract(tfm, &dhs_v, tls_vec(&z0_v, zeros, 32),
				      &tls->srt[TLS_SE_MS]);
	if (err)
		return err;

	if (tls->is_serv) {
		rl = "c ap traffic";
		tl = "s ap traffic";
	} else {
		tl = "c ap traffic";
		rl = "s ap traffic";
	}

	err = tls_crypto_hash(tls->hash_tfm, tls->buf, TLS_B_S_FIN + 1, tls_vec(&h_v, h, 32)); /* h3 */
	if (err)
		return err;

	err = tls_crypto_hkdf_expand(tfm, &tls->srt[TLS_SE_MS], tls_vec(&l_v, tl, 12),
				     &h_v, &tls->srt[TLS_SE_TAP]);
	if (err)
		return err;
	err = tls_crypto_hkdf_expand(tfm, &tls->srt[TLS_SE_MS], tls_vec(&l_v, rl, 12),
				     &h_v, &tls->srt[TLS_SE_RAP]);
	if (err)
		return err;

	pr_debug("[TLS_HS] ap keys: %32phN, %32phN\n", tls->srt[TLS_SE_TAP].data,
		 tls->srt[TLS_SE_RAP].data);
	return 0;
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

	err = tls_crypto_hash(tls->hash_tfm, tls->buf, TLS_B_S_CRT_VFY + 1, tls_vec(&h_v, h, 32)); /* h7 */
	if (err)
		return err;

	err = tls_crypto_hkdf_extract(tls->srt_tfm, &fks_v, &h_v, sf);
	if (err)
		return err;

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
	if (tls->ext.len)
		p = tls_put_data(p, &tls->ext);
	tls_put_num(len_p, (u32)(p - len_p) - 3, 3);
	tls_put_num(extlen_p, (u32)(p - extlen_p) - 2, 2);
	msg.len = (u32)(p - msg.data);
	if (tls_vec_cpy(&tls->buf[TLS_B_EE], &msg))
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
		if (tls_vec_cpy(&tls->buf[TLS_B_CRT_REQ], &msg))
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
	if (tls_vec_cpy(&tls->buf[TLS_B_S_CRT], &msg))
		return -ENOMEM;

	err = tls_vec_alloc(&sig, 256);
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
	err = tls_vec_cpy(&tls->buf[TLS_B_S_CRT_VFY], &msg);
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
	err = tls_vec_cpy(&tls->buf[TLS_B_S_FIN], &msg);
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

static int tls_ext_supported_groups_handle(struct tls_hs *tls, u8 *p, u32 len)
{
	int i;

	for (i = 0; i < len; i += 2, p += 2)
		if (*((u16 *)p) == htons(TLS_ECDHE_secp256r1))
			return 0;

	return -ENOENT;
}

static int tls_ext_key_share_handle(struct tls_hs *tls, u8 *p, u32 len)
{
	struct tls_vec x_v, y_v;
	u8 *x, *y;
	u32 n;

	if (tls->is_serv)
		len = tls_get_num(&p, 2);
	n = tls_get_num(&p, 2);
	len = tls_get_num(&p, 2);
	p++; /* legacy_form = 4 */
	x = p;
	p += 32;
	y = p;

	return tls_crypto_ecdh_compute(tls->kpp_tfm, &tls->srt[TLS_SE_DHE],
				       tls_vec(&x_v, x, 32), tls_vec(&y_v, y, 32));
}

static int tls_ext_supported_versions_handle(struct tls_hs *tls, u8 *p, u32 len)
{
	int i, n = 2;

	if (tls->is_serv)
		n = tls_get_num(&p, 1);

	for (i = 0; i < n; i += 2, p += 2)
		if (*((u16 *)p) == htons(TLS_MSG_version))
			return 0;

	return -ENOENT;
}

static int tls_ext_psk_handle(struct tls_hs *tls, u8 *p, u32 len)
{
	struct tls_vec pskid, b, vec, bin_v;
	u32 id, pskid_len, age_add, b_len;
	struct tls_psk *psk;
	u8 bin[32];
	int err;

	if (!tls->is_serv) {
		id = tls_get_num(&p, 2);
		pr_debug("[TLS_HS] ext psk %u\n", id);
		return 0;
	}

	len = tls_get_num(&p, 2);
	pskid_len = tls_get_num(&p, 2);
	tls_vec(&pskid, p, pskid_len);
	p += pskid_len;
	age_add = tls_get_num(&p, 4);

	for (psk = tls->psks; psk; psk = psk->next)
		if (!tls_vec_cmp(&psk->id, &pskid))
			break;
	if (!psk)
		return -EINVAL;

	tls_vec(&vec, tls->imsg.data, (u32)(p - tls->imsg.data));
	len = tls_get_num(&p, 2);
	b_len = tls_get_num(&p, 1);
	tls_vec(&b, p, b_len);
	tls_vec(&bin_v, bin, 32);
	err = tls_bin_generate(tls, psk, &vec, &bin_v);
	if (err)
		return err;

	if (tls_vec_cmp(&b, &bin_v))
		return -EINVAL;

	return tls_keys_ea_setup(tls);
}

static int tls_ext_early_data_handle(struct tls_hs *tls, u8 *p, u32 len)
{
	u32 v;

	v = tls_get_num(&p, 4);
	pr_debug("[TLS_HS] ext max_early_data_size %u\n", v);

	return 0;
}

static int tls_ext_server_name_handle(struct tls_hs *tls, u8 *p, u32 len)
{
	char name[20] = {'\0'};

	memcpy(name, p, len);
	pr_debug("[TLS_HS] ext server_name %s\n", name);

	return 0;
}

static int tls_ext_ec_point_formats_handle(struct tls_hs *tls, u8 *p, u32 len)
{
	pr_debug("[TLS_HS] ext ec point: %x\n", *((u16 *)p));
	return 0;
}

static int tls_ext_session_ticket_handle(struct tls_hs *tls, u8 *p, u32 len)
{
	pr_debug("[TLS_HS] ext session_ticket\n");
	return 0;
}

static int tls_ext_application_layer_protocol_negotiation_handle(struct tls_hs *tls, u8 *p, u32 len)
{
	pr_debug("[TLS_HS] ext application_layer_protocol_negotiation\n");
	return 0;
}

static int tls_ext_encrypt_then_mac_handle(struct tls_hs *tls, u8 *p, u32 len)
{
	pr_debug("[TLS_HS] ext encrypt_then_mac\n");
	return 0;
}

static int tls_ext_extended_master_srt_handle(struct tls_hs *tls, u8 *p, u32 len)
{
	pr_debug("[TLS_HS] ext extended_master_srt\n");
	return 0;
}

static int tls_ext_signature_algorithms_handle(struct tls_hs *tls, u8 *p, u32 len)
{
	int i;

	len = tls_get_num(&p, 2);

	for (i = 0; i < len; i += 2)
		pr_debug("[TLS_HS] ext signature_algorithms %d: %x", i, *((u16 *)(p + i)));

	return 0;
}

static int tls_ext_psk_kex_modes_handle(struct tls_hs *tls, u8 *p, u32 len)
{
	int i, n;

	len = tls_get_num(&p, 1);
	for (i = 0; i < len; i++) {
		n = tls_get_num(&p, 1);
		if (n == 1) {
			pr_debug("[TLS_HS] ext psk_kex_modes psk_dhe_ke\n");
			return 0;
		}
	}
	pr_debug("[TLS_HS] ext psk_kex_modes not supported\n");
	return -EINVAL;
}

static int tls_ext_default_handle(struct tls_hs *tls, u8 *p, u32 len)
{
	p -= 4;
	len += 4;

	tls_vec_set(&tls->ext, p, len);
	return 0;
}

static int tls_ext_handle(struct tls_hs *tls, u8 *ext_p, u32 ext_len)
{
	u16 type, len;
	int ret;
	u8 *p;

	p = ext_p;
	while (1) {
		type = tls_get_num(&p, 2);
		len = tls_get_num(&p, 2);

		pr_debug("[TLS_HS] ext handle type %d len %d\n", type, len);
		switch (type) {
		case TLS_EXT_server_name:
			ret = tls_ext_server_name_handle(tls, p, len);
			break;
		case TLS_EXT_supported_groups:
			ret = tls_ext_supported_groups_handle(tls, p, len);
			break;
		case TLS_EXT_ec_point_formats:
			ret = tls_ext_ec_point_formats_handle(tls, p, len);
			break;
		case TLS_EXT_signature_algorithms:
			ret = tls_ext_signature_algorithms_handle(tls, p, len);
			break;
		case TLS_EXT_application_layer_protocol_negotiation:
			ret = tls_ext_application_layer_protocol_negotiation_handle(tls, p, len);
			break;
		case TLS_EXT_encrypt_then_mac:
			ret = tls_ext_encrypt_then_mac_handle(tls, p, len);
			break;
		case TLS_EXT_extended_master_srt:
			ret = tls_ext_extended_master_srt_handle(tls, p, len);
			break;
		case TLS_EXT_session_ticket:
			ret = tls_ext_session_ticket_handle(tls, p, len);
			break;
		case TLS_EXT_psk:
			ret = tls_ext_psk_handle(tls, p, len);
			break;
		case TLS_EXT_early_data:
			ret = tls_ext_early_data_handle(tls, p, len);
			break;
		case TLS_EXT_supported_versions:
			ret = tls_ext_supported_versions_handle(tls, p, len);
			break;
		case TLS_EXT_psk_kex_modes:
			ret = tls_ext_psk_kex_modes_handle(tls, p, len);
			break;
		case TLS_EXT_key_share:
			ret = tls_ext_key_share_handle(tls, p, len);
			break;
		default:
			ret = tls_ext_default_handle(tls, p, len);
			break;
		}
		if (ret) {
			pr_err("[TLS_HS] ext handle err %d\n", ret);
			return ret;
		}
		p += len;
		if ((u32)(p - ext_p) >= ext_len)
			break;
	}
	return 0;
}

static int tls_keys_hs_setup(struct tls_hs *tls)
{
	struct tls_vec des_v, h_v, l_v = {"derived", 7};
	struct crypto_shash *tfm = tls->srt_tfm;
	u8 des[32], h[32], *rl, *tl;
	int err;

	err = tls_crypto_hash(tls->hash_tfm, NULL, 0, tls_vec(&h_v, h, 32)); /* h0 */
	if (err)
		return err;

	err = tls_crypto_hkdf_expand(tfm, &tls->srt[TLS_SE_EA], &l_v,
				     &h_v, tls_vec(&des_v, des, 32));
	if (err)
		return err;

	err = tls_crypto_hkdf_extract(tfm, &des_v, &tls->srt[TLS_SE_DHE],
				      &tls->srt[TLS_SE_HS]);
	if (err)
		return err;

	if (tls->is_serv) {
		rl = "c hs traffic";
		tl = "s hs traffic";
	} else {
		tl = "c hs traffic";
		rl = "s hs traffic";
	}

	err = tls_crypto_hash(tls->hash_tfm, tls->buf, TLS_B_SH + 1, tls_vec(&h_v, h, 32)); /* h2 */
	if (err)
		return err;

	err = tls_crypto_hkdf_expand(tfm, &tls->srt[TLS_SE_HS], tls_vec(&l_v, tl, 12),
				     &h_v, &tls->srt[TLS_SE_THS]);
	if (err)
		return err;
	err = tls_crypto_hkdf_expand(tfm, &tls->srt[TLS_SE_HS], tls_vec(&l_v, rl, 12),
				     &h_v, &tls->srt[TLS_SE_RHS]);
	if (err)
		return err;

	pr_debug("[TLS_HS] hs keys: %32phN, %32phN\n", tls->srt[TLS_SE_THS].data,
		 tls->srt[TLS_SE_RHS].data);
	return 0;
}

static int tls_msg_ch_handle(struct tls_hs *tls, u8 *p, u32 len)
{
	struct tls_vec x_v, y_v;
	u8 x[32], y[32];
	u32 n, i;
	int err;

	if (tls_vec_set(&tls->buf[TLS_B_CH], p - 4, len + 4))
		return -ENOMEM;

	n = tls_get_num(&p, 2);
	p += 32;
	len = tls_get_num(&p, 1);
	p += len;
	len = tls_get_num(&p, 2);
	for (i = 0; i < len; i += 2)
		pr_debug("[TLS_HS] msg ch cipher %d: %x\n", i, *((u16 *)(p + i)));
	p += len;
	len = tls_get_num(&p, 1);
	p += len;

	err = tls_hello_init(tls, tls_vec(&x_v, x, 32), tls_vec(&y_v, y, 32));
	if (err)
		return err;

	len = tls_get_num(&p, 2);
	if (!len)
		return -EINVAL;
	err = tls_ext_handle(tls, p, len);
	if (err)
		return err;

	err = tls_msg_sh_build(tls, &x_v, &y_v);
	if (err)
		return err;

	err = tls_keys_hs_setup(tls);
	if (err)
		return err;

	tls->state = TLS_ST_RCVD;
	return 0;
}

static int tls_msg_sh_handle(struct tls_hs *tls, u8 *p, u32 len)
{
	int err;
	u32 n;

	if (tls_vec_set(&tls->buf[TLS_B_SH], p - 4, len + 4))
		return -ENOMEM;

	n = tls_get_num(&p, 2);
	p += 32;
	len = tls_get_num(&p, 1);
	p += len;
	n = tls_get_num(&p, 2);
	len = tls_get_num(&p, 1);
	p += len;

	len = tls_get_num(&p, 2);
	if (!len)
		return -EINVAL;
	err = tls_ext_handle(tls, p, len);
	if (err)
		return err;

	err = tls_keys_hs_setup(tls);
	if (err)
		return err;

	tls->state = TLS_ST_RCVD;
	return 0;
}

static int tls_msg_ee_handle(struct tls_hs *tls, u8 *p, u32 len)
{
	int err;

	if (tls_vec_set(&tls->buf[TLS_B_EE], p - 4, len + 4))
		return -ENOMEM;

	len = tls_get_num(&p, 2);
	if (!len)
		return -EINVAL;

	err = tls_ext_handle(tls, p, len);
	if (err)
		return err;

	tls->state = TLS_ST_WAIT;
	return 0;
}

static int tls_crypto_crt_verify(struct tls_hs *tls)
{
	struct tls_crt *crts = tls->rcrts;
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

static int tls_msg_crt_handle(struct tls_hs *tls, u8 *p, u32 len)
{
	struct tls_crt *c, *crts = NULL, *prev;
	struct tls_vec v;
	u8 *crt_p, t;
	u32 clen;

	t = tls->is_serv ? TLS_B_C_CRT : TLS_B_S_CRT;
	if (tls_vec_set(&tls->buf[t], p - 4, len + 4))
		return -ENOMEM;
	p++;
	clen = tls_get_num(&p, 3);
	crt_p = p;
	pr_debug("[TLS_HS] crt total len %u\n", clen);
	while (1) {
		len = tls_get_num(&p, 3);
		pr_debug("[TLS_HS] crt one len %u\n", len);
		tls_vec(&v, p, len);
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
		p += len;
		len = tls_get_num(&p, 2);
		p += len;

		if ((u32)(p - crt_p) >= clen)
			break;
	}

	tls->rcrts = crts;

	return tls_crypto_crt_verify(tls);
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

static int tls_crtvfy_verify(struct tls_hs *tls, struct tls_vec *sig)
{
	u8 tlstbs[98 + 64], *p = tlstbs, *label, dig[32], h[32];
	struct x509_certificate *x = tls->rcrts->x509;
        struct crypto_shash *tfm = tls->hash_tfm;
        struct public_key_signature _s, *s = &_s;
        struct tls_vec h_v, vec, dig_v;
        int err;

	if (tls->is_serv) {
		label = "TLS 1.3, client CertificateVerify";
		err = tls_crypto_hash(tfm, tls->buf, TLS_B_C_CRT + 1, tls_vec(&h_v, h, 32)); /* h8 */
		if (err)
			return err;
	} else {
		label = "TLS 1.3, server CertificateVerify";
		err = tls_crypto_hash(tfm, tls->buf, TLS_B_S_CRT + 1, tls_vec(&h_v, h, 32)); /* h6 */
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

static int tls_msg_crtvfy_handle(struct tls_hs *tls, u8 *p, u32 len)
{
	struct tls_vec sig = {NULL, 0};
	u32 n, t;
	int err;

	t = tls->is_serv ? TLS_B_C_CRT_VFY : TLS_B_S_CRT_VFY;
	if (tls_vec_set(&tls->buf[t], p - 4, len + 4))
		return -ENOMEM;

	n = tls_get_num(&p, 2);

	len = tls_get_num(&p, 2);
	if (tls_vec_set(&sig, p, len))
		return -ENOMEM;
	p += len;

	err = tls_crtvfy_verify(tls, &sig);
	if (err)
		return err;

	kfree(sig.data);
	return 0;
}

static int tls_msg_crtreq_handle(struct tls_hs *tls, u8 *p, u32 len)
{
	if (tls_vec_set(&tls->buf[TLS_B_CRT_REQ], p - 4, len + 4))
		return -ENOMEM;

	len = tls_get_num(&p, 1);
	p += len;

	len = tls_get_num(&p, 2);
	if (!len)
		return -EINVAL;

	tls->crt_req = 1;

	return tls_ext_handle(tls, p, len);
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

	err = tls_crypto_hash(tls->hash_tfm, tls->buf, TLS_B_C_CRT_VFY + 1, tls_vec(&h_v, h, 32)); /* h9 */
	if (err)
		return err;

	err = tls_crypto_hkdf_extract(tls->srt_tfm, &fks_v, &h_v, cf);
	if (err)
		return err;

	return 0;
}

static int tls_keys_rm_setup(struct tls_hs *tls)
{
	struct tls_vec h_v, l_v = {"res master", 10};
	u8 h[32];
	int err;

	err = tls_crypto_hash(tls->hash_tfm, tls->buf, TLS_B_C_FIN + 1, tls_vec(&h_v, h, 32)); /* h4 */
	if (err)
		return err;

	return tls_crypto_hkdf_expand(tls->srt_tfm, &tls->srt[TLS_SE_MS], &l_v, &h_v,
				      &tls->srt[TLS_SE_RMS]);
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
	if (tls_vec_cpy(&tls->buf[TLS_B_C_CRT], &msg))
		return -ENOMEM;

	err = tls_vec_alloc(&sig, 256);
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
	err = tls_vec_cpy(&tls->buf[TLS_B_C_CRT_VFY], &msg);
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
	err = tls_vec_cpy(&tls->buf[TLS_B_C_FIN], &tls->omsg);
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

static int tls_msg_sfin_handle(struct tls_hs *tls, u8 *p, u32 len)
{
	struct tls_vec sf_v;
	u8 sf[32];
	int err;

	if (tls_vec_set(&tls->buf[TLS_B_S_FIN], p - 4, len + 4))
		return -ENOMEM;

	err = tls_sf_generate(tls, tls_vec(&sf_v, sf, 32));
	if (err)
		return err;
	if (sf_v.len != len || memcmp(sf_v.data, p, len))
		return -EINVAL;

	return tls_msg_cfin_build(tls);
}

static int tls_msg_cfin_handle(struct tls_hs *tls, u8 *p, u32 len)
{
	struct tls_vec cf_v;
	u8 cf[32];
	int err;

	if (tls_vec_set(&tls->buf[TLS_B_C_FIN], p - 4, len + 4))
		return -ENOMEM;

	err = tls_cf_generate(tls, tls_vec(&cf_v, cf, 32));
	if (err)
		return err;
	if (cf_v.len != len || memcmp(cf_v.data, p, len))
		return -EINVAL;

	err = tls_keys_rm_setup(tls);
	if (err)
		return err;
	tls->state = TLS_ST_CONNECTED;
	return 0;
}

static int tls_msg_fin_handle(struct tls_hs *tls, u8 *p, u32 len)
{
	if (!tls->is_serv)
		return tls_msg_sfin_handle(tls, p, len);

	return tls_msg_cfin_handle(tls, p, len);
}

static int tls_msg_ticket_handle(struct tls_hs *tls, u8 *p, u32 len)
{
	struct tls_vec id, nonce;
	u32 lifetime, age_add;
	struct tls_psk *psk;
	int err;

	lifetime = tls_get_num(&p, 4);
        age_add = tls_get_num(&p, 4);
	pr_debug("[TLS_HS] new session %u %u\n", age_add, lifetime);

        len = tls_get_num(&p, 1);
	tls_vec(&nonce, p, len);
        p += len;

        len = tls_get_num(&p, 2);
	tls_vec(&id, p, len);
        p += len;

	psk = tls_psk_new(&id, &tls->srt[TLS_SE_RMS], &nonce, age_add, lifetime);
	if (!psk)
		return -ENOMEM;
	if (tls->psks)
		psk->next = tls->psks;
	tls->psks = psk;

	len = tls_get_num(&p, 2);
	if (!len)
		return TLS_P_TICKET;

	err = tls_ext_handle(tls, p, len);
	if (err)
		return err;

	return TLS_P_TICKET;
}

static int tls_ku_build(struct tls_hs *tls, struct tls_vec *l, u8 req)
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

static int tls_msg_ku_handle(struct tls_hs *tls, u8 *p, u32 len)
{
	int err;
	u8 req;

	req = tls_get_num(&p, 1);
	if (req) {
		err = tls_ku_build(tls, NULL, 0);
		if (err)
			return err;
	}
	return TLS_P_KEY_UPDATE;
}

static int tls_msg_handle(struct tls_hs *tls, struct tls_vec *imsg)
{
	int ret = 0, len, remain;
	u8 *p, type;

	if (tls->cmsg.len) {
		pr_debug("[TLS_HS] msg handle recovered %d %d\n", tls->cmsg.len, imsg->len);
		*imsg = *tls_vec_add(&tls->cmsg, imsg);
	}

	tls->imsg = *imsg;
	p = imsg->data;
	remain = imsg->len;
	while (1) {
		if (remain < 4) {
			pr_debug("[TLS_HS] msg handle buffered with no hdr %d\n", remain);
			tls_vec_set(&tls->cmsg, p, remain);
			break;
		}
		type = tls_get_num(&p, 1);
		len = tls_get_num(&p, 3);
		if (remain < len + 4) {
			pr_debug("[TLS_HS] msg handle buffered %d %d %d\n", type, len, remain);
			tls_vec_set(&tls->cmsg, p - 4, remain);
			break;
		}
		pr_debug("[TLS_HS] msg handle type %d len %d\n", type, len);
		switch (type) {
		case TLS_MT_CLIENT_HELLO:
			ret = tls_msg_ch_handle(tls, p, len);
			break;
		case TLS_MT_SERVER_HELLO:
			ret = tls_msg_sh_handle(tls, p, len);
			break;
		case TLS_MT_ENCRYPTED_EXTENSIONS:
			ret = tls_msg_ee_handle(tls, p, len);
			break;
		case TLS_MT_CERTIFICATE:
			ret = tls_msg_crt_handle(tls, p, len);
			break;
		case TLS_MT_CERTIFICATE_REQUEST:
			ret = tls_msg_crtreq_handle(tls, p, len);
			break;
		case TLS_MT_CERTIFICATE_VERIFY:
			ret = tls_msg_crtvfy_handle(tls, p, len);
			break;
		case TLS_MT_FINISHED:
			ret = tls_msg_fin_handle(tls, p, len);
			break;
		case TLS_MT_NEWSESSION_TICKET:
			ret = tls_msg_ticket_handle(tls, p, len);
			break;
		case TLS_MT_KEY_UPDATE:
			ret = tls_msg_ku_handle(tls, p, len);
			break;
		default:
			ret = EPROTONOSUPPORT;
			break;
		}

		if (ret) {
			pr_err("[TLS_HS] msg handle err %d\n", ret);
			break;
		}

		p += len;
		remain = imsg->len - (int)(p - imsg->data);
		if (remain <= 0) {
			tls->cmsg.len = 0;
			break;
		}
	}
	return ret ?: tls->state;
}

int tls_handshake(struct tls_hs *tls, struct tls_vec *imsg, struct tls_vec *omsg)
{
	int ret = -EINVAL;

	tls->omsg.len = 0;

	if (imsg) {
		ret = tls_msg_handle(tls, imsg);
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
	*omsg = tls->omsg;
	return ret;
}
EXPORT_SYMBOL_GPL(tls_handshake);

static int tls_ticket_build(struct tls_hs *tls, struct tls_vec *id)
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

int tls_handshake_post(struct tls_hs *tls, u8 type, struct tls_vec *imsg, struct tls_vec *omsg)
{
	int ret = -EINVAL;

	tls->omsg.len = 0;
	if (type == TLS_P_NONE)
		ret = tls_msg_handle(tls, imsg);
	else if (type == TLS_P_TICKET)
		ret = tls_ticket_build(tls, imsg);
	else if (type == TLS_P_KEY_UPDATE)
		ret = tls_ku_build(tls, imsg, 1);
	*omsg = tls->omsg;
	return ret;
}
EXPORT_SYMBOL_GPL(tls_handshake_post);

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
	while (p->next)
		p = p->next;
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

int tls_handshake_set(struct tls_hs *tls, u8 type, struct tls_vec *vec)
{
	int ret = 0;

	switch (type) {
	case TLS_T_CA:
		ret = tls_set_ca(tls, vec);
		break;
	case TLS_T_CRTS:
		ret = tls_set_crts(tls, vec);
		break;
	case TLS_T_PKEY:
		return tls_vec_cpy(&tls->pkey, vec);
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
	}
	return ret;
}
EXPORT_SYMBOL_GPL(tls_handshake_set);

static int tls_get_psk(struct tls_hs *tls, struct tls_vec *vec)
{
	struct tls_psk *psk;
	u32 len = 0;
	u8 *p;

	if (!tls->psks)
		return 0;
	for (psk = tls->psks; psk; psk = psk->next)
		len += (20 + psk->id.len + psk->key.len + psk->nonce.len);

	if (tls_vec_alloc(vec, len))
		return -ENOMEM;

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
	}

	return 0;
}

static int tls_get_crts(struct tls_hs *tls, struct tls_vec *vec)
{
	struct tls_crt *c;
	u32 len = 0;
	u8 *p;

	if (!tls->tcrts)
		return 0;
	for (c = tls->tcrts; c; c = c->next)
		len += 4 + c->raw.len;

	if (tls_vec_alloc(vec, len))
		return -ENOMEM;

	p = vec->data;
	for (c = tls->tcrts; c; c = c->next) {
		*((u32 *)p) = c->raw.len;
		p += 4;
		p = tls_put_data(p, &c->raw);
	}

	return 0;
}

int tls_handshake_get(struct tls_hs *tls, u8 type, struct tls_vec *vec)
{
	int ret = 0;

	switch (type) {
	case TLS_T_MSG:
		*vec = tls->omsg;
		break;
	case TLS_T_EXT:
		*vec = tls->ext;
		break;
	case TLS_T_THS:
		*vec = tls->srt[TLS_SE_THS];
		break;
	case TLS_T_RHS:
		*vec = tls->srt[TLS_SE_RHS];
		break;
	case TLS_T_TAP:
		*vec = tls->srt[TLS_SE_TAP];
		break;
	case TLS_T_RAP:
		*vec = tls->srt[TLS_SE_RAP];
		break;
	case TLS_T_TEA:
		*vec = tls->srt[TLS_SE_TEA];
		break;
	case TLS_T_REA:
		*vec = tls->srt[TLS_SE_REA];
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

	tls_psk_free(tls->psks);
	tls_crt_free(tls->tcrts);
	tls_crt_free(tls->rcrts);
	tls_crt_free(tls->ca);
	kfree(tls->pkey.data);

	crypto_free_kpp(tls->kpp_tfm);
	crypto_free_shash(tls->hash_tfm);
	crypto_free_shash(tls->srt_tfm);
	crypto_free_akcipher(tls->akc_tfm);

	kfree(tls);
}
EXPORT_SYMBOL_GPL(tls_handshake_destroy);
