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

static int quic_crypto_keys_derive(struct quic_sock *qs, struct tls_vec *s, struct tls_vec *k,
				     struct tls_vec *i, struct tls_vec *hp_k)
{
	struct tls_vec hp_k_l = {"quic hp", 7}, k_l = {"quic key", 8}, i_l = {"quic iv", 7};
	int err;

	err = tls_hkdf_expand(qs->tls, s, &k_l, k);
	if (err)
		return err;
	err = tls_hkdf_expand(qs->tls, s, &i_l, i);
	if (err)
		return err;

	if (qs->state == QUIC_CS_CLIENT_POST_HANDSHAKE ||
	    qs->state == QUIC_CS_SERVER_POST_HANDSHAKE)
		return 0;

	return tls_hkdf_expand(qs->tls, s, &hp_k_l, hp_k);
}

static int quic_crypto_hd_encrypt(struct quic_sock *qs, struct sk_buff *skb, u8 *tx_hp_key)
{
	struct skcipher_request *req;
	struct crypto_skcipher *tfm;
	u8 mask[QUIC_KEYLEN], *p;
	struct scatterlist sg;
	int err, i;

	tfm = qs->crypt.skc_tfm;
	err = crypto_skcipher_setkey(tfm, tx_hp_key, QUIC_KEYLEN);
	if (err)
		return err;
	req = skcipher_request_alloc(tfm, 0);
	if (!req)
		return -ENOMEM;

	memcpy(mask, skb->data + qs->packet.pn_off + 4, QUIC_KEYLEN);
	sg_init_one(&sg, mask, QUIC_KEYLEN);
	skcipher_request_set_crypt(req, &sg, &sg, QUIC_KEYLEN, NULL);
	err = crypto_skcipher_encrypt(req);
	if (err)
		goto err;

	p = skb->data;
	*p = (uint8_t)(*p ^ (mask[0] & (((*p & 0x80) == 0x80) ? 0x0f : 0x1f)));
	p = skb->data + qs->packet.pn_off;
	for (i = 1; i <= qs->packet.pn_len; i++)
		*p++ ^= mask[i];
err:
	skcipher_request_free(req);
	return err;
}

static void *quic_crypto_aead_mem_alloc(struct crypto_aead *tfm, u8 **iv,
					struct aead_request **req,
					struct scatterlist **sg, int nsg)
{
	unsigned int iv_size, req_size;
	unsigned int len;
	u8 *mem;

	iv_size = crypto_aead_ivsize(tfm);
	req_size = sizeof(**req) + crypto_aead_reqsize(tfm);

	len = iv_size;
	len += crypto_aead_alignmask(tfm) & ~(crypto_tfm_ctx_alignment() - 1);
	len = ALIGN(len, crypto_tfm_ctx_alignment());
	len += req_size;
	len = ALIGN(len, __alignof__(struct scatterlist));
	len += nsg * sizeof(**sg);

	mem = kmalloc(len, GFP_ATOMIC);
	if (!mem)
		return NULL;

	*iv = (u8 *)PTR_ALIGN(mem, crypto_aead_alignmask(tfm) + 1);
	*req = (struct aead_request *)PTR_ALIGN(*iv + iv_size,
			crypto_tfm_ctx_alignment());
	*sg = (struct scatterlist *)PTR_ALIGN((u8 *)*req + req_size,
			__alignof__(struct scatterlist));

	return (void *)mem;
}

int quic_crypto_retry_encrypt(struct quic_sock *qs, u8 *in, u32 len, u8 *out)
{
	static u8 tx_key[16] = "\xbe\x0c\x69\x0b\x9f\x66\x57\x5a\x1d\x76\x6b\x54\xe3\x68\xc8\x4e";
	static u8 tx_iv[12] = "\x46\x15\x99\xd3\x5d\x63\x2b\xf2\x23\x98\x25\xbb";
	struct aead_request *req;
	struct crypto_aead *tfm;
	struct scatterlist *sg;
	void *ctx;
	int err;
	u8 *iv;

	tfm = qs->crypt.aead_tfm;
	err = crypto_aead_setauthsize(tfm, QUIC_TAGLEN);
	if (err)
		return err;
	err = crypto_aead_setkey(tfm, tx_key, QUIC_KEYLEN);
	if (err)
		return err;

	ctx = quic_crypto_aead_mem_alloc(tfm, &iv, &req, &sg, 2);
	if (!ctx)
		return err;

	sg_init_table(sg, 2);
	sg_set_buf(&sg[0], in, len);
	sg_set_buf(&sg[1], out, 16);

	memcpy(iv, tx_iv, QUIC_IVLEN);
	aead_request_set_tfm(req, tfm);
	aead_request_set_ad(req, len);
	aead_request_set_crypt(req, sg, sg, 0, iv);
	err = crypto_aead_encrypt(req);

	kfree(ctx);
	return err;
}

static int quic_crypto_pd_encrypt(struct quic_sock *qs, struct sk_buff *skb, u8 *tx_key, u8 *tx_iv)
{
	struct aead_request *req;
	struct crypto_aead *tfm;
	struct sk_buff *trailer;
	int nsg, err, hlen, len;
	struct scatterlist *sg;
	void *ctx;
	u8 *iv, i;
	__be64 n;

	tfm = qs->crypt.aead_tfm;
	err = crypto_aead_setauthsize(tfm, QUIC_TAGLEN);
	if (err)
		return err;
	err = crypto_aead_setkey(tfm, tx_key, QUIC_KEYLEN);
	if (err)
		return err;

	len = skb->len;
	nsg = skb_cow_data(skb, QUIC_TAGLEN, &trailer);
	if (nsg < 0)
		goto err;
	pskb_put(skb, trailer, QUIC_TAGLEN);

	ctx = quic_crypto_aead_mem_alloc(tfm, &iv, &req, &sg, nsg);
	if (!ctx)
		return err;

	sg_init_table(sg, nsg);
	err = skb_to_sgvec(skb, sg, 0, skb->len);
	if (err < 0)
		goto err;

	hlen = qs->packet.pn_off + qs->packet.pn_len;
	memcpy(iv, tx_iv, QUIC_IVLEN);
	n = cpu_to_be64(qs->packet.pn);
	for (i = 0; i < 8; i++)
		iv[QUIC_IVLEN - 8 + i] ^= ((u8 *)&n)[i];

	aead_request_set_tfm(req, tfm);
	aead_request_set_ad(req, hlen);
	aead_request_set_crypt(req, sg, sg, len - hlen, iv);
	err = crypto_aead_encrypt(req);

err:
	kfree(ctx);
	return err;
}

static int quic_crypto_pd_decrypt(struct quic_sock *qs, struct sk_buff *skb, u8 *rx_key, u8 *rx_iv)
{
	struct aead_request *req;
	struct crypto_aead *tfm;
	struct sk_buff *trailer;
	int nsg, hlen, len, err;
	struct scatterlist *sg;
	void *ctx;
	u8 *iv, i;
	__be64 n;

	tfm = qs->crypt.aead_tfm;
	err = crypto_aead_setauthsize(tfm, QUIC_TAGLEN);
	if (err)
		return err;
	err = crypto_aead_setkey(tfm, rx_key, QUIC_KEYLEN);
	if (err)
		return err;

	len = qs->packet.pn_off + qs->packet.pd_len;
	nsg = skb_cow_data(skb, 0, &trailer);
	if (nsg < 0)
		return err;
	ctx = quic_crypto_aead_mem_alloc(tfm, &iv, &req, &sg, nsg);
	if (!ctx)
		return err;

	sg_init_table(sg, nsg);
	err = skb_to_sgvec(skb, sg, 0, len);
	if (err < 0)
		goto err;

	hlen = qs->packet.pn_off + qs->packet.pn_len;
	memcpy(iv, rx_iv, QUIC_IVLEN);
	n = cpu_to_be64(qs->packet.pn);
	for (i = 0; i < 8; i++)
		iv[QUIC_IVLEN - 8 + i] ^= ((u8 *)&n)[i];

	aead_request_set_tfm(req, tfm);
	aead_request_set_ad(req, hlen);
	aead_request_set_crypt(req, sg, sg, len - hlen, iv);
	err = crypto_aead_decrypt(req);

err:
	kfree(ctx);
	return err;
}

static int quic_crypto_hd_decrypt(struct quic_sock *qs, struct sk_buff *skb, u8 *rx_hp_key)
{
	struct quic_lhdr *hdr = quic_lhdr(skb);
	struct skcipher_request *req;
	struct crypto_skcipher *tfm;
	u8 mask[QUIC_KEYLEN], *p;
	struct scatterlist sg;
	int err, i;

	tfm = qs->crypt.skc_tfm;
	err = crypto_skcipher_setkey(tfm, rx_hp_key, QUIC_KEYLEN);
	if (err)
		return err;
	req = skcipher_request_alloc(tfm, 0);
	if (!req)
		return -ENOMEM;

	p = (u8 *)hdr + qs->packet.pn_off;
	memcpy(mask, p + 4, QUIC_KEYLEN);
	sg_init_one(&sg, mask, QUIC_KEYLEN);
	skcipher_request_set_crypt(req, &sg, &sg, QUIC_KEYLEN, NULL);
	err = crypto_skcipher_encrypt(req);
	if (err)
		goto err;

	p = (u8 *)hdr;
	*p = (u8)(*p ^ (mask[0] & (((*p & 0x80) == 0x80) ? 0x0f : 0x1f)));
	qs->packet.pn_len = (*p & 0x03) + 1;
	p += qs->packet.pn_off;
	for (i = 0; i < qs->packet.pn_len; ++i)
		*(p + i) = *((u8 *)hdr + qs->packet.pn_off + i) ^ mask[i + 1];

	qs->packet.pn = quic_get_fixint(&p, qs->packet.pn_len);

err:
	skcipher_request_free(req);
	return 0;
}

int quic_crypto_encrypt(struct quic_sock *qs, struct sk_buff *skb, u8 type)
{
	u8 *key, *iv, *hp_key, k;
	int err;

	if (type == QUIC_PKT_INITIAL) {
		key = qs->crypt.tx_key;
		iv = qs->crypt.tx_iv;
		hp_key = qs->crypt.tx_hp_key;
	} else if (type == QUIC_PKT_0RTT) {
		key = qs->crypt.l1_tx_key;
		iv = qs->crypt.l1_tx_iv;
		hp_key = qs->crypt.l1_tx_hp_key;
	} else if (type == QUIC_PKT_HANDSHAKE) {
		key = qs->crypt.l2_tx_key;
		iv = qs->crypt.l2_tx_iv;
		hp_key = qs->crypt.l2_tx_hp_key;
	} else if (type == QUIC_PKT_SHORT) {
		k = qs->crypt.key_phase;
		key = qs->crypt.l3_tx_key[k];
		iv = qs->crypt.l3_tx_iv[k];
		hp_key = qs->crypt.l3_tx_hp_key;
	} else {
		return 0;
	}

	err = quic_crypto_pd_encrypt(qs, skb, key, iv);
	if (err)
		return err;

	return quic_crypto_hd_encrypt(qs, skb, hp_key);
}

int quic_crypto_decrypt(struct quic_sock *qs, struct sk_buff *skb, u8 type)
{
	u8 *key, *iv, *hp_key;
	struct quic_shdr *hdr;
	int err;

	if (type == QUIC_PKT_INITIAL) {
		key = qs->crypt.rx_key;
		iv = qs->crypt.rx_iv;
		hp_key = qs->crypt.rx_hp_key;
	} else if (type == QUIC_PKT_0RTT) {
		key = qs->crypt.l1_rx_key;
		iv = qs->crypt.l1_rx_iv;
		hp_key = qs->crypt.l1_rx_hp_key;
	} else if (type == QUIC_PKT_HANDSHAKE) {
		key = qs->crypt.l2_rx_key;
		iv = qs->crypt.l2_rx_iv;
		hp_key = qs->crypt.l2_rx_hp_key;
	} else if (type == QUIC_PKT_SHORT) {
		hp_key = qs->crypt.l3_rx_hp_key;
	} else {
		return 0;
	}

	err = quic_crypto_hd_decrypt(qs, skb, hp_key);
	if (err) {
		pr_warn("[QUIC] hd decrypt err %d\n", err);
		return err;
	}

	hdr = quic_shdr(skb);
	if (hdr->key != qs->crypt.key_phase) {
		if (!qs->crypt.key_pending) {
			err = quic_crypto_key_update(qs);
			if (err)
				return err;
			qs->crypt.key_pending = 1;
		}
	} else {
		if (qs->crypt.key_pending == 1) {
			u32 value[3] = {0};

			qs->crypt.key_pending = 0;
			value[0] = qs->crypt.key_phase;
			err = quic_evt_notify(qs, QUIC_EVT_KEY, QUIC_EVT_KEY_NEW, value);
			if (err)
				return err;
		}
	}

	if (type == QUIC_PKT_SHORT) {
		key = qs->crypt.l3_rx_key[hdr->key];
		iv = qs->crypt.l3_rx_iv[hdr->key];
	}

	return quic_crypto_pd_decrypt(qs, skb, key, iv);
}

int quic_crypto_initial_keys_install(struct quic_sock *qs)
{
	struct tls_vec salt = {"\x38\x76\x2c\xf7\xf5\x59\x34\xb3\x4d\x17\x9a\xe6\xa4\xc8\x0c\xad\xcc\xbb\x7f\x0a", 20};
	struct tls_vec srt_v, i_srt_v, l_v, dcid, k, iv, hp_k;
	u8 i_srt[32], srt[32];
	struct quic_cid *cid;
	char *tl, *rl;
	int err;

	if (qs->crypt.is_serv) {
		rl = "client in";
		tl = "server in";
		cid = qs->cids.scid.list;
	} else {
		tl = "client in";
		rl = "server in";
		cid = qs->cids.dcid.list;
	}
	tls_vec(&dcid, cid->id, cid->len);
	tls_vec(&srt_v, srt, 32);
	tls_vec(&i_srt_v, i_srt, 32);
	err = tls_hkdf_extract(qs->tls, &salt, &dcid, &srt_v);
	if (err)
		return err;

	tls_vec(&l_v, tl, 9);
	err = tls_hkdf_expand(qs->tls, &srt_v, &l_v, &i_srt_v);
	if (err)
		return err;

	tls_vec(&k, qs->crypt.tx_key, 16);
	tls_vec(&iv, qs->crypt.tx_iv, 12);
	tls_vec(&hp_k, qs->crypt.tx_hp_key, 16);
	err = quic_crypto_keys_derive(qs, &i_srt_v, &k, &iv, &hp_k);
	if (err)
		return err;
	pr_debug("[QUIC] in tx keys: %16phN, %12phN, %16phN\n", k.data, iv.data, hp_k.data);

	tls_vec(&l_v, rl, 9);
	err = tls_hkdf_expand(qs->tls, &srt_v, &l_v, &i_srt_v);
	if (err)
		return err;

	tls_vec(&k, qs->crypt.rx_key, 16);
	tls_vec(&iv, qs->crypt.rx_iv, 12);
	tls_vec(&hp_k, qs->crypt.rx_hp_key, 16);
	err = quic_crypto_keys_derive(qs, &i_srt_v, &k, &iv, &hp_k);
	if (err)
		return err;
	pr_debug("[QUIC] in rx keys: %16phN, %12phN, %16phN\n", k.data, iv.data, hp_k.data);
	return 0;
}

int quic_crypto_early_keys_install(struct quic_sock *qs)
{
	struct tls_vec srt = {NULL, 0}, k, iv, hp_k;
	int err;

	err = tls_handshake_get(qs->tls, TLS_T_TEA, &srt);
	if (err)
		return err;

	tls_vec(&k, qs->crypt.l1_tx_key, 16);
	tls_vec(&iv, qs->crypt.l1_tx_iv, 12);
	tls_vec(&hp_k, qs->crypt.l1_tx_hp_key, 16);
	err = quic_crypto_keys_derive(qs, &srt, &k, &iv, &hp_k);
	if (err)
		return err;
	pr_debug("[QUIC] ea tx keys: %16phN, %12phN, %16phN\n", k.data, iv.data, hp_k.data);

	err = tls_handshake_get(qs->tls, TLS_T_REA, &srt);
	if (err)
		return err;

	tls_vec(&k, qs->crypt.l1_rx_key, 16);
	tls_vec(&iv, qs->crypt.l1_rx_iv, 12);
	tls_vec(&hp_k, qs->crypt.l1_rx_hp_key, 16);
	err = quic_crypto_keys_derive(qs, &srt, &k, &iv, &hp_k);
	if (err)
		return err;
	pr_debug("[QUIC] ea rx keys: %16phN, %12phN, %16phN\n", k.data, iv.data, hp_k.data);
	return 0;
}

int quic_crypto_handshake_keys_install(struct quic_sock *qs)
{
	struct tls_vec srt = {NULL, 0}, k, iv, hp_k;
	int err;

	err = tls_handshake_get(qs->tls, TLS_T_THS, &srt);
	if (err)
		return err;

	tls_vec(&k, qs->crypt.l2_tx_key, 16);
	tls_vec(&iv, qs->crypt.l2_tx_iv, 12);
	tls_vec(&hp_k, qs->crypt.l2_tx_hp_key, 16);
	err = quic_crypto_keys_derive(qs, &srt, &k, &iv, &hp_k);
	if (err)
		return err;
	pr_debug("[QUIC] hs tx keys: %16phN, %12phN, %16phN\n", k.data, iv.data, hp_k.data);

	err = tls_handshake_get(qs->tls, TLS_T_RHS, &srt);
	if (err)
		return err;

	tls_vec(&k, qs->crypt.l2_rx_key, 16);
	tls_vec(&iv, qs->crypt.l2_rx_iv, 12);
	tls_vec(&hp_k, qs->crypt.l2_rx_hp_key, 16);
	err = quic_crypto_keys_derive(qs, &srt, &k, &iv, &hp_k);
	if (err)
		return err;
	pr_debug("[QUIC] hs rx keys: %16phN, %12phN, %16phN\n", k.data, iv.data, hp_k.data);
	return 0;
}

int quic_crypto_application_keys_install(struct quic_sock *qs)
{
	struct tls_vec srt = {NULL, 0}, k, iv, hp_k;
	u8 p = qs->crypt.key_phase;
	int err;

	err = tls_handshake_get(qs->tls, TLS_T_TAP, &srt);
	if (err)
		return err;

	tls_vec(&k, qs->crypt.l3_tx_key[p], 16);
	tls_vec(&iv, qs->crypt.l3_tx_iv[p], 12);
	tls_vec(&hp_k, qs->crypt.l3_tx_hp_key, 16);
	err = quic_crypto_keys_derive(qs, &srt, &k, &iv, &hp_k);
	if (err)
		return err;
	pr_debug("[QUIC] ap tx keys: %16phN, %12phN, %16phN\n", k.data, iv.data, hp_k.data);

	err = tls_handshake_get(qs->tls, TLS_T_RAP, &srt);
	if (err)
		return err;

	tls_vec(&k, qs->crypt.l3_rx_key[p], 16);
	tls_vec(&iv, qs->crypt.l3_rx_iv[p], 12);
	tls_vec(&hp_k, qs->crypt.l3_rx_hp_key, 16);
	err = quic_crypto_keys_derive(qs, &srt, &k, &iv, &hp_k);
	if (err)
		return err;
	pr_debug("[QUIC] ap rx keys: %16phN, %12phN, %16phN\n", k.data, iv.data, hp_k.data);
	return 0;
}

int quic_crypto_key_update(struct quic_sock *qs)
{
	struct tls_vec l = {"quic ku", 7}, vec;
	int err;

	err = tls_handshake_post(qs->tls, TLS_P_KEY_UPDATE, &l, &vec);
	if (err)
		return err;
	qs->crypt.key_phase = !!qs->crypt.key_phase;

	return quic_crypto_application_keys_install(qs);
}

int quic_crypto_init(struct quic_sock *qs)
{
	/* AEAD_AES_128_GCM in ECB mode */
	qs->crypt.skc_tfm = crypto_alloc_skcipher("ecb(aes)", 0, 0);
	if (IS_ERR(qs->crypt.skc_tfm))
		return PTR_ERR(qs->crypt.skc_tfm);

	/* TLS_AES_128_GCM_SHA256(0x1301) */
	qs->crypt.aead_tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(qs->crypt.aead_tfm)) {
		crypto_free_skcipher(qs->crypt.skc_tfm);
		return PTR_ERR(qs->crypt.aead_tfm);
	}
	return 0;
}

void quic_crypto_free(struct quic_sock *qs)
{
	crypto_free_skcipher(qs->crypt.skc_tfm);
	crypto_free_aead(qs->crypt.aead_tfm);
}

int quic_crypto_load(void)
{
	void *tfm;

	tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);
	crypto_free_shash(tfm);

	tfm = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);
	crypto_free_shash(tfm);

	/* AEAD_AES_128_GCM in ECB mode */
	tfm = crypto_alloc_skcipher("ecb(aes)", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);
	crypto_free_skcipher(tfm);

	/* secp256r1(0x0017) */
	tfm = crypto_alloc_kpp("ecdh-nist-p256", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);
	crypto_free_kpp(tfm);

	/* TLS_AES_128_GCM_SHA256(0x1301) */
	tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);
	crypto_free_aead(tfm);

	/* load mod for pkcs1 cert */
	tfm = crypto_alloc_akcipher("pkcs1pad(rsa,sha256)", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);
	crypto_free_akcipher(tfm);

	/* rsa_pss_rsae_sha256(0x0804) */
	tfm = crypto_alloc_akcipher("psspad(rsa,sha256)", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);
	crypto_free_akcipher(tfm);

	return 0;
}
