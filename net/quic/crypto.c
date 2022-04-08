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

static int quic_crypto_hkdf_extract(struct quic_sock *qs, u8 *key, int key_len,
				    u8 *data, int data_len, u8 prk[])
{
	struct crypto_shash *tfm = qs->crypt.sha_tfm;
	int err;

	err = crypto_shash_setkey(tfm, key, key_len);
	if (err)
		return err;

	err = crypto_shash_tfm_digest(tfm, data, data_len, prk);
	if (err)
		return err;

	return 0;
}

static int quic_crypto_hkdf_expand(struct quic_sock *qs, u8 *key, u8 *label,
				   int llen, u8 *hash, u8 *okm, int okmlen)
{
	struct crypto_shash *tfm = qs->crypt.sha_tfm;
	static const u8 LABEL[] = "tls13 ";
	SHASH_DESC_ON_STACK(desc, tfm);
	u8 tmp[QUIC_HKDF_HASHLEN];
	const u8 *prev = NULL;
	unsigned int infolen;
	u8 counter = 1;
	unsigned int i;
	u8 info[256];
	u8 *p = info;
	int err;

	*p++ = (u8)(okmlen / 256);
	*p++ = (u8)(okmlen % 256);
	*p++ = (u8)(sizeof(LABEL) - 1 + llen);
	memcpy(p, LABEL, sizeof(LABEL) - 1);
	p += sizeof(LABEL) - 1;
	memcpy(p, label, llen);
	p += llen;
	if (hash) {
		*p++ = okmlen;
		memcpy(p, hash, okmlen);
		p += okmlen;
	} else {
		*p++ = 0;
	}

	infolen = (unsigned int)(p - info);
	desc->tfm = tfm;

	err = crypto_shash_setkey(tfm, key, QUIC_HKDF_HASHLEN);
	if (err)
		return err;

	for (i = 0; i < okmlen; i += QUIC_HKDF_HASHLEN) {
		err = crypto_shash_init(desc);
		if (err)
			goto out;

		if (prev) {
			err = crypto_shash_update(desc, prev, QUIC_HKDF_HASHLEN);
			if (err)
				goto out;
		}

		err = crypto_shash_update(desc, info, infolen);
		if (err)
			goto out;

		BUILD_BUG_ON(sizeof(counter) != 1);
		if (okmlen - i < QUIC_HKDF_HASHLEN) {
			err = crypto_shash_finup(desc, &counter, 1, tmp);
			if (err)
				goto out;
			memcpy(&okm[i], tmp, okmlen - i);
			memzero_explicit(tmp, sizeof(tmp));
		} else {
			err = crypto_shash_finup(desc, &counter, 1, &okm[i]);
			if (err)
				goto out;
		}
		counter++;
		prev = &okm[i];
	}
out:
	shash_desc_zero(desc);
	return err;
}

static int quic_crypto_keys_derive(struct quic_sock *qs, u8 *srt, u8 *key,
				   u8 *iv, u8 *hp_key)
{
	u8 HP_KEY_LABEL[] = "quic hp";
	u8 KEY_LABEL[] = "quic key";
	u8 IV_LABEL[] = "quic iv";
	int llen, err;

	llen = sizeof(KEY_LABEL) - 1;
	err = quic_crypto_hkdf_expand(qs, srt, KEY_LABEL, llen, NULL, key, QUIC_KEYLEN);
	if (err)
		return err;
	llen = sizeof(IV_LABEL) - 1;
	err = quic_crypto_hkdf_expand(qs, srt, IV_LABEL, llen, NULL, iv, QUIC_IVLEN);
	if (err)
		return err;
	llen = sizeof(HP_KEY_LABEL) - 1;
	return quic_crypto_hkdf_expand(qs, srt, HP_KEY_LABEL, llen, NULL, hp_key, QUIC_KEYLEN);
}

static int quic_crypto_keys_create(struct quic_sock *qs, u8 type)
{
	u8 *tx_key, *tx_iv, *tx_hp_key;
	u8 *rx_key, *rx_iv, *rx_hp_key;
	u8 tx_srt[QUIC_HKDF_HASHLEN];
	u8 rx_srt[QUIC_HKDF_HASHLEN];
	u8 *i_srt, *level, *hash;
	char *tlabel, *rlabel;
	u8 *t_srt, *r_srt;
	int llen, err;

	if (type == QUIC_PKT_INITIAL) {
		i_srt = qs->crypt.es_secret;
		hash = NULL;

		tx_key = qs->crypt.tx_key;
		tx_iv = qs->crypt.tx_iv;
		tx_hp_key = qs->crypt.tx_hp_key;

		rx_key = qs->crypt.rx_key;
		rx_iv = qs->crypt.rx_iv;
		rx_hp_key = qs->crypt.rx_hp_key;

		t_srt = tx_srt;
		r_srt = rx_srt;
		if (qs->state < QUIC_CS_CLOSING) {
			tlabel = "client in";
			rlabel = "server in";
		} else {
			rlabel = "client in";
			tlabel = "server in";
		}
		level = "initial";
	} else if (type == QUIC_PKT_HANDSHAKE) {
		i_srt = qs->crypt.hs_secret;
		hash = qs->crypt.hash2;

		tx_key = qs->crypt.l2_tx_key;
		tx_iv = qs->crypt.l2_tx_iv;
		tx_hp_key = qs->crypt.l2_tx_hp_key;

		rx_key = qs->crypt.l2_rx_key;
		rx_iv = qs->crypt.l2_rx_iv;
		rx_hp_key = qs->crypt.l2_rx_hp_key;

		if (qs->state < QUIC_CS_CLOSING) {
			t_srt = qs->crypt.ch_secret;
			r_srt = qs->crypt.sh_secret;
			tlabel = "c hs traffic";
			rlabel = "s hs traffic";
		} else {
			r_srt = qs->crypt.ch_secret;
			t_srt = qs->crypt.sh_secret;
			rlabel = "c hs traffic";
			tlabel = "s hs traffic";
		}
		level = "handshake";
	} else if (type == QUIC_PKT_SHORT) {
		i_srt = qs->crypt.ms_secret;
		hash = qs->crypt.hash3;

		tx_key = qs->crypt.l3_tx_key;
		tx_iv = qs->crypt.l3_tx_iv;
		tx_hp_key = qs->crypt.l3_tx_hp_key;

		rx_key = qs->crypt.l3_rx_key;
		rx_iv = qs->crypt.l3_rx_iv;
		rx_hp_key = qs->crypt.l3_rx_hp_key;

		t_srt = tx_srt;
		r_srt = rx_srt;
		if (qs->state < QUIC_CS_CLOSING) {
			tlabel = "c ap traffic";
			rlabel = "s ap traffic";
		} else {
			rlabel = "c ap traffic";
			tlabel = "s ap traffic";
		}
		level = "application";
	}

	llen = strlen(tlabel);
	err = quic_crypto_hkdf_expand(qs, i_srt, tlabel, llen, hash, t_srt, QUIC_HKDF_HASHLEN);
	if (err)
		return err;
	pr_debug("%s tx secret: %32phN\n", level, t_srt);

	err = quic_crypto_keys_derive(qs, t_srt, tx_key, tx_iv, tx_hp_key);
	pr_debug("%s tx_key: %16phN\n", level, tx_key);
	pr_debug("%s tx_iv: %12phN\n", level, tx_iv);
	pr_debug("%s tx_hp_key: %16phN\n", level, tx_hp_key);

	llen = strlen(rlabel);
	err = quic_crypto_hkdf_expand(qs, i_srt, rlabel, llen, hash, r_srt, QUIC_HKDF_HASHLEN);
	if (err)
		return err;
	pr_debug("%s rx secret: %32phN\n", level, r_srt);

	err = quic_crypto_keys_derive(qs, r_srt, rx_key, rx_iv, rx_hp_key);
	if (err)
		return err;
	pr_debug("%s rx_key: %16phN\n", level, rx_key);
	pr_debug("%s rx_iv: %12phN\n", level, rx_iv);
	pr_debug("%s rx_hp_key: %16phN\n", level, rx_hp_key);

	return err;
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
	pr_debug("encrypt dp sample: %16phN\n", mask);
	sg_init_one(&sg, mask, QUIC_KEYLEN);
	skcipher_request_set_crypt(req, &sg, &sg, QUIC_KEYLEN, NULL);
	err = crypto_skcipher_encrypt(req);
	if (err)
		goto err;
	pr_debug("encrypt hp mask: %16phN\n", mask);

	p = skb->data;
	*p = (uint8_t)(*p ^ (mask[0] & (((*p & 0x80) == 0x80) ? 0x0f : 0x1f)));
	p = skb->data + qs->packet.pn_off;
	for (i = 1; i <= qs->packet.pn_len; i++)
		*p++ ^= mask[i];
err:
	skcipher_request_free(req);
	return err;
}

int quic_crypto_compute_ecdh_secret(struct quic_sock *qs, u8 *x, u8 *y)
{
	struct crypto_kpp *tfm = qs->crypt.kpp_tfm;
	u8 *tmp, *secret = qs->crypt.dhe_secret;
	struct scatterlist src, dst;
	struct kpp_request *req;
	int err;

	tmp = kmalloc(64, GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	req = kpp_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		err = -ENOMEM;
		goto free_tmp;
	}

	memcpy(tmp, x, QUIC_ECDHLEN); /* x */
	memcpy(&tmp[QUIC_ECDHLEN], y, QUIC_ECDHLEN); /* y */

	sg_init_one(&src, tmp, 64);
	sg_init_one(&dst, secret, QUIC_ECDHLEN);
	kpp_request_set_input(req, &src, 64);
	kpp_request_set_output(req, &dst, QUIC_ECDHLEN);
	err = crypto_kpp_compute_shared_secret(req);
	if (err < 0)
		pr_err("alg: ecdh: compute shared secret failed. err %d\n", err);
	kpp_request_free(req);
	pr_debug("dhe_secret: %32phN\n", secret);
free_tmp:
	kfree_sensitive(tmp);
	return err;
}

static int quic_crypto_hash(struct quic_sock *qs, struct quic_vlen key[], int n, u8 prk[])
{
	struct crypto_shash *tfm = qs->crypt.hash_tfm;
	SHASH_DESC_ON_STACK(desc, tfm);
	int err, i;

	desc->tfm = tfm;
	crypto_shash_init(desc);

	for (i = 0; i < n; i++) {
		err = crypto_shash_update(desc, key[i].v, key[i].len);
		if (err)
			goto out;
	}

	err = crypto_shash_final(desc, prk);
out:
	shash_desc_zero(desc);
	return err;
}

static int quic_crypto_signature_verify(struct quic_sock *qs, struct public_key *pkey,
					struct public_key_signature *sig)
{
	struct crypto_akcipher *tfm = qs->crypt.akc_tfm;
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

static int quic_crypto_signature_sign(struct quic_sock *qs, struct public_key *pkey,
				      struct public_key_signature *sig)
{
	struct crypto_akcipher *tfm = qs->crypt.akc_tfm;
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

static int quic_crypto_set_ecdh_privkey(struct crypto_kpp *tfm)
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

static int quic_crypto_generate_ecdh_public_key(struct crypto_kpp *tfm, u8 *x, u8 *y)
{
	struct kpp_request *req;
	struct scatterlist dst;
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

	sg_init_one(&dst, tmp, 64);
	kpp_request_set_input(req, NULL, 0);
	kpp_request_set_output(req, &dst, 64);

	err = crypto_kpp_generate_public_key(req);
	if (err < 0)
		goto free_all;

	memcpy(x, tmp, QUIC_ECDHLEN);
	memcpy(y, &tmp[QUIC_ECDHLEN], QUIC_ECDHLEN);

free_all:
	kpp_request_free(req);
free_tmp:
	kfree(tmp);
	return err;
}

static int quic_crypto_generate_ecdh_keys(struct quic_sock *qs)
{
	struct crypto_kpp *tfm;
	int err;

	tfm = qs->crypt.kpp_tfm;
	err = quic_crypto_set_ecdh_privkey(tfm);
	if (err)
		return err;

	err = quic_crypto_generate_ecdh_public_key(tfm, qs->crypt.ecdh_x, qs->crypt.ecdh_y);
	if (err)
		return err;

	pr_debug("ecdh X: %32phN\n", qs->crypt.ecdh_x);
	pr_debug("ecdh Y: %32phN\n", qs->crypt.ecdh_y);
	return 0;
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

	pr_debug("encrypt nonce: %12phN\n", iv);
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

	pr_debug("decrypt nonce: %12phN\n", iv);
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
	pr_debug("decrypt hp sample: %16phN\n", mask);
	sg_init_one(&sg, mask, QUIC_KEYLEN);
	skcipher_request_set_crypt(req, &sg, &sg, QUIC_KEYLEN, NULL);
	err = crypto_skcipher_encrypt(req);
	if (err)
		return err;
	pr_debug("decrypt hp mask: %16phN\n", mask);

	p = (u8 *)hdr;
	*p = (u8)(*p ^ (*p & (((*p & 0x80) == 0x80) ? 0x0f : 0x1f)));
	qs->packet.pn_len = (*p & 0x03) + 1;
	p += qs->packet.pn_off;
	for (i = 0; i < qs->packet.pn_len; ++i)
		*(p + i) = *((u8 *)hdr + qs->packet.pn_off + i) ^ mask[i + 1];

	qs->packet.pn = quic_get_fixint_next(&p, qs->packet.pn_len);
	pr_debug("decrypt hp pn: %u pn_len: %u\n", qs->packet.pn, qs->packet.pn_len);
	return 0;
}

/* exported */
int quic_crypto_server_cert_verify(struct quic_sock *qs)
{
	struct x509_certificate *cert = qs->crypt.cert;
	struct x509_certificate *x = cert, *p;
	struct public_key_signature *sig;
	struct asymmetric_key_id *auth;
	int err = 0;

	for (p = cert; p; p = p->next)
		p->seen = false;

	while (1) {
		x->seen = true;
		sig = x->sig;
		if (x->self_signed) {
			x->signer = x;
			break;
		}
		auth = sig->auth_ids[0];
		if (auth) {
			for (p = cert; p; p = p->next) {
				if (asymmetric_key_id_same(p->id, auth))
					goto check_skid;
			}
		} else if (sig->auth_ids[1]) {
			auth = sig->auth_ids[1];
			for (p = cert; p; p = p->next) {
				if (!p->skid)
					continue;
				if (asymmetric_key_id_same(p->skid, auth))
					goto found;
			}
		}
		return 0;

check_skid:
		if (sig->auth_ids[1] && !asymmetric_key_id_same(p->skid, sig->auth_ids[1])) {
			err = -EKEYREJECTED;
			break;
		}
found:
		if (p->seen)
			break;
		err = public_key_verify_signature(p->pub, x->sig);
		if (err < 0)
			break;
		x->signer = p;
		if (x == p)
			break;
		x = p;
	}

	pr_debug("server cert verified %d\n", err);
	return err;
}

/* exported */
#define TLS13_TBS_START_SIZE		64
#define TLS13_TBS_PREAMBLE_SIZE		(TLS13_TBS_START_SIZE + 33 + 1)
int quic_crypto_server_certvfy_verify(struct quic_sock *qs)
{
	u8 tls13tbs[TLS13_TBS_PREAMBLE_SIZE + 64], digest[QUIC_HASHLEN];
	u8 KEY_LABEL[] = "TLS 1.3, server CertificateVerify";
	struct x509_certificate *x = qs->crypt.cert;
	struct public_key_signature _s, *s = &_s;
	struct quic_vlen v;
	u8 *p = tls13tbs;
	int err;

	err = quic_crypto_hash(qs, qs->crypt.hs_buf, QUIC_H_CERT + 1, qs->crypt.hash6);
	if (err)
		return err;
	pr_debug("hash6: %32phN\n", qs->crypt.hash6);

	memset(p, 32, TLS13_TBS_START_SIZE);
	memcpy(p + TLS13_TBS_START_SIZE, KEY_LABEL, sizeof(KEY_LABEL));
	memcpy(p + TLS13_TBS_PREAMBLE_SIZE, qs->crypt.hash6, QUIC_HASHLEN);
	v.v = p;
	v.len = 130;
	err = quic_crypto_hash(qs, &v, 1, digest);
	if (err)
		return err;
	pr_debug("digest: %32phN\n", digest);

	s->s = qs->crypt.sig.v;
	s->s_size = qs->crypt.sig.len;
	s->digest = digest;
	s->digest_size = QUIC_HASHLEN;
	s->data = p;
	s->data_size = 130;
	s->encoding = "pss";
	s->pkey_algo = "rsa";
	s->hash_algo = "sha256";
	s->mgf = "mgf1";
	s->mgf_hash_algo = "sha256";
	s->salt_length = 32;
	s->trailer_field = 0xbc;

	err = quic_crypto_signature_verify(qs, x->pub, s);
	pr_debug("certvfy verified %d\n", err);

	return err;
}

int quic_crypto_server_certvfy_sign(struct quic_sock *qs)
{
	u8 tls13tbs[TLS13_TBS_PREAMBLE_SIZE + 64], digest[QUIC_HASHLEN];
	u8 KEY_LABEL[] = "TLS 1.3, server CertificateVerify";
	struct public_key_signature _s, *s = &_s;
	struct public_key _pkey, *pkey = &_pkey;
	struct quic_vlen v;
	u8 *p = tls13tbs;
	int err;

	memset(pkey, 0, sizeof(_pkey));
	pkey->key = qs->crypt.pkey.v;
	pkey->keylen = qs->crypt.pkey.len;
	pkey->key_is_private = true;

	err = quic_crypto_hash(qs, qs->crypt.hs_buf, QUIC_H_CERT + 1, qs->crypt.hash6);
	if (err)
		return err;
	pr_debug("hash6: %32phN\n", qs->crypt.hash6);

	memset(p, 32, TLS13_TBS_START_SIZE);
	memcpy(p + TLS13_TBS_START_SIZE, KEY_LABEL, sizeof(KEY_LABEL));
	memcpy(p + TLS13_TBS_PREAMBLE_SIZE, qs->crypt.hash6, QUIC_HASHLEN);
	v.v = p;
	v.len = 130;
	err = quic_crypto_hash(qs, &v, 1, digest);
	if (err)
		return err;
	pr_debug("digest: %32phN\n", digest);

	qs->crypt.sig.len = 256;
	qs->crypt.sig.v = kzalloc(qs->crypt.sig.len, GFP_ATOMIC);
	if (!qs->crypt.sig.v)
		return -ENOMEM;

	memset(s, 0, sizeof(_s));
	s->s = qs->crypt.sig.v;
	s->s_size = qs->crypt.sig.len;
	s->digest = digest;
	s->digest_size = QUIC_HASHLEN;
	s->data = p;
	s->data_size = 130;
	s->encoding = "pss";
	s->pkey_algo = "rsa";
	s->hash_algo = "sha256";
	s->mgf = "mgf1";
	s->mgf_hash_algo = "sha256";
	s->salt_length = 32;
	s->trailer_field = 0xbc;

	err = quic_crypto_signature_sign(qs, pkey, s);
	pr_debug("certvfy signed %d\n", err);

	return err;
}

/* exported */
int quic_crypto_server_finished_create(struct quic_sock *qs, u8 *sf)
{
	u8 KEY_LABEL[] = "finished";
	u8 fks[QUIC_HKDF_HASHLEN];
	int err, llen;

	llen = sizeof(KEY_LABEL) - 1;
	err = quic_crypto_hkdf_expand(qs, qs->crypt.sh_secret, KEY_LABEL, llen, NULL,
				      fks, QUIC_HKDF_HASHLEN);
	if (err)
		return err;
	pr_debug("fks: %32phN\n", fks);

	err = quic_crypto_hash(qs, qs->crypt.hs_buf, QUIC_H_CVFY + 1, qs->crypt.hash7);
	if (err)
		return err;
	pr_debug("hash7: %32phN\n", qs->crypt.hash7);

	err = quic_crypto_hkdf_extract(qs, fks, QUIC_HKDF_HASHLEN, qs->crypt.hash7,
				       QUIC_HKDF_HASHLEN, sf);
	if (err)
		return err;
	pr_debug("SF: %32phN\n", sf);
	return 0;
}

/* exported */
int quic_crypto_server_finished_verify(struct quic_sock *qs)
{
	u8 sf[QUIC_HKDF_HASHLEN];
	int err;

	err = quic_crypto_server_finished_create(qs, sf);
	if (err)
		return err;

	err = (qs->crypt.hs_buf[QUIC_H_SFIN].len - 4 != QUIC_HKDF_HASHLEN ||
	       memcmp(sf, qs->crypt.hs_buf[QUIC_H_SFIN].v + 4, QUIC_HKDF_HASHLEN));
	pr_debug("server finished verified %d\n", err);

	return err;
}

/* exported */
int quic_crypto_encrypt(struct quic_sock *qs, struct sk_buff *skb, u8 type)
{
	u8 *key, *iv, *hp_key;
	int err;

	if (type == QUIC_PKT_INITIAL) {
		key = qs->crypt.tx_key;
		iv = qs->crypt.tx_iv;
		hp_key = qs->crypt.tx_hp_key;
	} else if (type == QUIC_PKT_HANDSHAKE) {
		key = qs->crypt.l2_tx_key;
		iv = qs->crypt.l2_tx_iv;
		hp_key = qs->crypt.l2_tx_hp_key;
	} else if (type == QUIC_PKT_SHORT) {
		key = qs->crypt.l3_tx_key;
		iv = qs->crypt.l3_tx_iv;
		hp_key = qs->crypt.l3_tx_hp_key;
	}

	err = quic_crypto_pd_encrypt(qs, skb, key, iv);
	if (err)
		return err;

	return quic_crypto_hd_encrypt(qs, skb, hp_key);
}

/* exported */
int quic_crypto_decrypt(struct quic_sock *qs, struct sk_buff *skb, u8 type)
{
	u8 *key, *iv, *hp_key;
	int err;

	if (type == QUIC_PKT_INITIAL) {
		key = qs->crypt.rx_key;
		iv = qs->crypt.rx_iv;
		hp_key = qs->crypt.rx_hp_key;
	} else if (type == QUIC_PKT_HANDSHAKE) {
		key = qs->crypt.l2_rx_key;
		iv = qs->crypt.l2_rx_iv;
		hp_key = qs->crypt.l2_rx_hp_key;
	} else if (type == QUIC_PKT_SHORT) {
		key = qs->crypt.l3_rx_key;
		iv = qs->crypt.l3_rx_iv;
		hp_key = qs->crypt.l3_rx_hp_key;
	}

	err = quic_crypto_hd_decrypt(qs, skb, hp_key);
	if (err)
		return err;

	return quic_crypto_pd_decrypt(qs, skb, key, iv);
}

/* exported */
int quic_crypto_initial_keys_install(struct quic_sock *qs)
{
	static u8 salt[] =
	  "\x38\x76\x2c\xf7\xf5\x59\x34\xb3\x4d\x17\x9a\xe6\xa4\xc8\x0c\xad\xcc\xbb\x7f\x0a";
	int salt_len = sizeof(salt) - 1;
	u8 *dcid, dcid_len;
	int err;

	err = quic_crypto_generate_ecdh_keys(qs);
	if (err)
		return err;
	if (qs->state < QUIC_CS_CLOSING) {
		dcid = qs->dcid.id;
		dcid_len = qs->dcid.len;
	} else {
		dcid = qs->scid.id;
		dcid_len = qs->scid.len;
	}

	err = quic_crypto_hkdf_extract(qs, salt, salt_len, dcid,
				       dcid_len, qs->crypt.es_secret);
	if (err)
		return err;
	pr_debug("es secret: %32phN\n", qs->crypt.es_secret);

	return quic_crypto_keys_create(qs, QUIC_PKT_INITIAL);
}

/* exported */
int quic_crypto_handshake_keys_install(struct quic_sock *qs)
{
	u8 zeros[QUIC_HKDF_HASHLEN] = {0};
	u8 des_secret[QUIC_HKDF_HASHLEN];
	u8 es_secret[QUIC_HKDF_HASHLEN];
	u8 KEY_LABEL[] = "derived";
	int err, llen;

	err = quic_crypto_hash(qs, NULL, 0, qs->crypt.hash0);
	if (err)
		return err;
	pr_debug("hash0: %32phN\n", qs->crypt.hash0);

	err = quic_crypto_hkdf_extract(qs, zeros, 0, zeros,
				       QUIC_HKDF_HASHLEN, es_secret);
	if (err)
		return err;
	pr_debug("es_secret: %32phN\n", es_secret);

	llen = sizeof(KEY_LABEL) - 1;
	err = quic_crypto_hkdf_expand(qs, es_secret, KEY_LABEL, llen, qs->crypt.hash0,
				      des_secret, QUIC_HKDF_HASHLEN);
	if (err)
		return err;
	pr_debug("des_secret: %32phN\n", des_secret);

	err = quic_crypto_hkdf_extract(qs, des_secret, QUIC_HKDF_HASHLEN, qs->crypt.dhe_secret,
				       QUIC_HKDF_HASHLEN, qs->crypt.hs_secret);
	if (err)
		return err;
	pr_debug("hs_secret: %32phN\n", qs->crypt.hs_secret);

	err = quic_crypto_hash(qs, qs->crypt.hs_buf, QUIC_H_SH + 1, qs->crypt.hash2);
	if (err)
		return err;
	pr_debug("hash2: %32phN\n", qs->crypt.hash2);

	return quic_crypto_keys_create(qs, QUIC_PKT_HANDSHAKE);
}

/* exported */
int quic_crypto_application_keys_install(struct quic_sock *qs)
{
	u8 zeros[QUIC_HKDF_HASHLEN] = {0};
	u8 dhs_secret[QUIC_HKDF_HASHLEN];
	u8 FIN_KEY_LABEL[] = "finished";
	u8 KEY_LABEL[] = "derived";
	u8 fkc[QUIC_HKDF_HASHLEN];
	u8 cf[QUIC_HKDF_HASHLEN];
	int err, llen;

	err = quic_crypto_hash(qs, qs->crypt.hs_buf, QUIC_H_SFIN + 1, qs->crypt.hash3);
	if (err)
		return err;
	pr_debug("hash3: %32phN\n", qs->crypt.hash3);

	llen = sizeof(KEY_LABEL) - 1;
	err = quic_crypto_hkdf_expand(qs, qs->crypt.hs_secret, KEY_LABEL, llen, qs->crypt.hash0,
				      dhs_secret, QUIC_HKDF_HASHLEN);
	if (err)
		return err;
	pr_debug("dhs_secret: %32phN\n", dhs_secret);

	err = quic_crypto_hkdf_extract(qs, dhs_secret, QUIC_HKDF_HASHLEN,
				       zeros, QUIC_HKDF_HASHLEN, qs->crypt.ms_secret);
	if (err)
		return err;
	pr_debug("ms_secret: %32phN\n", qs->crypt.ms_secret);

	err = quic_crypto_keys_create(qs, QUIC_PKT_SHORT);
	if (err)
		return err;

	llen = sizeof(FIN_KEY_LABEL) - 1;
	err = quic_crypto_hkdf_expand(qs, qs->crypt.ch_secret, FIN_KEY_LABEL, llen, NULL,
				      fkc, QUIC_HKDF_HASHLEN);
	if (err)
		return err;
	pr_debug("fkc: %32phN\n", fkc);

	memcpy(qs->crypt.hash9, qs->crypt.hash3, QUIC_HKDF_HASHLEN);
	err = quic_crypto_hkdf_extract(qs, fkc, QUIC_HKDF_HASHLEN, qs->crypt.hash9,
				       QUIC_HKDF_HASHLEN, cf);
	if (err)
		return err;
	qs->crypt.hs_buf[QUIC_H_CFIN].len = QUIC_HKDF_HASHLEN;
	qs->crypt.hs_buf[QUIC_H_CFIN].v = quic_mem_dup(cf, qs->crypt.hs_buf[QUIC_H_CFIN].len);
	if (!qs->crypt.hs_buf[QUIC_H_CFIN].v)
		return -ENOMEM;
	pr_debug("CF: %32phN\n", qs->crypt.hs_buf[QUIC_H_CFIN].v);

	return 0;
}

/* exported */
int quic_crypto_init(struct quic_sock *qs)
{
	int err;

	qs->crypt.sha_tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
	if (IS_ERR(qs->crypt.sha_tfm)) {
		err = PTR_ERR(qs->crypt.sha_tfm);
		goto err;
	}

	qs->crypt.hash_tfm = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(qs->crypt.hash_tfm)) {
		err = PTR_ERR(qs->crypt.hash_tfm);
		goto err;
	}

	/* AEAD_AES_128_GCM in ECB mode */
	qs->crypt.skc_tfm = crypto_alloc_skcipher("ecb(aes)", 0, 0);
	if (IS_ERR(qs->crypt.skc_tfm)) {
		err = PTR_ERR(qs->crypt.skc_tfm);
		goto err;
	}

	/* secp256r1(0x0017) */
	qs->crypt.kpp_tfm = crypto_alloc_kpp("ecdh-nist-p256", 0, 0);
	if (IS_ERR(qs->crypt.kpp_tfm)) {
		err = PTR_ERR(qs->crypt.kpp_tfm);
		goto err;
	}

	/* TLS_AES_128_GCM_SHA256(0x1301) */
	qs->crypt.aead_tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(qs->crypt.aead_tfm)) {
		err = PTR_ERR(qs->crypt.aead_tfm);
		goto err;
	}

	/* rsa_pss_rsae_sha256(0x0804) */
	qs->crypt.akc_tfm = crypto_alloc_akcipher("psspad(rsa,sha256)", 0, 0);
	if (IS_ERR(qs->crypt.akc_tfm)) {
		err = PTR_ERR(qs->crypt.akc_tfm);
		goto err;
	}

	return 0;
err:
	quic_crypto_free(qs);
	return err;
}

/* exported */
void quic_crypto_free(struct quic_sock *qs)
{
	crypto_free_shash(qs->crypt.sha_tfm);
	crypto_free_shash(qs->crypt.hash_tfm);
	crypto_free_skcipher(qs->crypt.skc_tfm);
	crypto_free_kpp(qs->crypt.kpp_tfm);
	crypto_free_aead(qs->crypt.aead_tfm);
	crypto_free_akcipher(qs->crypt.akc_tfm);
}

/* exported */
int quic_crypto_load(void)
{
	struct quic_crypt c;

	c.sha_tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
	if (IS_ERR(c.sha_tfm))
		return PTR_ERR(c.sha_tfm);
	crypto_free_shash(c.sha_tfm);

	c.hash_tfm = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(c.hash_tfm))
		return PTR_ERR(c.hash_tfm);
	crypto_free_shash(c.hash_tfm);

	/* AEAD_AES_128_GCM in ECB mode */
	c.skc_tfm = crypto_alloc_skcipher("ecb(aes)", 0, 0);
	if (IS_ERR(c.skc_tfm))
		return PTR_ERR(c.skc_tfm);
	crypto_free_skcipher(c.skc_tfm);

	/* secp256r1(0x0017) */
	c.kpp_tfm = crypto_alloc_kpp("ecdh-nist-p256", 0, 0);
	if (IS_ERR(c.kpp_tfm))
		return PTR_ERR(c.kpp_tfm);
	crypto_free_kpp(c.kpp_tfm);

	/* TLS_AES_128_GCM_SHA256(0x1301) */
	c.aead_tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(c.aead_tfm))
		return PTR_ERR(c.aead_tfm);
	crypto_free_aead(c.aead_tfm);

	/* load mod for pkcs1 cert */
	c.akc_tfm = crypto_alloc_akcipher("pkcs1pad(rsa,sha256)", 0, 0);
	if (IS_ERR(c.akc_tfm))
		return PTR_ERR(c.akc_tfm);
	crypto_free_akcipher(c.akc_tfm);

	/* rsa_pss_rsae_sha256(0x0804) */
	c.akc_tfm = crypto_alloc_akcipher("psspad(rsa,sha256)", 0, 0);
	if (IS_ERR(c.akc_tfm))
		return PTR_ERR(c.akc_tfm);
	crypto_free_akcipher(c.akc_tfm);

	return 0;
}

void quic_crypt_free(struct quic_sock *qs)
{
	int i;

	kfree(qs->crypt.cert);
	kfree(qs->crypt.pkey.v);
	kfree(qs->crypt.sig.v);
	kfree(qs->crypt.crt.v);
	kfree(qs->crypt.hello.cipher_suites);
	kfree(qs->crypt.hello.compression_methods);

	for (i = 0; i < QUIC_H_COUNT; i++)
		kfree(qs->crypt.hs_buf[i].v);
}
