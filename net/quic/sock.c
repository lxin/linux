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

static void quic_shakehand_timeout(struct timer_list *t)
{
	struct quic_sock *qs = from_timer(qs, t, hs_timer);
	struct sock *sk = &qs->inet.sk;

	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		if (!mod_timer(&qs->hs_timer, jiffies + (HZ / 20)))
			sock_hold(sk);
		goto out;
	}
	sk->sk_err = -ETIMEDOUT;
	sk->sk_state_change(sk);
out:
	bh_unlock_sock(sk);
	sock_put(sk);
}

static void quic_retransmission_timeout(struct timer_list *t)
{
	struct quic_sock *qs = from_timer(qs, t, rtx_timer);
	struct sock *sk = &qs->inet.sk;
	int err;

	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		if (!mod_timer(&qs->hs_timer, jiffies + (HZ / 20)))
			sock_hold(sk);
		goto out;
	}
	err = quic_send_queue_rtx(qs);
	if (err) {
		sk->sk_err = err;
		sk->sk_state_change(sk);
	}
out:
	bh_unlock_sock(sk);
	sock_put(sk);
}

static int quic_copy_sock(struct quic_sock *nqs, struct quic_sock *qs)
{
	struct sock *nsk = &nqs->inet.sk;
	struct sock *sk = &qs->inet.sk;
	struct inet_sock *ninet = inet_sk(nsk);
	struct inet_sock *inet = inet_sk(sk);
	struct x509_certificate *x;

	nsk->sk_type = sk->sk_type;
	nsk->sk_bound_dev_if = sk->sk_bound_dev_if;
	nsk->sk_flags = sk->sk_flags;
	nsk->sk_tsflags = sk->sk_tsflags;
	nsk->sk_no_check_tx = sk->sk_no_check_tx;
	nsk->sk_no_check_rx = sk->sk_no_check_rx;
	nsk->sk_reuse = sk->sk_reuse;

	nsk->sk_shutdown = sk->sk_shutdown;
	nsk->sk_family = sk->sk_family;
	nsk->sk_protocol = IPPROTO_QUIC;
	nsk->sk_backlog_rcv = sk->sk_prot->backlog_rcv;
	nsk->sk_sndbuf = sk->sk_sndbuf;
	nsk->sk_rcvbuf = sk->sk_rcvbuf;
	nsk->sk_lingertime = sk->sk_lingertime;
	nsk->sk_rcvtimeo = sk->sk_rcvtimeo;
	nsk->sk_sndtimeo = sk->sk_sndtimeo;
	nsk->sk_rxhash = sk->sk_rxhash;

	ninet->inet_sport = inet->inet_sport;
	ninet->inet_saddr = inet->inet_saddr;
	ninet->inet_rcv_saddr = inet->inet_rcv_saddr;
	ninet->pmtudisc = inet->pmtudisc;
	ninet->inet_id = prandom_u32();
	ninet->uc_ttl = inet->uc_ttl;
	ninet->mc_loop = 1;
	ninet->mc_ttl = 1;
	ninet->mc_index = 0;
	ninet->mc_list = NULL;

	memcpy(&nqs->src, &qs->src, qs->af->addr_len);
	nqs->usk = quic_us_get(qs->usk);
	nqs->crypt.crt.len = qs->crypt.crt.len;
	nqs->crypt.crt.v = quic_mem_dup(qs->crypt.crt.v, nqs->crypt.crt.len);
	if (!nqs->crypt.crt.v)
		return -ENOMEM;
	x = x509_cert_parse(qs->crypt.crt.v, nqs->crypt.crt.len);
	if (IS_ERR(x))
		return PTR_ERR(x);
	nqs->crypt.cert = x;
	nqs->crypt.pkey.v = quic_mem_dup(qs->crypt.pkey.v, qs->crypt.pkey.len);
	if (!nqs->crypt.pkey.v)
		return -ENOMEM;
	nqs->crypt.pkey.len = qs->crypt.pkey.len;
	return 0;
}

struct quic_sock *quic_sock_create(struct quic_sock *qs)
{
	struct sock *sk = &qs->inet.sk;
	struct quic_sock *nqs;
	struct sock *nsk;

	nsk = sk_alloc(sock_net(sk), qs->af->sa_family, GFP_ATOMIC,
		       sk->sk_prot, sk->sk_kern_sock);
	if (!nsk)
		return NULL;

	sock_init_data(NULL, nsk);
	nqs = quic_sk(nsk);
	if (nsk->sk_prot->init(nsk)) {
		sk_common_release(nsk);
		return NULL;
	}
	if (quic_copy_sock(nqs, qs)) {
		sk_common_release(nsk);
		return NULL;
	}
	nqs->state = QUIC_CS_SERVER_INITIAL;

	return nqs;
}

struct quic_sock *quic_lsk_process(struct quic_sock *qs, struct sk_buff *skb)
{
	struct quic_rcv_cb *cb = QUIC_RCV_CB(skb);
	struct quic_sock *nqs;
	union quic_addr src;
	int err;

	cb->af->get_addr(&src, skb, 1);
	nqs = quic_sock_create(qs);
	if (!nqs)
		return NULL;
	err = quic_sock_init(nqs, &src, cb->scid, cb->scid_len,
			     cb->dcid, cb->dcid_len);
	if (err) {
		quic_sock_free(qs);
		return NULL;
	}
	err = quic_crypto_initial_keys_install(nqs);
	if (err) {
		quic_sock_free(qs);
		return NULL;
	}

	nqs->lsk = qs;
	return nqs;
}

void quic_start_rtx_timer(struct quic_sock *qs, u8 restart)
{
	if (restart || !timer_pending(&qs->rtx_timer)) {
		unsigned long interval = msecs_to_jiffies(QUIC_RTX_INTERVAL);

		if (!mod_timer(&qs->rtx_timer, jiffies + interval))
			sock_hold(&qs->inet.sk);
	}
}

void quic_stop_rtx_timer(struct quic_sock *qs)
{
	if (!del_timer(&qs->rtx_timer))
		sock_put(&qs->inet.sk);
}

void quic_start_hs_timer(struct quic_sock *qs, u8 restart)
{
	if (restart || !timer_pending(&qs->hs_timer)) {
		unsigned long interval = msecs_to_jiffies(QUIC_HS_INTERVAL);

		if (!mod_timer(&qs->hs_timer, jiffies + interval))
			sock_hold(&qs->inet.sk);
	}
}

void quic_stop_hs_timer(struct quic_sock *qs)
{
	if (!del_timer(&qs->hs_timer))
		sock_put(&qs->inet.sk);
}

int quic_sock_init(struct quic_sock *qs, union quic_addr *a, u8 *dcid, u8 dcid_len,
		   u8 *scid, u8 scid_len)
{
	struct net *net = sock_net(&qs->inet.sk);
	struct quic_hash_head *head;
	int err;

	INIT_LIST_HEAD(&qs->list);
	err = quic_strm_init(qs, 3, 3);
	if (err)
		goto err;

	err = quic_cid_init(qs, dcid, dcid_len, scid, scid_len);
	if (err)
		goto cid_err;

	err = quic_crypto_init(qs);
	if (err)
		goto crypt_err;

	err = quic_frame_init(qs);
	if (err)
		goto frame_err;

	err = quic_pnmap_init(qs, GFP_KERNEL);
	if (err)
		goto pnmap_err;

	head = quic_ssk_head(net, qs->scid.id);
	spin_lock(&head->lock);
	hlist_add_head(&qs->scid_node, &head->head);
	spin_unlock(&head->lock);

	qs->af->set_addr(&qs->inet.sk, a, false);
	memcpy(&qs->dest, a, qs->af->addr_len);
	head = quic_csk_head(net, &qs->src, &qs->dest);
	spin_lock(&head->lock);
	hlist_add_head(&qs->addr_node, &head->head);
	spin_unlock(&head->lock);

	timer_setup(&qs->hs_timer, quic_shakehand_timeout, 0);
	timer_setup(&qs->rtx_timer, quic_retransmission_timeout, 0);

	pr_info("quic sock init %p\n", qs);
	return 0;

pnmap_err:
	quic_frame_free(qs);
frame_err:
	quic_crypt_free(qs);
crypt_err:
	quic_cid_free(qs);
cid_err:
	quic_strm_free(qs);
err:
	pr_err("quic sock error %d\n", err);
	return err;
}

void quic_sock_free(struct quic_sock *qs)
{
	struct net *net = sock_net(&qs->inet.sk);
	struct quic_hash_head *head;

	if (del_timer_sync(&qs->rtx_timer))
		sock_put(&qs->inet.sk);

	if (del_timer_sync(&qs->hs_timer))
		sock_put(&qs->inet.sk);

	head = quic_csk_head(net, &qs->src, &qs->dest);
	spin_lock(&head->lock);
	hlist_del(&qs->addr_node);
	spin_unlock(&head->lock);

	head = quic_ssk_head(net, qs->scid.id);
	spin_lock(&head->lock);
	hlist_del(&qs->scid_node);
	spin_unlock(&head->lock);

	quic_pnmap_free(qs);
	quic_cid_free(qs);
	quic_strm_free(qs);
	quic_crypt_free(qs);
	quic_frame_free(qs);
}
