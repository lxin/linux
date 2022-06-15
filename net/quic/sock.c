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

struct quic_sock *quic_lsk_lookup(struct sk_buff *skb, union quic_addr *a)
{
	struct net *net = dev_net(skb->dev);
	struct quic_sock *qs, *s = NULL;
	struct quic_hash_head *head;

	head = quic_lsk_head(net, a);
	spin_lock(&head->lock);

	hlist_for_each_entry(qs, &head->head, node) {
		if (net == sock_net(&qs->inet.sk) &&
		    QUIC_RCV_CB(skb)->af == qs->af &&
		    !memcmp(a, quic_saddr_cur(qs), qs->af->addr_len)) {
			if (likely(refcount_inc_not_zero(&qs->inet.sk.sk_refcnt)))
				s = qs;
			goto out;
		}
	}

out:
	spin_unlock(&head->lock);
	return s;
}

struct quic_sock *quic_ssk_lookup(struct sk_buff *skb, u8 *scid, u8 *scid_len)
{
	struct quic_cid *cid = quic_cid_lookup(dev_net(skb->dev), scid, scid_len);

	if (!cid || !refcount_inc_not_zero(&cid->qs->inet.sk.sk_refcnt))
		return NULL;

	return cid->qs;
}

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
	pr_warn("hs timeout %d\n", sk->sk_err);
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
		if (!mod_timer(&qs->rtx_timer, jiffies + (HZ / 20)))
			sock_hold(sk);
		goto out;
	}
	err = quic_send_queue_rtx(qs);
	if (err) {
		pr_warn("rtx timeout %d\n", err);
		sk->sk_err = err;
		sk->sk_state_change(sk);
	}
out:
	bh_unlock_sock(sk);
	sock_put(sk);
}

static void quic_path_validation_timeout(struct timer_list *t)
{
	struct quic_sock *qs = from_timer(qs, t, path_timer);
	struct sock *sk = &qs->inet.sk;

	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		if (!mod_timer(&qs->path_timer, jiffies + (HZ / 20)))
			sock_hold(sk);
		goto out;
	}

	pr_info("cur path is not reachable and move back to old one\n");

	qs->path.dest.cur = !qs->path.dest.cur;
	sk_dst_reset(&qs->inet.sk);
out:
	bh_unlock_sock(sk);
	sock_put(sk);
}

static void quic_ping_timeout(struct timer_list *t)
{
	struct quic_sock *qs = from_timer(qs, t, ping_timer);
	struct sock *sk = &qs->inet.sk;
	struct sk_buff *skb;

	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		if (!mod_timer(&qs->ping_timer, jiffies + (HZ / 20)))
			sock_hold(sk);
		goto out;
	}

	if (qs->state != QUIC_CS_CLIENT_POST_HANDSHAKE &&
	    qs->state != QUIC_CS_SERVER_POST_HANDSHAKE)
		goto out;

	if (qs->packet.ping_cnt++ > 3) {
		sk->sk_err = -ETIMEDOUT;
		pr_warn("ping timeout %d\n", sk->sk_err);
		sk->sk_state_change(sk);
		goto out;
	}

	quic_start_ping_timer(qs, 0);
	qs->packet.f = &qs->frame.f[QUIC_PKT_SHORT];
	skb = quic_packet_create(qs, QUIC_PKT_SHORT, QUIC_FRAME_PING);
	if (!skb)
		goto out;
	skb_set_owner_w(skb, sk);
	qs->af->lower_xmit(qs, skb);

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

	memcpy(quic_saddr_cur(nqs), quic_saddr_cur(qs), qs->af->addr_len);
	nqs->path.src.usk[0] = quic_us_get(qs->path.src.usk[0]);
	nqs->path.src.usk[1] = quic_us_get(qs->path.src.usk[1]);
	if (qs->crypt.certs) {
		struct quic_cert *c, *p, *tmp, *certs = NULL;

		for (p = qs->crypt.certs; p; p = p->next) {
			c = quic_cert_create(p->raw.v, p->raw.len);
			if (!c) {
				nqs->crypt.certs = certs;
				return -ENOMEM;
			}
			if (certs)
				tmp->next = c;
			else
				certs = c;
			tmp = c;
		}
		nqs->crypt.certs = certs;
	}
	if (qs->crypt.pkey.len) {
		nqs->crypt.pkey.v = quic_mem_dup(qs->crypt.pkey.v, qs->crypt.pkey.len);
		if (!nqs->crypt.pkey.v)
			return -ENOMEM;
		nqs->crypt.pkey.len = qs->crypt.pkey.len;
	}
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
	nqs->lsk = qs;

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
		quic_sock_free(nqs);
		return NULL;
	}
	err = quic_crypto_initial_keys_install(nqs);
	if (err) {
		quic_sock_free(nqs);
		return NULL;
	}
	err = quic_packet_pre_process(nqs, skb);
	if (err) {
		quic_sock_free(nqs);
		return NULL;
	}
	return nqs;
}

void quic_start_rtx_timer(struct quic_sock *qs, u8 restart)
{
	if (restart || !timer_pending(&qs->rtx_timer)) {
		if (!mod_timer(&qs->rtx_timer, jiffies + qs->cong.rto))
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

void quic_start_path_timer(struct quic_sock *qs, u8 restart)
{
	if (restart || !timer_pending(&qs->path_timer)) {
		unsigned long interval = msecs_to_jiffies(QUIC_PATH_INTERVAL);

		if (!mod_timer(&qs->path_timer, jiffies + interval))
			sock_hold(&qs->inet.sk);
	}
}

void quic_stop_path_timer(struct quic_sock *qs)
{
	if (!del_timer(&qs->path_timer))
		sock_put(&qs->inet.sk);
}

void quic_start_ping_timer(struct quic_sock *qs, u8 restart)
{
	if (restart)
		qs->packet.ping_cnt = 0;

	if (restart || !timer_pending(&qs->ping_timer)) {
		unsigned long interval = msecs_to_jiffies(QUIC_PING_INTERVAL);

		if (!mod_timer(&qs->ping_timer, jiffies + interval))
			sock_hold(&qs->inet.sk);
	}
}

void quic_stop_ping_timer(struct quic_sock *qs)
{
	if (!del_timer(&qs->ping_timer))
		sock_put(&qs->inet.sk);
}

int quic_sock_init(struct quic_sock *qs, union quic_addr *a, u8 *dcid, u8 dcid_len,
		   u8 *scid, u8 scid_len)
{
	int err;

	INIT_LIST_HEAD(&qs->list);
	err = quic_strm_init(qs, 2, 2);
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

	qs->af->set_addr(&qs->inet.sk, a, false);
	memcpy(quic_daddr_cur(qs), a, qs->af->addr_len);

	timer_setup(&qs->hs_timer, quic_shakehand_timeout, 0);
	timer_setup(&qs->rtx_timer, quic_retransmission_timeout, 0);
	timer_setup(&qs->path_timer, quic_path_validation_timeout, 0);
	timer_setup(&qs->ping_timer, quic_ping_timeout, 0);

	pr_info("quic sock init %p\n", qs);
	return 0;

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
	if (del_timer_sync(&qs->ping_timer))
		sock_put(&qs->inet.sk);

	if (del_timer_sync(&qs->path_timer))
		sock_put(&qs->inet.sk);

	if (del_timer_sync(&qs->rtx_timer))
		sock_put(&qs->inet.sk);

	if (del_timer_sync(&qs->hs_timer))
		sock_put(&qs->inet.sk);

	pr_info("quic sock free %p\n", qs);
	quic_send_list_free(qs);
	quic_receive_list_free(qs);

	quic_cid_free(qs);
	quic_strm_free(qs);
	quic_crypt_free(qs);
	quic_frame_free(qs);
}
