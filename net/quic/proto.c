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

#include <linux/module.h>
#include <linux/init.h>
#include <net/net_namespace.h>
#include <net/protocol.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/route.h>
#include <net/inet_common.h>
#include <net/quic/quic.h>

struct quic_globals quic_globals __read_mostly;
struct percpu_counter quic_sockets_allocated;

long sysctl_quic_mem[3];
int sysctl_quic_rmem[3];
int sysctl_quic_wmem[3];

static void quic_v4_udp_conf_init(struct udp_port_cfg *udp_conf, union quic_addr *a)
{
	udp_conf->family = AF_INET;
	udp_conf->local_ip.s_addr = a->v4.sin_addr.s_addr;
	udp_conf->local_udp_port = a->v4.sin_port;
	udp_conf->use_udp6_rx_checksums = true;
}

static void quic_v6_udp_conf_init(struct udp_port_cfg *udp_conf, union quic_addr *a)
{
	udp_conf->family = AF_INET6;
	udp_conf->local_ip6 = a->v6.sin6_addr;
	udp_conf->local_udp_port = a->v6.sin6_port;
	udp_conf->use_udp6_rx_checksums = true;
}

static void quic_v4_get_addr(union quic_addr *a, struct sk_buff *skb, bool src)
{
	struct udphdr *uh = (struct udphdr *)(skb->head + QUIC_RCV_CB(skb)->udp_hdr);
	struct sockaddr_in *sa = &a->v4;

	a->v4.sin_family = AF_INET;
	if (src) {
		sa->sin_port = uh->source;
		sa->sin_addr.s_addr = ip_hdr(skb)->saddr;
	} else {
		sa->sin_port = uh->dest;
		sa->sin_addr.s_addr = ip_hdr(skb)->daddr;
	}
	memset(sa->sin_zero, 0, sizeof(sa->sin_zero));
}

static void quic_v6_get_addr(union quic_addr *a, struct sk_buff *skb, bool src)
{
	struct udphdr *uh = (struct udphdr *)(skb->head + QUIC_RCV_CB(skb)->udp_hdr);
	struct sockaddr_in6 *sa = &a->v6;

	a->v6.sin6_family = AF_INET6;
	a->v6.sin6_flowinfo = 0;
	a->v6.sin6_scope_id = ((struct inet6_skb_parm *)skb->cb)->iif;
	if (src) {
		sa->sin6_port = uh->source;
		sa->sin6_addr = ipv6_hdr(skb)->saddr;
	} else {
		sa->sin6_port = uh->dest;
		sa->sin6_addr = ipv6_hdr(skb)->daddr;
	}
}

static int quic_v4_get_name(struct socket *sock, struct sockaddr *uaddr, int peer)
{
	return inet_getname(sock, uaddr, peer);
}

static int quic_v6_get_name(struct socket *sock, struct sockaddr *uaddr, int peer)
{
	return inet6_getname(sock, uaddr, peer);
}

static void quic_v4_set_addr(struct sock *sk, union quic_addr *a, bool src)
{
	if (src) {
		inet_sk(sk)->inet_sport = a->v4.sin_port;
		inet_sk(sk)->inet_saddr = a->v4.sin_addr.s_addr;
	} else {
		inet_sk(sk)->inet_dport = a->v4.sin_port;
		inet_sk(sk)->inet_daddr = a->v4.sin_addr.s_addr;
	}
}

static void quic_v6_set_addr(struct sock *sk, union quic_addr *a, bool src)
{
	if (src) {
		inet_sk(sk)->inet_sport = a->v6.sin6_port;
		sk->sk_v6_rcv_saddr = a->v6.sin6_addr;
	} else {
		inet_sk(sk)->inet_dport = a->v6.sin6_port;
		sk->sk_v6_daddr = a->v6.sin6_addr;
	}
}

static void quic_v4_get_msgname(struct sk_buff *skb, union quic_addr *a)
{
	struct udphdr *uh = (struct udphdr *)(skb->head + QUIC_RCV_CB(skb)->udp_hdr);

	a->v4.sin_family = AF_INET;
	a->v4.sin_port = uh->source;
	a->v4.sin_addr.s_addr = ip_hdr(skb)->saddr;
}

static void quic_v6_get_msgname(struct sk_buff *skb, union quic_addr *a)
{
	struct udphdr *uh = (struct udphdr *)(skb->head + QUIC_RCV_CB(skb)->udp_hdr);

	a->v6.sin6_family = AF_INET6;
	a->v6.sin6_flowinfo = 0;
	a->v6.sin6_port = uh->source;
	a->v6.sin6_addr = ipv6_hdr(skb)->saddr;
}

static struct quic_af quic_af_inet = {
	.sa_family		= AF_INET,
	.addr_len		= sizeof(struct sockaddr_in),
	.iphdr_len		= sizeof(struct iphdr),
	.udp_conf_init		= quic_v4_udp_conf_init,
	.flow_route		= quic_v4_flow_route,
	.lower_xmit		= quic_v4_lower_xmit,
	.get_addr		= quic_v4_get_addr,
	.set_addr		= quic_v4_set_addr,
	.get_name		= quic_v4_get_name,
	.get_msgname		= quic_v4_get_msgname,
	.setsockopt		= ip_setsockopt,
	.getsockopt		= ip_getsockopt,
};

static struct quic_af quic_af_inet6 = {
	.sa_family		= AF_INET6,
	.addr_len		= sizeof(struct sockaddr_in6),
	.iphdr_len		= sizeof(struct ipv6hdr),
	.udp_conf_init		= quic_v6_udp_conf_init,
	.flow_route		= quic_v6_flow_route,
	.lower_xmit		= quic_v6_lower_xmit,
	.get_addr		= quic_v6_get_addr,
	.set_addr		= quic_v6_set_addr,
	.get_name		= quic_v6_get_name,
	.get_msgname		= quic_v6_get_msgname,
	.setsockopt		= ipv6_setsockopt,
	.getsockopt		= ipv6_getsockopt,
};

struct quic_af *quic_af_get(sa_family_t family)
{
	switch (family) {
	case AF_INET:
		return &quic_af_inet;
	case AF_INET6:
		return &quic_af_inet6;
	default:
		return NULL;
	}
}

static void quic_write_space(struct sock *sk)
{
	struct socket_wq *wq;

	rcu_read_lock();
	wq = rcu_dereference(sk->sk_wq);
	if (skwq_has_sleeper(wq))
		wake_up_interruptible_sync_poll(&wq->wait, EPOLLOUT |
				EPOLLWRNORM | EPOLLWRBAND);
	rcu_read_unlock();
}

static int quic_init_sock(struct sock *sk)
{
	struct quic_sock *qs = quic_sk(sk);
	struct net *net = sock_net(sk);

	INIT_LIST_HEAD(&qs->list);
	qs->af = quic_af_get(sk->sk_family);

	sk->sk_destruct = inet_sock_destruct;
	qs->params.local.max_udp_payload_size = net->quic.max_udp_payload_size;
	qs->params.local.initial_max_data = net->quic.initial_max_data;
	qs->packet.rcv_max = qs->params.local.initial_max_data;
	qs->params.local.initial_max_stream_data_bidi_local =
			net->quic.initial_max_stream_data_bidi_local;
	qs->params.local.initial_max_stream_data_bidi_remote =
			net->quic.initial_max_stream_data_bidi_remote;
	qs->params.local.initial_max_stream_data_uni =
			net->quic.initial_max_stream_data_uni;
	qs->params.local.initial_max_streams_bidi =
			net->quic.initial_max_streams_bidi;
	qs->params.local.initial_max_streams_uni =
			net->quic.initial_max_streams_uni;
	qs->params.peer = qs->params.local;
	qs->packet.snd_max = qs->params.peer.initial_max_data;

	qs->cong.rto = msecs_to_jiffies(QUIC_RTO_INIT);

	sk->sk_write_space = quic_write_space;
	sock_set_flag(sk, SOCK_USE_WRITE_QUEUE);
	inet_sk_set_state(sk, QUIC_SS_CLOSED);

	local_bh_disable();
	sk_sockets_allocated_inc(sk);
	sock_prot_inuse_add(net, sk->sk_prot, 1);
	local_bh_enable();
	return 0;
}

static void quic_destroy_sock(struct sock *sk)
{
	local_bh_disable();
	sk_sockets_allocated_dec(sk);
	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, -1);
	local_bh_enable();
}

static int quic_bind(struct sock *sk, struct sockaddr *addr, int addr_len)
{
	struct quic_sock *qs = quic_sk(sk);
	union quic_addr *a = quic_saddr_cur(qs);
	__u32 err = 0;

	lock_sock(sk);

	if (a->v4.sin_port || addr->sa_family != sk->sk_family ||
	    addr_len < qs->af->addr_len || !quic_a(addr)->v4.sin_port) {
		err = -EINVAL;
		goto out;
	}

	memcpy(a, addr, qs->af->addr_len);
	qs->af->set_addr(&qs->inet.sk, a, true);

	qs->path.src.usk[0] = quic_udp_sock_lookup(qs, a);
	if (!qs->path.src.usk[0])
		err = -ENOMEM;

out:
	release_sock(sk);
	return err;
}

static int quic_wait_for_connect(struct sock *sk, long timeo)
{
	for (;;) {
		int err = 0, exit = 1;
		DEFINE_WAIT(wait);

		prepare_to_wait_exclusive(sk_sleep(sk), &wait,
					  TASK_INTERRUPTIBLE);
		if (!timeo) {
			err = -EAGAIN;
			goto out;
		}
		if (sk->sk_err) {
			err = sk->sk_err;
			goto out;
		}
		if (signal_pending(current)) {
			err = sock_intr_errno(timeo);
			goto out;
		}

		if (quic_sk(sk)->state != QUIC_CS_CLIENT_WAIT_HANDSHAKE)
			goto out;

		exit = 0;
		release_sock(sk);
		timeo = schedule_timeout(timeo);
		lock_sock(sk);
out:
		finish_wait(sk_sleep(sk), &wait);
		if (exit)
			return err;
	}
}

static int quic_do_connect(struct sock *sk)
{
	struct quic_sock *qs = quic_sk(sk);
	struct sk_buff *skb;
	int err;

	if (sk->sk_state == QUIC_SS_LISTENING || sk->sk_state == QUIC_SS_ESTABLISHED)
		return -EISCONN;

	err = quic_crypto_initial_keys_install(qs);
	if (err)
		goto init_err;
	err = quic_crypto_early_keys_prepare(qs);
	if (err)
		goto init_err;
	skb = quic_packet_create(qs, QUIC_PKT_INITIAL, QUIC_FRAME_CRYPTO);
	if (!skb) {
		err = -ENOMEM;
		goto init_err;
	}
	err = quic_crypto_early_keys_install(qs);
	if (err)
		goto init_err;
	quic_write_queue_enqueue(qs, skb);
	if (qs->frame.stream.msg) {
		qs->frame.stream.mss -= skb->len;
		skb = quic_packet_create(qs, QUIC_PKT_0RTT, QUIC_FRAME_STREAM);
		if (!skb) {
			err = -ENOMEM;
			goto init_err;
		}
		quic_write_queue_enqueue(qs, skb);
	}
	err = quic_write_queue_flush(qs);
	if (err)
		goto route_err;

	quic_start_hs_timer(qs, 0);

	qs->state = QUIC_CS_CLIENT_WAIT_HANDSHAKE;
	inet_sk_set_state(sk, QUIC_SS_CONNECTING);
	return 0;

route_err:
	kfree_skb(skb);
init_err:
	quic_sock_free(qs);
	return err;
}

static int quic_inet_connect(struct socket *sock, struct sockaddr *addr, int addr_len, int flags)
{
	struct sock *sk = sock->sk;
	struct quic_sock *qs;
	u8 dcid[8], scid[8];
	long timeo;
	int err;

	lock_sock(sk);

	get_random_bytes(dcid, 8);
	get_random_bytes(scid, 8);
	qs = quic_sk(sk);
	if (addr->sa_family != sk->sk_family || addr_len < qs->af->addr_len ||
	    !quic_a(addr)->v4.sin_port) {
		err = -EINVAL;
		goto out;
	}
	qs->state = QUIC_CS_CLIENT_INITIAL;
	err = quic_sock_init(qs, quic_a(addr), dcid, 8, scid, 8);
	if (err)
		return err;

	err = quic_do_connect(sk);
	if (err) {
		quic_sock_free(qs);
		goto out;
	}

	timeo = sock_sndtimeo(sk, flags & O_NONBLOCK);
	err = quic_wait_for_connect(sk, timeo);
out:
	release_sock(sk);
	return err;
}

static void quic_close(struct sock *sk, long timeout)
{
	struct quic_sock *qs = quic_sk(sk);
	struct sk_buff *skb;

	lock_sock(sk);
	if (sk->sk_state == QUIC_SS_LISTENING) {
		struct quic_hash_head *head;

		if (!hlist_unhashed(&qs->node)) {
			head = quic_lsk_head(sock_net(sk), quic_saddr_cur(qs));
			spin_lock(&head->lock);
			hlist_del(&qs->node);
			spin_unlock(&head->lock);
		}
	} else if (sk->sk_state != QUIC_SS_CLOSED) {
		pr_info("close %u %u\n", READ_ONCE(sk->sk_sndbuf),
			READ_ONCE(sk->sk_wmem_queued));
		if (qs->state != QUIC_CS_CLOSING) {
			qs->frame.close.err = QUIC_ERROR_NO_ERROR;
			skb = quic_packet_create(qs, QUIC_PKT_SHORT,
						 QUIC_FRAME_CONNECTION_CLOSE_APP);
			if (skb) {
				quic_write_queue_enqueue(qs, skb);
				quic_write_queue_flush(qs);
			}
		}
		qs->state = QUIC_CS_CLOSING;
		quic_sock_free(qs);
	}

	quic_us_put(qs->path.src.usk[0]);
	quic_us_put(qs->path.src.usk[1]);

	inet_sk_set_state(sk, QUIC_SS_CLOSED);
	release_sock(sk);

	sk_common_release(sk);
}

static int quic_wait_for_sndbuf(struct sock *sk, long timeo, u32 msg_len)
{
	struct quic_sock *qs = quic_sk(sk);

	for (;;) {
		int err = 0, exit = 1;
		DEFINE_WAIT(wait);

		prepare_to_wait_exclusive(sk_sleep(sk), &wait,
					  TASK_INTERRUPTIBLE);
		if (!timeo) {
			err = -EAGAIN;
			goto out;
		}
		if (sk->sk_err) {
			err = sk->sk_err;
			pr_warn("wait sndbuf sk_err %d\n", err);
			goto out;
		}
		if (signal_pending(current)) {
			err = sock_intr_errno(timeo);
			goto out;
		}

		if (qs->state != QUIC_CS_CLIENT_WAIT_HANDSHAKE &&
		    qs->state != QUIC_CS_SERVER_WAIT_HANDSHAKE &&
		    qs->state != QUIC_CS_CLIENT_POST_HANDSHAKE &&
		    qs->state != QUIC_CS_SERVER_POST_HANDSHAKE) {
			err = -EPIPE;
			pr_warn("wait sndbuf state %u, %d\n", qs->state, err);
			goto out;
		}

		if ((int)msg_len <= quic_stream_wspace(sk))
			goto out;

		exit = 0;
		release_sock(sk);
		timeo = schedule_timeout(timeo);
		lock_sock(sk);
out:
		finish_wait(sk_sleep(sk), &wait);
		if (exit)
			return err;
	}
}

int quic_dst_mss_check(struct quic_sock *qs, int hdr)
{
	struct sock *sk = &qs->inet.sk;
	struct dst_entry *dst;
	int mss;

	dst = __sk_dst_check(sk, 0);
	if (!dst) {
		if (qs->af->flow_route(qs))
			return -EHOSTUNREACH;
		dst = __sk_dst_get(sk);
	}

	mss = dst_mtu(dst);
	mss -= (qs->af->iphdr_len + sizeof(struct udphdr));
	if (hdr == 1) {
		mss -= (sizeof(struct quic_shdr));
		mss -= (qs->cids.dcid.cur->len + QUIC_TAGLEN);
	} else if (hdr == 2) {
		mss -= (sizeof(struct quic_lhdr) + 4);
		mss -= (1 + qs->cids.dcid.cur->len + 1 + qs->cids.scid.cur->len);
		mss -= (quic_put_varint_len(qs->token.len) + qs->token.len);
		mss -= (4 + 2);
		mss -= QUIC_TAGLEN;
	} else if (hdr == 3) {
		mss -= (qs->af->iphdr_len + sizeof(struct udphdr));
		mss -= (sizeof(struct quic_lhdr) + 4);
		mss -= (1 + qs->cids.dcid.cur->len + 1 + qs->cids.scid.cur->len);
		mss -= (4 + 2);
		mss -= QUIC_TAGLEN;
	}

	return mss;
}

static int quic_msghdr_parse(struct msghdr *msg, struct quic_sndinfo *info)
{
	struct quic_sndinfo *s;
	struct cmsghdr *cmsg;

	for_each_cmsghdr(cmsg, msg) {
		if (!CMSG_OK(msg, cmsg))
			return -EINVAL;

		if (cmsg->cmsg_level != IPPROTO_QUIC)
			continue;

		switch (cmsg->cmsg_type) {
		case QUIC_SNDINFO:
			if (cmsg->cmsg_len != CMSG_LEN(sizeof(*s)))
				return -EINVAL;
			s = CMSG_DATA(cmsg);
			info->stream_id = s->stream_id;
			break;
		default:
			return -EINVAL;
		}
	}

	return 0;
}

static void quic_wfree(struct sk_buff *skb)
{
	struct sock *sk = skb->sk;

	sk_wmem_queued_add(sk, -skb->truesize);

	if (quic_stream_wspace(sk) > 0)
		sk->sk_write_space(sk);
}

static void quic_set_owner_w(struct sk_buff *skb, struct sock *sk)
{
	sk_wmem_queued_add(sk, skb->truesize);

	skb->sk = sk;
	skb->destructor = quic_wfree;
}

static int quic_sendmsg(struct sock *sk, struct msghdr *msg, size_t msg_len)
{
	struct quic_sock *qs = quic_sk(sk);
	struct quic_strm *strm;
	struct sockaddr *addr;
	struct quic_sndinfo s;
	u8 dcid[8], scid[8];
	struct sk_buff *skb;
	int err, mss;
	long timeo;

	err = quic_msghdr_parse(msg, &s);
	if (err)
		return err;

	lock_sock(sk);

	if (qs->state == QUIC_CS_CLOSING) {
		err = -EPIPE;
		goto err;
	}

	if (qs->state == QUIC_CS_CLOSED) { /* 0RTT data */
		if (!qs->crypt.psks || !msg->msg_name) {
			err = -EPIPE;
			goto err;
		}

		get_random_bytes(dcid, 8);
		get_random_bytes(scid, 8);

		addr = msg->msg_name;
		if (addr->sa_family != sk->sk_family || msg->msg_namelen < qs->af->addr_len ||
		    !quic_a(addr)->v4.sin_port) {
			err = -EINVAL;
			goto err;
		}
		qs->state = QUIC_CS_CLIENT_INITIAL;
		err = quic_sock_init(qs, quic_a(addr), dcid, 8, scid, 8);
		if (err)
			goto err;

		mss = quic_dst_mss_check(qs, 3);
		if (mss < 0) {
			err = mss;
			goto err;
		}

		qs->frame.stream.mss = mss;
		qs->frame.stream.sid = s.stream_id;
		qs->frame.stream.msg = &msg->msg_iter;
		qs->frame.stream.fin = msg->msg_flags & MSG_EOR;
		err = quic_do_connect(sk);
		if (err)
			goto err;
		timeo = sock_sndtimeo(sk, 0);
		err = quic_wait_for_connect(sk, timeo);
		if (err)
			goto err;
		if (!iov_iter_count(qs->frame.stream.msg))
			goto out;
	}

	mss = quic_dst_mss_check(qs, 1);
	if (mss < 0) {
		err = mss;
		goto err;
	}

	strm = quic_strm_snd_get(qs, s.stream_id);
	if (!strm) {
		err = -EINVAL;
		goto err;
	}
	if (strm->snd_state == QUIC_STRM_L_READY) {
		strm->snd_state = QUIC_STRM_L_SEND;
	} else if (strm->snd_state >= QUIC_STRM_L_SENT) {
		err = -EPIPE;
		goto err;
	}

	qs->frame.stream.mss = mss;
	qs->frame.stream.sid = s.stream_id;
	qs->frame.stream.msg = &msg->msg_iter;
	qs->frame.stream.fin = msg->msg_flags & MSG_EOR;
	while (iov_iter_count(qs->frame.stream.msg) > 0) {
		if (quic_stream_wspace(sk) <= 0) {
			timeo = sock_sndtimeo(sk, msg->msg_flags & MSG_DONTWAIT);
			err = quic_wait_for_sndbuf(sk, timeo, msg_len);
			if (err)
				goto err;

			qs->frame.stream.mss = mss;
			qs->frame.stream.sid = s.stream_id;
			qs->frame.stream.msg = &msg->msg_iter;
			qs->frame.stream.fin = msg->msg_flags & MSG_EOR;
		}

		qs->packet.f = &qs->frame.f[QUIC_PKT_SHORT];
		skb = quic_packet_create(qs, QUIC_PKT_SHORT, QUIC_FRAME_STREAM);
		if (!skb) {
			err = -ENOMEM;
			goto err;
		}
		QUIC_SND_CB(skb)->strm_id = s.stream_id;
		QUIC_SND_CB(skb)->mlen = qs->frame.stream.len;
		quic_set_owner_w(skb, sk);
		quic_write_queue_enqueue(qs, skb);
		err = quic_write_queue_flush(qs);
		if (err)
			goto err;
	}
out:
	release_sock(sk);
	return msg_len;
err:
	release_sock(sk);
	return err;
}

static int quic_wait_for_packet(struct sock *sk, long timeo)
{
	struct quic_sock *qs = quic_sk(sk);

	for (;;) {
		int err = 0, exit = 1;
		DEFINE_WAIT(wait);

		prepare_to_wait_exclusive(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);

		if (!skb_queue_empty(&sk->sk_receive_queue))
			goto out;

		err = -EAGAIN;
		if (!timeo)
			goto out;

		err = sock_intr_errno(timeo);
		if (signal_pending(current))
			goto out;

		if (qs->state != QUIC_CS_CLIENT_WAIT_HANDSHAKE &&
		    qs->state != QUIC_CS_SERVER_WAIT_HANDSHAKE &&
		    qs->state != QUIC_CS_CLIENT_POST_HANDSHAKE &&
		    qs->state != QUIC_CS_SERVER_POST_HANDSHAKE) {
			err = -EPIPE;
			pr_warn("wait packet state %u, %d\n", qs->state, err);
			goto out;
		}
		if (sk->sk_err) {
			err = sk->sk_err;
			pr_warn("wait rcv pkt sk_err %d\n", err);
			goto out;
		}

		exit = 0;
		release_sock(sk);
		timeo = schedule_timeout(timeo);
		lock_sock(sk);
out:
		finish_wait(sk_sleep(sk), &wait);
		if (exit)
			return err;
	}
}

static int quic_read_flow_control(struct quic_sock *qs, struct sk_buff *skb)
{
	u32 pkt_rwnd = qs->params.local.initial_max_data;
	u32 sid = QUIC_RCV_CB(skb)->strm_id, strm_rwnd;
	struct quic_packet *pkt = &qs->packet;
	struct quic_strm *strm;

	strm = quic_strm_rcv_get(qs, sid);
	strm_rwnd = quic_strm_max_get(qs, sid);
	strm->rcv_len += skb->len;
	pkt->rcv_len += skb->len;

	if (pkt->rcv_max - pkt->rcv_len < pkt_rwnd / 2 &&
	    pkt->rcv_max - pkt->rcv_len > pkt_rwnd / 8) {
		qs->frame.max.limit = pkt_rwnd + pkt->rcv_len;
		qs->packet.rcv_max = pkt_rwnd + pkt->rcv_len;
		pr_debug("flow control set max data %u, %llu\n", pkt_rwnd, pkt->rcv_len);
		skb = quic_packet_create(qs, QUIC_PKT_SHORT, QUIC_FRAME_MAX_DATA);
		if (skb)
			quic_write_queue_enqueue(qs, skb);
	}

	if (strm->rcv_max - strm->rcv_len < strm_rwnd / 2 &&
	    strm->rcv_max - strm->rcv_len > strm_rwnd / 8) {
		qs->frame.stream.sid = sid;
		qs->frame.max.limit = strm_rwnd + strm->rcv_len;
		strm->rcv_max = strm_rwnd + strm->rcv_len;
		pr_debug("flow control set max stream data %u, %llu\n", strm_rwnd, strm->rcv_len);
		skb = quic_packet_create(qs, QUIC_PKT_SHORT, QUIC_FRAME_MAX_STREAM_DATA);
		if (skb)
			quic_write_queue_enqueue(qs, skb);
	}

	return 0;
}

static int quic_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
			int noblock, int flags, int *addr_len)
{
	union quic_addr *addr = (union quic_addr *)msg->msg_name;
	struct quic_sock *qs = quic_sk(sk);
	struct quic_strm *strm;
	struct quic_rcvinfo r;
	struct sk_buff *skb;
	int copy, err;
	long timeo;

	lock_sock(sk);

	if (qs->state == QUIC_CS_CLOSING) {
		err = -EPIPE;
		goto out;
	}

	timeo = sock_rcvtimeo(sk, noblock);
	err = quic_wait_for_packet(sk, timeo);
	if (err)
		goto out;

	skb = skb_peek(&sk->sk_receive_queue);
	copy = min_t(int, skb->len, len);
	err = skb_copy_datagram_msg(skb, 0, msg, copy);
	if (err)
		goto out;

	if (copy != skb->len)
		msg->msg_flags |= MSG_TRUNC;

	r.stream_id = QUIC_RCV_CB(skb)->strm_id;
	put_cmsg(msg, IPPROTO_QUIC, QUIC_RCVINFO, sizeof(r), &r);

	if (QUIC_RCV_CB(skb)->is_evt) {
		msg->msg_flags |= MSG_NOTIFICATION;
		goto evt;
	}

	strm = quic_strm_rcv_get(qs, QUIC_RCV_CB(skb)->strm_id);
	if (!strm) {
		err = -EPIPE;
		goto out;
	}
	if (QUIC_RCV_CB(skb)->strm_fin) {
		strm->rcv_state = QUIC_STRM_P_READ;
		msg->msg_flags |= MSG_EOR;
	}
	quic_read_flow_control(qs, skb);

	if (addr) {
		qs->af->get_msgname(skb, addr);
		*addr_len = qs->af->addr_len;
	}

evt:
	err = copy;
	if (flags & MSG_PEEK)
		goto out;
	kfree_skb(__skb_dequeue(&sk->sk_receive_queue));

out:
	release_sock(sk);
	return err;
}

static int quic_wait_for_accept(struct sock *sk, long timeo)
{
	struct quic_sock *qs = quic_sk(sk);
	DEFINE_WAIT(wait);
	int err = 0;

	for (;;) {
		prepare_to_wait_exclusive(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);
		if (list_empty(&qs->list)) {
			release_sock(sk);
			timeo = schedule_timeout(timeo);
			lock_sock(sk);
		}

		if (sk->sk_state != QUIC_SS_LISTENING) {
			err = -EINVAL;
			break;
		}

		if (!list_empty(&qs->list)) {
			err = 0;
			break;
		}

		if (signal_pending(current)) {
			err = sock_intr_errno(timeo);
			break;
		}

		if (!timeo) {
			err = -EAGAIN;
			break;
		}
	}

	finish_wait(sk_sleep(sk), &wait);
	return err;
}

static struct sock *quic_accept(struct sock *sk, int flags, int *err, bool kern)
{
	struct sock *nsk = NULL;
	struct quic_sock *qs;
	int error = 0;
	long timeo;

	lock_sock(sk);

	if (sk->sk_state != QUIC_SS_LISTENING) {
		error = -EINVAL;
		goto out;
	}

	timeo = sock_rcvtimeo(sk, flags & O_NONBLOCK);
	error = quic_wait_for_accept(sk, timeo);
	if (error)
		goto out;

	qs = list_entry(quic_sk(sk)->list.next, struct quic_sock, list);
	list_del_init(&qs->list);
	nsk = &qs->inet.sk;
	inet_sk_set_state(nsk, QUIC_SS_ESTABLISHED);

out:
	release_sock(sk);
	*err = error;
	return nsk;
}

static int quic_hash(struct sock *sk)
{
	return 0;
}

static void quic_unhash(struct sock *sk)
{
}

static int quic_inet_listen(struct socket *sock, int backlog)
{
	struct quic_hash_head *head;
	struct sock *sk = sock->sk;
	struct quic_sock *qs, *q;
	union quic_addr *a;
	int err = 0;

	lock_sock(sk);
	sk->sk_state = QUIC_SS_LISTENING;
	sk->sk_max_ack_backlog = backlog;

	qs = quic_sk(sk);
	a = quic_saddr_cur(qs);
	head = quic_lsk_head(sock_net(sk), a);
	spin_lock(&head->lock);

	hlist_for_each_entry(q, &head->head, node) {
		if (sock_net(sk) == sock_net(&q->inet.sk) &&
		    !memcmp(a, quic_saddr_cur(q), qs->af->addr_len)) {
			err = -EADDRINUSE;
			goto out;
		}
	}

	hlist_add_head(&qs->node, &head->head);

out:
	spin_unlock(&head->lock);
	release_sock(sk);
	return err;
}

int quic_inet_getname(struct socket *sock, struct sockaddr *uaddr, int peer)
{
	return quic_sk(sock->sk)->af->get_name(sock, uaddr, peer);
}

struct quic_cert *quic_cert_create(u8 *cert, int len)
{
	struct x509_certificate *x;
	struct quic_cert *c;

	c = kzalloc(sizeof(*c), GFP_ATOMIC);
	if (!c)
		return NULL;

	c->raw.len = len;
	c->raw.v = quic_mem_dup(cert, len);
	if (!c->raw.v) {
		kfree(c);
		return NULL;
	}

	x = x509_cert_parse(c->raw.v, len);
	if (IS_ERR(x)) {
		quic_cert_free(c);
		return NULL;
	}
	c->cert = x;

	return c;
}

void quic_cert_free(struct quic_cert *cert)
{
	struct quic_cert *c, *p = cert;

	while (p) {
		c = p->next;
		kfree(p->cert);
		kfree(p->raw.v);
		kfree(p);
		p = c;
	}
}

static int quic_setsockopt_root_ca(struct sock *sk, u8 *cert, unsigned int len)
{
	struct quic_sock *qs = quic_sk(sk);
	struct quic_cert *c;

	if (!len) {
		quic_cert_free(qs->crypt.ca);
		qs->crypt.ca = NULL;
		return 0;
	}

	c = quic_cert_create(cert, len);
	if (!c)
		return -ENOMEM;

	qs->crypt.ca = c;
	return 0;
}

static int quic_setsockopt_cert(struct sock *sk, u8 *cert, unsigned int len)
{
	struct quic_sock *qs = quic_sk(sk);
	struct quic_cert *c, *p;

	if (!len) {
		quic_cert_free(qs->crypt.certs);
		qs->crypt.certs = NULL;
		return 0;
	}

	c = quic_cert_create(cert, len);
	if (!c)
		return -ENOMEM;

	p = qs->crypt.certs;
	if (p) {
		for (; p->next; p = p->next)
			;
		p->next = c;
	} else {
		qs->crypt.certs = c;
	}

	return 0;
}

static int quic_setsockopt_cert_chain(struct sock *sk, u8 *cert, unsigned int len)
{
	struct quic_cert *c, *certs = NULL, *p = NULL;
	struct quic_sock *qs = quic_sk(sk);
	int clen, err = 0;

	while (len > 0) {
		clen = *((u32 *)cert);
		cert += 4;
		len -= 4;
		c = quic_cert_create(cert, clen);
		if (!c) {
			err = -ENOMEM;
			goto out;
		}

		cert += clen;
		len -= clen;
		if (!certs)
			certs = c;
		else
			p->next = c;
		p = c;
	}

out:
	quic_cert_free(qs->crypt.certs);
	qs->crypt.certs = certs;

	return 0;
}

static int quic_setsockopt_pkey(struct sock *sk, u8 *pkey, unsigned int len)
{
	struct quic_sock *qs = quic_sk(sk);

	pkey = quic_mem_dup(pkey, len);
	if (!pkey)
		return -ENOMEM;

	kfree(qs->crypt.pkey.v);
	qs->crypt.pkey.v = pkey;
	qs->crypt.pkey.len = len;

	return 0;
}

static int quic_setsockopt_cur_cid(struct sock *sk, u32 *cur, unsigned int len, bool is_scid)
{
	struct quic_sock *qs = quic_sk(sk);
	struct quic_cid *cid;

	if (len != sizeof(*cur))
		return -EINVAL;

	if (is_scid) {
		cid = quic_cid_get(qs->cids.scid.list, *cur);
		if (!cid)
			return -EINVAL;

		qs->cids.scid.cur = cid;
		return 0;
	}

	cid = quic_cid_get(qs->cids.dcid.list, *cur);
	if (!cid)
		return -EINVAL;

	qs->cids.dcid.cur = cid;
	return 0;
}

static int quic_setsockopt_cur_saddr(struct sock *sk, union quic_addr *a, unsigned int len)
{
	struct quic_sock *qs = quic_sk(sk);
	struct quic_usock *usk;

	if (len != qs->af->addr_len)
		return -EINVAL;
	usk = quic_udp_sock_lookup(qs, a);
	if (!usk)
		return -EINVAL;

	qs->path.src.cur = !qs->path.src.cur;
	memcpy(quic_saddr_cur(qs), a, len);
	quic_us_put(qs->path.src.usk[qs->path.src.cur]);
	qs->path.src.usk[qs->path.src.cur] = usk;
	sk_dst_reset(&qs->inet.sk);

	return 0;
}

static int quic_setsockopt_reset_stream(struct sock *sk, u32 *sid, unsigned int len)
{
	struct quic_sock *qs = quic_sk(sk);
	struct quic_strm *strm;
	struct sk_buff *skb;
	int err;

	if (len != sizeof(*sid))
		return -EINVAL;

	strm = quic_strm_snd_get(qs, *sid);
	if (!strm)
		return -EINVAL;
	qs->frame.stream.sid = *sid;
	skb = quic_packet_create(qs, QUIC_PKT_SHORT, QUIC_FRAME_RESET_STREAM);
	if (!skb)
		return -ENOMEM;

	strm->snd_state = QUIC_STRM_L_RESET_SENT;
	quic_write_queue_enqueue(qs, skb);
	err = quic_write_queue_flush(qs);

	return err;
}

static int quic_setsockopt_stop_sending(struct sock *sk, u32 *sid, unsigned int len)
{
	struct quic_sock *qs = quic_sk(sk);
	struct quic_strm *strm;
	struct sk_buff *skb;
	int err;

	if (len != sizeof(*sid))
		return -EINVAL;

	strm = quic_strm_rcv_get(qs, *sid);
	if (!strm)
		return -EINVAL;
	qs->frame.stream.sid = *sid;
	skb = quic_packet_create(qs, QUIC_PKT_SHORT, QUIC_FRAME_STOP_SENDING);
	if (!skb)
		return -ENOMEM;

	quic_write_queue_enqueue(qs, skb);
	err = quic_write_queue_flush(qs);

	return err;
}

static int quic_setsockopt_max_streams(struct sock *sk, struct quic_idv *idv, unsigned int len)
{
	struct quic_sock *qs = quic_sk(sk);
	struct sk_buff *skb;

	if (len != sizeof(*idv))
		return -EINVAL;

	if (!idv->id) {
		if (idv->value <= qs->params.peer.initial_max_streams_uni)
			return -EINVAL;
		qs->frame.max.limit = idv->value;
		skb = quic_packet_create(qs, QUIC_PKT_SHORT, QUIC_FRAME_MAX_STREAMS_UNI);
		if (!skb)
			return -ENOMEM;
		qs->params.peer.initial_max_streams_uni = idv->value;
		quic_write_queue_enqueue(qs, skb);
		return quic_write_queue_flush(qs);
	}

	if (idv->value <= qs->params.peer.initial_max_streams_bidi)
		return -EINVAL;
	qs->frame.max.limit = idv->value;
	skb = quic_packet_create(qs, QUIC_PKT_SHORT, QUIC_FRAME_MAX_STREAMS_BIDI);
	if (!skb)
		return -ENOMEM;
	qs->params.peer.initial_max_streams_bidi = idv->value;
	quic_write_queue_enqueue(qs, skb);
	return quic_write_queue_flush(qs);
}

static int quic_setsockopt_event(struct sock *sk, struct quic_idv *idv, unsigned int len)
{
	struct quic_sock *qs = quic_sk(sk);

	if (len != sizeof(*idv))
		return -EINVAL;
	if (idv->id >= QUIC_EVT_MAX)
		return -EINVAL;

	if (idv->value)
		qs->packet.events |= (1 << idv->id);
	else
		qs->packet.events &= ~(1 << idv->id);

	return 0;
}

static int quic_setsockopt_events(struct sock *sk, u32 *events, unsigned int len)
{
	struct quic_sock *qs = quic_sk(sk);

	if (len != sizeof(*events))
		return -EINVAL;

	qs->packet.events = *events;
	return 0;
}

static int quic_setsockopt_new_ticket(struct sock *sk, u8 *pskid, unsigned int len)
{
	struct quic_sock *qs = quic_sk(sk);
	struct sk_buff *skb;
	u8 nonce[8];
	int err;

	if (len < sizeof(*pskid) || qs->state != QUIC_CS_SERVER_POST_HANDSHAKE ||
	    qs->crypt.psks)
		return -EINVAL;

	get_random_bytes(nonce, 8);
	err = quic_crypto_psk_create(qs, pskid, len, nonce, 8,
				     qs->crypt.rms_secret, QUIC_HKDF_HASHLEN);
	if (err)
		return err;

	qs->packet.ticket = quic_packet_create(qs, QUIC_PKT_SHORT, QUIC_FRAME_CRYPTO);
	if (!qs->packet.ticket) {
		quic_crypto_psk_free(qs);
		return -ENOMEM;
	}

	skb = skb_clone(qs->packet.ticket, GFP_ATOMIC);
	if (skb) {
		skb_set_owner_w(skb, sk);
		qs->af->lower_xmit(qs, skb);
		quic_start_rtx_timer(qs, 0);
	}

	return 0;
}

static int quic_setsockopt_load_ticket(struct sock *sk, u8 *psk, unsigned int len)
{
	u32 expire, sent_at, *p = (u32 *)psk;
	u32 nonce_len, pskid_len, mskey_len;
	struct quic_sock *qs = quic_sk(sk);
	u8 *nonce, *pskid, *mskey;
	struct quic_psk *psks;
	int err;

	if (len < 20 || qs->state != QUIC_CS_CLOSED || qs->crypt.psks)
		return -EINVAL;

	pskid_len = *p++;
	nonce_len = *p++;
	mskey_len = *p++;
	sent_at = *p++;
	expire = *p++;

	psk = (u8 *)p;
	pskid = psk;
	nonce = psk + pskid_len;
	mskey = psk + pskid_len + nonce_len;
	err = quic_crypto_psk_create(qs, pskid, pskid_len, nonce, nonce_len,
				     mskey, mskey_len);
	if (err)
		return err;

	psks = qs->crypt.psks;
	psks->psk_sent_at = sent_at + 5000;
	psks->psk_expire = expire;
	pr_debug("load ticket %u %u: %8phN(%u), %8phN(%u), %8phN(%u)\n",
		 psks->psk_sent_at, psks->psk_expire,
		 psks->pskid.v, psks->pskid.len, psks->nonce.v,
		 psks->nonce.len, psks->mskey.v, psks->mskey.len);

	return 0;
}

static int quic_setsockopt_key_update(struct sock *sk, u8 *key, unsigned int len)
{
	struct quic_sock *qs = quic_sk(sk);
	int err;

	if (qs->crypt.key_pending ||
	    (qs->state != QUIC_CS_SERVER_POST_HANDSHAKE &&
	     qs->state != QUIC_CS_CLIENT_POST_HANDSHAKE))
		return -EINVAL;

	err = quic_crypto_key_update(qs);
	if (err)
		return err;

	qs->crypt.key_pending = 1;
	return 0;
}

static int quic_setsockopt_new_token(struct sock *sk, u8 *token, unsigned int len)
{
	struct quic_sock *qs = quic_sk(sk);
	struct sk_buff *skb;
	char t[8];

	if (!qs->lsk)
		return -EINVAL;

	if (!len) {
		token = t;
		get_random_bytes(token, 8);
		len = 8;
	}

	kfree(qs->token.token);
	qs->token.token = quic_mem_dup(token, len);
	if (!qs->token.token)
		return -ENOMEM;
	qs->token.len = len;

	skb = quic_packet_create(qs, QUIC_PKT_SHORT, QUIC_FRAME_NEW_TOKEN);
	if (!skb)
		return -ENOMEM;
	qs->packet.token = skb;

	skb = skb_clone(skb, GFP_ATOMIC);
	if (skb) {
		quic_write_queue_enqueue(qs, skb);
		quic_write_queue_flush(qs);
	}

	return 0;
}

static int quic_setsockopt_load_token(struct sock *sk, u8 *token, unsigned int len)
{
	struct quic_sock *qs = quic_sk(sk);

	kfree(qs->token.token);
	qs->token.token = quic_mem_dup(token, len);
	if (!qs->token.token)
		return -ENOMEM;
	qs->token.len = len;

	return 0;
}

static int quic_setsockopt_cert_request(struct sock *sk, u8 *v, unsigned int len)
{
	if (!len)
		return -EINVAL;

	quic_sk(sk)->crypt.cert_req = !!(*v);
	return 0;
}

static int quic_setsockopt_new_cid(struct sock *sk, u32 *cid, unsigned int len)
{
	struct quic_sock *qs = quic_sk(sk);
	struct quic_cid *tmp;
	struct sk_buff *skb;
	int err, cur = 0;

	if (len != sizeof(*cid))
		return -EINVAL;

	if (*cid > qs->cids.scid.first + qs->cids.scid.cnt - 1)
		return -EINVAL;

	tmp = qs->cids.scid.list;
	while (tmp->next) {
		if (tmp->no >= *cid)
			break;
		qs->cids.scid.list = tmp->next;
		if (tmp == qs->cids.scid.cur) {
			qs->cids.scid.cur = qs->cids.scid.list;
			cur = 1;
		}
		qs->cids.scid.cnt--;
		quic_cid_destroy(tmp);
		tmp = qs->cids.scid.list;
		qs->cids.scid.first = *cid;
	}

	if (cur) {
		u32 value[3] = {0};

		value[0] = 0;
		value[1] = qs->cids.scid.cur->no;
		err = quic_evt_notify(qs, QUIC_EVT_CIDS, QUIC_EVT_CIDS_CUR, value);
		if (err)
			return err;
	}

	qs->frame.cid.no = *cid;
	skb = quic_packet_create(qs, QUIC_PKT_SHORT, QUIC_FRAME_NEW_CONNECTION_ID);
	if (!skb)
		return -ENOMEM;

	quic_write_queue_enqueue(qs, skb);
	err = quic_write_queue_flush(qs);

	return err;
}

static int quic_setsockopt_retire_cid(struct sock *sk, u32 *cid, unsigned int len)
{
	struct quic_sock *qs = quic_sk(sk);
	struct quic_cid *tmp;
	struct sk_buff *skb;
	int cur = 0;

	if (len != sizeof(*cid))
		return -EINVAL;

	if (*cid > qs->cids.dcid.first + qs->cids.dcid.cnt - 1)
		return -EINVAL;

	tmp = qs->cids.dcid.list;
	while (tmp->next) {
		if (tmp->no > *cid)
			break;
		qs->cids.dcid.list = tmp->next;
		if (tmp == qs->cids.dcid.cur) {
			qs->cids.dcid.cur = qs->cids.dcid.list;
			cur = 1;
		}
		qs->cids.dcid.cnt--;
		quic_cid_destroy(tmp);
		tmp = qs->cids.dcid.list;
		qs->cids.dcid.first = *cid + 1;
	}

	if (cur) {
		u32 value[3] = {0};
		int err;

		value[0] = 1;
		value[1] = qs->cids.dcid.cur->no;
		err = quic_evt_notify(qs, QUIC_EVT_CIDS, QUIC_EVT_CIDS_CUR, value);
		if (err)
			return err;
	}

	qs->frame.cid.no = *cid;
	skb = quic_packet_create(qs, QUIC_PKT_SHORT, QUIC_FRAME_RETIRE_CONNECTION_ID);
	if (!skb)
		return -ENOMEM;

	quic_write_queue_enqueue(qs, skb);
	return quic_write_queue_flush(qs);
}

static int quic_setsockopt(struct sock *sk, int level, int optname,
			   sockptr_t optval, unsigned int optlen)
{
	struct quic_sock *qs = quic_sk(sk);
	int retval = 0, listen;
	void *kopt = NULL;

	if (level != SOL_QUIC)
		return qs->af->setsockopt(sk, level, optname, optval, optlen);

	if (optlen > 0) {
		kopt = memdup_sockptr(optval, optlen);
		if (IS_ERR(kopt))
			return PTR_ERR(kopt);
	}

	lock_sock(sk);

	if (qs->state == QUIC_CS_CLOSING) {
		retval = -EPIPE;
		goto out;
	}

	listen = sk->sk_state == QUIC_SS_LISTENING;
	switch (optname) {
	case QUIC_SOCKOPT_CERT:
		retval = quic_setsockopt_cert(sk, kopt, optlen);
		break;
	case QUIC_SOCKOPT_CERT_CHAIN:
		retval = quic_setsockopt_cert_chain(sk, kopt, optlen);
		break;
	case QUIC_SOCKOPT_ROOT_CA:
		retval = quic_setsockopt_root_ca(sk, kopt, optlen);
		break;
	case QUIC_SOCKOPT_PKEY:
		retval = quic_setsockopt_pkey(sk, kopt, optlen);
		break;
	case QUIC_SOCKOPT_NEW_SCID:
		retval = quic_setsockopt_new_cid(sk, kopt, optlen);
		break;
	case QUIC_SOCKOPT_DEL_DCID:
		retval = quic_setsockopt_retire_cid(sk, kopt, optlen);
		break;
	case QUIC_SOCKOPT_CUR_SCID:
		retval = quic_setsockopt_cur_cid(sk, kopt, optlen, true);
		break;
	case QUIC_SOCKOPT_CUR_DCID:
		retval = quic_setsockopt_cur_cid(sk, kopt, optlen, false);
		break;
	case QUIC_SOCKOPT_CUR_SADDR:
		retval = quic_setsockopt_cur_saddr(sk, kopt, optlen);
		break;
	case QUIC_SOCKOPT_RESET_STREAM:
		retval = quic_setsockopt_reset_stream(sk, kopt, optlen);
		break;
	case QUIC_SOCKOPT_STOP_SENDING:
		retval = quic_setsockopt_stop_sending(sk, kopt, optlen);
		break;
	case QUIC_SOCKOPT_MAX_STREAMS:
		retval = quic_setsockopt_max_streams(sk, kopt, optlen);
		break;
	case QUIC_SOCKOPT_EVENT:
		retval = quic_setsockopt_event(sk, kopt, optlen);
		break;
	case QUIC_SOCKOPT_EVENTS:
		retval = quic_setsockopt_events(sk, kopt, optlen);
		break;
	case QUIC_SOCKOPT_NEW_TICKET:
		retval = quic_setsockopt_new_ticket(sk, kopt, optlen);
		break;
	case QUIC_SOCKOPT_LOAD_TICKET:
		retval = quic_setsockopt_load_ticket(sk, kopt, optlen);
		break;
	case QUIC_SOCKOPT_KEY_UPDATE:
		retval = quic_setsockopt_key_update(sk, kopt, optlen);
		break;
	case QUIC_SOCKOPT_NEW_TOKEN:
		retval = quic_setsockopt_new_token(sk, kopt, optlen);
		break;
	case QUIC_SOCKOPT_LOAD_TOKEN:
		retval = quic_setsockopt_load_token(sk, kopt, optlen);
		break;
	case QUIC_SOCKOPT_CERT_REQUEST:
		retval = quic_setsockopt_cert_request(sk, kopt, optlen);
		break;
	default:
		retval = -ENOPROTOOPT;
		break;
	}
out:
	release_sock(sk);
	kfree(kopt);
	return retval;
}

static int quic_getsockopt_cert(struct sock *sk, int len, char __user *optval,
				int __user *optlen)
{
	struct quic_sock *qs = quic_sk(sk);
	struct quic_cert *c;

	c = qs->crypt.certs;
	if (len < c->raw.len)
		return -EINVAL;

	len = c->raw.len;
	if (put_user(len, optlen))
		return -EFAULT;

	if (len && copy_to_user(optval, c->raw.v, len))
		return -EFAULT;

	return 0;
}

static int quic_getsockopt_cert_chain(struct sock *sk, int len, char __user *optval,
				      int __user *optlen)
{
	struct quic_sock *qs = quic_sk(sk);
	struct quic_cert *c;
	int clen = 0;
	u8 *p, *tmp;

	for (c = qs->crypt.certs; c; c = c->next)
		clen += (4 + c->raw.len);

	if (len < clen)
		return -EINVAL;

	tmp = kzalloc(clen, GFP_KERNEL);
	if (!tmp)
		return -EINVAL;
	p = tmp;
	for (c = qs->crypt.certs; c; c = c->next) {
		*((u32 *)p) = c->raw.len;
		p += 4;
		memcpy(p, c->raw.v, c->raw.len);
		p += c->raw.len;
	}
	len = clen;
	if (put_user(len, optlen)) {
		kfree(tmp);
		return -EFAULT;
	}

	if (len && copy_to_user(optval, tmp, len)) {
		kfree(tmp);
		return -EFAULT;
	}

	kfree(tmp);
	return 0;
}

static int quic_getsockopt_pkey(struct sock *sk, int len, char __user *optval,
				int __user *optlen)
{
	struct quic_sock *qs = quic_sk(sk);

	if (len < qs->crypt.pkey.len)
		return -EINVAL;

	len = qs->crypt.pkey.len;
	if (put_user(len, optlen))
		return -EFAULT;

	if (len && copy_to_user(optval, qs->crypt.pkey.v, len))
		return -EFAULT;

	return 0;
}

static int quic_getsockopt_all_cids(struct sock *sk, int len, char __user *optval,
				    int __user *optlen, u8 is_scid)
{
	struct quic_sock *qs = quic_sk(sk);
	struct quic_scc all;

	if (len < sizeof(all))
		return -EINVAL;

	len = sizeof(all);
	if (put_user(len, optlen))
		return -EFAULT;

	if (is_scid) {
		all.start = qs->cids.scid.first;
		all.cur = qs->cids.scid.cur->no;
		all.cnt = qs->cids.scid.cnt;
	} else {
		all.start = qs->cids.dcid.first;
		all.cur = qs->cids.dcid.cur->no;
		all.cnt = qs->cids.dcid.cnt;
	}

	if (len && copy_to_user(optval, &all, len))
		return -EFAULT;

	return 0;
}

static int quic_getsockopt_cur_cid(struct sock *sk, int len, char __user *optval,
				   int __user *optlen, bool is_scid)
{
	struct quic_sock *qs = quic_sk(sk);
	u32 cur;

	if (len < sizeof(cur))
		return -EINVAL;

	len = sizeof(cur);
	if (put_user(len, optlen))
		return -EFAULT;

	cur = is_scid ? qs->cids.scid.cur->no : qs->cids.dcid.cur->no;

	if (len && copy_to_user(optval, &cur, len))
		return -EFAULT;

	return 0;
}

static int quic_getsockopt_cur_saddr(struct sock *sk, int len, char __user *optval,
				     int __user *optlen)
{
	struct quic_sock *qs = quic_sk(sk);

	if (len < qs->af->addr_len)
		return -EINVAL;

	len = qs->af->addr_len;
	if (put_user(len, optlen))
		return -EFAULT;

	if (len && copy_to_user(optval, quic_saddr_cur(qs), len))
		return -EFAULT;

	return 0;
}

static int quic_getsockopt_stream_state(struct sock *sk, int len, char __user *optval,
					int __user *optlen)
{
	struct quic_sock *qs = quic_sk(sk);
	struct quic_strm *strm;
	struct quic_idv idv;

	if (len < sizeof(idv))
		return -EINVAL;

	len = sizeof(idv);
	if (copy_from_user(&idv, optval, len))
		return -EFAULT;

	strm = quic_strm_get(qs, idv.id);
	if (!strm)
		return -EINVAL;

	idv.value = strm->rcv_state | strm->snd_state;

	if (put_user(len, optlen))
		return -EFAULT;

	if (len && copy_to_user(optval, &idv, len))
		return -EFAULT;

	return 0;
}

static int quic_getsockopt_max_streams(struct sock *sk, int len, char __user *optval,
				       int __user *optlen)
{
	struct quic_sock *qs = quic_sk(sk);
	struct quic_idv idv;

	if (len < sizeof(idv))
		return -EINVAL;

	len = sizeof(idv);
	if (copy_from_user(&idv, optval, len))
		return -EFAULT;

	idv.value = idv.id ? qs->params.peer.initial_max_streams_bidi
			   : qs->params.peer.initial_max_streams_uni;

	if (put_user(len, optlen))
		return -EFAULT;

	if (len && copy_to_user(optval, &idv, len))
		return -EFAULT;

	return 0;
}

static int quic_getsockopt_event(struct sock *sk, int len, char __user *optval,
				 int __user *optlen)
{
	struct quic_sock *qs = quic_sk(sk);
	struct quic_idv idv;

	if (len < sizeof(idv))
		return -EINVAL;

	len = sizeof(idv);
	if (copy_from_user(&idv, optval, len))
		return -EFAULT;

	if (idv.id >= QUIC_EVT_MAX)
		return -EINVAL;

	idv.value = qs->packet.events & (1 << idv.id);

	if (put_user(len, optlen))
		return -EFAULT;

	if (len && copy_to_user(optval, &idv, len))
		return -EFAULT;

	return 0;
}

static int quic_getsockopt_events(struct sock *sk, int len, char __user *optval,
				  int __user *optlen)
{
	struct quic_sock *qs = quic_sk(sk);
	u32 events;

	if (len < sizeof(events))
		return -EINVAL;

	len = sizeof(events);
	events = qs->packet.events;

	if (put_user(len, optlen))
		return -EFAULT;

	if (copy_to_user(optval, &events, len))
		return -EFAULT;

	return 0;
}

static int quic_getsockopt(struct sock *sk, int level, int optname,
			   char __user *optval, int __user *optlen)
{
	struct quic_sock *qs = quic_sk(sk);
	int retval = 0;
	int len;

	if (level != SOL_QUIC)
		return qs->af->getsockopt(sk, level, optname, optval, optlen);

	if (get_user(len, optlen))
		return -EFAULT;

	if (len < 0)
		return -EINVAL;

	lock_sock(sk);

	if (qs->state == QUIC_CS_CLOSING) {
		retval = -EPIPE;
		goto out;
	}

	switch (optname) {
	case QUIC_SOCKOPT_CERT:
		retval = quic_getsockopt_cert(sk, len, optval, optlen);
		break;
	case QUIC_SOCKOPT_CERT_CHAIN:
		retval = quic_getsockopt_cert_chain(sk, len, optval, optlen);
		break;
	case QUIC_SOCKOPT_PKEY:
		retval = quic_getsockopt_pkey(sk, len, optval, optlen);
		break;
	case QUIC_SOCKOPT_ALL_SCID:
		retval = quic_getsockopt_all_cids(sk, len, optval, optlen, true);
		break;
	case QUIC_SOCKOPT_ALL_DCID:
		retval = quic_getsockopt_all_cids(sk, len, optval, optlen, false);
		break;
	case QUIC_SOCKOPT_CUR_SCID:
		retval = quic_getsockopt_cur_cid(sk, len, optval, optlen, true);
		break;
	case QUIC_SOCKOPT_CUR_DCID:
		retval = quic_getsockopt_cur_cid(sk, len, optval, optlen, false);
		break;
	case QUIC_SOCKOPT_CUR_SADDR:
		retval = quic_getsockopt_cur_saddr(sk, len, optval, optlen);
		break;
	case QUIC_SOCKOPT_STREAM_STATE:
		retval = quic_getsockopt_stream_state(sk, len, optval, optlen);
		break;
	case QUIC_SOCKOPT_MAX_STREAMS:
		retval = quic_getsockopt_max_streams(sk, len, optval, optlen);
		break;
	case QUIC_SOCKOPT_EVENT:
		retval = quic_getsockopt_event(sk, len, optval, optlen);
		break;
	case QUIC_SOCKOPT_EVENTS:
		retval = quic_getsockopt_events(sk, len, optval, optlen);
		break;
	default:
		retval = -ENOPROTOOPT;
		break;
	}
out:
	release_sock(sk);
	return retval;
}

struct proto quic_stream_prot = {
	.name		=  "QUIC",
	.owner		=  THIS_MODULE,
	.init		=  quic_init_sock,
	.destroy	=  quic_destroy_sock,
	.setsockopt	=  quic_setsockopt,
	.getsockopt	=  quic_getsockopt,
	.bind		=  quic_bind,
	.close		=  quic_close,
	.sendmsg	=  quic_sendmsg,
	.recvmsg	=  quic_recvmsg,
	.accept		=  quic_accept,
	.hash		=  quic_hash,
	.unhash		=  quic_unhash,
	.backlog_rcv	=  quic_do_rcv,
	.no_autobind	=  true,
	.obj_size	=  sizeof(struct quic_sock),
	.sockets_allocated	=  &quic_sockets_allocated,
};

struct proto quic_seqpacket_prot = {
	.name		=  "QUIC",
	.owner		=  THIS_MODULE,
	.init		=  quic_init_sock,
	.destroy	=  quic_destroy_sock,
	.setsockopt	=  quic_setsockopt,
	.getsockopt	=  quic_getsockopt,
	.bind		=  quic_bind,
	.close		=  quic_close,
	.sendmsg	=  quic_sendmsg,
	.recvmsg	=  quic_recvmsg,
	.accept		=  quic_accept,
	.hash		=  quic_hash,
	.unhash		=  quic_unhash,
	.backlog_rcv	=  quic_do_rcv,
	.no_autobind	=  true,
	.obj_size	=  sizeof(struct quic_sock),
};

static const struct proto_ops quic_proto_ops = {
	.family		   = PF_INET,
	.owner		   = THIS_MODULE,
	.release	   = inet_release,
	.bind		   = inet_bind,
	.connect	   = quic_inet_connect,
	.socketpair	   = sock_no_socketpair,
	.accept		   = inet_accept,
	.getname	   = quic_inet_getname,
	.poll		   = datagram_poll,
	.ioctl		   = inet_ioctl,
	.gettstamp	   = sock_gettstamp,
	.listen		   = quic_inet_listen,
	.shutdown	   = inet_shutdown,
	.setsockopt	   = sock_common_setsockopt,
	.getsockopt	   = sock_common_getsockopt,
	.sendmsg	   = inet_sendmsg,
	.recvmsg	   = inet_recvmsg,
	.mmap		   = sock_no_mmap,
	.sendpage	   = sock_no_sendpage,
};

/* For normal socket */
static struct inet_protosw quic_stream_protosw = {
	.type       = SOCK_STREAM,
	.protocol   = IPPROTO_QUIC,
	.prot       = &quic_stream_prot,
	.ops        = &quic_proto_ops,
};

/* For shakehand up-call daemon socket */
static struct inet_protosw quic_seqpacket_protosw = {
	.type       = SOCK_SEQPACKET,
	.protocol   = IPPROTO_QUIC,
	.prot       = &quic_seqpacket_prot,
	.ops        = &quic_proto_ops,
};

static int quic_v4_protosw_init(void)
{
	int err;

	err = proto_register(&quic_stream_prot, 1);
	if (err)
		return err;

	err = proto_register(&quic_seqpacket_prot, 1);
	if (err)
		return err;

	inet_register_protosw(&quic_stream_protosw);
	inet_register_protosw(&quic_seqpacket_protosw);

	return 0;
}

static void quic_v4_protosw_exit(void)
{
	inet_unregister_protosw(&quic_stream_protosw);
	proto_unregister(&quic_stream_prot);
	inet_unregister_protosw(&quic_seqpacket_protosw);
	proto_unregister(&quic_seqpacket_prot);
}

static int __net_init quic_net_init(struct net *net)
{
	net->quic.max_udp_payload_size = 65527;
	net->quic.initial_max_data = QUIC_MAX_DATA;
	net->quic.initial_max_stream_data_bidi_local = QUIC_MAX_DATA;
	net->quic.initial_max_stream_data_bidi_remote = QUIC_MAX_DATA;
	net->quic.initial_max_stream_data_uni = QUIC_MAX_DATA;
	net->quic.initial_max_streams_bidi = 3;
	net->quic.initial_max_streams_uni = 3;

	return quic_sysctl_net_register(net);
}

static void __net_exit quic_net_exit(struct net *net)
{
	quic_sysctl_net_unregister(net);
}

static struct pernet_operations quic_net_ops = {
	.init = quic_net_init,
	.exit = quic_net_exit,
};

static struct quic_hash_head *quic_hash_create(int size)
{
	struct quic_hash_head *head;
	int i;

	head = kmalloc_array(size, sizeof(*head), GFP_KERNEL);
	if (!head)
		return NULL;
	for (i = 0; i < size; i++) {
		spin_lock_init(&head[i].lock);
		INIT_HLIST_HEAD(&head[i].head);
	}
	return head;
}

static int quic_hash_init(void)
{
	quic_usk_size = QUIC_HASH_SIZE;
	quic_usk_hash = quic_hash_create(quic_usk_size);
	if (!quic_usk_hash)
		goto err;

	quic_lsk_size = QUIC_HASH_SIZE;
	quic_lsk_hash = quic_hash_create(quic_lsk_size);
	if (!quic_lsk_hash)
		goto err_lsk;

	quic_csk_size = QUIC_HASH_SIZE;
	quic_csk_hash = quic_hash_create(quic_csk_size);
	if (!quic_csk_hash)
		goto err_csk;

	quic_cid_size = QUIC_HASH_SIZE;
	quic_cid_hash = quic_hash_create(quic_cid_size);
	if (!quic_cid_hash)
		goto err_cid;

	return 0;
err_cid:
	kfree(quic_csk_hash);
err_csk:
	kfree(quic_lsk_hash);
err_lsk:
	kfree(quic_usk_hash);
err:
	return -ENOMEM;
}

static void quic_hash_destroy(void)
{
	kfree(quic_cid_hash);
	kfree(quic_csk_hash);
	kfree(quic_lsk_hash);
	kfree(quic_usk_hash);
}

static __init int quic_init(void)
{
	unsigned long limit;
	int err = -ENOMEM;
	int max_share;

	if (quic_crypto_load())
		goto err;
	if (quic_hash_init())
		goto err;
	err = percpu_counter_init(&quic_sockets_allocated, 0, GFP_KERNEL);
	if (err)
		goto err_percpu_counter;

	err = quic_v4_protosw_init();
	if (err)
		goto err_protosw;

	err = register_pernet_subsys(&quic_net_ops);
	if (err)
		goto err_def_ops;

	/* these initial mem values are from sctp */
	limit = nr_free_buffer_pages() / 8;
	limit = max(limit, 128UL);
	sysctl_quic_mem[0] = limit / 4 * 3;
	sysctl_quic_mem[1] = limit;
	sysctl_quic_mem[2] = sysctl_quic_mem[0] * 2;

	limit = (sysctl_quic_mem[1]) << (PAGE_SHIFT - 7);
	max_share = min(4UL * 1024 * 1024, limit);

	sysctl_quic_rmem[0] = SK_MEM_QUANTUM;
	sysctl_quic_rmem[1] = 1500 * SKB_TRUESIZE(1);
	sysctl_quic_rmem[2] = max(sysctl_quic_rmem[1], max_share);

	sysctl_quic_wmem[0] = SK_MEM_QUANTUM;
	sysctl_quic_wmem[1] = 16 * 1024;
	sysctl_quic_wmem[2] = max(64 * 1024, max_share);

	quic_sysctl_register();
	pr_info("QUIC init\n");
	return 0;

err_def_ops:
	quic_v4_protosw_exit();
err_protosw:
	percpu_counter_destroy(&quic_sockets_allocated);
err_percpu_counter:
	quic_hash_destroy();
err:
	pr_err("QUIC init error\n");
	return err;
}

static __exit void quic_exit(void)
{
	quic_sysctl_unregister();
	unregister_pernet_subsys(&quic_net_ops);
	quic_v4_protosw_exit();
	percpu_counter_destroy(&quic_sockets_allocated);
	quic_hash_destroy();
	pr_info("QUIC exit\n");
}

module_init(quic_init);
module_exit(quic_exit);

MODULE_ALIAS("net-pf-" __stringify(PF_INET) "-proto-144");
MODULE_ALIAS("net-pf-" __stringify(PF_INET6) "-proto-144");
MODULE_AUTHOR("Xin Long <lucien.xin@gmail.com>");
MODULE_DESCRIPTION("Support for the QUIC protocol (draft-ietf-quic-transport-34)");
MODULE_LICENSE("GPL");
