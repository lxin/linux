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
	struct udphdr *uh = (struct udphdr *)(skb->data - sizeof(*uh));
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
	struct udphdr *uh = (struct udphdr *)(skb->data - sizeof(*uh));
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
	a->v4.sin_family = AF_INET;
	a->v4.sin_port = QUIC_RCV_CB(skb)->src_port;
	a->v4.sin_addr.s_addr = ip_hdr(skb)->saddr;
}

static void quic_v6_get_msgname(struct sk_buff *skb, union quic_addr *a)
{
	a->v6.sin6_family = AF_INET6;
	a->v6.sin6_flowinfo = 0;
	a->v6.sin6_port = QUIC_RCV_CB(skb)->src_port;
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

struct quic_sock *quic_lsk_lookup(struct sk_buff *skb, union quic_addr *a)
{
	struct net *net = dev_net(skb->dev);
	struct quic_sock *qs, *s = NULL;
	struct quic_hash_head *head;

	head = quic_lsk_head(net, a);
	spin_lock(&head->lock);

	hlist_for_each_entry(qs, &head->head, addr_node) {
		if (net == sock_net(&qs->inet.sk) &&
		    QUIC_RCV_CB(skb)->af == qs->af &&
		    !memcmp(a, &qs->src, qs->af->addr_len)) {
			if (likely(refcount_inc_not_zero(&qs->inet.sk.sk_refcnt)))
				s = qs;
			goto out;
		}
	}

out:
	spin_unlock(&head->lock);
	return s;
}

struct quic_sock *quic_ssk_lookup(struct sk_buff *skb, u8 *scid, u8 scid_len)
{
	struct net *net = dev_net(skb->dev);
	struct quic_sock *qs, *s = NULL;
	struct quic_hash_head *head;

	head = quic_ssk_head(net, scid);
	spin_lock(&head->lock);

	hlist_for_each_entry(qs, &head->head, scid_node) {
		if (net == sock_net(&qs->inet.sk) &&
		    (!scid_len || scid_len == qs->scid.len) &&
		    !memcmp(scid, qs->scid.id, qs->scid.len)) {
			if (likely(refcount_inc_not_zero(&qs->inet.sk.sk_refcnt)))
				s = qs;
			goto out;
		}
	}

out:
	spin_unlock(&head->lock);
	return s;
}

static int quic_init_sock(struct sock *sk)
{
	struct quic_sock *qs = quic_sk(sk);
	struct net *net = sock_net(sk);

	INIT_LIST_HEAD(&qs->list);
	qs->af = quic_af_get(sk->sk_family);

	sk->sk_destruct = inet_sock_destruct;
	qs->params = net->quic.p;
	sk->sk_rcvbuf = qs->params.initial_max_data;

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
	__u32 err = 0;

	lock_sock(sk);

	if (qs->src.v4.sin_port || addr->sa_family != sk->sk_family ||
	    addr_len < qs->af->addr_len || !quic_a(addr)->v4.sin_port) {
		err = -EINVAL;
		goto out;
	}

	memcpy(&qs->src, addr, qs->af->addr_len);
	qs->af->set_addr(&qs->inet.sk, &qs->src, true);

	qs->usk = quic_udp_sock_lookup(qs);
	if (!qs->usk)
		err = -ENOMEM;

out:
	release_sock(sk);
	return err;
}

static int quic_wait_for_connect(struct sock *sk, long timeo)
{
	DEFINE_WAIT(wait);
	int err = 0;

	for (;;) {
		prepare_to_wait_exclusive(sk_sleep(sk), &wait,
					  TASK_INTERRUPTIBLE);
		if (!timeo) {
			err = -EAGAIN;
			break;
		}
		if (sk->sk_err) {
			err = sk->sk_err;
			break;
		}
		if (signal_pending(current)) {
			err = sock_intr_errno(timeo);
			break;
		}

		if (quic_sk(sk)->state != QUIC_CS_CLIENT_INITIAL)
			break;

		release_sock(sk);
		timeo = schedule_timeout(timeo);
		lock_sock(sk);
	}

	finish_wait(sk_sleep(sk), &wait);
	return err;
}

static int quic_inet_connect(struct socket *sock, struct sockaddr *addr, int addr_len, int flags)
{
	struct sock *sk = sock->sk;
	struct quic_sock *qs;
	struct sk_buff *skb;
	u8 dcid[8], scid[8];
	long timeo;
	int err;

	lock_sock(sk);
	qs = quic_sk(sk);
	if (addr->sa_family != sk->sk_family || addr_len < qs->af->addr_len ||
	    !quic_a(addr)->v4.sin_port) {
		err = -EINVAL;
		goto err;
	}
	if (sk->sk_state == QUIC_SS_LISTENING || sk->sk_state == QUIC_SS_ESTABLISHED) {
		err = -EISCONN;
		goto err;
	}

	get_random_bytes(dcid, 8);
	get_random_bytes(scid, 8);
	qs->state = QUIC_CS_CLIENT_INITIAL;
	err = quic_sock_init(qs, quic_a(addr), dcid, 8, scid, 8);
	if (err)
		goto err;

	err = quic_crypto_initial_keys_install(qs);
	if (err)
		goto init_err;
	skb = quic_packet_create(qs, QUIC_PKT_INITIAL, QUIC_FRAME_CRYPTO);
	if (!skb) {
		err = -ENOMEM;
		goto init_err;
	}
	quic_write_queue_enqueue(qs, skb);
	err = quic_write_queue_flush(qs);
	if (err)
		goto route_err;

	quic_start_hs_timer(qs, 0);

	qs->state = QUIC_CS_CLIENT_WAIT_HANDSHAKE;
	inet_sk_set_state(sk, QUIC_SS_CONNECTING);
	timeo = sock_sndtimeo(sk, flags & O_NONBLOCK);
	err = quic_wait_for_connect(sk, timeo);
	goto err;

route_err:
	kfree_skb(skb);
init_err:
	quic_sock_free(qs);
err:
	release_sock(sk);
	return err;
}

static void quic_close(struct sock *sk, long timeout)
{
	struct quic_sock *qs = quic_sk(sk);

	lock_sock(sk);
	if (sk->sk_state == QUIC_SS_LISTENING) {
		struct quic_hash_head *head;

		head = quic_lsk_head(sock_net(sk), &qs->src);
		spin_lock(&head->lock);
		hlist_del(&qs->addr_node);
		spin_unlock(&head->lock);
	} else if (sk->sk_state != QUIC_SS_CLOSED) {
		quic_sock_free(qs);
	}

	if (qs->usk)
		quic_us_put(qs->usk);

	inet_sk_set_state(sk, QUIC_SS_CLOSED);
	release_sock(sk);

	sk_common_release(sk);
}

static int quic_wait_for_sndbuf(struct sock *sk, long timeo, u32 msg_len)
{
	struct quic_sock *qs = quic_sk(sk);
	DEFINE_WAIT(wait);
	int err = 0;

	for (;;) {
		prepare_to_wait_exclusive(sk_sleep(sk), &wait,
					  TASK_INTERRUPTIBLE);
		if (!timeo) {
			err = -EAGAIN;
			break;
		}
		if (sk->sk_err) {
			err = sk->sk_err;
			break;
		}
		if (signal_pending(current)) {
			err = sock_intr_errno(timeo);
			break;
		}

		if (qs->state != QUIC_CS_CLIENT_WAIT_HANDSHAKE &&
		    qs->state != QUIC_CS_SERVER_WAIT_HANDSHAKE &&
		    qs->state != QUIC_CS_CLIENT_POST_HANDSHAKE &&
		    qs->state != QUIC_CS_SERVER_POST_HANDSHAKE) {
			err = -EPIPE;
			break;
		}

		if ((int)msg_len <= quic_stream_wspace(sk))
			break;

		release_sock(sk);
		timeo = schedule_timeout(timeo);
		lock_sock(sk);
	}

	finish_wait(sk_sleep(sk), &wait);
	return err;
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
		mss -= (qs->dcid.len + QUIC_TAGLEN);
	} else if (hdr == 2) {
		mss -= (sizeof(struct quic_lhdr) + 4);
		mss -= (1 + qs->dcid.len + 1 + qs->scid.len);
		mss -= (quic_put_varint_len(qs->token.len) + qs->token.len);
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

static int quic_sendmsg(struct sock *sk, struct msghdr *msg, size_t msg_len)
{
	struct quic_sock *qs = quic_sk(sk);
	struct quic_sndinfo s;
	struct sk_buff *skb;
	int err, mss;
	long timeo;

	err = quic_msghdr_parse(msg, &s);
	if (err)
		return err;

	lock_sock(sk);
	mss = quic_dst_mss_check(qs, 1);
	if (mss < 0) {
		err = mss;
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

		qs->packet.f = &qs->frame.f[QUIC_PKT_SHORT / 2];
		skb = quic_packet_create(qs, QUIC_PKT_SHORT, QUIC_FRAME_STREAM);
		if (!skb) {
			err = -ENOMEM;
			goto err;
		}

		quic_wmem_queued_add(sk, skb->truesize);
		quic_write_queue_enqueue(qs, skb);
		err = quic_write_queue_flush(qs);
		if (err)
			goto err;
	}

	release_sock(sk);
	return msg_len;
err:
	release_sock(sk);
	return err;
}

static int quic_wait_for_packet(struct sock *sk, long timeo)
{
	DEFINE_WAIT(wait);
	int err;

	for (;;) {
		prepare_to_wait_exclusive(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);

		err = 0;
		if (!skb_queue_empty(&sk->sk_receive_queue))
			break;

		err = -EAGAIN;
		if (!timeo)
			break;

		err = sock_intr_errno(timeo);
		if (signal_pending(current))
			break;

		err = sock_error(sk);
		if (err)
			break;

		release_sock(sk);
		timeo = schedule_timeout(timeo);
		lock_sock(sk);
	}

	finish_wait(sk_sleep(sk), &wait);
	return err;
}

static int quic_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
			int noblock, int flags, int *addr_len)
{
	union quic_addr *addr = (union quic_addr *)msg->msg_name;
	struct quic_sock *qs = quic_sk(sk);
	struct quic_rcvinfo r;
	struct sk_buff *skb;
	int copy, err;
	long timeo;

	lock_sock(sk);

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

	if (QUIC_RCV_CB(skb)->strm_fin)
		msg->msg_flags |= MSG_EOR;

	if (addr) {
		qs->af->get_msgname(skb, addr);
		*addr_len = qs->af->addr_len;
	}

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
	int err = 0;

	lock_sock(sk);
	sk->sk_state = QUIC_SS_LISTENING;
	sk->sk_max_ack_backlog = backlog;

	qs = quic_sk(sk);
	head = quic_lsk_head(sock_net(sk), &qs->src);
	spin_lock(&head->lock);

	hlist_for_each_entry(q, &head->head, addr_node) {
		if (sock_net(sk) == sock_net(&q->inet.sk) &&
		    !memcmp(&qs->src, &q->src, qs->af->addr_len)) {
			err = -EADDRINUSE;
			goto out;
		}
	}

	hlist_add_head(&qs->addr_node, &head->head);

out:
	spin_unlock(&head->lock);
	release_sock(sk);
	return err;
}

int quic_inet_getname(struct socket *sock, struct sockaddr *uaddr, int peer)
{
	return quic_sk(sock->sk)->af->get_name(sock, uaddr, peer);
}

static int quic_setsockopt_cert(struct sock *sk, u8 *cert, unsigned int len)
{
	struct quic_sock *qs = quic_sk(sk);
	struct x509_certificate *x;

	x = x509_cert_parse(cert, len);
	if (IS_ERR(x))
		return PTR_ERR(x);

	qs->crypt.crt.len = len;
	qs->crypt.crt.v = quic_mem_dup(cert, qs->crypt.crt.len);
	if (!qs->crypt.crt.v) {
		kfree(x);
		return -ENOMEM;
	}

	qs->crypt.cert = x;

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

static int quic_setsockopt(struct sock *sk, int level, int optname,
			   sockptr_t optval, unsigned int optlen)
{
	struct quic_sock *qs = quic_sk(sk);
	void *kopt = NULL;
	int retval = 0;

	if (level != SOL_QUIC)
		return qs->af->setsockopt(sk, level, optname, optval, optlen);

	if (optlen > 0) {
		kopt = memdup_sockptr(optval, optlen);
		if (IS_ERR(kopt))
			return PTR_ERR(kopt);
	}

	lock_sock(sk);
	switch (optname) {
	case QUIC_SOCKOPT_CERT:
		retval = quic_setsockopt_cert(sk, kopt, optlen);
		break;
	case QUIC_SOCKOPT_PKEY:
		retval = quic_setsockopt_pkey(sk, kopt, optlen);
		break;
	default:
		retval = -ENOPROTOOPT;
		break;
	}
	release_sock(sk);
	kfree(kopt);
	return retval;
}

static int quic_getsockopt_cert(struct sock *sk, int len, char __user *optval,
				int __user *optlen)
{
	struct quic_sock *qs = quic_sk(sk);

	if (len < qs->crypt.crt.len)
		return -EINVAL;

	len = qs->crypt.crt.len;
	if (put_user(len, optlen))
		return -EFAULT;

	if (len && copy_to_user(optval, qs->crypt.crt.v, len))
		return -EFAULT;

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

	switch (optname) {
	case QUIC_SOCKOPT_CERT:
		retval = quic_getsockopt_cert(sk, len, optval, optlen);
		break;
	case QUIC_SOCKOPT_PKEY:
		retval = quic_getsockopt_pkey(sk, len, optval, optlen);
		break;
	default:
		retval = -ENOPROTOOPT;
		break;
	}

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
	net->quic.p.max_udp_payload_size = 65527;
	net->quic.p.initial_max_data = SK_RMEM_MAX;
	net->quic.p.initial_max_stream_data_bidi_local = SK_RMEM_MAX;
	net->quic.p.initial_max_stream_data_bidi_remote = SK_WMEM_MAX;
	net->quic.p.initial_max_stream_data_uni = SK_RMEM_MAX;
	net->quic.p.initial_max_streams_bidi = 3;
	net->quic.p.initial_max_streams_uni = 3;

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

	quic_ssk_size = QUIC_HASH_SIZE;
	quic_ssk_hash = quic_hash_create(quic_ssk_size);
	if (!quic_ssk_hash)
		goto err_ssk;

	return 0;
err_ssk:
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
	kfree(quic_ssk_hash);
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
