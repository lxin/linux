/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2021
 *
 * This file is part of the SCTP kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#ifndef __net_quic_h__
#define __net_quic_h__

#include <linux/generic-radix-tree.h>
#include <net/udp_tunnel.h>
#include <net/netns/quic.h>
#include <linux/workqueue.h>
#include <linux/swap.h>
#include <linux/quic.h>
#include <crypto/hash.h>
#include <crypto/sha2.h>
#include <crypto/aead.h>
#include <crypto/skcipher.h>
#include <crypto/akcipher.h>
#include <crypto/kpp.h>
#include <crypto/ecdh.h>
#include <crypto/x509_parser.h>

struct quic_hash_head {
	spinlock_t		lock;
	struct hlist_head	head;
};

struct quic_globals {
	struct quic_hash_head	*usk_hash;
	struct quic_hash_head	*lsk_hash;
	struct quic_hash_head	*csk_hash;
	struct quic_hash_head	*ssk_hash;
	int usk_size;
	int lsk_size;
	int csk_size;
	int ssk_size;
};
extern struct quic_globals quic_globals;
extern long sysctl_quic_mem[3];
extern int sysctl_quic_rmem[3];
extern int sysctl_quic_wmem[3];

#define quic_usk_hash		(quic_globals.usk_hash)
#define quic_usk_size		(quic_globals.usk_size)
#define quic_lsk_hash		(quic_globals.lsk_hash)
#define quic_lsk_size		(quic_globals.lsk_size)
#define quic_csk_hash		(quic_globals.csk_hash)
#define quic_csk_size		(quic_globals.csk_size)
#define quic_ssk_hash		(quic_globals.ssk_hash)
#define quic_ssk_size		(quic_globals.ssk_size)

enum {
	QUIC_SS_CLOSED		= TCP_CLOSE,
	QUIC_SS_LISTENING	= TCP_LISTEN,
	QUIC_SS_CONNECTING	= TCP_SYN_SENT,
	QUIC_SS_ESTABLISHED	= TCP_ESTABLISHED,
};

enum quic_state {
	QUIC_CS_CLIENT_INITIAL,
	QUIC_CS_CLIENT_WAIT_HANDSHAKE,
	QUIC_CS_CLIENT_TLS_HANDSHAKE_FAILED,
	QUIC_CS_CLIENT_POST_HANDSHAKE,
	QUIC_CS_CLOSING,
	QUIC_CS_SERVER_INITIAL,
	QUIC_CS_SERVER_WAIT_HANDSHAKE,
	QUIC_CS_SERVER_TLS_HANDSHAKE_FAILED,
	QUIC_CS_SERVER_POST_HANDSHAKE,
};

union quic_addr {
	struct sockaddr_in6 v6;
	struct sockaddr_in v4;
	struct sockaddr sa;
};

struct quic_usock {
	struct hlist_node node; /* usk hash table */
	refcount_t refcnt;
	struct sock *sk;
	union quic_addr a;
};

struct quic_istrm {
	__u32 id;
	__u32 cnt;
	__u32 offset;
};

struct quic_strm {
	GENRADIX(struct quic_istrm) bi;
	GENRADIX(struct quic_istrm) uni;
	__u16 bi_cnt;
	__u16 uni_cnt;
};

struct quic_cid {
	struct quic_cid *next;
	__u8 *id;
	__u8 len;
};

struct quic_vlen {
	__u8 *v;
	__u32 len;
};

#define QUIC_MSG_legacy_version	0x0303
#define QUIC_AES_128_GCM_SHA256	0x1301
#define QUIC_ECDHE_secp256r1	0x0017
#define QUIC_SAE_rsa_pss_rsae_sha256	0x0804
#define QUIC_MSG_version	0x0304

#define QUIC_HKDF_HMAC_ALG	"hmac(sha256)"
#define QUIC_HKDF_HASHLEN	SHA256_DIGEST_SIZE

#define QUIC_KEYLEN		16
#define QUIC_IVLEN		12
#define QUIC_TAGLEN		16
#define QUIC_ECDHLEN		32
#define QUIC_HASHLEN		32

#define QUIC_MIN_INIT_LEN	1200

#define QUIC_HASH_SIZE		64

struct quic_initial_param {
	u32 type; /* 1 */
	u32 length; /* u24, len of client hello below */
	u16 version;
	u8 random[32];
	u8 session_id_len;
	u8 *session_id; /* var */
	u16 cipher_suites_len;
	u8 *cipher_suites; /* var */
	u8 compression_methods_len;
	u8 *compression_methods; /* var */
	u16 extensions_len;
};

#define QUIC_H_CH	0
#define QUIC_H_SH	1
#define QUIC_H_EE	2
#define QUIC_H_CERT	3
#define QUIC_H_CVFY	4
#define QUIC_H_SFIN	5
#define QUIC_H_CFIN	6
#define QUIC_H_COUNT	7

struct quic_crypt {
	struct crypto_shash *sha_tfm;
	u8 ch_secret[QUIC_HKDF_HASHLEN];
	u8 sh_secret[QUIC_HKDF_HASHLEN];
	u8 es_secret[QUIC_HKDF_HASHLEN];
	u8 hs_secret[QUIC_HKDF_HASHLEN];
	u8 ms_secret[QUIC_HKDF_HASHLEN];
	u8 dhe_secret[QUIC_HKDF_HASHLEN];
	u8 capp_secret[QUIC_HKDF_HASHLEN];
	u8 sapp_secret[QUIC_HKDF_HASHLEN];

	struct crypto_shash *hash_tfm;
	u8 hash0[QUIC_HASHLEN];
	u8 hash2[QUIC_HASHLEN];
	u8 hash3[QUIC_HASHLEN];
	u8 hash6[QUIC_HASHLEN];
	u8 hash7[QUIC_HASHLEN];
	u8 hash9[QUIC_HASHLEN];

	struct crypto_kpp *kpp_tfm;
	u8 ecdh_x[QUIC_ECDHLEN];
	u8 ecdh_y[QUIC_ECDHLEN];

	struct crypto_aead *aead_tfm;
	u8 tx_key[QUIC_KEYLEN];
	u8 tx_iv[QUIC_IVLEN];
	u8 rx_key[QUIC_KEYLEN];
	u8 rx_iv[QUIC_IVLEN];
	u8 l2_tx_key[QUIC_KEYLEN];
	u8 l2_tx_iv[QUIC_IVLEN];
	u8 l2_rx_key[QUIC_KEYLEN];
	u8 l2_rx_iv[QUIC_IVLEN];
	u8 l3_tx_key[QUIC_KEYLEN];
	u8 l3_tx_iv[QUIC_IVLEN];
	u8 l3_rx_key[QUIC_KEYLEN];
	u8 l3_rx_iv[QUIC_IVLEN];

	struct crypto_skcipher *skc_tfm;
	u8 tx_hp_key[QUIC_KEYLEN];
	u8 rx_hp_key[QUIC_KEYLEN];
	u8 l2_tx_hp_key[QUIC_KEYLEN];
	u8 l2_rx_hp_key[QUIC_KEYLEN];
	u8 l3_tx_hp_key[QUIC_KEYLEN];
	u8 l3_rx_hp_key[QUIC_KEYLEN];

	struct quic_initial_param hello;
	struct quic_vlen hs_buf[QUIC_H_COUNT];

	struct crypto_akcipher *akc_tfm;
	struct x509_certificate *cert;
	struct quic_vlen pkey;
	struct quic_vlen sig;
	struct quic_vlen crt;
};

#define QUIC_FR_NR	4

struct quic_frame {
	struct quic_vlen f[QUIC_FR_NR];
	u8 need_ack:1;
	u8 has_strm:1;
	struct {
		u8 type;
		u32 off;
		u8 *msg;
		u32 msg_off;
	} crypto;
	struct {
		struct iov_iter *msg;
		u32 sid;
		u32 mss;
		u32 off;
		u8  fin;
	} stream;
};

struct quic_packet {
	struct sk_buff *recv_list;
	struct sk_buff *skb;
	u32 in_tx_pn;
	u32 hs_tx_pn;
	u32 ad_tx_pn;

	struct quic_vlen *f;
	u32 pd_len;
	u32 pn;
	u8 pn_len;
	u8 pn_off;
	u8 type;
	u8 cork;
};

struct quic_pnmap {
	unsigned long *pn_map;
	u32 cum_pn_ack_point;
	u32 max_pn_seen;
	u32 base_pn;
	u16 len;
};

struct quic_sock {
	struct inet_sock	inet;

	struct hlist_node	addr_node; /* addr hash key, lsk or csk hash table */
	struct hlist_node	scid_node; /* scid hash key, ssk hash table */
	struct list_head	list; /* listen sock head or accept sock list*/

	struct quic_sock	*lsk; /* listening sock */
	struct quic_usock	*usk; /* udp sock */

	struct quic_af		*af;
	union quic_addr		src;
	union quic_addr		dest;

	struct quic_cid		scid;
	struct quic_cid		dcid;

	struct quic_params	params;
	struct quic_vlen	token;
	enum quic_state		state;

	struct quic_packet	packet;
	struct quic_frame	frame;
	struct quic_crypt	crypt;
	struct quic_strm	strm;

	struct quic_pnmap	pnmap;

	struct timer_list	hs_timer;
	struct timer_list	rtx_timer;
};

struct quic_af {
	sa_family_t sa_family;
	int addr_len;
	int iphdr_len;
	void (*udp_conf_init)(struct udp_port_cfg *udp_conf, union quic_addr *a);
	int (*flow_route)(struct quic_sock *qs);
	void (*lower_xmit)(struct quic_sock *qs, struct sk_buff *skb);
	void (*get_addr)(union quic_addr *a, struct sk_buff *skb, bool src);
	void (*set_addr)(struct sock *sk, union quic_addr *a, bool src);
	int (*get_name)(struct socket *sock, struct sockaddr *uaddr, int peer);
	void (*get_msgname)(struct sk_buff *skb, union quic_addr *a);
	int (*setsockopt)(struct sock *sk, int level, int optname, sockptr_t optval,
			  unsigned int optlen);
	int (*getsockopt)(struct sock *sk, int level, int optname, char __user *optval,
			  int __user *optlen);
};

enum quic_pkt_type {
	QUIC_PKT_VERSION_NEGOTIATION = 0xf0,
	QUIC_PKT_INITIAL = 0x0,
	QUIC_PKT_0RTT = 0x1,
	QUIC_PKT_HANDSHAKE = 0x2,
	QUIC_PKT_RETRY = 0x3,
	QUIC_PKT_SHORT = 0x4
};

enum {
	QUIC_FRAME_PADDING = 0x00,
	QUIC_FRAME_PING = 0x01,
	QUIC_FRAME_ACK = 0x02,
	QUIC_FRAME_ACK_ECN = 0x03,
	QUIC_FRAME_RESET_STREAM = 0x04,
	QUIC_FRAME_STOP_SENDING = 0x05,
	QUIC_FRAME_CRYPTO = 0x06,
	QUIC_FRAME_NEW_TOKEN = 0x07,
	QUIC_FRAME_STREAM = 0x08,
	QUIC_FRAME_MAX_DATA = 0x10,
	QUIC_FRAME_MAX_STREAM_DATA = 0x11,
	QUIC_FRAME_MAX_STREAMS_BIDI = 0x12,
	QUIC_FRAME_MAX_STREAMS_UNI = 0x13,
	QUIC_FRAME_DATA_BLOCKED = 0x14,
	QUIC_FRAME_STREAM_DATA_BLOCKED = 0x15,
	QUIC_FRAME_STREAMS_BLOCKED_BIDI = 0x16,
	QUIC_FRAME_STREAMS_BLOCKED_UNI = 0x17,
	QUIC_FRAME_NEW_CONNECTION_ID = 0x18,
	QUIC_FRAME_RETIRE_CONNECTION_ID = 0x19,
	QUIC_FRAME_PATH_CHALLENGE = 0x1a,
	QUIC_FRAME_PATH_RESPONSE = 0x1b,
	QUIC_FRAME_CONNECTION_CLOSE = 0x1c,
	QUIC_FRAME_CONNECTION_CLOSE_APP = 0x1d,
	QUIC_FRAME_HANDSHAKE_DONE = 0x1e,
	QUIC_FRAME_DATAGRAM = 0x30,
	QUIC_FRAME_DATAGRAM_LEN = 0x31,
};

#define QUIC_MT_HELLO_REQUEST                   0
#define QUIC_MT_CLIENT_HELLO                    1
#define QUIC_MT_SERVER_HELLO                    2
#define QUIC_MT_NEWSESSION_TICKET               4
#define QUIC_MT_END_OF_EARLY_DATA               5
#define QUIC_MT_ENCRYPTED_EXTENSIONS            8
#define QUIC_MT_CERTIFICATE                     11
#define QUIC_MT_SERVER_KEY_EXCHANGE             12
#define QUIC_MT_CERTIFICATE_REQUEST             13
#define QUIC_MT_SERVER_DONE                     14
#define QUIC_MT_CERTIFICATE_VERIFY              15
#define QUIC_MT_CLIENT_KEY_EXCHANGE             16
#define QUIC_MT_FINISHED                        20
#define QUIC_MT_CERTIFICATE_URL                 21
#define QUIC_MT_CERTIFICATE_STATUS              22
#define QUIC_MT_SUPPLEMENTAL_DATA               23
#define QUIC_MT_KEY_UPDATE                      24

#define QUIC_EXT_server_name                 0
#define QUIC_EXT_max_fragment_length         1
#define QUIC_EXT_client_certificate_url      2
#define QUIC_EXT_trusted_ca_keys             3
#define QUIC_EXT_truncated_hmac              4
#define QUIC_EXT_status_request              5
#define QUIC_EXT_user_mapping                6
#define QUIC_EXT_client_authz                7
#define QUIC_EXT_server_authz                8
#define QUIC_EXT_cert_type                   9
#define QUIC_EXT_supported_groups            10
#define QUIC_EXT_ec_point_formats            11
#define QUIC_EXT_srp                         12
#define QUIC_EXT_signature_algorithms        13
#define QUIC_EXT_use_srtp                    14
#define QUIC_EXT_heartbeat                   15
#define QUIC_EXT_application_layer_protocol_negotiation 16
#define QUIC_EXT_signed_certificate_timestamp 18
#define QUIC_EXT_padding                     21
#define QUIC_EXT_encrypt_then_mac            22
#define QUIC_EXT_extended_master_secret      23
#define QUIC_EXT_session_ticket              35
#define QUIC_EXT_psk                         41
#define QUIC_EXT_early_data                  42
#define QUIC_EXT_supported_versions          43
#define QUIC_EXT_cookie                      44
#define QUIC_EXT_psk_kex_modes               45
#define QUIC_EXT_certificate_authorities     47
#define QUIC_EXT_post_handshake_auth         49
#define QUIC_EXT_signature_algorithms_cert   50
#define QUIC_EXT_key_share                   51
#define QUIC_EXT_quic_transport_parameters_draft	0xffa5
#define QUIC_EXT_quic_transport_parameters		0x0039

#define QUIC_VERSION_V1 0x1

union quic_num_x {
	u8	num_8;
	u16	num_16;
	u32	num_32;
	u64	num_64;
	u8	num_b[8];
};

static inline u32 quic_get_varint_len(const u8 *p)
{
	return (u32)(1u << (*p >> 6));
}

static inline u64 quic_get_varint(u32 *plen, const u8 *p)
{
	union quic_num_x num;

	*plen = (u32)(1u << (*p >> 6));

	switch (*plen) {
	case 1:
		return *p;
	case 2:
		memcpy(&num.num_16, p, 2);
		num.num_b[0] &= 0x3f;
		return ntohs(num.num_16);
	case 4:
		memcpy(&num.num_32, p, 4);
		num.num_b[0] &= 0x3f;
		return ntohl(num.num_32);
	case 8:
		memcpy(&num.num_64, p, 8);
		num.num_b[0] &= 0x3f;
		return be64_to_cpu(num.num_64);
	}

	return 0;
}

static inline u32 quic_get_varint_next(u8 **p, u32 *plen)
{
	u32 v = quic_get_varint(plen, *p);

	*p += *plen;
	return v;
}

static inline u32 quic_put_varint_len(u64 n)
{
	if (n < 64)
		return 1;
	if (n < 16384)
		return 2;
	if (n < 1073741824)
		return 4;
	return 8;
}

static inline u32 quic_put_varint_lens(u32 n)
{
	u32 len = quic_put_varint_len(n);

	return len + quic_put_varint_len(len);
}

static inline u8 *quic_put_varint(u8 *p, u64 n)
{
	union quic_num_x num;

	num.num_64 = n;
	if (n < 64) {
		*p++ = num.num_8;
		return p;
	}
	if (n < 16384) {
		num.num_16 = htons(num.num_16);
		memcpy(p, &num.num_16, 2);
		*p |= 0x40;
		return p + 2;
	}
	if (n < 1073741824) {
		num.num_32 = htonl(num.num_32);
		memcpy(p, &num.num_32, 4);
		*p |= 0x80;
		return p + 4;
	}
	num.num_64 = htonl(num.num_64);
	memcpy(p, &num.num_64, 8);
	*p |= 0xc0;
	return p + 8;
}

static inline u32 quic_get_pkt_num(const u8 *p, u32 pkt_numlen)
{
	union quic_num_x num;

	num.num_32 = 0;
	switch (pkt_numlen) {
	case 1:
		return *p;
	case 2:
		memcpy(&num.num_16, p, 2);
		return ntohs(num.num_16);
	case 3:
		memcpy(((u8 *)&num.num_32) + 1, p, 3);
		return ntohl(num.num_32);
	case 4:
		memcpy(&num.num_32, p, 4);
		return ntohl(num.num_32);
	}
	return 0;
}

static inline u32 quic_get_fixint_next(u8 **p, u32 len)
{
	u32 v = quic_get_pkt_num(*p, len);

	*p += len;
	return v;
}

static inline u32 quic_put_pkt_numlen(u32 n)
{
	if (n > 0xffffff)
		return 4;
	if (n > 0xffff)
		return 3;
	if (n > 0xff)
		return 2;
	return 1;
}

static inline u8 *quic_put_pkt_num(u8 *p, u64 pkt_num, u8 len)
{
	union quic_num_x num;

	num.num_64 = pkt_num;

	switch (len) {
	case 1:
		*p++ = num.num_8;
		return p;
	case 2:
		num.num_16 = htons(num.num_16);
		memcpy(p, &num.num_16, 2);
		return p + 2;
	case 3:
		num.num_32 = htonl(num.num_32);
		memcpy(p, ((u8 *)&num.num_32) + 1, 3);
		return p + 3;
	case 4:
		num.num_32 = htonl(num.num_32);
		memcpy(p, &num.num_32, 4);
		return p + 4;
	default:
		return NULL;
	}
}

static inline u8 *quic_put_pkt_data(u8 *p, u8 *data, u32 len)
{
	if (!len)
		return p;

	memcpy(p, data, len);
	return p + len;
}

struct quic_rcv_cb {
	struct quic_af *af;
	u8 *dcid;
	u8 *scid;
	u8 dcid_len;
	u8 scid_len;
	u32 strm_id;
	u32 strm_off;
	u8 strm_fin;
	__be16 src_port;
};
struct quic_snd_cb {
	struct sk_buff *last;
	u8 has_strm:1;
	int count;
	u32 pn;
	int cnt;
	u8 type;
};
#define QUIC_RCV_CB(__skb)	((struct quic_rcv_cb *)&((__skb)->cb[0]))
#define QUIC_SND_CB(__skb)	((struct quic_snd_cb *)&((__skb)->cb[0]))

#define QUIC_HS_INTERVAL	5000
#define QUIC_RTX_INTERVAL	2000

struct quic_lhdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8 pnl:2,
	     reserved:2,
	     type:2,
	     fixed:1,
	     form:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8 form:1,
	     fixed:1,
	     type:2,
	     reserved:2,
	     pnl:2;
#endif
};

struct quic_shdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8 pnl:2,
	     key:1,
	     reserved:2,
	     spin:1,
	     fixed:1,
	     form:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8 form:1,
	     fixed:1,
	     spin:1,
	     reserved:2,
	     key:1,
	     pnl:2;
#endif
};

static inline struct quic_sock *quic_sk(const struct sock *sk)
{
	return (struct quic_sock *)sk;
}

static inline union quic_addr *quic_a(const struct sockaddr *addr)
{
	return (union quic_addr *)addr;
}

static inline __u32 quic_ahash(const struct net *net, const union quic_addr *a)
{
	__u32 addr = (a->sa.sa_family == AF_INET6) ? jhash(&a->v6.sin6_addr, 16, 0)
						   : (__force __u32)a->v4.sin_addr.s_addr;

	return  jhash_3words(addr, (__force __u32)a->v4.sin_port, net_hash_mix(net), 0);
}

static inline struct quic_hash_head *quic_usk_head(struct net *net, union quic_addr *a)
{
	return &quic_usk_hash[quic_ahash(net, a) & (quic_usk_size - 1)];
}

static inline struct quic_hash_head *quic_lsk_head(struct net *net, union quic_addr *a)
{
	return &quic_lsk_hash[quic_ahash(net, a) & (quic_lsk_size - 1)];
}

static inline struct quic_hash_head *quic_csk_head(struct net *net, union quic_addr *s,
						   union quic_addr *d)
{
	return &quic_csk_hash[jhash_2words(quic_ahash(net, s), quic_ahash(net, d), 0) &
			       (quic_csk_size - 1)];
}

static inline struct quic_hash_head *quic_ssk_head(struct net *net, u8 *scid)
{
	return &quic_ssk_hash[jhash(scid, 4, 0) & (quic_ssk_size - 1)];
}

static inline void quic_us_destroy(struct quic_usock *us)
{
	struct quic_hash_head *head = quic_usk_head(sock_net(us->sk), &us->a);

	spin_lock(&head->lock);
	__hlist_del(&us->node);
	spin_unlock(&head->lock);

	udp_tunnel_sock_release(us->sk->sk_socket);
	kfree(us);
}

static inline struct quic_usock *quic_us_get(struct quic_usock *us)
{
	refcount_inc(&us->refcnt);
	return us;
}

static inline void quic_us_put(struct quic_usock *us)
{
	if (refcount_dec_and_test(&us->refcnt))
		quic_us_destroy(us);
}

static inline struct quic_lhdr *quic_lhdr(struct sk_buff *skb)
{
	return (struct quic_lhdr *)skb_transport_header(skb);
}

static inline struct quic_shdr *quic_shdr(struct sk_buff *skb)
{
	return (struct quic_shdr *)skb_transport_header(skb);
}

static inline u8 *quic_mem_dup(u8 *p, int len)
{
	u8 *n;

	n = kzalloc(len, GFP_ATOMIC);
	if (!n)
		return NULL;
	memcpy(n, p, len);
	return n;
}


static inline int quic_stream_wspace(struct sock *sk)
{
	return sk_stream_wspace(sk);
}

static inline void quic_wmem_queued_add(struct sock *sk, int val)
{
	return sk_wmem_queued_add(sk, val);
}

static inline void quic_wmem_free_skb(struct sock *sk, struct sk_buff *skb)
{
	sk_wmem_queued_add(sk, -skb->truesize);
	__kfree_skb(skb);
}

static inline struct quic_istrm *quic_istrm_get(struct quic_sock *qs, u32 sid)
{
	struct quic_strm *strm = &qs->strm;

	if (sid & 0x2)
		return genradix_ptr(&strm->uni, (sid >> 2));

	return genradix_ptr(&strm->bi, (sid >> 2));
}

/* proto.c */
struct quic_sock *quic_lsk_lookup(struct sk_buff *skb, union quic_addr *a);
struct quic_sock *quic_ssk_lookup(struct sk_buff *skb, u8 *scid, u8 scid_len);
struct quic_af *quic_af_get(sa_family_t family);
int quic_dst_mss_check(struct quic_sock *qs, int hdr);

/* udp.c */
struct quic_usock *quic_udp_sock_lookup(struct quic_sock *qs);

/* strm.c */
int quic_strm_init(struct quic_sock *qs, u32 uni_cnt, u32 bi_cnt);
void quic_strm_free(struct quic_sock *qs);

/* sock.c */
int quic_sock_init(struct quic_sock *qs, union quic_addr *a,
		   u8 *dcid, u8 dcid_len, u8 *scid, u8 scid_len);
struct quic_sock *quic_lsk_process(struct quic_sock *qs, struct sk_buff *skb);
void quic_sock_free(struct quic_sock *qs);
void quic_start_rtx_timer(struct quic_sock *qs, u8 restart);
void quic_stop_rtx_timer(struct quic_sock *qs);
void quic_start_hs_timer(struct quic_sock *qs, u8 restart);
void quic_stop_hs_timer(struct quic_sock *qs);

/* packet.c */
int quic_packet_process(struct quic_sock *qs, struct sk_buff *skb);
struct sk_buff *quic_packet_create(struct quic_sock *qs, u8 type, u8 ftype);

/* frame.c */
int quic_frame_create(struct quic_sock *qs, u8 type);
int quic_frame_process(struct quic_sock *qs, u8 *p, u32 len);
int quic_frame_init(struct quic_sock *qs);
void quic_frame_free(struct quic_sock *qs);

/* crypto.c */
int quic_crypto_load(void);
int quic_crypto_init(struct quic_sock *qs);
void quic_crypto_free(struct quic_sock *qs);
void quic_crypt_free(struct quic_sock *qs);
int quic_crypto_encrypt(struct quic_sock *qs, struct sk_buff *skb, u8 type);
int quic_crypto_decrypt(struct quic_sock *qs, struct sk_buff *skb, u8 type);
int quic_crypto_initial_keys_install(struct quic_sock *qs);
int quic_crypto_compute_ecdh_secret(struct quic_sock *qs, u8 *x, u8 *y);
int quic_crypto_handshake_keys_install(struct quic_sock *qs);
int quic_crypto_application_keys_install(struct quic_sock *qs);
int quic_crypto_server_cert_verify(struct quic_sock *qs);
int quic_crypto_server_certvfy_sign(struct quic_sock *qs);
int quic_crypto_server_certvfy_verify(struct quic_sock *qs);
int quic_crypto_server_finished_create(struct quic_sock *qs, u8 *sf);
int quic_crypto_server_finished_verify(struct quic_sock *qs);

/* input.c */
int quic_rcv(struct sk_buff *skb);
int quic_do_rcv(struct sock *sk, struct sk_buff *skb);
int quic_pnmap_init(struct quic_sock *qs, gfp_t gfp);
void quic_pnmap_free(struct quic_sock *qs);
int quic_pnmap_mark(struct quic_sock *qs, u32 pn);
int quic_receive_list_add(struct quic_sock *qs, struct sk_buff *skb);

/* output.c */
int quic_v4_flow_route(struct quic_sock *qs);
int quic_v6_flow_route(struct quic_sock *qs);
void quic_v4_lower_xmit(struct quic_sock *qs, struct sk_buff *skb);
void quic_v6_lower_xmit(struct quic_sock *qs, struct sk_buff *skb);
int quic_write_queue_flush(struct quic_sock *qs);
void quic_write_queue_enqueue(struct quic_sock *qs, struct sk_buff *skb);
void quic_send_queue_add(struct quic_sock *qs, struct sk_buff *skb);
void quic_send_queue_check(struct quic_sock *qs, u32 v);
int quic_send_queue_rtx(struct quic_sock *qs);

/* cid.c */
int quic_cid_init(struct quic_sock *qs, u8 *dcid, int dcid_len, u8 *scid, int scid_len);
void quic_cid_free(struct quic_sock *qs);

/* msg.c */
int quic_msg_process(struct quic_sock *qs, u8 *p, u32 hs_offset, u32 hs_len, u32 left);

/* exts.c */
int quic_exts_process(struct quic_sock *qs, u8 *p);

/* sysctl.c */
void quic_sysctl_register(void);
void quic_sysctl_unregister(void);
int quic_sysctl_net_register(struct net *net);
void quic_sysctl_net_unregister(struct net *net);

#endif /* __net_quic_h__ */
