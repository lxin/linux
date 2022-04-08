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

int quic_cid_path_change(struct quic_sock *qs, union quic_addr *a)
{
	u32 value[3] = {0};
	int err;

	qs->path.dest.cur = !qs->path.dest.cur;
	memcpy(quic_daddr_cur(qs), a, qs->af->addr_len);
	sk_dst_reset(&qs->inet.sk);

	qs->frame.path.data = qs->path.dest.data[qs->path.dest.cur];
	err = quic_frame_create(qs, QUIC_FRAME_PATH_CHALLENGE);
	if (err)
		return err;
	quic_start_path_timer(qs, false);

	value[0] = ntohs(a->v4.sin_port);
	err = quic_evt_notify(qs, QUIC_EVT_ADDRESS, QUIC_EVT_ADDRESS_NEW, value);

	return err;
}

struct quic_cid *quic_cid_lookup(struct net *net, u8 *scid, u8 *scid_len)
{
	struct quic_hash_head *head = quic_cid_head(net, scid);
	struct quic_cid *cid;

	spin_lock(&head->lock);

	hlist_for_each_entry(cid, &head->head, node) {
		if (net == sock_net(&cid->qs->inet.sk) &&
		    (!*scid_len || *scid_len == cid->len) &&
		    !memcmp(scid, cid->id, cid->len)) {
			*scid_len = cid->len;
			spin_unlock(&head->lock);
			return cid;
		}
	}

	spin_unlock(&head->lock);
	return NULL;
}

struct quic_cid *quic_cid_get(struct quic_cid *cids, u32 no)
{
	struct quic_cid *cid;

	for (cid = cids; cid; cid = cid->next)
		if (cid->no == no)
			return cid;
	return NULL;
}

static void quic_cid_free_rcu(struct rcu_head *head)
{
	struct quic_cid *cid = container_of(head, struct quic_cid, rcu);

	kfree(cid->id);
	cid->id = NULL;
	cid->len = 0;
	kfree(cid);
}

void quic_cid_destroy(struct quic_cid *cid)
{
	struct quic_hash_head *head;

	if (!hlist_unhashed(&cid->node)) {
		head = quic_cid_head(sock_net(&cid->qs->inet.sk), cid->id);
		spin_lock(&head->lock);
		hlist_del_init(&cid->node);
		spin_unlock(&head->lock);
	}

	call_rcu(&cid->rcu, quic_cid_free_rcu);
}

int quic_cid_init(struct quic_sock *qs, u8 *dcid, int dcid_len,
		  u8 *scid, int scid_len)
{
	struct net *net = sock_net(&qs->inet.sk);
	struct quic_hash_head *head;
	struct quic_cid *cid;
	u8 *buf;

	if (dcid) {
		buf = kzalloc(dcid_len, GFP_ATOMIC);
		cid = kzalloc(sizeof(*cid), GFP_ATOMIC);
		if (!buf || !cid) {
			kfree(buf);
			return -ENOMEM;
		}

		memcpy(buf, dcid, dcid_len);
		cid->id = buf;
		cid->len = dcid_len;
		cid->qs = qs;
		qs->cids.dcid.list = cid;
		qs->cids.dcid.cur = cid;
		qs->cids.dcid.cnt = 1;
	}
	if (scid) {
		buf = kzalloc(scid_len, GFP_ATOMIC);
		cid = kzalloc(sizeof(*cid), GFP_ATOMIC);
		if (!buf || !cid) {
			if (qs->cids.dcid.list) {
				quic_cid_destroy(qs->cids.dcid.list);
				qs->cids.dcid.list = NULL;
				qs->cids.dcid.cur = NULL;
				qs->cids.dcid.cnt = 0;
			}
			kfree(buf);
			return -ENOMEM;
		}
		memcpy(buf, scid, scid_len);
		cid->id = buf;
		cid->len = scid_len;
		cid->qs = qs;
		qs->cids.scid.list = cid;
		qs->cids.scid.cur = cid;
		qs->cids.scid.cnt = 1;

		head = quic_cid_head(net, cid->id);
		spin_lock(&head->lock);
		hlist_add_head(&cid->node, &head->head);
		spin_unlock(&head->lock);
	}

	return 0;
}

void quic_cid_free(struct quic_sock *qs)
{
	struct quic_cid *cid;

	for (cid = qs->cids.dcid.list; cid; cid = cid->next)
		quic_cid_destroy(cid);
	qs->cids.dcid.list = NULL;
	qs->cids.dcid.cur = NULL;
	qs->cids.dcid.cnt = 0;

	for (cid = qs->cids.scid.list; cid; cid = cid->next)
		quic_cid_destroy(cid);
	qs->cids.scid.list = NULL;
	qs->cids.scid.cur = NULL;
	qs->cids.scid.cnt = 0;
}
