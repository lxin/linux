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

int quic_cid_init(struct quic_sock *qs, u8 *dcid, int dcid_len,
		  u8 *scid, int scid_len)
{
	u8 *buf;

	if (dcid) {
		buf = kzalloc(dcid_len, GFP_KERNEL);
		if (!buf)
			return -ENOMEM;
		memcpy(buf, dcid, dcid_len);

		qs->dcid.id = buf;
		qs->dcid.len = dcid_len;
	}
	if (scid) {
		buf = kzalloc(scid_len, GFP_KERNEL);
		if (!buf) {
			if (dcid) {
				kfree(qs->dcid.id);
				qs->dcid.id = NULL;
				qs->dcid.len = 0;
			}
			return -ENOMEM;
		}
		memcpy(buf, scid, scid_len);
		qs->scid.id = buf;
		qs->scid.len = scid_len;
	}

	return 0;
}

void quic_cid_free(struct quic_sock *qs)
{
	kfree(qs->dcid.id);
	qs->dcid.id = NULL;
	qs->dcid.len = 0;
	kfree(qs->scid.id);
	qs->scid.id = NULL;
	qs->scid.len = 0;
}
