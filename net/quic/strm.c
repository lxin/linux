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

int quic_strm_init(struct quic_sock *qs, u32 uni_cnt, u32 bi_cnt)
{
	int err;

	qs->strm.uni_cnt = uni_cnt;
	err = genradix_prealloc(&qs->strm.uni, qs->strm.uni_cnt, GFP_ATOMIC);
	if (err)
		return err;

	qs->strm.bi_cnt = bi_cnt;
	err = genradix_prealloc(&qs->strm.bi, qs->strm.bi_cnt, GFP_ATOMIC);
	if (err)
		genradix_free(&qs->strm.uni);

	return err;
}

void quic_strm_free(struct quic_sock *qs)
{
	genradix_free(&qs->strm.uni);
	genradix_free(&qs->strm.bi);
}
