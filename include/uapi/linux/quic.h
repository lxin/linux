/* SPDX-License-Identifier: GPL-2.0-or-later WITH Linux-syscall-note */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2021
 *
 * This file is part of the SCTP kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#ifndef _UAPI_QUIC_H
#define _UAPI_QUIC_H

#include <linux/types.h>

struct quic_sndinfo {
	__u32 stream_id;
};

struct quic_rcvinfo {
	__u32 stream_id;
};

enum quic_cmsg_type {
	QUIC_SNDINFO,
	QUIC_RCVINFO,
};

#define QUIC_SOCKOPT_CERT	0
#define QUIC_SOCKOPT_PKEY	1

#endif /* _UAPI_QUIC_H */
