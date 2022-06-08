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

struct quic_scc {
	__u32 start;
	__u32 cnt;
	__u32 cur;
};

struct quic_idv {
	__u32 id;
	__u32 value;
};

enum quic_evt_type {
	QUIC_EVT_CIDS,		/* NEW, DEL, CUR */
	QUIC_EVT_STREAMS,	/* RESET, STOP, MAX, BLOCKED */
	QUIC_EVT_ADDRESS,	/* NEW */
	QUIC_EVT_TICKET,	/* NEW */
	QUIC_EVT_KEY,		/* NEW */
	QUIC_EVT_MAX,
};

enum quic_evt_stms_type {
	QUIC_EVT_STREAMS_RESET,
	QUIC_EVT_STREAMS_STOP,
	QUIC_EVT_STREAMS_MAX,
	QUIC_EVT_STREAMS_BLOCKED,
};

enum quic_evt_cids_type {
	QUIC_EVT_CIDS_NEW,
	QUIC_EVT_CIDS_DEL,
	QUIC_EVT_CIDS_CUR,
};

enum quic_evt_addr_type {
	QUIC_EVT_ADDRESS_NEW,
};

enum quic_evt_ticket_type {
	QUIC_EVT_TICKET_NEW,
};

enum quic_evt_key_type {
	QUIC_EVT_KEY_NEW,
};

struct quic_evt_msg {
	u8 evt_type;
	u8 sub_type;
	u32 value[3];
	u8 data[];
};

/* certificate and private key */
#define QUIC_SOCKOPT_CERT		0
#define QUIC_SOCKOPT_PKEY		1

/* connection id related */
#define QUIC_SOCKOPT_NEW_SCID		2
#define QUIC_SOCKOPT_DEL_DCID		3
#define QUIC_SOCKOPT_CUR_SCID		4
#define QUIC_SOCKOPT_CUR_DCID		5
#define QUIC_SOCKOPT_ALL_SCID		6
#define QUIC_SOCKOPT_ALL_DCID		7

/* connection migration related */
#define QUIC_SOCKOPT_CUR_SADDR		8

/* stream operation related */
#define QUIC_SOCKOPT_RESET_STREAM	9
#define QUIC_SOCKOPT_STOP_SENDING	10
#define QUIC_SOCKOPT_STREAM_STATE	11
#define QUIC_SOCKOPT_MAX_STREAMS	12

/* event */
#define QUIC_SOCKOPT_EVENT		13
#define QUIC_SOCKOPT_EVENTS		14

/* ticket */
#define QUIC_SOCKOPT_NEW_TICKET		15
#define QUIC_SOCKOPT_LOAD_TICKET	16

/* key */
#define QUIC_SOCKOPT_KEY_UPDATE		17

/* certificate chain */
#define QUIC_SOCKOPT_CERT_CHAIN		18
#define QUIC_SOCKOPT_ROOT_CA		19

#define MSG_NOTIFICATION		0x8000

#endif /* _UAPI_QUIC_H */
