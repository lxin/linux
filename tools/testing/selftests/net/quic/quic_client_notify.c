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
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define IPPROTO_QUIC 144
#define SOL_QUIC 144

struct quic_sndinfo {
	uint32_t stream_id;
};

struct quic_rcvinfo {
	uint32_t stream_id;
};

enum quic_cmsg_type {
	QUIC_SNDINFO,
	QUIC_RCVINFO,
};

struct quic_scc {
	uint32_t start;
	uint32_t cnt;
	uint32_t cur;
};

struct quic_idv {
	uint32_t id;
	uint32_t value;
};

enum quic_evt_type {
	QUIC_EVT_CIDS,		/* NEW, DEL, CUR */
	QUIC_EVT_STREAMS,	/* RESET, STOP, MAX, BLOCKED */
	QUIC_EVT_ADDRESS,	/* NEW */
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

struct quic_evt_msg {
	uint8_t evt_type;
	uint8_t sub_type;
	uint32_t value[3];
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

#define MSG_NOTIFICATION		0x8000

int quic_recvmsg(int s, void *msg, size_t len, struct quic_rcvinfo *rinfo, int *msg_flags)
{
	char incmsg[CMSG_SPACE(sizeof(struct quic_rcvinfo))];
	struct cmsghdr *cmsg = NULL;
	struct msghdr inmsg;
	struct iovec iov;
	int error;

	memset(&inmsg, 0, sizeof(inmsg));

	iov.iov_base = msg;
	iov.iov_len = len;

	inmsg.msg_name = NULL;
	inmsg.msg_namelen = 0;
	inmsg.msg_iov = &iov;
	inmsg.msg_iovlen = 1;
	inmsg.msg_control = incmsg;
	inmsg.msg_controllen = sizeof(incmsg);

	error = recvmsg(s, &inmsg, msg_flags ? *msg_flags : 0);
	if (error < 0)
		return error;

	if (msg_flags)
		*msg_flags = inmsg.msg_flags;

	if (!rinfo)
		return error;

	for (cmsg = CMSG_FIRSTHDR(&inmsg); cmsg != NULL; cmsg = CMSG_NXTHDR(&inmsg, cmsg))
		if (SOL_QUIC == cmsg->cmsg_level && QUIC_RCVINFO == cmsg->cmsg_type)
			break;
	if (cmsg)
		memcpy(rinfo, CMSG_DATA(cmsg), sizeof(struct quic_rcvinfo));

	return error;
}

int quic_sendmsg(int s, const void *msg, size_t len, uint32_t flags, uint32_t stream_id)
{
	struct quic_sndinfo *sinfo;
	struct msghdr outmsg;
	struct cmsghdr *cmsg;
	struct iovec iov;
	char outcmsg[CMSG_SPACE(sizeof(*sinfo))];

	outmsg.msg_name = NULL;
	outmsg.msg_namelen = 0;
	outmsg.msg_iov = &iov;
	iov.iov_base = (void *)msg;
	iov.iov_len = len;
	outmsg.msg_iovlen = 1;

	outmsg.msg_control = outcmsg;
	outmsg.msg_controllen = sizeof(outcmsg);
	outmsg.msg_flags = 0;

	cmsg = CMSG_FIRSTHDR(&outmsg);
	cmsg->cmsg_level = SOL_QUIC;
	cmsg->cmsg_type = 0;
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct quic_sndinfo));

	outmsg.msg_controllen = cmsg->cmsg_len;
	sinfo = (struct quic_sndinfo *)CMSG_DATA(cmsg);
	memset(sinfo, 0, sizeof(struct quic_sndinfo));
	sinfo->stream_id = stream_id;

	return sendmsg(s, &outmsg, flags);
}

int main(void)
{
	struct sockaddr_in s_addr, c_addr, n_addr;
	int sd, ret, sid, len, events, cid;
	char s_msg[2000], c_msg[2000];
	struct quic_rcvinfo r;
	struct quic_idv idv;

	sd = socket(AF_INET, SOCK_STREAM, IPPROTO_QUIC);

	c_addr.sin_family = AF_INET;
	c_addr.sin_port = htons(4321);
	c_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	if (bind(sd, (struct sockaddr *)&c_addr, sizeof(c_addr)) < 0) {
		printf("Unable to bind\n");
		return -1;
	}

	s_addr.sin_family = AF_INET;
	s_addr.sin_port = htons(1234);
	s_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	if (connect(sd, (struct sockaddr *)&s_addr, sizeof(s_addr)) < 0) {
		printf("Unable to connect %d\n", errno);
		return -1;
	}

	sleep(1);
	events = 0xf;
	len = sizeof(events);
	ret = setsockopt(sd, SOL_QUIC, QUIC_SOCKOPT_EVENTS, &events, len);
	if (ret < 0) {
		printf("setsockopt %u %u\n", ret, errno);
		return 1;
	}

	sleep(1);
	len = sizeof(events);
	ret = getsockopt(sd, SOL_QUIC, QUIC_SOCKOPT_EVENTS, &events, &len);
	if (ret < 0) {
		printf("getsockopt %u %u\n", ret, errno);
		return 1;
	}
	printf("events %u\n", events);

	sleep(3);
	memset(c_msg, 'c', sizeof(c_msg) - 1);
	ret = quic_sendmsg(sd, c_msg, strlen(c_msg), MSG_EOR, 0);
	if (ret == -1) {
		printf("send %d %d\n", ret, errno);
		return 1;
	}

	sleep(1);
	while (1) {
		int msg_flags;

		memset(s_msg, 0, sizeof(s_msg));
		ret = quic_recvmsg(sd, s_msg, sizeof(s_msg), &r, &msg_flags);
		if (ret == -1) {
			printf("send %d %d\n", ret, errno);
			return 1;
		}
		if (msg_flags & MSG_NOTIFICATION) {
			char type = s_msg[0];

			if (type == QUIC_EVT_STREAMS)  {
				struct quic_evt_msg *es = (struct quic_evt_msg *)s_msg;

				printf("notification type %u, %u: %u, %u, %u\n",
					es->evt_type, es->sub_type,
					es->value[0], es->value[1], es->value[2]);
			}
			if (type == QUIC_EVT_CIDS)  {
				struct quic_evt_msg *es = (struct quic_evt_msg *)s_msg;

				printf("notification type %u, %u: %u, %u, %u\n",
					es->evt_type, es->sub_type,
					es->value[0], es->value[1], es->value[2]);
			}
			if (type == QUIC_EVT_ADDRESS)  {
				struct quic_evt_msg *es = (struct quic_evt_msg *)s_msg;

				printf("notification type %u, %u: %u, %u, %u\n",
					es->evt_type, es->sub_type,
					es->value[0], es->value[1], es->value[2]);
			}
			continue;
		}
		printf("data recv %d %d %s\n", ret, r.stream_id, s_msg);
	}

	sleep(2);
	close(sd);
	return 0;
}
