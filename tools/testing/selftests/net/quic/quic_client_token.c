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
#include <fcntl.h>
#include <sys/stat.h>
#include <stdlib.h>

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

enum quic_evt_type {
	QUIC_EVT_CIDS,          /* NEW, DEL, CUR */
	QUIC_EVT_STREAMS,       /* RESET, STOP, MAX, BLOCKED */
	QUIC_EVT_ADDRESS,       /* NEW */
	QUIC_EVT_TICKET,        /* NEW */
	QUIC_EVT_KEY,           /* NEW */
	QUIC_EVT_TOKEN,         /* NEW */
	QUIC_EVT_MAX,
};

struct quic_evt_msg {
	uint8_t evt_type;
	uint8_t sub_type;
	uint32_t value[3];
	uint8_t data[];
};

#define IPPROTO_QUIC	144
#define SOL_QUIC	144

#define QUIC_SOCKOPT_EVENT		13
#define QUIC_SOCKOPT_EVENTS		14

#define QUIC_SOCKOPT_NEW_TOKEN          20
#define QUIC_SOCKOPT_LOAD_TOKEN         21

#define MSG_NOTIFICATION                0x8000

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

int get_token(char **buf)
{
	*buf = malloc(8);
	if (!(*buf))
		return -ENOMEM;
	memset(*buf, 0x1, 8);

	return 8;
}

int main(void)
{
	int sd, ret, buf_len, events, len, msg_flags;
	struct sockaddr_in s_addr, c_addr;
	char s_msg[2000], c_msg[2000];
	struct quic_rcvinfo r;
	char *buf, type;

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
	events = (1 << QUIC_EVT_TOKEN);
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

	memset(s_msg, 0, sizeof(s_msg));
	ret = quic_recvmsg(sd, s_msg, sizeof(s_msg), &r, &msg_flags);
	if (ret == -1) {
		printf("recv %d %d\n", ret, errno);
		return 1;
	}
	printf("recv %d\n", ret);
	if (msg_flags & MSG_NOTIFICATION) {
		type = s_msg[0];
		if (type == QUIC_EVT_TOKEN)  {
			struct quic_evt_msg *es = (struct quic_evt_msg *)s_msg;

			printf("notification type %u, %u: %u, %u, %u\n",
				es->evt_type, es->sub_type,
				es->value[0], es->value[1], es->value[2]);
			buf = es->data;
			buf_len = es->value[0];
			sleep(3);
			close(sd);
		}
	}

	sd = socket(AF_INET, SOCK_STREAM, IPPROTO_QUIC);

	c_addr.sin_family = AF_INET;
	c_addr.sin_port = htons(4321);
	c_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	if (bind(sd, (struct sockaddr *)&c_addr, sizeof(c_addr)) < 0) {
		printf("Unable to bind\n");
		return -1;
	}

	if (setsockopt(sd, SOL_QUIC, QUIC_SOCKOPT_LOAD_TOKEN, buf, buf_len) < 0) {
		printf("Unable to setsockopt token %d\n", errno);
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
	memset(c_msg, 'c', sizeof(c_msg) - 1);
	ret = quic_sendmsg(sd, c_msg, strlen(c_msg), 0, 0);
	if (ret == -1) {
		printf("send %d %d\n", ret, errno);
		sleep(100);
		return 1;
	}
	printf("send %d\n", ret);

	sleep(1);
	memset(s_msg, 0, sizeof(s_msg));
	ret = quic_recvmsg(sd, s_msg, sizeof(s_msg), &r, 0);
	if (ret == -1) {
		printf("recv %d %d\n", ret, errno);
		return 1;
	}
	printf("recv %d %d %s\n", ret, r.stream_id, s_msg);

	memset(s_msg, 0, sizeof(s_msg));
	ret = quic_recvmsg(sd, s_msg, sizeof(s_msg), &r, 0);
	if (ret == -1) {
		printf("recv %d %d\n", ret, errno);
		return 1;
	}
	printf("recv %d %d %s\n", ret, r.stream_id, s_msg);

	sleep(2);
	close(sd);
	return 0;
}
