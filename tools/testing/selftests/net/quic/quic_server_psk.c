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
#include <errno.h>
#include <stdio.h>
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

#define IPPROTO_QUIC    144
#define SOL_QUIC        144

struct quic_all_cids {
	uint32_t scid_first;
	uint32_t scid_cur;
	uint32_t scid_cnt;
	uint32_t dcid_first;
	uint32_t dcid_cur;
	uint32_t dcid_cnt;
};

struct quic_idv {
	uint32_t id;
	uint32_t value;
};

enum quic_evt_type {
	QUIC_EVT_CIDS,          /* NEW, DEL, CUR */
	QUIC_EVT_STREAMS,       /* RESET, STOP, MAX, BLOCKED */
	QUIC_EVT_ADDRESS,
	QUIC_EVT_TICKET,
	QUIC_EVT_MAX,
};

enum quic_evt_strms_type {
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

struct quic_evt_msg {
	uint8_t evt_type;
	uint8_t sub_type;
	uint32_t value[3];
};

/* certificate and private key */
#define QUIC_SOCKOPT_CERT               0
#define QUIC_SOCKOPT_PKEY               1

/* connection id related */
#define QUIC_SOCKOPT_NEW_SCID           2
#define QUIC_SOCKOPT_DEL_DCID           3
#define QUIC_SOCKOPT_CUR_SCID           4
#define QUIC_SOCKOPT_CUR_DCID           5
#define QUIC_SOCKOPT_ALL_SCID           6
#define QUIC_SOCKOPT_ALL_DCID           7

/* connection migration related */
#define QUIC_SOCKOPT_CUR_SADDR          8

/* stream operation related */
#define QUIC_SOCKOPT_RESET_STREAM       9
#define QUIC_SOCKOPT_STOP_SENDING       10
#define QUIC_SOCKOPT_STREAM_STATE       11
#define QUIC_SOCKOPT_MAX_STREAMS        12

/* event */
#define QUIC_SOCKOPT_EVENT              13
#define QUIC_SOCKOPT_EVENTS             14

/* ticket */
#define QUIC_SOCKOPT_NEW_TICKET		15
#define QUIC_SOCKOPT_LOAD_TICKET	16

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

#define PSK_FILE	"cs_psks/psk.der"
int get_psk(char **buf)
{
	int fd = open(PSK_FILE, O_RDONLY);
	struct stat sb;

	if (fd == -1)
		return -1;
	if (stat(PSK_FILE, &sb) == -1)
		return -1;

	*buf = malloc(sb.st_size);
	if (!(*buf))
		return -ENOMEM;
	read(fd, *buf, sb.st_size);

	close(fd);
	return sb.st_size;
}

#define MSG_LEN	1999
int main(void)
{
	int sd, ret, buf_len, ad, msg_flags;
	struct sockaddr_in s_addr, c_addr;
	char s_msg[MSG_LEN + 1];
	unsigned int addr_len;
	struct quic_rcvinfo r;
	char *buf;

	sd = socket(AF_INET, SOCK_STREAM, IPPROTO_QUIC);

	memset(&s_addr, 0x00, sizeof(s_addr));
	s_addr.sin_family = AF_INET;
	s_addr.sin_port = htons(1234);
	s_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	if (bind(sd, (struct sockaddr *)&s_addr, sizeof(s_addr)) < 0) {
		printf("Unable to bind\n");
		return -1;
	}

	buf_len = get_psk(&buf);
	if (setsockopt(sd, SOL_QUIC, QUIC_SOCKOPT_LOAD_TICKET, buf, buf_len) < 0) {
		printf("Unable to setsockopt PSK %d\n", errno);
		return -1;
	}
	printf("PSK File %d\n", buf_len);
	if (listen(sd, 3)) {
		printf("Unable to listen\n");
		return -1;
	}

	ad = accept(sd, (struct sockaddr *)&c_addr, &addr_len);
	if (ad == -1) {
		printf("Unable to accept %d\n", errno);
		goto err;
	}
	memset(s_msg, 0, sizeof(s_msg));
	ret = quic_recvmsg(ad, s_msg, sizeof(s_msg), &r, &msg_flags);
	if (ret == -1) {
		printf("recv %d %d\n", ret, errno);
		goto err;
	}
	printf("recv %d %d %s\n", ret, r.stream_id, s_msg);

	memset(s_msg, 's', sizeof(s_msg) - 1);
	ret = quic_sendmsg(ad, s_msg, strlen(s_msg), MSG_EOR, 1);
	if (ret == -1) {
		printf("send %d %d\n", ret, errno);
		return 1;
	}
	memset(s_msg, 0, sizeof(s_msg));
	ret = quic_recvmsg(ad, s_msg, sizeof(s_msg), &r, &msg_flags);
	if (ret == -1) {
		printf("recv %d %d\n", ret, errno);
		goto err;
	}
	printf("recv %d %d %s\n", ret, r.stream_id, s_msg);

err:
	sleep(2);
	close(ad);
	close(sd);
	return 0;
}
