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

#define IPPROTO_QUIC	144
#define SOL_QUIC	144

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
#define QUIC_SOCKOPT_NEW_TICKET         15
#define QUIC_SOCKOPT_LOAD_TICKET        16

/* key */
#define QUIC_SOCKOPT_KEY_UPDATE         17

/* certificate chain */
#define QUIC_SOCKOPT_CERT_CHAIN         18
#define QUIC_SOCKOPT_ROOT_CA            19

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

int get_cert(char **buf, char *name)
{
	int fd = open(name, O_RDONLY);
	struct stat sb;

	if (fd == -1)
		return -1;
	if (stat(name, &sb) == -1)
		return -1;

	*buf = malloc(sb.st_size);
	if (!(*buf))
		return -ENOMEM;
	read(fd, *buf, sb.st_size);

	close(fd);
	return sb.st_size;
}

int get_pkey(char **buf, char *name)
{
	int fd = open(name, O_RDONLY);
	struct stat sb;

	if (fd == -1)
		return -1;
	if (stat(name, &sb) == -1)
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
	char s_msg[MSG_LEN + 1], c_msg[MSG_LEN + 1];
	int sd, ret, buf_len, ad, addr_len;
	struct sockaddr_in s_addr, c_addr;
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
	if (listen(sd, 3)) {
		printf("Unable to listen\n");
		return -1;
	}

	buf_len = get_cert(&buf, "./ss_cert/ServerCert.der");
	printf("Cert File %d\n", buf_len);
	if (setsockopt(sd, SOL_QUIC, QUIC_SOCKOPT_CERT_CHAIN, buf, buf_len) < 0) {
		printf("Unable to setsockopt cert %d\n", errno);
		return -1;
	}

	/* Or use setsockopt(QUIC_SOCKOPT_CERT) for ServerCA.der,
	 * IntermediateCA.der and RootCA.der one by one.
	 */

	buf_len = get_pkey(&buf, "./ss_cert/ServerKey.der");
	printf("Priv_key File %d\n", buf_len);
	if (setsockopt(sd, SOL_QUIC, QUIC_SOCKOPT_PKEY, buf, buf_len) < 0) {
		printf("Unable to setsockopt pkey %d\n", errno);
		return -1;
	}

	ad = accept(sd, (struct sockaddr *)&c_addr, &addr_len);
	if (ad == -1) {
		printf("Unable to accept %d\n", errno);
		return -1;
	}

	sleep(1);
	memset(s_msg, 's', sizeof(s_msg) - 1);
	ret = quic_sendmsg(ad, s_msg, strlen(s_msg), 0, 3);
	if (ret == -1) {
		printf("send %d %d\n", ret, errno);
		return 1;
	}

	sleep(1);
	memset(c_msg, 0, sizeof(c_msg));
	ret = quic_recvmsg(ad, c_msg, sizeof(c_msg), &r, 0);
	if (ret == -1) {
		printf("send %d %d\n", ret, errno);
		return 1;
	}
	printf("recv %d %d %s\n", ret, r.stream_id, c_msg);

	memset(c_msg, 0, sizeof(c_msg));
	ret = quic_recvmsg(ad, c_msg, sizeof(c_msg), &r, 0);
	if (ret == -1) {
		printf("send %d %d\n", ret, errno);
		return 1;
	}
	printf("recv %d %d %s\n", ret, r.stream_id, c_msg);

	sleep(2);
	close(ad);
	close(sd);
	return 0;
}
