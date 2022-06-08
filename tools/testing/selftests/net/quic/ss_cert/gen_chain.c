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
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
	int chain_fd, cert_fd, i;
	char *name, *buf, *p;
	unsigned int len;
	struct stat sb;

	if (argc < 2) {
		printf("generate: ./gen_chain CHAIN_FILE CERT_FILE1 CERT_FILE2 ...\n");
		printf("dump: ./gen_chain CHAIN_FILE\n");
		return 0;
	}
	name = argv[1];
	if (argc == 2) {
		chain_fd = open(name, O_RDONLY);
		if (chain_fd == -1) {
			printf("open chain file %s error %d\n", name, errno);
			return 1;
		}
		if (stat(name, &sb) == -1) {
			printf("get chain file info %s error %d\n", name, errno);
			return -1;
		}
		buf = malloc(sb.st_size);
		if (!buf) {
			printf("allocate buf error %d\n", errno);
			return -1;
		}
		read(chain_fd, buf, sb.st_size);
		close(chain_fd);
		p = buf;
		while ((unsigned int)(p - buf) < sb.st_size) {
			len = *((unsigned int *)p);
			printf("Cert %d: %d\n", i, len);
			p += 4;
			p += len;
		}
		return 0;
	}

	chain_fd = open(name, O_WRONLY | O_CREAT, 0644);
	if (chain_fd == -1) {
		printf("open chain file %s error %d\n", name, errno);
		return 1;
	}
	for (i = 2; i < argc; i++) {
		name = argv[i];
		cert_fd = open(name, O_RDONLY);
		if (cert_fd == -1) {
			printf("open cert file %s error %d\n", name, errno);
			return 1;
		}
		if (stat(name, &sb) == -1) {
			printf("get cert file info %s error %d\n", name, errno);
			return -1;
		}
		buf = malloc(sb.st_size + 4);
		if (!buf) {
			printf("allocate buf error %d\n", errno);
			return -1;
		}
		read(cert_fd, buf + 4, sb.st_size);
		close(cert_fd);
		*((unsigned int *)buf) = sb.st_size;
		write(chain_fd, buf, sb.st_size + 4);
		printf("write file %s: %d\n", name, sb.st_size);
		free(buf);
	}
	printf("to chain file *%s*\n", argv[1]);
	close(chain_fd);

	return 0;
}
