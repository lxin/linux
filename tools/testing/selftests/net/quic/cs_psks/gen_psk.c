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
#include <string.h>
#include <stdlib.h>

struct quic_psk {
	uint32_t pskid_len; /* 4 */
	uint8_t pskid[4];
	uint32_t mskey_len; /* 32 */
	uint8_t mskey[32];
	uint32_t nonce_len; /* 8 */
	uint8_t nonce[8];
	uint32_t psk_sent_at;
	uint32_t psk_expire;
};

void print_key(char *str, uint8_t key[], int len)
{
	int i;

	if (!len)
		return;
	printf("%s: ", str);
	for (i = 0; i < len; i++)
		printf("%02x", key[i]);
	printf("\n");
}

void copy_key(uint8_t key[], char str[], int len)
{
	char tmp[3] = {'\0'};
	int i;

	for (i = 0; i < len; i += 2) {
		tmp[0] = str[i];
		tmp[1] = str[i + 1];
		key[i/2] = strtol(tmp, NULL, 16);
	}
}

int main(int argc, char *argv[])
{
	struct quic_psk psk;
	int fd, len;
	char *name;

	if (argc == 4 && strlen(argv[2]) == 8 && strlen(argv[3]) == 64) {
		psk.psk_sent_at = 0;
		psk.psk_expire = 0;
		psk.pskid_len = 4;
		copy_key(psk.pskid, argv[2], 8);
		psk.mskey_len = 32;
		copy_key(psk.mskey, argv[3], 64);
		psk.nonce_len = 8; /* changed */

		name = argv[1];
		fd = open(name, O_WRONLY | O_CREAT, 0644);
		if (fd == -1) {
			printf("open file %s error %d\n", name, errno);
			return 1;
		}
		len = write(fd, &psk, sizeof(psk));
		printf("write file %s len %d\n", name, len);
		close(fd);
		return 0;
	} else if (argc == 2) {
		name = argv[1];
		fd = open(name, O_RDONLY);
		if (fd == -1) {
			printf("open file %s error %d\n", name, errno);
			return 1;
		}
		len = read(fd, &psk, sizeof(psk));
		printf("read file %s len %d %d\n", name, len, psk.pskid_len);
		print_key("id", psk.pskid, psk.pskid_len);
		print_key("nonce", psk.nonce, psk.nonce_len); /* changed */
		print_key("master key", psk.mskey, psk.mskey_len);
		printf("age_add %u lieftime %u\n", psk.psk_sent_at, psk.psk_expire);
		return 0;
	}

	printf("generate: ./gen_psk NAME PSKID MASTER_KEY\n");
	printf("  PSKID: 4-byte hex, such as '13aa0f7e'\n");
	printf("  MASTER_KEY: 32-byte hex, such as ");
	printf("'5ac851e04710692cdb8da27668839d604353668f78158a3f6a98f34045057283'\n");
	printf("dump:  ./gen_psk NAME\n");
	return 1;
}
