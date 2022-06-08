#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

gcc quic_client_certs.c -o quic_client_certs
./quic_client_certs
