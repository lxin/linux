#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

echo "file net/quic/* +p" > /sys/kernel/debug/dynamic_debug/control
gcc quic_client.c -o quic_client
./quic_client
