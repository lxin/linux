#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

modprobe quic
dmesg -C
echo "file net/quic/* +p" > /sys/kernel/debug/dynamic_debug/control
gcc quic_server_certs.c -o quic_server_certs
ip link set lo mtu 1500
./quic_server_certs
