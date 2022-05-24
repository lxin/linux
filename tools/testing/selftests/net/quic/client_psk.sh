#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

modprobe quic
ip link set lo mtu 1500
echo "file net/quic/* +p" > /sys/kernel/debug/dynamic_debug/control
gcc quic_client_psk.c -o quic_client_psk
./quic_client_psk
