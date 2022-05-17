#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

modprobe quic
echo "file net/quic/* +p" > /sys/kernel/debug/dynamic_debug/control
gcc quic_server_notify.c -o quic_server_notify
ip link set lo mtu 1500
./quic_server_notify
