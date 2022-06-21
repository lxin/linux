#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

modprobe quic
echo "file net/quic/* +p" > /sys/kernel/debug/dynamic_debug/control
gcc quic_client_ccert.c -o quic_client_ccert
./quic_client_ccert
