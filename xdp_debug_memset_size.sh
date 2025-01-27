#!/bin/sh

sudo clang -O2 -g -Wall -target bpf -c xdp_debug_memset_size.c -o xdp_debug_memset_size.o
sudo ip link set enp2s0f1 xdpdrv off
sudo ip link set enp2s0f1 xdpdrv obj xdp_debug_memset_size.o sec debug
sudo ip addr add 10.10.10.1/24 dev enp2s0f1
