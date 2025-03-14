#!/bin/sh

sudo clang -O2 -g -Wall -target bpf -c xdp_debug_memset_size.c -o xdp_debug_memset_size.o
# sudo ip link set enp13s0f0np0 xdpdrv off
# sudo ip link set enp13s0f0np0 xdpdrv obj xdp_debug_memset_size.o sec debug
sudo ip link set enp13s0f0 xdpdrv off
sudo ip link set enp13s0f0 xdpdrv obj xdp_debug_memset_size.o sec debug
