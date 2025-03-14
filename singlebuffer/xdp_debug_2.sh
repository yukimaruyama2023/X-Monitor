#!/bin/sh

sudo clang -O2 -g -Wall -target bpf -c xdp_debug_2.c -o xdp_debug_2.o
sudo ip link set enp13s0f0np0 xdpdrv off
sudo ip link set enp13s0f0np0 xdpdrv obj xdp_debug_2.o sec debug
