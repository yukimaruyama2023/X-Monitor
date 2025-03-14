#!/bin/sh

sudo clang -O2 -g -Wall -target bpf -c xdp_test_cpu_multibuffer.c -o xdp_test_cpu_multibuffer.o
sudo ip link set enp13s0f0np0 xdpdrv off
sudo ip link set enp13s0f0np0 xdpdrv obj xdp_test_cpu_multibuffer.o sec xdp.frags
