#!/bin/sh

sudo clang -O2 -g -Wall -target bpf -c xdp_test_user_multibuffer.c -o xdp_test_user_multibuffer.o
sudo ip link set enp13s0f0np0 xdpdrv off
sudo ip link set enp13s0f0np0 xdpdrv obj xdp_test_user_multibuffer.o sec xdp.frags
