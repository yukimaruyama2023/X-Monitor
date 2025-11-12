#!/bin/sh

sudo clang -O2 -g -Wall -target bpf -c xdp_multibuffer_echo.c -o xdp_multibuffer_echo.o
sudo ip link set enp7s0f0np0 xdpdrv off
sudo ip link set enp7s0f0np0 xdpdrv obj xdp_multibuffer_echo.o sec xdp.frags
