#!/bin/sh

sudo clang -O2 -g -Wall -target bpf -c xdp_user_monitoring_kern.c -o xdp_user_monitoring_kern.o
sudo ip link set enp2s0f1 xdpdrv off
sudo ip link set enp2s0f1 xdpdrv obj xdp_user_monitoring_kern.o sec monitoring
