#!/bin/sh

sudo clang -O2 -g -Wall -target bpf -c xdp_user_monitoring_kern.c -o xdp_user_monitoring_kern.o
sudo ip link set enp13s0f0 xdpdrv off
sudo ip link set enp13s0f0 xdpdrv obj xdp_user_monitoring_kern.o sec monitoring
