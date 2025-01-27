#!/bin/sh

clang -O2 -g -Wall -target bpf -c xdp_cpu_monitoring_kern.c -o xdp_cpu_monitoring_kern.o
sudo ip link set enp2s0f1 xdpdrv off
sudo ip link set enp2s0f1 xdpdrv obj xdp_cpu_monitoring_kern.o sec monitoring
sudo ip addr add 10.10.10.1/24 dev enp2s0f1
