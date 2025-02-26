#!/bin/sh

clang -O2 -g -Wall -target bpf -c xdp_cpu_monitoring_kern.c -o xdp_cpu_monitoring_kern.o
sudo ip link set enp13s0f0np0 xdpdrv off
sudo ip link set enp13s0f0np0 xdpdrv obj xdp_cpu_monitoring_kern.o sec monitoring
