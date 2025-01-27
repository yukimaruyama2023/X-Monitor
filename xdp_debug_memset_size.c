#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <netinet/in.h> // needed for "IPPROTO_UDP and htons"
#include <stdint.h>
#include "memcached_metrics.h"

#define ETH_ALEN 6
#define PORT_NUM 22222
#define BUF_SIZE 1024
#define NUM_BUF 1

static __always_inline void swap_src_dst_mac(struct ethhdr *eth) {
  __u8 h_tmp[ETH_ALEN];

  __builtin_memcpy(h_tmp, eth->h_source, ETH_ALEN);
  __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
  __builtin_memcpy(eth->h_dest, h_tmp, ETH_ALEN);
}

static __always_inline void swap_src_dst_ip(struct iphdr *ip) {
  __be32 tmp = ip->saddr;
  ip->saddr = ip->daddr;
  ip->daddr = tmp;
}

static __always_inline void swap_port(struct udphdr *udp) {
  /* __be32 tmp = udp->source; */
  udp->source = udp->dest;
  udp->dest = 52822; // equivalent to bpf_htons(22222)
}

const char fmt[] SEC(".rodata") = "Hello, eBPF! metris value is 0x%lx\n";

SEC("debug")
int debug_test(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct ethhdr *eth = data;
  struct iphdr *ip = data + sizeof(struct ethhdr);
  struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
  char *payload = data + sizeof(struct ethhdr) + sizeof(struct iphdr) +
                  sizeof(struct udphdr);

  // check if the packet is monitoring request
  if ((void *)(eth + 1) > data_end)
    return XDP_PASS;
  // if (eth->h_proto != ETH_P_IP) return XDP_PASS;
  if ((void *)(ip + 1) > data_end)
    return XDP_PASS;
  if (ip->protocol != IPPROTO_UDP)
    return XDP_PASS;
  if ((void *)(udp + 1) > data_end)
    return XDP_PASS;
  if (udp->dest != htons(PORT_NUM))
    return XDP_PASS;

  // char buffer[NUM_BUF][BUF_SIZE];
  //
  // char *ptr[NUM_BUF];
  // for (int i = 0; i < NUM_BUF; i++) {
  //   if (i == 0) {
  //     ptr[i] = (void *)((uint64_t)buffer);
  //   } else {
  //     ptr[i] = (void *)((uint64_t)ptr[i - 1] + BUF_SIZE);
  //   }
  // }
  //
  // for (int i = 0; i < NUM_BUF; i++) {
  //   __builtin_memset(ptr[i], 'x', BUF_SIZE);
  // }
  //
  // for (int i = 0; i < NUM_BUF; i++) {
  //   if ((void *)payload + sizeof(buffer[i]) > data_end) {
  //     return XDP_PASS;
  //   }
  //   __builtin_memcpy(payload, buffer[i], sizeof(buffer[i]));
  //   payload += sizeof(buffer[i]);
  // }
  
  swap_src_dst_mac(eth);
  swap_src_dst_ip(ip);
  swap_port(udp);

  udp->check = 0;

  return XDP_TX;
}

char _license[] SEC("license") = "GPL";
