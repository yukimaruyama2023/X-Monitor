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

  char buffer_a[BUF_SIZE];
  char buffer_b[BUF_SIZE];
  char buffer_c[BUF_SIZE];
  char buffer_d[BUF_SIZE];
  char buffer_e[BUF_SIZE];
  char buffer_f[BUF_SIZE];
  char buffer_g[BUF_SIZE];
  char buffer_h[BUF_SIZE];
  char buffer_i[BUF_SIZE];
  char buffer_j[BUF_SIZE];

  __builtin_memset(buffer_a, 'a', BUF_SIZE);
  __builtin_memset(buffer_b, 'b', BUF_SIZE);
  __builtin_memset(buffer_c, 'c', BUF_SIZE);
  __builtin_memset(buffer_d, 'd', BUF_SIZE);
  __builtin_memset(buffer_e, 'e', BUF_SIZE);
  __builtin_memset(buffer_f, 'f', BUF_SIZE);
  __builtin_memset(buffer_g, 'g', BUF_SIZE);
  __builtin_memset(buffer_h, 'h', BUF_SIZE);
  __builtin_memset(buffer_i, 'i', BUF_SIZE);
  __builtin_memset(buffer_j, 'j', BUF_SIZE);

  if ((void *)payload + sizeof(buffer_a) > data_end) {
    return XDP_PASS;
  }
  __builtin_memcpy(payload, buffer_a, sizeof(buffer_a));
  payload += sizeof(buffer_a);

  if ((void *)payload + sizeof(buffer_b) > data_end) {
    return XDP_PASS;
  }
  __builtin_memcpy(payload, buffer_b, sizeof(buffer_b));
  payload += sizeof(buffer_b);

  if ((void *)payload + sizeof(buffer_c) > data_end) {
    return XDP_PASS;
  }
  __builtin_memcpy(payload, buffer_c, sizeof(buffer_c));
  payload += sizeof(buffer_c);

  if ((void *)payload + sizeof(buffer_d) > data_end) {
    return XDP_PASS;
  }
  __builtin_memcpy(payload, buffer_d, sizeof(buffer_d));
  payload += sizeof(buffer_d);

  if ((void *)payload + sizeof(buffer_e) > data_end) {
    return XDP_PASS;
  }
  __builtin_memcpy(payload, buffer_e, sizeof(buffer_e));
  payload += sizeof(buffer_e);

  if ((void *)payload + sizeof(buffer_f) > data_end) {
    return XDP_PASS;
  }
  __builtin_memcpy(payload, buffer_f, sizeof(buffer_f));
  payload += sizeof(buffer_f);

  if ((void *)payload + sizeof(buffer_g) > data_end) {
    return XDP_PASS;
  }
  __builtin_memcpy(payload, buffer_g, sizeof(buffer_g));
  payload += sizeof(buffer_g);

  if ((void *)payload + sizeof(buffer_h) > data_end) {
    return XDP_PASS;
  }
  __builtin_memcpy(payload, buffer_h, sizeof(buffer_h));
  payload += sizeof(buffer_h);

  if ((void *)payload + sizeof(buffer_i) > data_end) {
    return XDP_PASS;
  }
  __builtin_memcpy(payload, buffer_i, sizeof(buffer_i));
  payload += sizeof(buffer_i);

  if ((void *)payload + sizeof(buffer_j) > data_end) {
    return XDP_PASS;
  }
  __builtin_memcpy(payload, buffer_j, sizeof(buffer_j));
  payload += sizeof(buffer_j);

  swap_src_dst_mac(eth);
  swap_src_dst_ip(ip);
  swap_port(udp);

  udp->check = 0;

  return XDP_TX;
}

char _license[] SEC("license") = "GPL";
