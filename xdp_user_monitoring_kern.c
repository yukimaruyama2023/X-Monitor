#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <netinet/in.h> // needed for "IPPROTO_UDP and htons"
#include <stdint.h>
// #include <linux/in.h> // needed for "IPPROTO_UDP"
#include "memcached_metrics.h"

#define ETH_ALEN 6
#define METRICS_SIZE 1025
#define PORT_NUM 22222
#define NUM_APP 1
#define __BPF_STACK_LIMIT__ 4096
#define MAX_BPF_STACK 4096

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

SEC("monitoring")
int monitor(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct ethhdr *eth = data;
  struct iphdr *ip = data + sizeof(struct ethhdr);
  struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
  char *payload = data + sizeof(struct ethhdr) + sizeof(struct iphdr) +
                  sizeof(struct udphdr);

  // check if the packet is for monitoring
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

  // char buffer[NUM_APP][METRICS_SIZE];
  // __builtin_memset(buffer, 'a', NUM_APP * METRICS_SIZE); // initialize double
  // array with 'a'

  char buffer[NUM_APP][METRICS_SIZE];
  char *buffer_p = (char *)buffer;
  // char *buffer_p2 = (char *)(buffer + 1024);
  __builtin_memset(buffer_p, 'a', 1 * 1024); // initialize double array with 'a'
  // __builtin_memset(buffer_p2, 'a', 1 * 1024); // initialize double array with
  // 'a'

  // int port_array[13] = {11211, 11212, 11213, 11214,11215,11216,11217,
  //   11218,11219,11220,11221,11222,11223};

  int port_array[3] = {11211, 11212, 11213};
  for (int i = 0; i < NUM_APP; i++) {
    if (bpf_get_application_metrics(port_array[i], &buffer[i][0],
                                    METRICS_SIZE) < 0) {
      return XDP_ABORTED;
    }
  }
  // __builtin_memset(buffer_p2, 'a', 1 * METRICS_SIZE); // initialize double
  // array with 'a'

  // int port = 11211;
  // char *ptr;
  // ptr = (char *)bpf_get_application_metrics_v2(port);
  // bpf_get_application_metrics_v2(port);
  // bpf_get_test(port);

  struct stats *stats = (struct stats *)buffer[0];
  struct stats_state *stats_state =
      (struct stats_state *)(buffer[0] + sizeof(struct stats));

  if ((void *)(payload + sizeof(stats->total_items)) > data_end) {
    return XDP_PASS;
  }
  *(uint64_t *)payload = (uint64_t)stats->total_items;
  payload += sizeof(stats->total_items);
  if ((void *)(payload + sizeof(stats_state->curr_items)) > data_end) {
    return XDP_PASS;
  }
  *(uint64_t *)payload = (uint64_t)stats_state->curr_items;
  payload += sizeof(stats_state->curr_items);

  // __builtin_memset(buffer_p2, 'a', 1 * 1024); // initialize double array with
  // 'a'

  swap_src_dst_mac(eth);
  swap_src_dst_ip(ip);
  swap_port(udp);

  udp->check = 0;

  return XDP_TX;
}

char _license[] SEC("license") = "GPL";
