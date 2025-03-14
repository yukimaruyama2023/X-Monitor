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
#define NUM_APP 1

enum {
  STATS,
  STATS_STATE,
  SETTINGS,
  RUSAGE,
  THREAD_STATS,
  SLAB_STATS,
  TOTALS,
};

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

const char fmt[] SEC(".rodata") = "Hello, eBPF! metris[0] size is %d\n";
const char fmt_v2[] SEC(".rodata") = "Hello, eBPF! metris[1] size is %d\n";

SEC("debug")
int monitor(struct xdp_md *ctx) {
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

  int port = 11211;

  struct memcached_metrics {
    struct stats stats;
    struct stats_state stats_state;
    struct settings settings;
    struct rusage rusage;
    struct thread_stats thread_stats;
    struct slab_stats slab_stats;
    itemstats_t totals;
  };

  struct memcached_metrics memcached_metrics;
  struct memcached_metrics *ptr = &memcached_metrics;

  __builtin_memset((void *)ptr, 'a', sizeof(struct memcached_metrics));

  bpf_get_application_metrics(port, STATS,
                              (char *)&memcached_metrics.stats,
                              sizeof(struct stats));
  // bpf_get_application_metrics(port, STATS_STATE,
  //                             (char *)&memcached_metrics.stats_state,
  //                             sizeof(struct stats_state));
  // bpf_get_application_metrics(port, SETTINGS,
  //                             (char *)&memcached_metrics.settings,
  //                             sizeof(struct settings));
  // bpf_get_application_metrics(port, RUSAGE,
  //                             (char *)&memcached_metrics.rusage,
  //                             sizeof(struct rusage));
  // bpf_get_application_metrics(port, THREAD_STATS,
  //                             (char *)&memcached_metrics.thread_stats,
  //                             sizeof(struct thread_stats));
  // bpf_get_application_metrics(port, SLAB_STATS,
  //                             (char *)&memcached_metrics.slab_stats,
  //                             sizeof(struct slab_stats));
  // bpf_get_application_metrics(port, TOTALS,
  //                             (char *)&memcached_metrics.totals,
  //                             sizeof(itemstats_t));

  if ((void *)payload + sizeof(memcached_metrics) > data_end) {
      return XDP_PASS;
    __builtin_memcpy(payload, &memcached_metrics,
                     sizeof(memcached_metrics));
    payload += sizeof(memcached_metrics);
  }

  swap_src_dst_mac(eth);
  swap_src_dst_ip(ip);
  swap_port(udp);

  udp->check = 0;

  return XDP_TX;
}

char _license[] SEC("license") = "GPL";
