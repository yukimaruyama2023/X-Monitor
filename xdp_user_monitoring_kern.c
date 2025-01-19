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
// #define METRICS_SIZE 740
#define PORT_NUM 22222
#define NUM_APP 3
// #define __BPF_STACK_LIMIT__ 4096
// #define MAX_BPF_STACK 4096

#define STATS_OFFSET 0x0
#define STATS_STATE_OFFSET 0xe0
#define SETTINGS_OFFSET 0x120
#define RUSAGE_OFFSET 0x280
#define THREAD_STATS_OFFSET 0x320
#define SLAB_STATS_OFFSET 0x1c60
#define TOTALS_OFFSET 0x1ca0

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

const char fmt[] SEC(".rodata") =
    "Hello, eBPF! metris size is 0x%lx, and buffer size is 0x%lx\n";

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

  int port_array[13] = {11211, 11212, 11213, 11214, 11215, 11216, 11217,
                        11218, 11219, 11220, 11221, 11222, 11223};

  struct stats stats;
  struct stats_state stats_state;
  struct settings settings;
  struct rusage rusage;
  struct thread_stats thread_stats;
  struct slab_stats slab_stats;
  itemstats_t totals;

  char buf_stats[sizeof(stats)];
  char buf_stats_state[sizeof(stats_state)];
  char buf_settings[sizeof(settings)];
  char buf_rusage[sizeof(rusage)];
  char buf_thread_stats[sizeof(thread_stats)];
  char buf_slab_stats[sizeof(slab_stats)];
  char buf_totals[sizeof(totals)];

  bpf_store42();
  __builtin_memset(buf_stats, 'a', sizeof(buf_stats));
  __builtin_memset(buf_stats_state, 'b', sizeof(buf_stats_state));
  __builtin_memset(buf_settings, 'c', sizeof(buf_settings));
  __builtin_memset(buf_rusage, 'd', sizeof(buf_rusage));
  __builtin_memset(buf_thread_stats, 'd', sizeof(buf_thread_stats));
  __builtin_memset(buf_slab_stats, 'e', sizeof(buf_slab_stats));
  __builtin_memset(buf_totals, 'f', sizeof(buf_totals));

  bpf_get_application_metrics(port_array[0], STATS_OFFSET, sizeof(stats),
                              buf_stats);
  bpf_get_application_metrics(port_array[0], STATS_STATE_OFFSET,
                              sizeof(stats_state), buf_stats_state);
  bpf_get_application_metrics(port_array[0], SETTINGS_OFFSET, sizeof(settings),
                              buf_settings);
  bpf_get_application_metrics(port_array[0], RUSAGE_OFFSET, sizeof(rusage),
                              buf_rusage);
  bpf_get_application_metrics(port_array[0], THREAD_STATS_OFFSET,
                              sizeof(thread_stats), buf_thread_stats);
  bpf_get_application_metrics(port_array[0], SLAB_STATS_OFFSET,
                              sizeof(slab_stats), buf_slab_stats);
  bpf_get_application_metrics(port_array[0], TOTALS_OFFSET, sizeof(totals),
                              buf_totals);
  bpf_trace_printk(fmt, sizeof(fmt), sizeof(stats), sizeof(buf_stats));

  if ((void *)payload + sizeof(buf_stats) > data_end) {
    return XDP_PASS;
  }
  __builtin_memcpy(payload, buf_stats, sizeof(buf_stats));
  payload += sizeof(buf_stats);

  if ((void *)payload + sizeof(buf_stats_state) > data_end) {
    return XDP_PASS;
  }
  __builtin_memcpy(payload, buf_stats_state, sizeof(buf_stats_state));
  payload += sizeof(buf_stats_state);

  if ((void*)payload + sizeof(buf_settings) > data_end) {
    return XDP_PASS;
  }
  __builtin_memcpy(payload, buf_settings, sizeof(buf_settings));
  payload += sizeof(buf_settings);

  if ((void *)payload + sizeof(buf_rusage) > data_end) {
    return XDP_PASS;
  }
  __builtin_memcpy(payload, buf_rusage, sizeof(buf_rusage));
  payload += sizeof(buf_rusage);

  if ((void *)payload + sizeof(buf_thread_stats) > data_end) {
    return XDP_PASS;
  }
  __builtin_memcpy(payload, buf_thread_stats, sizeof(buf_thread_stats));
  payload += sizeof(buf_thread_stats);

  if ((void *)payload + sizeof(buf_slab_stats) > data_end) {
    return XDP_PASS;
  }
  __builtin_memcpy(payload, buf_slab_stats, sizeof(buf_slab_stats));
  payload += sizeof(buf_slab_stats);

  if ((void *)payload + sizeof(buf_totals) > data_end) {
    return XDP_PASS;
  }
  __builtin_memcpy(payload, buf_totals, sizeof(buf_totals));
  payload += sizeof(buf_totals);

  swap_src_dst_mac(eth);
  swap_src_dst_ip(ip);
  swap_port(udp);

  udp->check = 0;

  return XDP_TX;
}

char _license[] SEC("license") = "GPL";
