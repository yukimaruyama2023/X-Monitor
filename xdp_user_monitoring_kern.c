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
#define NUM_APP 2

#define STATS_OFFSET 0x0
#define STATS_STATE_OFFSET 0xe0
#define SETTINGS_OFFSET 0x120
#define RUSAGE_OFFSET 0x280
#define THREAD_STATS_OFFSET 0x320
#define SLAB_STATS_OFFSET 0x1c60
#define TOTALS_OFFSET 0x1ca0

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

const char fmt[] SEC(".rodata") =
    "Hello, eBPF! metris value is 0x%lx\n";

SEC("monitoring")
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

  int port_array[10] = {11211, 11212, 11213, 11214, 11215,
                        11216, 11217, 11218, 11219, 11220};

  struct stats stats[NUM_APP];
  struct stats_state stats_state[NUM_APP];
  struct settings settings[NUM_APP];
  struct rusage rusage[NUM_APP];
  struct thread_stats thread_stats[NUM_APP];
  struct slab_stats slab_stats[NUM_APP];
  itemstats_t totals[NUM_APP];

  char buf_stats[NUM_APP][sizeof(struct stats)];
  char buf_stats_state[NUM_APP][sizeof(struct stats_state)];
  char buf_settings[NUM_APP][sizeof(struct settings)];
  char buf_rusage[NUM_APP][sizeof(struct rusage)];
  char buf_thread_stats[NUM_APP][sizeof(struct thread_stats)];
  char buf_slab_stats[NUM_APP][sizeof(struct slab_stats)];
  char buf_totals[NUM_APP][sizeof(itemstats_t)];
  
  // char buf_stats[NUM_APP][sizeof(stats)];
  // char buf_stats_state[NUM_APP][sizeof(stats_state)];
  // char buf_settings[NUM_APP][sizeof(settings)];
  // char buf_rusage[NUM_APP][sizeof(rusage)];
  // char buf_thread_stats[NUM_APP][sizeof(thread_stats)];
  // char buf_slab_stats[NUM_APP][sizeof(slab_stats)];
  // char buf_totals[NUM_APP][sizeof(totals)];

  __builtin_memset(buf_stats, 'a', sizeof(buf_stats));
  __builtin_memset(buf_stats_state, 'b', sizeof(buf_stats_state));
  __builtin_memset(buf_settings, 'c', sizeof(buf_settings));
  __builtin_memset(buf_rusage, 'd', sizeof(buf_rusage));
  __builtin_memset(buf_thread_stats, 'd', sizeof(buf_thread_stats));
  __builtin_memset(buf_slab_stats, 'e', sizeof(buf_slab_stats));
  __builtin_memset(buf_totals, 'f', sizeof(buf_totals));

  for (int i = 0; i < NUM_APP; i++) {
    bpf_get_application_metrics(port_array[i], STATS, buf_stats[i],
                                sizeof(struct stats));
    bpf_get_application_metrics(port_array[i], STATS_STATE, buf_stats_state[i],
                                sizeof(struct stats_state));
    bpf_get_application_metrics(port_array[i], SETTINGS, buf_settings[i],
                                sizeof(struct settings));
    bpf_get_application_metrics(port_array[i], RUSAGE, buf_rusage[i],
                                sizeof(struct rusage));
    bpf_get_application_metrics(port_array[i], THREAD_STATS,
                                buf_thread_stats[i], sizeof(struct thread_stats));
    bpf_get_application_metrics(port_array[i], SLAB_STATS, buf_slab_stats[i],
                                sizeof(struct slab_stats));
    bpf_get_application_metrics(port_array[i], TOTALS, buf_totals[i],
                                sizeof(itemstats_t));
  }
  // bpf_trace_printk(fmt, sizeof(fmt), sizeof(stats), sizeof(buf_stats));
  // bpf_trace_printk(fmt, sizeof(fmt), sizeof(stats_state),
  //                  sizeof(buf_stats_state));
  // bpf_trace_printk(fmt, sizeof(fmt), sizeof(settings), sizeof(buf_settings));
  // bpf_trace_printk(fmt, sizeof(fmt), sizeof(rusage), sizeof(buf_rusage));
  // bpf_trace_printk(fmt, sizeof(fmt), sizeof(thread_stats),
  //                  sizeof(buf_thread_stats));
  // bpf_trace_printk(fmt, sizeof(fmt), sizeof(slab_stats),
  //                  sizeof(buf_slab_stats));
  // bpf_trace_printk(fmt, sizeof(fmt), sizeof(totals), sizeof(buf_totals));

  for (int i = 0; i < NUM_APP; i++) {
    if ((void *)payload + sizeof(struct stats) > data_end) {
      return XDP_PASS;
    }
    __builtin_memcpy(payload, buf_stats[i], sizeof(struct stats));
    payload += sizeof(struct stats);

    if ((void *)payload + sizeof(struct stats_state) > data_end) {
      return XDP_PASS;
    }
    __builtin_memcpy(payload, buf_stats_state[i], sizeof(struct stats_state));
    payload += sizeof(struct stats_state);
    
    if ((void *)payload + sizeof(struct settings) > data_end) {
      return XDP_PASS;
    }
    __builtin_memcpy(payload, buf_settings[i], sizeof(struct settings));
    payload += sizeof(struct settings);
    
    if ((void *)payload + sizeof(struct rusage) > data_end) {
      return XDP_PASS;
    }
    __builtin_memcpy(payload, buf_rusage[i], sizeof(struct rusage));
    payload += sizeof(struct rusage);
    
    if ((void *)payload + sizeof(struct thread_stats) > data_end) {
      return XDP_PASS;
    }
    __builtin_memcpy(payload, buf_thread_stats[i], sizeof(struct thread_stats));
    payload += sizeof(struct thread_stats);
    
    if ((void *)payload + sizeof(struct slab_stats) > data_end) {
      return XDP_PASS;
    }
    __builtin_memcpy(payload, buf_slab_stats[i], sizeof(struct slab_stats));
    payload += sizeof(struct slab_stats);
    
    if ((void *)payload + sizeof(itemstats_t) > data_end) {
      return XDP_PASS;
    }
    __builtin_memcpy(payload, buf_totals[i], sizeof(itemstats_t));
    payload += sizeof(itemstats_t);
  }

  swap_src_dst_mac(eth);
  swap_src_dst_ip(ip);
  swap_port(udp);

  udp->check = 0;

  return XDP_TX;
}

char _license[] SEC("license") = "GPL";
