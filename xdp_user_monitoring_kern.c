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

const char fmt[] SEC(".rodata") = "Hello, eBPF! metris value is 0x%lx\n";

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

  __builtin_memset(buf_stats, 'a', sizeof(buf_stats));
  __builtin_memset(buf_stats_state, 'b', sizeof(buf_stats_state));
  __builtin_memset(buf_settings, 'c', sizeof(buf_settings));
  __builtin_memset(buf_rusage, 'd', sizeof(buf_rusage));
  __builtin_memset(buf_thread_stats, 'd', sizeof(buf_thread_stats));
  __builtin_memset(buf_slab_stats, 'e', sizeof(buf_slab_stats));
  __builtin_memset(buf_totals, 'f', sizeof(buf_totals));

  // for (int i = 0; i < NUM_APP; i++) {
  //   bpf_get_application_metrics(port_array[i], STATS, buf_stats[i],
  //                               sizeof(struct stats));
  //   bpf_get_application_metrics(port_array[i], STATS_STATE,
  //   buf_stats_state[i],
  //                               sizeof(struct stats_state));
  //   bpf_get_application_metrics(port_array[i], SETTINGS, buf_settings[i],
  //                               sizeof(struct settings));
  //   bpf_get_application_metrics(port_array[i], RUSAGE, buf_rusage[i],
  //                               sizeof(struct rusage));
  //   // bpf_get_application_metrics(port_array[i], THREAD_STATS,
  //   //                             buf_thread_stats[i], sizeof(struct
  //   //                             thread_stats));
  //   bpf_get_application_metrics(port_array[i], SLAB_STATS, buf_slab_stats[i],
  //                               sizeof(struct slab_stats));
  //   bpf_get_application_metrics(port_array[i], TOTALS, buf_totals[i],
  //                               sizeof(itemstats_t));
  // }

  bpf_get_application_metrics(port_array[0], STATS, buf_stats[0],
                              sizeof(struct stats));
  bpf_get_application_metrics(port_array[0], STATS_STATE, buf_stats_state[0],
                              sizeof(struct stats_state));
  bpf_get_application_metrics(port_array[0], SETTINGS, buf_settings[0],
                              sizeof(struct settings));
  bpf_get_application_metrics(port_array[0], RUSAGE, buf_rusage[0],
                              sizeof(struct rusage));
  // bpf_get_application_metrics(port_array[0], THREAD_STATS,
  // buf_thread_stats[0],
  //                             sizeof(struct thread_stats));
  bpf_get_application_metrics(port_array[0], SLAB_STATS, buf_slab_stats[0],
                              sizeof(struct slab_stats));
  bpf_get_application_metrics(port_array[0], TOTALS, buf_totals[0],
                              sizeof(itemstats_t));

  bpf_get_application_metrics(port_array[1], STATS, buf_stats[1],
                              sizeof(struct stats));
  bpf_get_application_metrics(port_array[1], STATS_STATE, buf_stats_state[1],
                              sizeof(struct stats_state));
  bpf_get_application_metrics(port_array[1], SETTINGS, buf_settings[1],
                              sizeof(struct settings));
  bpf_get_application_metrics(port_array[1], RUSAGE, buf_rusage[1],
                              sizeof(struct rusage));
  // bpf_get_application_metrics(port_array[1], THREAD_STATS,
  // buf_thread_stats[1],
  //                             sizeof(struct thread_stats));
  bpf_get_application_metrics(port_array[1], SLAB_STATS, buf_slab_stats[1],
                              sizeof(struct slab_stats));
  bpf_get_application_metrics(port_array[1], TOTALS, buf_totals[1],
                              sizeof(itemstats_t));

  bpf_get_application_metrics(port_array[2], STATS, buf_stats[2],
                              sizeof(struct stats));
  bpf_get_application_metrics(port_array[2], STATS_STATE, buf_stats_state[2],
                              sizeof(struct stats_state));
  bpf_get_application_metrics(port_array[2], SETTINGS, buf_settings[2],
                              sizeof(struct settings));
  bpf_get_application_metrics(port_array[2], RUSAGE, buf_rusage[2],
                              sizeof(struct rusage));
  // bpf_get_application_metrics(port_array[2], THREAD_STATS,
  // buf_thread_stats[2],
  //                             sizeof(struct thread_stats));
  bpf_get_application_metrics(port_array[2], SLAB_STATS, buf_slab_stats[2],
                              sizeof(struct slab_stats));
  bpf_get_application_metrics(port_array[2], TOTALS, buf_totals[2],
                              sizeof(itemstats_t));

  bpf_get_application_metrics(port_array[3], STATS, buf_stats[3],
                              sizeof(struct stats));
  bpf_get_application_metrics(port_array[3], STATS_STATE, buf_stats_state[3],
                              sizeof(struct stats_state));
  bpf_get_application_metrics(port_array[3], SETTINGS, buf_settings[3],
                              sizeof(struct settings));
  bpf_get_application_metrics(port_array[3], RUSAGE, buf_rusage[3],
                              sizeof(struct rusage));
  // bpf_get_application_metrics(port_array[3], THREAD_STATS,
  // buf_thread_stats[3],
  //                             sizeof(struct thread_stats));
  bpf_get_application_metrics(port_array[3], SLAB_STATS, buf_slab_stats[3],
                              sizeof(struct slab_stats));
  bpf_get_application_metrics(port_array[3], TOTALS, buf_totals[3],
                              sizeof(itemstats_t));
  bpf_get_application_metrics(port_array[4], STATS, buf_stats[4],
                              sizeof(struct stats));
  bpf_get_application_metrics(port_array[4], STATS_STATE, buf_stats_state[4],
                              sizeof(struct stats_state));
  bpf_get_application_metrics(port_array[4], SETTINGS, buf_settings[4],
                              sizeof(struct settings));
  bpf_get_application_metrics(port_array[4], RUSAGE, buf_rusage[4],
                              sizeof(struct rusage));
  // bpf_get_application_metrics(port_array[4], THREAD_STATS,
  // buf_thread_stats[4],
  //                             sizeof(struct thread_stats));
  bpf_get_application_metrics(port_array[4], SLAB_STATS, buf_slab_stats[4],
                              sizeof(struct slab_stats));
  bpf_get_application_metrics(port_array[4], TOTALS, buf_totals[4],
                              sizeof(itemstats_t));

  bpf_get_application_metrics(port_array[5], STATS, buf_stats[5],
                              sizeof(struct stats));
  bpf_get_application_metrics(port_array[5], STATS_STATE, buf_stats_state[5],
                              sizeof(struct stats_state));
  bpf_get_application_metrics(port_array[5], SETTINGS, buf_settings[5],
                              sizeof(struct settings));
  bpf_get_application_metrics(port_array[5], RUSAGE, buf_rusage[5],
                              sizeof(struct rusage));
  // bpf_get_application_metrics(port_array[5], THREAD_STATS,
  // buf_thread_stats[5],
  //                             sizeof(struct thread_stats));
  bpf_get_application_metrics(port_array[5], SLAB_STATS, buf_slab_stats[5],
                              sizeof(struct slab_stats));
  bpf_get_application_metrics(port_array[5], TOTALS, buf_totals[5],
                              sizeof(itemstats_t));

  // bpf_get_application_metrics(port_array[6], STATS, buf_stats[6],
  //                             sizeof(struct stats));
  // bpf_get_application_metrics(port_array[6], STATS_STATE, buf_stats_state[6],
  //                             sizeof(struct stats_state));
  // bpf_get_application_metrics(port_array[6], SETTINGS, buf_settings[6],
  //                             sizeof(struct settings));
  // bpf_get_application_metrics(port_array[6], RUSAGE, buf_rusage[6],
  //                             sizeof(struct rusage));
  // // bpf_get_application_metrics(port_array[6], THREAD_STATS, buf_thread_stats[6],
  // //                             sizeof(struct thread_stats));
  // bpf_get_application_metrics(port_array[6], SLAB_STATS, buf_slab_stats[6],
  //                             sizeof(struct slab_stats));
  // bpf_get_application_metrics(port_array[6], TOTALS, buf_totals[6],
  //                             sizeof(itemstats_t));

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

    // if ((void *)payload + sizeof(struct thread_stats) > data_end) {
    //   return XDP_PASS;
    // }
    // __builtin_memcpy(payload, buf_thread_stats[i], sizeof(struct
    // thread_stats)); payload += sizeof(struct thread_stats);

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
