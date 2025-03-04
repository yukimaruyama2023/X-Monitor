#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <netinet/in.h> // needed for "IPPROTO_UDP and htons"

#define VLAN_HDR_LEN 4  // (not used since VLAN not expected)

// Inline helper to swap Ethernet MAC addresses
static __always_inline void swap_src_dst_mac(struct ethhdr *eth) {
    __u8 tmp[ETH_ALEN];
    __builtin_memcpy(tmp, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, tmp, ETH_ALEN);
}

// Inline helper to swap IPv4 addresses
static __always_inline void swap_src_dst_ip(struct iphdr *iph) {
    __be32 tmp = iph->saddr;
    iph->saddr = iph->daddr;
    iph->daddr = tmp;
}

// Inline helper to swap UDP port numbers
static __always_inline void swap_src_dst_udp(struct udphdr *udph) {
    // __be16 tmp = udph->source;
    udph->source = udph->dest;
    udph->dest   = 52822;
}

// XDP program entry (multi-buffer aware)
SEC("xdp.frags")
int xdp_udp_echo(struct xdp_md *ctx) {
    void *data     = (void *)(unsigned long)ctx->data;
    void *data_end = (void *)(unsigned long)ctx->data_end;
    
    struct ethhdr eth;
    if (bpf_xdp_load_bytes(ctx, 0, &eth, sizeof(eth)) < 0) {
        return XDP_DROP;  // ヘッダがフラグメント等で読み込めなければDROP
    }
  
    struct iphdr ip;
    if (bpf_xdp_load_bytes(ctx, sizeof(eth), &ip, sizeof(ip))) {
        return XDP_DROP;
    }
    if (ip.protocol != IPPROTO_UDP) {
        return XDP_DROP; // Not UDP, drop (no other protocols considered)
    }

    struct udphdr udp;
    if (bpf_xdp_load_bytes(ctx, sizeof(eth) + sizeof(ip), &udp, sizeof(udp))) {
        return XDP_DROP;
    }

    swap_src_dst_mac(&eth);
    swap_src_dst_ip(&ip);
    swap_src_dst_udp(&udp);
    
    udp.check = 0;
    if (bpf_xdp_store_bytes(ctx, 0, &eth, sizeof(eth)) < 0 ||
        bpf_xdp_store_bytes(ctx, sizeof(eth), &ip, sizeof(ip)) < 0 ||
        bpf_xdp_store_bytes(ctx, sizeof(eth) + sizeof(ip), &udp, sizeof(udp)) < 0) {
        return XDP_DROP;
    }

    return XDP_TX;
}

// License must be specified for BPF programs
char _license[] SEC("license") = "GPL";
