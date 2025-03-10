#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <netinet/in.h> // needed for "IPPROTO_UDP"

static __always_inline void swap_src_dst_mac(struct ethhdr *eth) {
    __u8 tmp[ETH_ALEN];
    __builtin_memcpy(tmp, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, tmp, ETH_ALEN);
}

static __always_inline void swap_src_dst_ip(struct iphdr *ip) {
    __be32 tmp = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp;
}

static __always_inline void swap_src_dst_udp(struct udphdr *udp) {
    udp->source = udp->dest;
    udp->dest = 52822;
}

SEC("xdp.frags")
int xdp_udp_echo(struct xdp_md *ctx) {
    void *data     = (void *)(unsigned long)ctx->data;
    void *data_end = (void *)(unsigned long)ctx->data_end;

    struct ethhdr eth;
    if (bpf_xdp_load_bytes(ctx, 0, &eth, sizeof(eth)) < 0) {
        return XDP_DROP;
    }

    __u64 offset = sizeof(struct ethhdr);

    struct iphdr ip;
    if (bpf_xdp_load_bytes(ctx, offset, &ip, sizeof(ip)) < 0) {
        return XDP_DROP;
    }

    __u64 ip_header_length = ip.ihl * 4;
    if (ip_header_length < sizeof(struct iphdr)) {
        return XDP_DROP;
    }

    if (ip.protocol != IPPROTO_UDP) {
        return XDP_DROP;
    }

    offset += ip_header_length;

    struct udphdr udp;
    if (bpf_xdp_load_bytes(ctx, offset, &udp, sizeof(udp)) < 0) {
        return XDP_DROP;
    }

    bpf_printk("multi-buffer");
    bpf_printk("Before swap: MAC src=%02x:%02x:%02x:%02x:%02x:%02x -> dst=%02x:%02x:%02x:%02x:%02x:%02x",
               eth.h_source[0], eth.h_source[1], eth.h_source[2],
               eth.h_source[3], eth.h_source[4], eth.h_source[5],
               eth.h_dest[0], eth.h_dest[1], eth.h_dest[2],
               eth.h_dest[3], eth.h_dest[4], eth.h_dest[5]);

    bpf_printk("Before swap: IP src=%pI4 -> dst=%pI4", &ip.saddr, &ip.daddr);

    swap_src_dst_mac(&eth);
    swap_src_dst_ip(&ip);
    swap_src_dst_udp(&udp);
    udp.check = 0;

    bpf_printk("After swap : MAC src=%02x:%02x:%02x:%02x:%02x:%02x -> dst=%02x:%02x:%02x:%02x:%02x:%02x",
               eth.h_source[0], eth.h_source[1], eth.h_source[2],
               eth.h_source[3], eth.h_source[4], eth.h_source[5],
               eth.h_dest[0], eth.h_dest[1], eth.h_dest[2],
               eth.h_dest[3], eth.h_dest[4], eth.h_dest[5]);

    bpf_printk("After swap : IP src=%pI4 -> dst=%pI4", &ip.saddr, &ip.daddr);
    bpf_printk("");

    bpf_xdp_store_bytes(ctx, 0, &eth, sizeof(struct ethhdr));
    bpf_xdp_store_bytes(ctx, sizeof(struct ethhdr), &ip, sizeof(struct iphdr));
    bpf_xdp_store_bytes(ctx, sizeof(struct ethhdr) + sizeof(struct iphdr), &udp, sizeof(struct udphdr));

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
