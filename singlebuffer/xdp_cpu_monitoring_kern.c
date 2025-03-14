#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <netinet/in.h> // needed for "IPPROTO_UDP"
 
#define ETH_ALEN 6
#define PORT_NUM 22222

static __always_inline void swap_src_dst_mac(struct ethhdr *eth)
{
    __u8 h_tmp[ETH_ALEN];

    __builtin_memcpy(h_tmp, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, h_tmp, ETH_ALEN);
}

static __always_inline void swap_src_dst_ip(struct iphdr *ip)
{
    __be32 tmp = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp;
}

static __always_inline void swap_port(struct udphdr *udp)
{
    /* __be32 tmp = udp->source; */
    udp->source = udp->dest;
    udp->dest = 52822; // equivalent to bpf_htons(22222) 
}

SEC("xdp.frags")
int udp(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end; 
    void *data = (void *)(long)ctx->data; 
    struct ethhdr *eth = data;
    struct iphdr *ip = data + sizeof(struct ethhdr);
    struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    char *payload = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

    long all_cpu_metrics[10] = {0,0,0,0,0,0,0,0,0,0};
    bpf_get_all_cpu_metrics(all_cpu_metrics);

    // check if the packet is for monitoring
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    /* if (eth->h_proto != ETH_P_IP) return XDP_PASS; */
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP) return XDP_PASS;
    if ((void *)(udp + 1) > data_end) return XDP_PASS;
    if (udp->dest != htons(PORT_NUM)) return XDP_PASS;

    // load metrics to the packet
    for (int i = 0; i < 10; i++) {
        if ((void *)payload + sizeof(long) > data_end) return XDP_PASS;
        *(long *)payload = (long)all_cpu_metrics[i];
        payload += sizeof(long);
    }

    bpf_printk("cpu_monitoring");
    bpf_printk("Before swap : MAC src=%02x:%02x:%02x:%02x:%02x:%02x -> dst=%02x:%02x:%02x:%02x:%02x:%02x",
               eth->h_source[0], eth->h_source[1], eth->h_source[2],
               eth->h_source[3], eth->h_source[4], eth->h_source[5],
               eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
               eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    bpf_printk("Before swap : IP src=%pI4 -> dst=%pI4", &ip->saddr, &ip->daddr);


    swap_src_dst_mac(eth);
    swap_src_dst_ip(ip);
    // swap_port(udp);

    bpf_printk("After swap  : MAC src=%02x:%02x:%02x:%02x:%02x:%02x -> dst=%02x:%02x:%02x:%02x:%02x:%02x",
               eth->h_source[0], eth->h_source[1], eth->h_source[2],
               eth->h_source[3], eth->h_source[4], eth->h_source[5],
               eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
               eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    bpf_printk("After swap  : IP src=%pI4 -> dst=%pI4", &ip->saddr, &ip->daddr);
    bpf_printk("");

    udp->check = 0;

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
