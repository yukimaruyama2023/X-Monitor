#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <netinet/in.h> // needed for "IPPROTO_UDP"
 
#define ETH_ALEN 6
#define METRICS_SIZE 70
#define PORT_NUM 22222
#define NUM_APP 3

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

SEC("monitoring")
int monitor(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end; 
    void *data = (void *)(long)ctx->data; 
    struct ethhdr *eth = data;
    struct iphdr *ip = data + sizeof(struct ethhdr);
    struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    char *payload = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

    // check if the packet is for monitoring
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    // if (eth->h_proto != ETH_P_IP) return XDP_PASS;
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP) return XDP_PASS;
    if ((void *)(udp + 1) > data_end) return XDP_PASS;
    if (udp->dest != htons(PORT_NUM)) return XDP_PASS;

    char buffer[NUM_APP][METRICS_SIZE];

    for (int i = 0; i < NUM_APP; i++) {
        for (int j = 0; j < METRICS_SIZE; j++) {
            buffer[i][j] = 'a';
        }
    }

    int port_array[3] = {11211, 11212, 11213};

    for (int i = 0; i < NUM_APP; i++) {
        if (bpf_get_application_metrics(port_array[i], &buffer[i][0], METRICS_SIZE) < 0) {
            return XDP_ABORTED;
        }
    }

    for (int i = 0; i < NUM_APP; i++) {
        if ((void *)(payload + METRICS_SIZE) > data_end) {
            return XDP_PASS;
        }

        __builtin_memcpy(payload, &buffer[i][0], METRICS_SIZE);
        payload += METRICS_SIZE;
    }


    swap_src_dst_mac(eth);
    swap_src_dst_ip(ip);
    swap_port(udp);

    udp->check = 0;

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
