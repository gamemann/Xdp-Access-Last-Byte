#include <linux/bpf.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include <netinet/in.h>

#include "common.h"

SEC("xdp_prog")
int prog(struct xdp_md* ctx) {
    // Initialize data and data end.
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;

    // Initialite IP header and check.
    struct iphdr* iph = data + sizeof(struct ethhdr);

    if (iph + 1 > (struct iphdr *)data_end)
        return XDP_DROP;

    // We only want to deal with TCP packets.
    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // Initialize TCP header and check.
    struct tcphdr* tcph = (struct tcphdr*)iph + 1;

    if (tcph + 1 > (struct tcphdr *)data_end)
        return XDP_DROP;

    // Retrieve IP header's length.
    __u16 ipLen = ntohs(iph->tot_len);

    // Initialize payload.
    __u8* pl = (__u8*)(tcph + 1);
    
    // Retrieve offset to last packet.
    __u16 off = ipLen - (iph->ihl * 4) - (tcph->doff * 4);

    // Initialize last byte of data and check.
    __u8* last = pl + off;

    if (last + 1 > (__u8*)data_end)
        return XDP_PASS;

    if (last < (__u8*)data)
        return XDP_PASS;

    // Print the last byte of data to /sys/kernel/tracing/trace_pipe.
    bpf_printk("Last byte of packet is %d.\n", *last);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";