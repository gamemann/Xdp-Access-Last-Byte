#include <linux/bpf.h>

#include "common.h"

SEC("xdp_prog")
int prog(struct xdp_md* ctx) {
    // Initialize data and data_end.
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;

    // Retrieve the full length of our packet to use as an offset to the last byte of data from the start of our packet using data_end and data.
    __u16 off = (__u16)(data_end - data);

    // Initialize our last byte of data.
    __u8* last = data + off;

    // Make sure our last byte is within the packet's bounds by comparing to data and data_end.
    if (last + 1 > (__u8*)data_end)
        return XDP_PASS;

    if (last < (__u8*)data)
        return XDP_PASS;

    // Print the last byte of data to /sys/kernel/tracing/trace_pipe.
    bpf_printk("Last byte of packet is %d.\n", *last);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";