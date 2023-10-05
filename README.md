I'm creating this repository to store my findings on accessing the last byte of data in a packet within [XDP](https://www.iovisor.org/technology/xdp). This is currently **unresolved**.

## Building
You can use the `make` command to quickly build this project. Otherwise, you can use the following commands.

```bash
clang -O2 -g -target bpf -o build/last_one.o -c src/last_one.c
clang -O2 -g -target bpf -o build/last_two.o -c src/last_two.c
```

## Attaching The XDP Programs
You can attempt to attach the XDP object files after building via `make` by performing the following command as root (or using `sudo`).

```bash
ip link set <interfaceName> xdp obj build/<prog>.o section xdp_prog
```

* `<interfaceName>` - The interface name that you want to attach the XDP program to (`ip a`, `ip link`, and `ifconfig` are commands to list interface names in most Linux distros).
* `<prog>` - The test program to attach after building via `make` (e.g. `last_one` or `last_two`).

## Findings So Far
### `last_one.c`
In our [last_one.c](./src/last_one.c) XDP program, we try to use `data` and `data_end` to retrieve the offset to the last byte of data in the packet. We then store the byte in our `last` pointer. Afterwards, we check if the last byte is within the packet's bounds by comparing it to `data` and `data_end`.

```C
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
```

This fails with the following.

```
libbpf: prog 'prog': BPF program load failed: Permission denied
libbpf: prog 'prog': -- BEGIN PROG LOAD LOG --
0: R1=ctx(off=0,imm=0) R10=fp0
; void* data = (void*)(long)ctx->data;
0: (61) r2 = *(u32 *)(r1 +0)          ; R1=ctx(off=0,imm=0) R2_w=pkt(off=0,r=0,imm=0)
; void* data_end = (void*)(long)ctx->data_end;
1: (61) r3 = *(u32 *)(r1 +4)          ; R1=ctx(off=0,imm=0) R3_w=pkt_end(off=0,imm=0)
; __u16 off = (__u16)(data_end - data);
2: (bf) r4 = r3                       ; R3_w=pkt_end(off=0,imm=0) R4_w=pkt_end(off=0,imm=0)
3: (1f) r4 -= r2                      ; R2_w=pkt(off=0,r=0,imm=0) R4_w=scalar()
; __u8* last = data + off;
4: (57) r4 &= 65535                   ; R4_w=scalar(umax=65535,var_off=(0x0; 0xffff))
; __u8* last = data + off;
5: (bf) r1 = r2                       ; R1_w=pkt(off=0,r=0,imm=0) R2_w=pkt(off=0,r=0,imm=0)
6: (0f) r1 += r4                      ; R1_w=pkt(id=1,off=0,r=0,umax=65535,var_off=(0x0; 0xffff)) R4_w=scalar(umax=65535,var_off=(0x0; 0xffff))
; if (last + 1 > (__u8*)data_end)
7: (bf) r4 = r1                       ; R1_w=pkt(id=1,off=0,r=0,umax=65535,var_off=(0x0; 0xffff)) R4_w=pkt(id=1,off=0,r=0,umax=65535,var_off=(0x0; 0xffff))
8: (07) r4 += 1                       ; R4_w=pkt(id=1,off=1,r=0,umax=65535,var_off=(0x0; 0xffff))
; if (last + 1 > (__u8*)data_end)
9: (2d) if r4 > r3 goto pc+6          ; R3_w=pkt_end(off=0,imm=0) R4_w=pkt(id=1,off=1,r=0,umax=65535,var_off=(0x0; 0xffff))
10: (2d) if r2 > r1 goto pc+5         ; R1_w=pkt(id=1,off=0,r=0,umax=65535,var_off=(0x0; 0xffff)) R2_w=pkt(off=0,r=0,imm=0)
; bpf_printk("Last byte of packet is %d.\n", *last);
11: (71) r3 = *(u8 *)(r1 +0)
invalid access to packet, off=0 size=1, R1(id=1,off=0,r=0)
R1 offset is outside of the packet
processed 12 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --
libbpf: prog 'prog': failed to load: -13
libbpf: failed to load object 'build/last_one.o'
```

**Note** - Even checking the value of `off` to make sure it's over 0 doesn't work (e.g. `if (off < 1) return XDP_PASS;`).

### `last_two.c`
In our [last_two.c](./src/last_two.c) XDP program, we try a different approach by initializing and checking both the IPv4 and TCP headers. We are only dealing with TCP packets in this case. We then retrieve the total length of the IP header by accessing the `iph->total_len` field and then converting the value from *network byte order* to *host byte order* since it's an 16-bit integer.

we also initialize a pointer to the start of our packet's payload.

From there, we retrieve our offset to the the packet's last byte from the start of our payload data by subtracting the size of our IP and TCP headers from the IP header's total length. Aftewards, we initialize the last byte of data by adding the start of our payload data in memory to our offset calculated above and check if the last byte is within the packet's bounds by comparing to `data` and `data_end`.

```C
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
```

This also fails with the following.

```
libbpf: prog 'prog': BPF program load failed: Permission denied
libbpf: prog 'prog': -- BEGIN PROG LOAD LOG --
0: R1=ctx(off=0,imm=0) R10=fp0
; int prog(struct xdp_md *ctx) {
0: (b7) r0 = 1                        ; R0_w=1
; void* data_end = (void*)(long)ctx->data_end;
1: (61) r2 = *(u32 *)(r1 +4)          ; R1=ctx(off=0,imm=0) R2_w=pkt_end(off=0,imm=0)
; void* data = (void*)(long)ctx->data;
2: (61) r1 = *(u32 *)(r1 +0)          ; R1_w=pkt(off=0,r=0,imm=0)
; if (iph + 1 > (struct iphdr *)data_end)
3: (bf) r3 = r1                       ; R1_w=pkt(off=0,r=0,imm=0) R3_w=pkt(off=0,r=0,imm=0)
4: (07) r3 += 34                      ; R3_w=pkt(off=34,r=0,imm=0)
; if (iph + 1 > (struct iphdr *)data_end)
5: (2d) if r3 > r2 goto pc+31         ; R2_w=pkt_end(off=0,imm=0) R3_w=pkt(off=34,r=34,imm=0)
; if (iph->protocol != IPPROTO_TCP)
6: (71) r3 = *(u8 *)(r1 +23)          ; R1_w=pkt(off=0,r=34,imm=0) R3_w=scalar(umax=255,var_off=(0x0; 0xff))
7: (b7) r0 = 2                        ; R0_w=2
; if (iph->protocol != IPPROTO_TCP)
8: (55) if r3 != 0x6 goto pc+28       ; R3_w=6
; if (tcph + 1 > (struct tcphdr *)data_end)
9: (bf) r3 = r1                       ; R1_w=pkt(off=0,r=34,imm=0) R3_w=pkt(off=0,r=34,imm=0)
10: (07) r3 += 54                     ; R3_w=pkt(off=54,r=34,imm=0)
11: (b7) r0 = 1                       ; R0=1
; if (tcph + 1 > (struct tcphdr *)data_end)
12: (2d) if r3 > r2 goto pc+24        ; R2=pkt_end(off=0,imm=0) R3=pkt(off=54,r=54,imm=0)
; __u16 off = ipLen - (iph->ihl * 4) - (tcph->doff * 4);
13: (71) r4 = *(u8 *)(r1 +14)         ; R1=pkt(off=0,r=54,imm=0) R4_w=scalar(umax=255,var_off=(0x0; 0xff))
; __u16 off = ipLen - (iph->ihl * 4) - (tcph->doff * 4);
14: (67) r4 <<= 2                     ; R4_w=scalar(umax=1020,var_off=(0x0; 0x3fc))
15: (57) r4 &= 60                     ; R4_w=scalar(umax=60,var_off=(0x0; 0x3c))
; __u16 off = ipLen - (iph->ihl * 4) - (tcph->doff * 4);
16: (69) r5 = *(u16 *)(r1 +46)        ; R1=pkt(off=0,r=54,imm=0) R5_w=scalar(umax=65535,var_off=(0x0; 0xffff))
; __u16 off = ipLen - (iph->ihl * 4) - (tcph->doff * 4);
17: (77) r5 >>= 2                     ; R5_w=scalar(umax=16383,var_off=(0x0; 0x3fff))
18: (57) r5 &= 60                     ; R5_w=scalar(umax=60,var_off=(0x0; 0x3c))
; __u16 off = ipLen - (iph->ihl * 4) - (tcph->doff * 4);
19: (0f) r5 += r4                     ; R4_w=scalar(umax=60,var_off=(0x0; 0x3c)) R5_w=scalar(umax=120,var_off=(0x0; 0x7c))
; __u16 ipLen = ntohs(iph->tot_len);
20: (69) r4 = *(u16 *)(r1 +16)        ; R1=pkt(off=0,r=54,imm=0) R4_w=scalar(umax=65535,var_off=(0x0; 0xffff))
21: (dc) r4 = be16 r4                 ; R4_w=scalar()
; __u16 off = ipLen - (iph->ihl * 4) - (tcph->doff * 4);
22: (1f) r4 -= r5                     ; R4_w=scalar() R5_w=scalar(umax=120,var_off=(0x0; 0x7c))
23: (57) r4 &= 65535                  ; R4_w=scalar(umax=65535,var_off=(0x0; 0xffff))
; __u8 *last = pl + off;
24: (0f) r3 += r4                     ; R3_w=pkt(id=1,off=54,r=0,umax=65535,var_off=(0x0; 0xffff)) R4_w=scalar(umax=65535,var_off=(0x0; 0xffff))
; if (last + 1 > (__u8 *)data_end)
25: (bf) r4 = r3                      ; R3_w=pkt(id=1,off=54,r=0,umax=65535,var_off=(0x0; 0xffff)) R4_w=pkt(id=1,off=54,r=0,umax=65535,var_off=(0x0; 0xffff))
26: (07) r4 += 1                      ; R4_w=pkt(id=1,off=55,r=0,umax=65535,var_off=(0x0; 0xffff))
27: (b7) r0 = 2                       ; R0_w=2
; if (last + 1 > (__u8 *)data_end)
28: (2d) if r4 > r2 goto pc+8         ; R2=pkt_end(off=0,imm=0) R4_w=pkt(id=1,off=55,r=0,umax=65535,var_off=(0x0; 0xffff))
29: (b7) r0 = 2                       ; R0=2
30: (2d) if r1 > r3 goto pc+6         ; R1=pkt(off=0,r=54,imm=0) R3=pkt(id=1,off=54,r=0,umax=65535,var_off=(0x0; 0xffff))
; bpf_printk("Last byte of packet is %d.\n", *last);
31: (71) r3 = *(u8 *)(r3 +0)
invalid access to packet, off=54 size=1, R3(id=1,off=54,r=0)
R3 offset is outside of the packet
processed 32 insns (limit 1000000) max_states_per_insn 0 total_states 2 peak_states 2 mark_read 1
-- END PROG LOAD LOG --
libbpf: prog 'prog': failed to load: -13
libbpf: failed to load object 'build/last_two.o'
```

## Conclusion
This is unfortunately not yet resolved in my case, but I will update this repository when/if I do find a solution. I really feel our [last_one.c](./src/last_one.c) XDP program is the best option due to its simplicity and not relying on the value of `iph->total_len` (since this can be set incorrectly in malformed packets).