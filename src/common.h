/* Only add BPF helpers we need for testing */

static long (*bpf_trace_printk)(const char *fmt, __u32 fmt_size, ...) = (void *) 6;

#ifndef ___bpf_nth
    #define ___bpf_nth(_, _1, _2, _3, _4, _5, _6, _7, _8, _9, _a, _b, _c, N, ...) N
#endif

#ifdef BPF_NO_GLOBAL_DATA
    #define BPF_PRINTK_FMT_MOD
#else
    #define BPF_PRINTK_FMT_MOD static const
#endif

#define __bpf_printk(fmt, ...)				\
({							\
	BPF_PRINTK_FMT_MOD char ____fmt[] = fmt;	\
	bpf_trace_printk(____fmt, sizeof(____fmt),	\
			 ##__VA_ARGS__);		\
})

#define ___bpf_pick_printk(...) \
	___bpf_nth(_, ##__VA_ARGS__, __bpf_vprintk, __bpf_vprintk, __bpf_vprintk,	\
		   __bpf_vprintk, __bpf_vprintk, __bpf_vprintk, __bpf_vprintk,		\
		   __bpf_vprintk, __bpf_vprintk, __bpf_printk /*3*/, __bpf_printk /*2*/,\
		   __bpf_printk /*1*/, __bpf_printk /*0*/)

#define bpf_printk(fmt, args...) ___bpf_pick_printk(args)(fmt, ##args)

#if __GNUC__ && !__clang__
    #define SEC(name) __attribute__((section(name), used))
#else
    #define SEC(name) \
        _Pragma("GCC diagnostic push")					    \
        _Pragma("GCC diagnostic ignored \"-Wignored-attributes\"")	    \
        __attribute__((section(name), used))				    \
        _Pragma("GCC diagnostic pop")					    \

#endif

#ifndef htons
    #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        #define htons(x) ((__be16)___constant_swab16((x)))
    #elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        #define htons(x) (x)
    #endif
#endif