#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#ifndef __section
# define __section(NAME) __attribute__((section(NAME), used))
#endif


struct {
  __uint(type, BPF_MAP_TYPE_QUEUE);
  __uint(max_entries, 100);
  __type(value, long);
} recent_arrival SEC(".maps");

__section("prog")
int xdp_drop(struct xdp_md *ctx)
{
    // long recv_time = bpf_ktime_get_ns();
    long recv_time = 1;
    bpf_map_push_elem(&recent_arrival, &recv_time, BPF_EXIST);
    bpf_printk("got a packet from time %ld", recv_time);

    return XDP_PASS;
}

char __license[] __section("license") = "GPL";
