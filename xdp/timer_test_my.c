#define KBUILD_MODNAME "program"
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <time.h>
#define N 5
#define HEARTBEAT_PORT 8888
#define DELTA 1000000000

struct {
  __uint(type, BPF_MAP_TYPE_QUEUE);
  __uint(max_entries, N);
  __type(value, __u64);
} recent_arrival SEC(".maps");

// idx 0 is for K (the max number rceived)
// idx 1 is for EA (estimated arrival time)
// idx 2 is for U (the intermediate value)
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 3);
	__type(key, __u32);
	__type(value, __u64);
} book_keeping SEC(".maps");

// for unicast case, set size to 1
// BPF_ARRAY(timer  s, struct elem, 1);
struct elem {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, int);
	__type(value, struct elem);
} timers SEC(".maps");

__u32 debug = 0;


static int timer_cb1(void *map, int *key, struct elem * arrElem) {
  bpf_printk("suspect that node %d is down", *key);
  debug++;
  return 0;
}

SEC("XDP")
int myprogram(struct xdp_md *ctx) {
    struct elem * my_timer;
    bpf_printk("new arrival");
    bpf_timer_init(&(heartbeat_timer->timer), &timers, CLOCK_MONOTONIC);
    bpf_timer_set_callback(&(heartbeat_timer->timer), timer_cb1);
    bpf_timer_start(&(heartbeat_timer->timer), *ea - recv_time, 0);
}