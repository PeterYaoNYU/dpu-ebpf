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

struct {
  __uint(type, BPF_MAP_TYPE_QUEUE);
  __uint(max_entries, N);
  __type(value, __u64);
} recent_arrival SEC(".maps");

// idx 0 is for K (the max number rceived)
// idx 1 is for EA (estimated arrival time)
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
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


__u32 key_to_k = 0;
__u32 key_to_ea = 1;
// this needs to be changed in a multicast setting 
__u32 key_to_timer = 0;
__u64 zero = 0;
SEC("xdp")
int myprogram(struct xdp_md *ctx) {
  int ipsize = 0;
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct ethhdr *eth = data;
  struct iphdr *ip;
  struct udphdr *udp;
  void *load;

  __u64 sequence;

  // must include this line, otherwise the kernel will not allow to load this program  
  if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(__u64)> data_end) {
    return XDP_PASS;
  }

  ipsize = sizeof(*eth);
  ip = data + ipsize;
  ipsize += sizeof(struct iphdr);

  if (eth->h_proto != bpf_htons(ETH_P_IP)) {
    return XDP_PASS;
  }

  if (ip->protocol != IPPROTO_UDP) {
    return XDP_PASS;
  }

  udp = data + ipsize;

// improvement: use a range of port numbers to provide scability  
  if (udp->dest == bpf_htons(HEARTBEAT_PORT)){
    __u64 recv_time = bpf_ktime_get_ns();
    // estimated arrival time  
    __u64 * ea;

    load = data + ipsize + sizeof(struct udphdr);
    sequence = bpf_ntohl(*(__u64 *)load);
    // bpf_printk("heartbeat message caught at time: %ld, sequence number: %d, debug:%d", recv_time, sequence, debug);

    __u64 * k_ptr = bpf_map_lookup_elem(&book_keeping, &key_to_k);
    if (k_ptr && sequence > *k_ptr) {
      bpf_printk("heartbeat message caught at time: %ld, sequence number: %d, debug:%d", recv_time, sequence, debug);
      if (sequence < N) {
        bpf_map_push_elem(&recent_arrival, &recv_time, BPF_EXIST);
        bpf_map_update_elem(&book_keeping, &key_to_k, &sequence, BPF_ANY);
        ea = (__u64*)bpf_map_lookup_elem(&book_keeping, &key_to_ea);
        if (ea) {
          *ea = *ea + recv_time;
          bpf_map_update_elem(&book_keeping, &key_to_ea, ea, BPF_ANY);
        } else {
          bpf_printk("failed to get ea from map");
        }
      } else if (sequence == N) {
        struct elem * heartbeat_timer;
        ea = 0;
        ea = (__u64*)bpf_map_lookup_elem(&book_keeping, &key_to_ea);
        if (ea) {
          *ea = *ea + recv_time;
          *ea = *ea / N;
          bpf_map_update_elem(&book_keeping, &key_to_ea, ea, BPF_ANY);
        } else {
          bpf_printk("failed to get ea from map");
        }
        bpf_map_push_elem(&recent_arrival, &recv_time, BPF_EXIST);
        bpf_map_update_elem(&book_keeping, &key_to_k, &sequence, BPF_ANY);

        heartbeat_timer = (struct elem*)bpf_map_lookup_elem(&timers, &key_to_timer);
        if (heartbeat_timer && ea){
          bpf_printk("timer ready");
          bpf_timer_init(&(heartbeat_timer->timer), &timers, CLOCK_MONOTONIC);
          bpf_timer_set_callback(&(heartbeat_timer->timer), timer_cb1);
          bpf_timer_start(&heartbeat_timer->timer, 1, 0);
        } else {
          bpf_printk("cannot locate the timer from the array");
        }
      } else {
        __u64 old_arrival_time;
        struct elem * heartbeat_timer;
        bpf_map_pop_elem(&recent_arrival,&old_arrival_time);
        bpf_map_push_elem(&recent_arrival, &recv_time, BPF_ANY);
        ea = (__u64*)bpf_map_lookup_elem(&book_keeping, &key_to_ea);
        
        if (ea) {
          *ea = *ea + (recv_time - (old_arrival_time))/N;
          bpf_printk("new arrival estimate: %ld", *ea);
          bpf_map_update_elem(&book_keeping,&key_to_ea, ea, BPF_ANY);

          struct elem * heartbeat_timer = (struct elem*)bpf_map_lookup_elem(&timers, &key_to_timer);
          if (heartbeat_timer && ea){
            bpf_printk("timer ready");
            bpf_timer_cancel(&(heartbeat_timer->timer));
            // bpf_timer_init(&(heartbeat_timer->timer), &timers, CLOCK_MONOTONIC);
            // bpf_timer_set_callback(&(heartbeat_timer->timer), timer_cb1);
            bpf_timer_start(&(heartbeat_timer->timer), 1, 0);
          } else {
            bpf_printk("fail to find the timer from the map");
          }
        }
        bpf_map_update_elem(&book_keeping, &key_to_k, &sequence, BPF_ANY);
      }
    }
    return XDP_DROP;
  }
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";