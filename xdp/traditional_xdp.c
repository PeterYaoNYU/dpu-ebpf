#define KBUILD_MODNAME "program"
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <time.h>
#include <errno.h>
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
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} timers SEC(".maps");

// __u32 * debug;
// __u32 key_to_debug = 0;

static int timer_cb1(void *map, int *key, struct elem * arrElem) {
  bpf_printk("suspect that node %d is down", *key);
  return 0;
}


__u32 key_to_k = 0;
__u32 key_to_ea = 1;
// this needs to be changed in a multicast setting 
__u32 key_to_timer = 0;
__u64 zero = 0;
__u32 key_to_u = 2;
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
    __u64 ea_val = 0;
    __u64 * ea = &ea_val;
    struct elem * heartbeat_timer;

    load = data + ipsize + sizeof(struct udphdr);
    sequence = bpf_ntohl(*(__u64 *)load);
    // bpf_printk("heartbeat message caught at time: %ld, sequence number: %d, debug:%d", recv_time, sequence, debug);

    __u64 * k_ptr = (__u64 * )bpf_map_lookup_elem(&book_keeping, &key_to_k);
    if (k_ptr && sequence >= *k_ptr) {
      __u64* u;

      bpf_printk("heartbeat message caught at time: %ld, sequence number: %d", recv_time, sequence);
      if (sequence == 0) {
        bpf_map_push_elem(&recent_arrival, &recv_time, BPF_EXIST);
        bpf_map_update_elem(&book_keeping, &key_to_u, &recv_time, BPF_ANY);
        u = (__u64*)bpf_map_lookup_elem(&book_keeping, &key_to_u);
        if (u){
          bpf_printk("first u is : %ld", *u);
        }
        heartbeat_timer = (struct elem*)bpf_map_lookup_elem(&timers, &key_to_timer);
        if (heartbeat_timer){
          // this line of code is questionable, given that sequence is an unsigned long
          bpf_printk("recv_time for sequence 0: %ld", recv_time);
          *ea = recv_time + ((sequence+1)* DELTA)/2;
          bpf_printk("new arrival estimate: %ld, recv_time: %ld", *ea, recv_time);
          if (bpf_timer_init(&(heartbeat_timer->timer), &timers, CLOCK_MONOTONIC) == -EPERM){
            bpf_printk("timer init error");
          }
          if (bpf_timer_set_callback(&(heartbeat_timer->timer), timer_cb1) != 0){
            bpf_printk("set callback erro");
          }
          if (bpf_timer_start(&(heartbeat_timer->timer), *ea - recv_time, 0) != 0){
            bpf_printk("timer start error");
          }
          bpf_printk("timer set for seq = 0");
        }
      }else if (sequence < N) {
        __u64 * u;
        bpf_map_push_elem(&recent_arrival, &recv_time, BPF_EXIST);
        bpf_map_update_elem(&book_keeping, &key_to_k, &sequence, BPF_ANY);
        u = (__u64*)bpf_map_lookup_elem(&book_keeping, &key_to_u);
        ea = (__u64*)bpf_map_lookup_elem(&book_keeping, &key_to_ea);
        heartbeat_timer = (struct elem*)bpf_map_lookup_elem(&timers, &key_to_timer);
        if (u && ea && heartbeat_timer){
          bpf_printk("old u is: %ld", *u);
          *u = recv_time/(sequence+1) +  (*u) * sequence / (sequence+1);
          // *ea = (__u64) (*u + (float)((sequence+1)* DELTA)/2);
          *ea = *u + ((sequence+1)* DELTA)/2;
          bpf_printk("u is: %ld", *u);
          bpf_printk("new arrival estimate: %ld", *ea);
          bpf_map_update_elem(&book_keeping, &key_to_u, u, BPF_ANY);
          bpf_map_update_elem(&book_keeping, &key_to_ea, ea, BPF_ANY);
          int ret;
          ret = bpf_timer_cancel(&(heartbeat_timer->timer));
          if (ret==0){
            bpf_printk("cancelling a timer that is not active");
          } else if (ret ==1 ){
            bpf_printk("cancelling an active timer");
          } else {
            bpf_printk("error occurred while cancelling a timer");
          }
          if (bpf_timer_init(&(heartbeat_timer->timer), &timers, CLOCK_MONOTONIC) == -EPERM){
            bpf_printk("timer init error");
          }
          if (bpf_timer_set_callback(&(heartbeat_timer->timer), timer_cb1) != 0){
            bpf_printk("set callback erro");
          }
          if (bpf_timer_start(&(heartbeat_timer->timer), *ea - recv_time, 0) != 0){
            bpf_printk("error occurred while starting the timer");
          } else {
            bpf_printk("timer started success for seq = %d", sequence);
          }
        } else {
          bpf_printk("failed to get needed resources from map");
        }
      } else {
        __u64 old_arrival_time;
        bpf_map_pop_elem(&recent_arrival, &old_arrival_time);
        bpf_map_push_elem(&recent_arrival, &recv_time, BPF_ANY);
        ea = (__u64*)bpf_map_lookup_elem(&book_keeping, &key_to_ea);
        
        if (ea) {
          *ea = *ea + (recv_time - (old_arrival_time))/N;
          bpf_printk("new arrival estimate: %ld", *ea);
          bpf_map_update_elem(&book_keeping,&key_to_ea, ea, BPF_ANY);
          struct elem * heartbeat_timer = (struct elem*)bpf_map_lookup_elem(&timers, &key_to_timer);
          if (heartbeat_timer && ea){
            int ret;
            ret = bpf_timer_cancel(&(heartbeat_timer->timer));
            if (ret==0){
              bpf_printk("cancelling a timer that is not active");
            } else if (ret ==1 ){
              bpf_printk("cancelling an active timer");
            } else {
              bpf_printk("error occurred while cancelling a timer");
            }
            if (bpf_timer_init(&(heartbeat_timer->timer), &timers, CLOCK_MONOTONIC) == -EPERM){
              bpf_printk("timer init error");
            }
            if (bpf_timer_set_callback(&(heartbeat_timer->timer), timer_cb1) != 0){
              bpf_printk("set callback erro");
            }
            if (bpf_timer_start(&(heartbeat_timer->timer), *ea - recv_time, 0) != 0){
              bpf_printk("error occurred while starting the timer");
            } else {
              bpf_printk("timer started success for seq = %d", sequence);
            }
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