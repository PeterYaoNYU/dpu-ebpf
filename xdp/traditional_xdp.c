#define KBUILD_MODNAME "program"
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
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

__u32 key_to_k = 0;
__u32 key_to_ea = 1;
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
    // uint32_t key_to_timer = 0;

    load = data + ipsize + sizeof(struct udphdr);
    sequence = bpf_ntohl(*(__u64 *)load);
    bpf_printk("heartbeat message caught at time: %ld, sequence number: %d", recv_time, sequence);

    __u64 * k_ptr = bpf_map_lookup_elem(&book_keeping, &key_to_k);
    if (k_ptr && sequence > *k_ptr) {
      if (sequence < N-1) {
        bpf_map_push_elem(&recent_arrival, &recv_time, BPF_EXIST);
        bpf_map_update_elem(&book_keeping, &key_to_k, &sequence, BPF_ANY);
        ea = (__u64*)bpf_map_lookup_elem(&book_keeping, &key_to_ea);
        if (ea) {
          *ea = *ea + recv_time;
          bpf_map_update_elem(&book_keeping, &key_to_ea, ea, BPF_ANY);
        } else {
          bpf_printk("failed to get ea from map");
        }
      } else if (sequence == N-1) {
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
      } else {
        __u64 old_arrival_time;
        bpf_map_pop_elem(&recent_arrival,&old_arrival_time);
  //       recent_arrival.push(&recv_time, BPF_EXIST);
  //       ea = (u64*)book_keeping.lookup(&key_to_ea);
        
  //       if (ea) {
  //         *ea = *ea + (recv_time - (old_arrival_time))/sequence;
  //         bpf_trace_printk("new arrival estimate: %ld", *ea);
  //         book_keeping.update(&key_to_ea, ea);      

  //         timer = (struct bpf_timer*)timers.lookup(&key_to_timer);
  //         if (timer){
  //           // struct timers_table_t * timers_ptr = &timers;
  //           bpf_trace_printk("the pinter to timers: %ld", &timers);
  //           // bpf_timer_init(timer, &timers, CLOCK_REALTIME);
  //         }
  //       }
  //       book_keeping.update(&key_to_k, &sequence);
      }
    }
    return XDP_DROP;
  }
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";