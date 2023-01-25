#define KBUILD_MODNAME "program"
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/udp.h>

#define N 5

#define HEARTBEAT_PORT 8888

struct elem {
	struct bpf_timer t;
};

BPF_QUEUE(recent_arrival, u64, N);

// idx 0 is for K (the max number re)
// idx 1 is for EA (estimated arrival time)
BPF_TABLE("percpu_array", uint32_t, u64, book_keeping, 2);

// for unicast case, set size to 1
BPF_ARRAY(timers, struct elem, 1);

int myprogram(struct xdp_md *ctx) {
  int ipsize = 0;
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct ethhdr *eth = data;
  struct iphdr *ip;
  struct udphdr *udp;
  void *load;

  uint32_t key = 0;
  u64 * tsp;

  u64 sequence;

  // must include this line, otherwise the kernel will not allow to load this program  
  if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(u64)> data_end) {
    return XDP_PASS;
  }

  ipsize = sizeof(*eth);
  ip = data + ipsize;
  ipsize += sizeof(struct iphdr);

  if (eth->h_proto != htons(ETH_P_IP)) {
    return XDP_PASS;
  }

  if (ip->protocol != IPPROTO_UDP) {
    return XDP_PASS;
  }

  udp = data + ipsize;

  // how about using a port number to identify if it is reallty a heartbeat msg?
  if (udp->dest == htons(HEARTBEAT_PORT)){
    u64 recv_time = bpf_ktime_get_ns();
    // estimated arrival time  
    u64 * ea;
    uint32_t key_to_k = 0;
    uint32_t key_to_ea = 1;

    load = data + ipsize + sizeof(struct udphdr);

    sequence =ntohl(*(u64 *)load);

    bpf_trace_printk("heartbeat message caught at time: %ld, sequence number: %d", recv_time, sequence);

    u64 zero = 0;
    u64 * k_ptr = (u64 *) book_keeping.lookup_or_try_init(&key_to_k, &zero);
    
    if (k_ptr && sequence > *k_ptr) {
      if (sequence < N-1) {
        recent_arrival.push(&recv_time, BPF_EXIST);
        book_keeping.update(&key_to_k, &sequence);
        ea = (u64*)book_keeping.lookup(&key_to_ea);
        if (ea) {
          *ea = *ea + recv_time;
          book_keeping.update(&key_to_ea, ea);      
        } else {
          bpf_trace_printk("failed to get ea from map");
        }
      } else if (sequence == N-1) {
        uint32_t i;
        ea = 0;
        u64 * arrival_time;

        ea = (u64*)book_keeping.lookup(&key_to_ea);
        if (ea) {
          *ea = *ea + recv_time;
          *ea = *ea / N;
          book_keeping.update(&key_to_ea, ea);      
        } else {
          bpf_trace_printk("failed to get ea from map");
        }
        recent_arrival.push(&recv_time, BPF_EXIST);
        book_keeping.update(&key_to_k, &sequence);
      } else {
        u64 old_arrival_time;
        recent_arrival.pop(&old_arrival_time);
        recent_arrival.push(&recv_time, BPF_EXIST);
        ea = (u64*)book_keeping.lookup(&key_to_ea);
        
        if (ea) {
          *ea = *ea + (recv_time - (old_arrival_time))/sequence;
          bpf_trace_printk("new arrival estimate: %ld", *ea);
          book_keeping.update(&key_to_ea, ea);      
        }
        book_keeping.update(&key_to_k, &sequence);
      }
    }
    return XDP_DROP;
  }
  return XDP_PASS;
}