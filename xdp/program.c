#define KBUILD_MODNAME "program"
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/udp.h>

#define N 100

#define HEARTBEAT_PORT 8888

// the last one keeps track of k
BPF_TABLE("percpu_array", uint32_t, u64, recent_arrival, N);
BPF_TABLE("percpu_array", uint32_t, u64, book_keeping, 2);

int myprogram(struct xdp_md *ctx) {
  // bpf_trace_printk("new network packet");
  int ipsize = 0;
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct ethhdr *eth = data;
  struct iphdr *ip;
  struct udphdr *udp;
  void *load;

  uint32_t key = 0;
  u64 * tsp;
  u64 delta = 0;

  uint32_t sequence;

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
    bpf_trace_printk("ipsize: %d", ipsize);
    bpf_trace_printk("size of udp: %d", sizeof(struct udphdr));
    u64 recv_time = bpf_ktime_get_ns();
    tsp = recent_arrival.lookup(&key);
    if (tsp != 0) {
       delta = recv_time - *tsp;
    }
    recent_arrival.update(&key, &recv_time);

    load = data + ipsize + sizeof(struct udphdr);

    sequence =ntohl(*(u64 *)load);
    bpf_trace_printk("the sequence number read: %d", sequence);

    bpf_trace_printk("heartbeat message caught at time: %ld, interval from last arrival: %ld, sequence number: %d", recv_time, delta, sequence);

    
    return XDP_DROP;
  }
  // msg = (struct net_data*)(long)(data + ipsize + sizeof(struct udphdr));
  // if (memcpy(msg, "heartbeat", 9)==0) {
  //   bpf_trace_printk("heartbeat reveived");
  //   return XDP_DROP;
  // }
  return XDP_PASS;
}