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

int myprogram(struct xdp_md *ctx) {
  // bpf_trace_printk("new network packet");
  int ipsize = 0;
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct ethhdr *eth = data;
  struct iphdr *ip;

  uint32_t key = 0;
  u64 * tsp;
  u64 delta = 0;


  if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr)> data_end) {
    return XDP_PASS;
  }

  ipsize = sizeof(*eth);
  ip = data + ipsize;
  ipsize += sizeof(struct iphdr);

  struct udphdr *udp = data + ipsize;

  if (eth->h_proto != htons(ETH_P_IP)) {
    return XDP_PASS;
  }

  if (ip->protocol != IPPROTO_UDP) {
    return XDP_PASS;
  }
  // how about using a port number to identify if it is reallty a heartbeat msg?
  if (udp->dest == htons(HEARTBEAT_PORT)){
    u64 recv_time = bpf_ktime_get_ns();
    tsp = recent_arrival.lookup(&key);
    if (tsp != 0) {
       delta = recv_time - *tsp;
    }
    recent_arrival.update(&key, &recv_time);

    bpf_trace_printk("heartbeat message caught at time: %ld, interval from last arrival: %ld", recv_time, delta);



    
    return XDP_DROP;
  }
  // msg = (struct net_data*)(long)(data + ipsize + sizeof(struct udphdr));
  // if (memcpy(msg, "heartbeat", 9)==0) {
  //   bpf_trace_printk("heartbeat reveived");
  //   return XDP_DROP;
  // }
  return XDP_PASS;
}
