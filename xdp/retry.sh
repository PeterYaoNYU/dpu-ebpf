ip link set dev eth0 xdp off
make clean
make
rm -f /sys/fs/bpf/tc/globals/timers
ip link set dev eth0 xdp obj traditional_xdp.o sec xdp
cat /sys/kernel/debug/tracing/trace_pipe