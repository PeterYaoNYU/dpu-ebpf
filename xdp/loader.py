#!/usr/bin/python3

from bcc import BPF
import time
import sys

device = "eth0"
b = BPF(src_file="program.c")
fn = b.load_func("myprogram", BPF.XDP)
b.attach_xdp(device, fn, 0)

b.trace_print();

while 1:
    try:
        time.sleep(1)
        print("second passed")
    except KeyboardInterrupt:
        print("Removing filter from device")
        break

b.remove_xdp(device, 0)
