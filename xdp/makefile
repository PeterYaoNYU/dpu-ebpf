all: traditional_xdp.c
	clang -target bpf -c traditional_xdp.c -o traditional_xdp.o -g -O2

test: timer_test.c 
	clang -target bpf -c timer_test.c -o timer_test.o -g -O2

clean:
	rm -f traditional_xdp.o 
