all : tcp_block

tcp_block:
	gcc -o tcp_block main.cpp -lpcap
clean:
	rm -f tcp_block

