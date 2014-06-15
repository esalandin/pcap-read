LDFLAGS = -L ../libpcap-1.5.3
LDLIBS = -lpcap.1.5.3
CXXFLAGS = -g
CC=c++

OBJS= pcap-read.o TcpPacket.o TcpXdrBuffer.o

.PHONY: all test

all: pcap-read

test: pcap-read
	./pcap-read captures/verizon-11062014.pcap

pcap-read: $(OBJS)

clean:
	rm -f pcap-read $(OBJS)