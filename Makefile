LDFLAGS = -L ../libpcap-1.5.3
LDLIBS = -lpcap.1.5.3
CXXFLAGS = -g

.PHONY: all test

all: pcap-read

test: pcap-read
	./pcap-read captures/verizon-11062014.pcap

clean:
	rm -f pcap-read