#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>

#include "TcpPacket.h"
#include "TcpXdrBuffer.h"


#include <unordered_map>
class XdrSocketKey
{
public:
    struct in_addr ip_src, ip_dst;
    uint16_t port_src, port_dst;
    XdrSocketKey(struct in_addr, uint16_t, struct in_addr, uint16_t);
    XdrSocketKey(const TcpPacket &);
    void dump() const;
};

//hash function needed by stl::map
class XdrSocketHash
{
public:
    std::size_t
    operator() (const XdrSocketKey & k) const
    {
    size_t h=0;
    h= k.ip_src.s_addr+3*k.ip_dst.s_addr+5*k.port_src+7*k.port_dst;
    return h;
    }
};

//compare function needed by tl::map
class XdrSocketHashCmp
{
public:
    bool operator() (const XdrSocketKey & lhs, const XdrSocketKey & rhs) const
    {
        return lhs.ip_src.s_addr==rhs.ip_dst.s_addr &&
               lhs.ip_dst.s_addr==rhs.ip_dst.s_addr &&
               lhs.port_src==rhs.port_src &&
               lhs.port_dst==rhs.port_dst;
    }
};

typedef std::unordered_map<XdrSocketKey, TcpXdrBuffer, XdrSocketHash, XdrSocketHashCmp> MMPortBufferStore;

class MultiPortTcpXdrBuffer
{
public:
    void add_pkt(const TcpPacket & tcp_pkt);
private:
    MMPortBufferStore bs_map;
    bool clean;
};

XdrSocketKey::XdrSocketKey(struct in_addr ip1, uint16_t p1, struct in_addr ip2, uint16_t p2) :
                ip_src(ip1), ip_dst(ip2), port_src(p1), port_dst(p2)
{
}

XdrSocketKey::XdrSocketKey(const TcpPacket & tcp_pkt) :
                ip_src(tcp_pkt.ip_src),
                ip_dst(tcp_pkt.ip_dst),
                port_src(tcp_pkt.port_src),
                port_dst(tcp_pkt.port_dst)
{
}

void XdrSocketKey::dump() const
{
    printf("%s, ", inet_ntoa(ip_src));
    printf("%u ", port_src);
    printf("->");
    printf("%s, ", inet_ntoa(ip_dst));
    printf("%u", port_dst);
    printf("\n");
}

void MultiPortTcpXdrBuffer::add_pkt(const TcpPacket & tcp_pkt)
{
    XdrSocketKey key(tcp_pkt);
    key.dump();
    TcpXdrBuffer &tcp_buf= bs_map[key];
    tcp_buf.add(tcp_pkt.tcp_data, tcp_pkt.tcp_len);
    clean= 0;
}

//-------------------------------------------------------------------
int main(int argc, char **argv) 
{ 
  //temporary packet buffers 
  struct pcap_pkthdr header; // The header that pcap gives us 
  const uint8_t *packet; // The actual packet
  
  //check command line arguments 
  if (argc < 2) { 
    fprintf(stderr, "Usage: %s [input pcap]\n", argv[0]);
    exit(1); 
  } 
  
  const char *fname= argv[1];

    //----------------- 
    //open the pcap file 
    pcap_t *handle; 
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_offline(fname, errbuf);   //call pcap library function
 
    if (handle == NULL) { 
      fprintf(stderr,"Couldn't open pcap file %s: %s\n", fname, errbuf);
      return(2); 
    } 
 
    MultiPortTcpXdrBuffer multi_buffer;

    //----------------- 
    while ( (packet = pcap_next(handle,&header) ) != 0 /* && TcpPacket::pkt_counter<40 */) {
      // header contains information about the packet (e.g. timestamp) 
      TcpPacket tcp_p(packet, header.len);
      tcp_p.dump();
      multi_buffer.add_pkt(tcp_p);

    } //end internal loop for reading packets (all in one file) 
 
    pcap_close(handle);  //close the pcap file 
 
    return 0;
}
