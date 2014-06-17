#ifndef TCP_PACKET_H
#define TCP_PACKET_H

#include <arpa/inet.h>

enum pkt_error {
    e_no_error = 0,
    e_init,
    e_pcap_len,
    e_len_ether_offset,
    e_ether_type,
    e_ip_header_length,
    e_ip_len,
    e_ip_protocol,
    e_tcp_header_len,
    e_max
};

class TcpPacket {

public:
    pkt_error error;
    static unsigned int pkt_counter;
    uint8_t *data;
    uint8_t *ip_data;
    unsigned int ip_len;
    struct in_addr ip_src, ip_dst;
    uint16_t port_src, port_dst;
    uint8_t *tcp_data;
    unsigned int tcp_len;

    TcpPacket(void);
    TcpPacket(const uint8_t *, int);
    ~TcpPacket(void);
    void dump();

private:
    TcpPacket(const TcpPacket&); // avoid copy constructor
    TcpPacket& operator=(const TcpPacket&); //avoid assignment

public:
    static const int ether_type_ip= 0x0800;

};
#endif //TCP_PACKET_H
