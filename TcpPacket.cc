#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "TcpPacket.h"

uint TcpPacket::pkt_counter = 0;

TcpPacket::TcpPacket(void)
{
  error= e_init;
  data= NULL;
  ip_data= NULL;
  ip_len= 0;
  inet_aton("0.0.0.0", &ip_src);
  inet_aton("0.0.0.0", &ip_dst);
  port_src= 0;
  port_dst= 0;
  tcp_data= NULL;
  tcp_len= 0;
}

TcpPacket::TcpPacket(const u_char *pcap_pkt, int pcap_len)
{
    pkt_counter++;
    data= NULL;
    ip_data= NULL;
    ip_len= 0;
    inet_aton("0.0.0.0", &ip_src);
    inet_aton("0.0.0.0", &ip_dst);
    port_src= 0;
    port_dst= 0;
    tcp_data= NULL;
    tcp_len= 0;

    if (pcap_pkt==0 || pcap_len==0)
        {
        error= e_pcap_len;
        return;
        }
    data= static_cast<u_char *> (malloc(pcap_len));
    memcpy(data, pcap_pkt, pcap_len);

    int ether_type = ((int)(data[12]) << 8) | (int)data[13];
    int ether_offset = 0;
    if (ether_type == ether_type_ip) //most common
      ether_offset = 14;
    else
       {
       error= e_ether_type;
       return;
       }
    if (ether_offset+20>=pcap_len)
        {
            error= e_len_ether_offset;
            return;
        }
    u_char *ip_header= data + ether_offset;
    // http://en.wikipedia.org/wiki/IPv4_header#Header
    int ip_hl= ip_header[0] & 0x0F; // normally 20
    int ip_total_length= (ip_header[2]<<8) + ip_header[3];
    int ip_protocol= ip_header[9];
    memcpy(&ip_src, ip_header+12, 4);
    memcpy(&ip_dst, ip_header+16, 4);

    if (ip_hl<5 || ip_hl>15 || ip_hl*4>ip_total_length)
        {
        error= e_ip_header_length;
        return;
        }

    if (ether_offset + ip_total_length > pcap_len)
        {
        error= e_ip_len;
        return;
        }

    if (ip_protocol != 6)
        {
        error= e_ip_protocol;
        return;
        }

    ip_data= ip_header + ip_hl *4;
    ip_len= ip_total_length - ip_hl*4;

    // http://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure
    u_char *tcp_hdr= ip_data;
    port_src= (tcp_hdr[0]<<8) + tcp_hdr[1];
    port_dst= (tcp_hdr[2]<<8) + tcp_hdr[3];
    uint8_t tcp_data_offset= tcp_hdr[12]>>4;

    if (tcp_data_offset < 5 || tcp_data_offset > 15 || tcp_data_offset*4 > ip_len)
        {
        error= e_tcp_header_len;
        return;
        }

    uint tcp_header_len= tcp_data_offset*4;

    tcp_data= tcp_hdr + tcp_header_len;
    tcp_len= ip_len - tcp_header_len;

    error= e_no_error;
}

TcpPacket::~TcpPacket(void)
{
    free(data);
}

void TcpPacket::dump()
{
    printf("cnt= %u; ", pkt_counter);
    printf("error= %u; ", error);
    printf("ip_src %s; ", inet_ntoa(ip_src));
    printf("ip_dst %s; ", inet_ntoa(ip_dst));
    printf("port_src= %u; ", port_src);
    printf("port_dst= %u; ", port_dst);
    printf("tcp_len= %u; ", tcp_len);
    if (tcp_len>0)
        {
        printf("tcp_data[]= ");
        for (uint i=0; i<tcp_len && i<32; ++i)
            {
            printf("%02X ", tcp_data[i]);
            }
        }
    printf("\n");
}
