#include <stdio.h>

#include "MTcpXdrBuffer.h"

XdrSocketKey::XdrSocketKey()
{
    ip_src.s_addr= 0;
    ip_dst.s_addr= 0;
    port_src= 0;
    port_dst= 0;
}

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

bool XdrSocketKey::isNull() const
{
    bool rv= ip_src.s_addr == 0 &&
             ip_dst.s_addr == 0 &&
             port_src == 0 &&
             port_dst == 0;
    return rv;
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
