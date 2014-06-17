#ifndef M_TCP_XDR_BUFFER_H
#define M_TCP_XDR_BUFFER_H

#include "TcpPacket.h"
#include "TcpXdrBuffer.h"

#include <unordered_map>

class XdrSocketKey
{
public:
    struct in_addr ip_src, ip_dst;
    uint16_t port_src, port_dst;
    XdrSocketKey();
    XdrSocketKey(struct in_addr, uint16_t, struct in_addr, uint16_t);
    XdrSocketKey(const TcpPacket &);
    void dump() const;
    bool isNull() const;
};

//hash function needed by stl::map
class XdrSocketHash
{
public:
    size_t operator() (const XdrSocketKey & k) const
    {
    size_t h=0;
    h= k.ip_src.s_addr+3*k.ip_dst.s_addr+5*k.port_src+7*k.port_dst;
    return h;
    }
};

//compare function needed by stl::map
class XdrSocketHashCmp
{
public:
    bool operator() (const XdrSocketKey & lhs, const XdrSocketKey & rhs) const
    {
    bool rv= lhs.ip_src.s_addr==rhs.ip_src.s_addr &&
             lhs.ip_dst.s_addr==rhs.ip_dst.s_addr &&
             lhs.port_src==rhs.port_src &&
             lhs.port_dst==rhs.port_dst;
    return rv;
    }
};

typedef std::unordered_map<XdrSocketKey, TcpXdrBuffer, XdrSocketHash, XdrSocketHashCmp> MultiBufferStore;

#endif //M_TCP_XDR_BUFFER_H
