#ifndef PCAP_XDRS_H
#define PCAP_XDRS_H

#include "MTcpXdrBuffer.h"
#include <pcap.h>

class PcapXdrs
{
public:
    const char* pcap_fname;
    pcap_t *pcap_handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    XdrSocketKey last_key;
    MultiBufferStore buffer_store;
    unsigned int pkt_no, xdr_no;
    unsigned int xdr_size_max;
    PcapXdrs();
    ~PcapXdrs();
    bool open_file(const char*);
    uint8_t* get_xdr(unsigned int &);
};

#endif //PCAP_XDRS_H
