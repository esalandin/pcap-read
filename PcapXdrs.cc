#include "PcapXdrs.h"

PcapXdrs::PcapXdrs()
{
    pcap_fname= NULL;
    pcap_handle= NULL;
    errbuf[0]= '\0';
    pkt_no= 0;
    xdr_no= 0;
    xdr_size_max= 0;
}

PcapXdrs::~PcapXdrs()
{
    if (pcap_handle)
        {
        pcap_close(pcap_handle);
        }
}

bool PcapXdrs::open_file(const char * fname)
{
    pcap_fname= fname;
    pcap_handle = pcap_open_offline(pcap_fname, errbuf);   //call pcap library function
    if (pcap_handle == NULL)
        {
            fprintf (stderr, "Couldn't open pcap file %s: %s\n", fname, errbuf);
            return false;
        }
    return true;
}

uint8_t* PcapXdrs::get_xdr(unsigned int & xdr_size_out)
{
    const uint8_t *pcap_pkt= NULL;
    uint8_t *xdr_ptr= NULL;
    unsigned int xdr_size= 0;

    do
    {
    if (!last_key.isNull())
        {
        TcpXdrBuffer &tcp_buf= buffer_store[last_key];
        xdr_ptr= tcp_buf.get_xdr(xdr_size, true);
        if (!xdr_ptr)
            {
            last_key= XdrSocketKey(); // set to null
            }
        else
            {
            // found !
            ++ xdr_no;
            if (xdr_size_max < xdr_size)
                xdr_size_max= xdr_size;
            break;
            }
        }
    // we never reach here if there is data left to process in existing buffers
    struct pcap_pkthdr pcap_header;
    pcap_pkt= pcap_next(pcap_handle, &pcap_header);
    if (pcap_pkt)
        {
        ++pkt_no;
        TcpPacket tcp_p(pcap_pkt, pcap_header.len);
        // tcp_p.dump();
        last_key= XdrSocketKey(tcp_p);
        TcpXdrBuffer &tcp_buf= buffer_store[last_key];
        tcp_buf.add(tcp_p.tcp_data, tcp_p.tcp_len, tcp_p.pkt_counter);
        }
    }
    while (pcap_pkt);

    xdr_size_out= xdr_size;
    return xdr_ptr;
}
