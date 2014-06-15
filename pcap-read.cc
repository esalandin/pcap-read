#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>

#include "TcpPacket.h"

class TcpXdrBuffer
{
public:
    u_char *data;
    uint start;
    uint end;
    TcpXdrBuffer(void);
    ~TcpXdrBuffer(void);
    void add(u_char*, uint);
    void remove(uint);
    uint xdr_size() const;
    u_char* get_xdr(uint&, bool= 0);
};

TcpXdrBuffer::TcpXdrBuffer()
{
    data= NULL;
    start= end= 0;
}

TcpXdrBuffer::~TcpXdrBuffer()
{
    free(data);
}

void TcpXdrBuffer::add(u_char *newdata_ptr, uint newdata_len)
{
    if (start==end && end!=0)
        {
        free(data);
        data= NULL;
        start= end= 0;
        }

    if (newdata_ptr==NULL || newdata_len == 0)
        {
        return;
        }

    data= static_cast<u_char*>(realloc(data, end+newdata_len));
    memcpy(data+end, newdata_ptr, newdata_len);
    end += newdata_len;
}

void TcpXdrBuffer::remove(uint size)
{
    if (end < start + size)
        {
        printf("error remove");
        return;
        }
    start += size;
    return;
}

uint TcpXdrBuffer::xdr_size() const
{
    if (end-start<8)
        {
        return 0;
        }
    uint size= 0;
    u_char *xdr_header= data+start;
    for (int i=0; i<4; ++i)
        {
        size = (size << 8) + xdr_header[4+i];
        }
    return size;
}

u_char* TcpXdrBuffer::get_xdr(uint &xdr_size_out, bool want_remove)
{
    uint xdr_sz= xdr_size();
    if (xdr_sz==0)
        {
        xdr_size_out= 0;
        return NULL;
        }
    if (end-start < xdr_sz+8)
        {
        xdr_size_out= 0;
        return NULL;
        }
    xdr_size_out= 8+xdr_sz;
    u_char *xdr_ptr= data + start;

    if (want_remove)
        {
        remove(8+xdr_sz);
        }

    return xdr_ptr;
}

//-------------------------------------------------------------------
int main(int argc, char **argv) 
{ 
  //temporary packet buffers 
  struct pcap_pkthdr header; // The header that pcap gives us 
  const u_char *packet; // The actual packet 
  
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
 
    TcpXdrBuffer tcp_buffer;

    //----------------- 
    while ( (packet = pcap_next(handle,&header) ) != 0 && TcpPacket::pkt_counter<40) {
      // header contains information about the packet (e.g. timestamp) 
      TcpPacket tcp_p(packet, header.len);
      tcp_p.dump();
      tcp_buffer.add(tcp_p.tcp_data, tcp_p.tcp_len);
      u_char *xdr_ptr= NULL;
      uint xdr_size= 0;
      do
          {
          xdr_ptr= tcp_buffer.get_xdr(xdr_size, true);
          printf("xdr_size= %u; ", xdr_size);
          for (int i=0; i<xdr_size; ++i)
              {
              printf("%02X ", xdr_ptr[i]);
              }
          printf("\n");
          }
      while (xdr_ptr);

    } //end internal loop for reading packets (all in one file) 
 
    pcap_close(handle);  //close the pcap file 
 
    return 0;
}
