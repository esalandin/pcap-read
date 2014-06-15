#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>

#include "TcpPacket.h"
#include "TcpXdrBuffer.h"
#include "MTcpXdrBuffer.h"

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
 
    MultiBufferStore buffer_store;
    unsigned int xdr_no= 0;
    //----------------- 
    while ( (packet = pcap_next(handle,&header) ) != 0 ) {
      // header contains information about the packet (e.g. timestamp) 
      TcpPacket tcp_p(packet, header.len);
      tcp_p.dump();
      XdrSocketKey socket_key(tcp_p);
      socket_key.dump();
      TcpXdrBuffer &tcp_buf= buffer_store[socket_key];
      tcp_buf.add(tcp_p.tcp_data, tcp_p.tcp_len);

      uint8_t *xdr_ptr= NULL;
      unsigned int xdr_size= 0;
      do
          {
          xdr_ptr= tcp_buf.get_xdr(xdr_size, true);
          if (xdr_ptr)
              ++xdr_no;
          printf("xdr_size= %u; ", xdr_size);
          for (int i=0; i<xdr_size; ++i)
              {
              printf("%02X ", xdr_ptr[i]);
              }
          printf("\n");
          }
      while (xdr_ptr);
    } //end internal loop for reading packets (all in one file) 
    printf("found %u xdrs\n", xdr_no);
    pcap_close(handle);  //close the pcap file 
 
    return 0;
}
