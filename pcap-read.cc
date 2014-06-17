#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "PcapXdrs.h"

//-------------------------------------------------------------------
int main(int argc, char **argv) 
{ 
  //check command line arguments 
  if (argc < 2) { 
    fprintf(stderr, "Usage: %s [input pcap]\n", argv[0]);
    exit(1); 
  } 

  PcapXdrs pcapXdrSource;
  pcapXdrSource.open_file(argv[1]);
  
  uint8_t *xdr_ptr= NULL;
  unsigned int  xdr_size= 0;
  while ((xdr_ptr= pcapXdrSource.get_xdr(xdr_size)) != NULL )
      {
      printf("xdr size= %u; ", xdr_size);
      for (unsigned int i= 0; i<xdr_size && i< 80; ++i)
          {
          printf("%02X ", xdr_ptr[i]);
          }
      printf("\n");
      fflush(stdout);
      }
    printf("%u packets; %u xdrs; xdr_max_size= %u;\n", pcapXdrSource.pkt_no, pcapXdrSource.xdr_no, pcapXdrSource.xdr_size_max);
    return 0;
}
