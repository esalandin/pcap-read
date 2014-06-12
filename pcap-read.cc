#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

//defines for the packet type code in an ETHERNET header
#define ETHER_TYPE_IP (0x0800)
#define ETHER_TYPE_8021Q (0x8100)
//------------------------------------------------------------------- 

void dump_iphdr(const struct ip *ip) {
	fprintf(stderr, "ip_len %u; ", ntohs(ip->ip_len));
	fprintf(stderr, "ip_src %s; ", inet_ntoa(ip->ip_src));
	fprintf(stderr, "ip_dst %s; ", inet_ntoa(ip->ip_dst));
	if (ip->ip_p == 6) {
		fprintf(stderr, "ip_p TCP;");
	}
	else {
		fprintf(stderr, "ip_p %u; ", ip->ip_p);
	}
	fprintf(stderr, "\n");
}

//-------------------------------------------------------------------
int main(int argc, char **argv) 
{ 
  unsigned int pkt_counter=0;   // packet counter 
 
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
    char errbuf[PCAP_ERRBUF_SIZE]; //not sure what to do with this, oh well 
    handle = pcap_open_offline(fname, errbuf);   //call pcap library function
 
    if (handle == NULL) { 
      fprintf(stderr,"Couldn't open pcap file %s: %s\n", fname, errbuf);
      return(2); 
    } 
 
    //----------------- 
    //begin processing the packets in this particular file, one at a time 
 
    while ((packet = pcap_next(handle,&header))!=0) {
      // header contains information about the packet (e.g. timestamp) 
      u_char *pkt_ptr = (u_char *)packet; //cast a pointer to the packet data 
      
      //parse the first (ethernet) header, grabbing the type field 
      int ether_type = ((int)(pkt_ptr[12]) << 8) | (int)pkt_ptr[13]; 
      int ether_offset = 0; 
 
      if (ether_type == ETHER_TYPE_IP) //most common 
        ether_offset = 14; 
      else {
         fprintf(stderr, "Unknown ethernet type, %04X, skipping...\n", ether_type); 
         continue;
      }

      //parse the IP header 
      pkt_ptr += ether_offset;  //skip past the Ethernet II header 
      struct ip *ip_hdr = (struct ip *)pkt_ptr; //point to an IP header structure 
      // dump_iphdr(ip_hdr);
      int packet_length = ntohs(ip_hdr->ip_len); 
 
      uint ip_header_len= ip_hdr->ip_hl*4;
      pkt_ptr += ip_header_len;

      if (ip_hdr->ip_p != 6) {
    	  fprintf(stderr, "Unknown ip protocol %u\n", ip_hdr->ip_p);
    	  continue;
      }

      u_char *tcp_hdr= pkt_ptr;

      uint16_t src_port= (tcp_hdr[0]<<8) + tcp_hdr[1];
      uint16_t dst_port= (tcp_hdr[2]<<8) + tcp_hdr[3];
      uint32_t seq_num= (tcp_hdr[4]<<24) + (tcp_hdr[5]<<16) + (tcp_hdr[6]<<8) + tcp_hdr[7];
      uint8_t data_offset= tcp_hdr[12]>>4;
      //... parse needed options....
      uint tcp_header_len= data_offset*4;

      pkt_ptr += tcp_header_len;
      uint payload_size= packet_length - ip_header_len - tcp_header_len;
      // here data starts....
      printf("packet %u; ", pkt_counter+1);
      printf("len= %u; ", payload_size);
      for (uint i=0; i<payload_size && i<32; ++i) {
    	  printf("%02X ", pkt_ptr[i]);
      }
      printf("\n");

      pkt_counter++; //increment number of packets seen 
 
    } //end internal loop for reading packets (all in one file) 
 
    pcap_close(handle);  //close the pcap file 
 
  //---------- Done with Main Packet Processing Loop --------------  
 
  return 0; //done
} //end of main() function

