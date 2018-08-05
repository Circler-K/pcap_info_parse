#include <pcap.h>
#include <stdio.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }
  struct ip *ip_packet_handler;
  struct ether_header *eth_packet_handler;
  struct tcphdr *tcp_packet_handler;
  int datasize;
  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int i;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    eth_packet_handler = (struct ether_header *)packet;
    packet+=sizeof(struct ether_header);
    printf("====================================\nS : ");
    for(i=0;i<6;++i){
    	printf("%x",eth_packet_handler->ether_shost[i]);
    	if (i!=5){
    		printf(":");
    	}
    	else{
		puts("");
    		break;
    	}
    }
    printf("D : ");
    for(i=0;i<6;++i){
    	printf("%x",eth_packet_handler->ether_dhost[i]);
    	if (i!=5){
    		printf(":");
    	}
    	else{
		puts("");
    		break;
    	}
    }

	
    printf("ether_type = 0x%X\n",eth_packet_handler->ether_type);
    if( eth_packet_handler->ether_type != 0x08 )
    {
	printf("====================================\n");
	continue;
    }
	

    ip_packet_handler = (struct ip *)packet;
    packet += ip_packet_handler->ip_hl * 4;

    
    char *addr_src_ip = inet_ntoa(ip_packet_handler->ip_src);   
    printf("addr_src_ip :");
    puts(addr_src_ip);
    char *addr_dst_ip = inet_ntoa(ip_packet_handler->ip_dst);
    printf("addr_dst_ip : ");
    puts(addr_dst_ip);


    printf("ip_protocol = 0x%X \n",ip_packet_handler->ip_p);
    if( ip_packet_handler->ip_p != 6 )    
    {
	printf("====================================\n");
	continue;
    }


    tcp_packet_handler = (struct tcphdr *)packet;
    packet += tcp_packet_handler->th_off * 4;

    datasize = (int)(ip_packet_handler->ip_len) - (ip_packet_handler->ip_hl * 4 + tcp_packet_handler->th_off * 4) ;
    printf("srcport : %hu\ndstport : %hu\n\n",htons(tcp_packet_handler->th_sport),htons(tcp_packet_handler->th_dport));
    printf("datasize : %d\n",datasize);
    for(int i = 0;i< 16/*datasize*/; i++ ){
	    printf("\\x%x ",packet[i]);
	    //putchar(packet[i]);
    }
    puts("");
    printf("====================================\n");

 }

  pcap_close(handle);
  return 0;
}
