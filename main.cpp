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
  struct ip *ip_head;
  struct ether_header *eth;
  struct tcphdr *tcp;
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

    eth = (struct ether_header *)packet;
    packet+=sizeof(struct ether_header);
    printf("============================================\n");
    for(i=0;i<6;++i){
    	printf("%x",eth->ether_shost[i]);
    	if (i!=5){
    		printf(":");
    	}
    	else{
		puts("");
    		break;
    	}
    }
    for(i=0;i<6;++i){
    	printf("%x",eth->ether_dhost[i]);
    	if (i!=5){
    		printf(":");
    	}
    	else{
		puts("");
    		break;
    	}
    }

	
    printf("ether_type = 0x%X\n",eth->ether_type);
    if( eth->ether_type != 0x08 )
    {
	printf("============================================\n");
	continue;
    }
	

    ip_head = (struct ip *)packet;
    packet += ip_head->ip_hl * 4;

    
    char *addr_src_ip = inet_ntoa(ip_head->ip_src);   
    char *addr_dst_ip = inet_ntoa(ip_head->ip_dst);
    puts(addr_src_ip); 
    puts(addr_dst_ip);


    printf("ip_protocol = 0x%X \n",ip_head->ip_p);
    if( ip_head->ip_p != 6 )    
    {
	printf("============================================\n");
	continue;
    }


    tcp = (struct tcphdr *)packet;
    packet += tcp->th_off * 4;

    datasize = (int)(ip_head->ip_len) - (ip_head->ip_hl * 4 + tcp->th_off * 4) ;
    printf("srcport : %hu\ndstport : %hu\n\n",htons(tcp->th_sport),htons(tcp->th_dport));
    for(int i = 0;i< datasize; i++ )
	    putchar(packet[i]);

    printf("============================================\n");

 }

  pcap_close(handle);
  return 0;
}
