#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
// #include "my_fixedheader.h"

/* Ethernet Header */
struct ethheader {
  u_char  ether_dhost[6]; /* destination host address */
  u_char  ether_shost[6]; /* source host address */
  u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address
  struct  in_addr    iph_destip;   //Destination IP address
};

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;               // source port
    u_short tcp_dport;               // destination port
    u_int   tcp_seq;                 // sequence number
    u_int   tcp_ack;                 // acknowledgement number
    u_char  tcp_offx2;               // data offset, rsvd
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;                 // window
    u_short tcp_sum;                 // checksum
    u_short tcp_urp;                 // urgent pointer
};

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)(packet + sizeof(struct ethheader)); 
    struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip->iph_ihl * 4);
	
	// printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));   
	// printf("         To: %s\n", inet_ntoa(ip->iph_destip));    
	// Ethernet 정보 출력
	 for (int i = 0; i < 6; i++) {
        eth->ether_shost[i] = i + 1; // 예시 MAC 주소 설정
        eth->ether_dhost[i] = 6 - i; // 예시 MAC 주소 설정
    }

    // Source MAC 주소 출력
    printf("Source MAC: ");
    for (int i = 0; i < 6; i++) {
        printf("%02X", eth->ether_shost[i]);
        if (i < 5) printf(":");
    }
    printf("\n");

    // Destination MAC 주소 출력
    printf("Destination MAC: ");
    for (int i = 0; i < 6; i++) {
        printf("%02X", eth->ether_dhost[i]);
        if (i < 5) printf(":");
    }
    printf("\n");

    // printf("Source MAC: %s\n", ether_ntoa((struct ether_addr *)eth->ether_shost));
   //  printf("Destination MAC: %s\n", ether_ntoa((struct ether_addr *)eth->ether_dhost));

    // IP 정보 출력
    printf("Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("Destination IP: %s\n", inet_ntoa(ip->iph_destip));

    // TCP 포트 정보 출력
    printf("Source Port: %d\n", ntohs(tcp->tcp_sport));
    printf("Destination Port: %d\n", ntohs(tcp->tcp_dport));
    // printf("\n");


    // TCP 헤더 길이 계산
    int tcp_header_len = tcp->tcp_offx2 >> 4; // TCP 헤더 길이는 4바이트 단위로 표현되므로 비트 이동을 통해 계산합니다.

    // 데이터 영역 출력 (메시지 출력)
    int data_len = ntohs(ip->iph_len) - (ip->iph_ihl * 4) - (tcp_header_len * 4);
    if (data_len > 0) {
        printf("Message: ");
        for (int i = 0; i < data_len && i < 10; i++) { // 메시지의 처음 10바이트만 출력
            printf("%c", packet[sizeof(struct ethheader) + ip->iph_ihl * 4 + tcp_header_len * 4 + i]);
        }
        printf("\n");
    }
    printf("\n");
    // /* determine protocol */
    // switch(ip->iph_protocol) {                                 
    //     case IPPROTO_TCP:
    //         printf("   Protocol: TCP\n");
    //         return;
    //     case IPPROTO_UDP:
    //         printf("   Protocol: UDP\n");
    //         return;
    //     case IPPROTO_ICMP:
    //         printf("   Protocol: ICMP\n");
    //         return;
    //     default:
    //         printf("   Protocol: others\n");
    //         return;
    // }
  }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  // char filter_exp[] = "icmp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("enp0s1", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code
  // pcap_compile(handle, &fp, filter_exp, 0, net);
  // if (pcap_setfilter(handle, &fp) !=0) {
  //     pcap_perror(handle, "Error:");
  //     exit(EXIT_FAILURE);
  // }

  // Step 3: Capture packets
  // pcap_loop(handle, -1, got_packet, NULL);
  pcap_loop(handle, 0, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}



