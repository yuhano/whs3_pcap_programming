#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>

/* Ethernet header */
struct ethheader {
    u_char  ether_dhost[6];    /* destination host address */
    u_char  ether_shost[6];    /* source host address */
    u_short ether_type;                     /* IP? ARP? RARP? etc */
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
    u_short tcp_sport;               /* source port */
    u_short tcp_dport;               /* destination port */
    u_int   tcp_seq;                 /* sequence number */
    u_int   tcp_ack;                 /* acknowledgement number */
    u_char  tcp_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
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
    u_short tcp_win;                 /* window */
    u_short tcp_sum;                 /* checksum */
    u_short tcp_urp;                 /* urgent pointer */
};


/* Helper function to print a MAC address */
void print_mac_address(const u_char *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2],
           mac[3], mac[4], mac[5]);
}
 
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    // 이더넷 헤더 포인터 가져오기
    struct ethheader *eth = (struct ethheader *)packet;

    // IP 패킷인지 확인 (0x0800은 IP 프로토콜)
    if (ntohs(eth->ether_type) == 0x0800) {
        // IP 헤더 포인터 가져오기
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        // TCP 프로토콜인지 확인
        if(ip->iph_protocol == IPPROTO_TCP) {

            // 이더넷 헤더 정보 출력
            printf("----- Ethernet Header -----\n");
            printf("Source MAC: ");
            print_mac_address(eth->ether_shost);
            printf("\nDestination MAC: ");
            print_mac_address(eth->ether_dhost);
            printf("\n");

            // IP 헤더 정보 출력
            printf("----- IP Header -----\n");
            printf("Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
            printf("Destination IP: %s\n", inet_ntoa(ip->iph_destip));

            // IP 헤더 길이 계산 (바이트 단위)
            int ip_header_length = ip->iph_ihl * 4;

            // TCP 헤더 포인터 가져오기
            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_length);

            // TCP 헤더 정보 출력
            printf("----- TCP Header -----\n");
            printf("Source Port: %d\n", ntohs(tcp->tcp_sport));
            printf("Destination Port: %d\n", ntohs(tcp->tcp_dport));

            // TCP 헤더 길이 계산 (바이트 단위)
            int tcp_header_length = TH_OFF(tcp) * 4;

            // 전체 헤더 크기 계산
            int total_headers_size = sizeof(struct ethheader) + ip_header_length + tcp_header_length;

            // IP 전체 길이 가져오기
            int ip_total_length = ntohs(ip->iph_len);

            // 페이로드 길이 계산
            int payload_length = ip_total_length - ip_header_length - tcp_header_length;

            // 페이로드가 존재하면 출력 (최대 16바이트만 출력)
            if (payload_length > 0) {
                int print_length = payload_length < 16 ? payload_length : 16;
                printf("----- Payload (%d bytes total, showing %d bytes) -----\n   ", payload_length, print_length);
                for (int i = 0; i < print_length; i++) {
                    u_char byte = *(packet + total_headers_size + i);
                    if (byte >= 32 && byte < 127)
                        printf("%c", byte); // 출력 가능한 문자는 그대로 출력
                    else
                        printf(".");       // 그 외 문자는 점(.)으로 출력
                }
                printf("\n");
            }
        }
        printf("\n");
    }
}

int main()
{
    char *dev = "eth0";  // 사용할 네트워크 인터페이스 이름 (필요 시 변경)
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // 1단계: NIC에서 라이브 pcap 세션 열기
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    // 2단계: TCP 패킷만 수집하기 위한 필터 설정
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net = 0;
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    // 3단계: 패킷 캡처 시작 (-1은 무한 반복)
    pcap_loop(handle, -1, got_packet, NULL);

    // 세션 종료 및 정리
    pcap_close(handle);
    return 0;
}