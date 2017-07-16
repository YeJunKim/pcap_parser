#include <pcap.h> 
#include <stdio.h>
#include <time.h>
#include <arpa/inet.h>

/* 4 bytes IP address */
typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header{
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service
    u_short tlen;           // Total length
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    u_short crc;            // Header checksum
    ip_address  saddr;      // Source address
    ip_address  daddr;      // Destination address
    u_int   op_pad;         // Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header{
    u_short sport;          // Source port
    u_short dport;          // Destination port
    u_short len;            // Datagram length
    u_short crc;            // Checksum
}udp_header;


int mac_addr()
{
		int i,j = 0;
        const u_char *packet;
        u_short ether_type; 
        memcpy(&ether_type, packet+12, 2);
        ether_type=ntohs(ether_type);

        printf("mac.dst: ");
        for(i=0;i<5;i++)
                printf("%02x:", packet[i]); 
        printf("%02x\n", packet[i+1]);

        printf("mac.src : ");
        for(j=6;j<11;j++)
                printf("%02x:", packet[j]);
        printf("%02x\n", packet[j+1]);
}

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    ip_header *ih;
    udp_header *uh;
    u_int ip_len;
    u_short sport,dport;
    time_t local_tv_sec;
    int i;

    printf("-------------------------------------------------------------------------------\n");
    /* print timestamp and length of the packet */
    printf("len:%d \n", header->len);

    /* retireve the position of the ip header */
    ih = (ip_header *) (pkt_data + 14); //length of ethernet header

    /* retireve the position of the udp header */
    ip_len = (ih->ver_ihl & 0xf) * 4;
    uh = (udp_header *) ((u_char*)ih + ip_len);

    /* convert from network byte order to host byte order */
    sport = ntohs( uh->sport );
    dport = ntohs( uh->dport );
    
    mac_addr();
    /* print ip addresses and udp ports */
    printf("src ip : %d.%d.%d.%d\nsrc port : %d \ndst ip : %d.%d.%d.%d\ndst port : %d\n",
        ih->saddr.byte1,
        ih->saddr.byte2,
        ih->saddr.byte3,
        ih->saddr.byte4,
        sport,
        ih->daddr.byte1,
        ih->daddr.byte2,
        ih->daddr.byte3,
        ih->daddr.byte4,
        dport);
    printf("\n-------------------------------------------------------------------------------\n");
}

int main(int argc, char * argv[]) {
    pcap_t * handle; /* Session handle */
    char * dev;
    char errbuf[PCAP_ERRBUF_SIZE]; /* Error string */
    struct pcap_pkthdr header; /* The header that pcap gives us */


        dev = pcap_lookupdev(errbuf);
        handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);
        
            printf("-------------------grep packet------------------------\n");
            pcap_loop(handle, 0, packet_handler, NULL);
            printf("------------------------------------------------------\n");
        pcap_close(handle);
    return (0);
}
