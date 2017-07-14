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

int print_packet(const u_char * packet, int len) {
    int i = 0;
    for (i = 0; i < len; ++i) {
        if(i<=11)
        {
            if ( * packet < 16) {
                if (i == 0)
                    printf("mac.dst : ");
                else if (i == 6)
                    printf("\nmac.src : ");

                if (i == 0 || i == 6)
                    printf("0%x", * packet);
                else
                    printf(" : 0%x", * packet);


            }
            else {
                if (i == 0)
                    printf("mac.dst : ");
                else if (i == 6)
                    printf("\nmac.src : ");
                if (i == 0)
                    printf("%x", * packet);
                else
                    printf(" : %x", * packet);
                

            }
        }
        packet++;
    }
}

int capture_packet()
{
    pcap_t * handle; /* Session handle */
    char * dev; /* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE]; /* Error string */
    struct bpf_program fp; /* The compiled filter */
    bpf_u_int32 mask; /* Our netmask */
    bpf_u_int32 net; /* Our IP */
    struct pcap_pkthdr header; /* The header that pcap gives us */
    const u_char * packet; /* The actual packet */
 

    
        /* Define the device */
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        }
        /* Find the properties for the device */
        if (pcap_lookupnet(dev, & net, & mask, errbuf) == -1) {
            fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
            net = 0;
            mask = 0;
        }
        /* Open the session in promiscuous mode */
        handle = pcap_open_live(dev, BUFSIZ, 1, 100, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        }

        /* Grab a packet */
        packet = pcap_next(handle, & header);

        if (header.len != 0) {
            print_packet(packet, header.len);
        }

        /* And close the session */
        pcap_close(handle);
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
    capture_packet();

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
