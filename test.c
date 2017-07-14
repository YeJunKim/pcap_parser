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

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    ip_header *ih;
    udp_header *uh;
    u_int ip_len;
    u_short sport,dport;
    time_t local_tv_sec;


    /* print timestamp and length of the packet */
    printf("len:%d ", header->len);

    /* retireve the position of the ip header */
    ih = (ip_header *) (pkt_data + 14); //length of ethernet header

    /* retireve the position of the udp header */
    ip_len = (ih->ver_ihl & 0xf) * 4;
    uh = (udp_header *) ((u_char*)ih + ip_len);

    /* convert from network byte order to host byte order */
    sport = ntohs( uh->sport );
    dport = ntohs( uh->dport );

    /* print ip addresses and udp ports */
    printf("src ip : %d.%d.%d.%d:%d -> dst ip : %d.%d.%d.%d:%d\n",
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
}

void print_packet(const u_char * packet, int len) {
    int i = 0;
    int a, b, c, d;
    for (i = 0; i < len; ++i) {
        if(i<=11)
        {
            if ( * packet < 16) {
                if (i == 0 || i == 6)
                    printf("0%x", * packet);
                else
                    printf(" : 0%x", * packet);

                if (i == 5)
                    printf("    <<<This is mac.dst\n");
                else if (i == 11)
                    printf("    <<<This is mac.src\n");
            }
            else {
                if (i == 0)
                    printf("%x", * packet);
                else
                    printf(" : %x", * packet);
                
                if (i == 5)
                    printf("    <<<This is mac.dst\n");
                else if (i == 11)
                    printf("    <<<This is mac.src\n");
            }
        }
        else if(i >= 26 && i <= 33)
        {   
            if (i == 26 || i == 30)
                printf("%d", * packet);
            else
                printf(".%d", * packet);
            if (i == 29)
                printf("    <<<This is ip.src\n");
            else if (i == 33)
                 printf("    <<<This is ip.dst\n");
            
        }
        else if(i >= 34 && i <= 37)
        {
            if (i == 34 || i == 36)
                printf("0x");
            if ( * packet < 16) {
                printf("0%x", * packet);
                if (i == 35)
                    printf("    <<<This is port.src\n");
                else if (i == 37)
                    printf("    <<<This is port.dst\n");
            }
            else{
                printf("%x", * packet);
                if (i == 35)
                    printf("    <<<This is port.src\n");
                else if (i == 37)
                    printf("    <<<This is port.dst\n");
            }
        }
        packet++;
    }
    printf("\nEnd grep packet.\n\n\n");
}

int main(int argc, char * argv[]) {
    pcap_t * handle; /* Session handle */
    char * dev; /* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE]; /* Error string */
    struct bpf_program fp; /* The compiled filter */
    char filter_exp[] = "port 80"; /* The filter expression */
    bpf_u_int32 mask; /* Our netmask */
    bpf_u_int32 net; /* Our IP */
    struct pcap_pkthdr header; /* The header that pcap gives us */
    const u_char * packet; /* The actual packet */
    int j = 0;

    printf("Start packet capture!\n");

    while (1) {
        /* Define the device */
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
            return (2);
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
            return (2);
        }
        /* Compile and apply the filter */
        if (pcap_compile(handle, & fp, filter_exp, 0, net) == -1) {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
            return (2);
        }

        if (pcap_setfilter(handle, & fp) == -1) {
            fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
            return (2);
        }

        /* Grab a packet */
        packet = pcap_next(handle, & header);

        if (header.len != 0) {
            printf("-------------------grep packet------------------------\n");
            pcap_loop(handle, 0, packet_handler, NULL);
            print_packet(packet, header.len);
            printf("------------------------------------------------------\n");
        }

        /* And close the session */
        pcap_close(handle);
        j++;
    }

    return (0);
}
