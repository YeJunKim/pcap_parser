#include <pcap.h> 
#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <arpa/inet.h>

typedef struct ip_address{
    uint8_t byte1;
    uint8_t byte2;
    uint8_t byte3;
    uint8_t byte4;
}ip_address;

typedef struct ip_header{
    uint8_t  ver_ihl;    
    ip_address  saddr;      
    ip_address  daddr;      
}ip_header;

typedef struct udp_header{
    u_short sport;          
    u_short dport;      
    uint16_t len;        
}udp_header;

typedef struct ethernet_address{
    uint8_t smac;
    uint8_t dmac;
}eth_address;


int mac_addr()
{
        int i,j = 0;
        const u_char *packet;

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
    eth_address *eh;
    u_int ip_len;
    u_short sport, dport;

    printf("-------------------------------------------------------------------------------\n");
    printf("len:%d \n", header->len);

    ih = (ip_header *) (pkt_data + 14); 

    ip_len = (ih->ver_ihl & 0xf) * 4;
    uh = (udp_header *) ((u_char*)ih + ip_len);

    eh = (eth_address *) (u_char*)(pkt_data);

    //printf("src port : %s\n", inet_ntop(AF_INET, &(uh->sport), sport, 100 ));
    //printf("dest port : %s\n", inet_ntop(AF_INET, &(uh->dport), dport, 100 ));
    
    
    printf("src port : %d\n", ntohs(uh->sport));
    printf("dest port : %d\n", ntohs(uh->dport));

    mac_addr();
    printf("src ip : %d.%d.%d.%d\ndst ip : %d.%d.%d.%d\n",
        ih->saddr.byte1,
        ih->saddr.byte2,
        ih->saddr.byte3,
        ih->saddr.byte4,

        ih->daddr.byte1,
        ih->daddr.byte2,
        ih->daddr.byte3,
        ih->daddr.byte4);
    printf("\n-------------------------------------------------------------------------------\n");
}

int main(int argc, char * argv[]) {
    pcap_t * handle; 
    char * dev;
    char errbuf[PCAP_ERRBUF_SIZE]; 

    dev = pcap_lookupdev(errbuf);
    handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);
        
    printf("-------------------grep packet------------------------\n");
    pcap_loop(handle, 0, packet_handler, NULL);
    printf("------------------------------------------------------\n");
    pcap_close(handle);
    return  0;
}
