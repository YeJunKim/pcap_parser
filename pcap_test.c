#include <pcap.h>

void dump(const u_char *packet,int len);
			
int main()
{
    struct pcap_pkthdr header;
    unsigned char *packet;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *device;
    int i;
    int count = 1;
  
    while(1)
    {
        pcap_t *pcap_handle;
        device = pcap_lookupdev(errbuf);
  
        if(device == 0)
            printf("Err_lookupdev%s\n",errbuf);

        printf("try[%d]...device: %s \n",count, device);

        pcap_handle = pcap_open_live(device, 4096, 1, 1000, errbuf);
        
        if(pcap_handle == 0)
            printf("Err_pcap_open_live...%s\n",errbuf);
        

        packet = pcap_next(pcap_handle, &header);    
        
        if (header.len>0)
           dump(packet, header.len);
        
        packet = '\0';
        count++;

        pcap_close(pcap_handle);
    }
  
    return 0;
}


void dump(const u_char *packet,int len)
{
    int i = 0;    
  
    for(i=0; i<len; ++i)
    {
        if(*packet < 16)
            printf("0x0%x ", *packet);
        else
            printf("0x%x ",*packet);
        packet++;

        if(i%16 == 15)
            printf("\n");
    
  }
  
  printf("\n\n\n");
}
