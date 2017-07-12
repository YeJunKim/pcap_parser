#include <pcap.h>
#include <stdio.h>

void print_packet(const u_char *packet, int len)
{
    int i = 0;
    
    for(i=0; i<len; ++i)
    {
        if(*packet < 16)
            printf("0x0%x ", *packet);
        else
            printf("0x%x ", *packet);

        packet++;

        if(i%16 == 15)
            printf("\n");
    }

    printf("\nEnd grep packet.\n\n\n");
}

int main(int argc, char *argv[])
{
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "port 80";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
    int count = 1;
    

    while(1)
    {
	    /* Define the device */
    	dev = pcap_lookupdev(errbuf);
    	if (dev == NULL) {
    		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
    		return(2);
    	}
    	/* Find the properties for the device */
    	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
    		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
    		net = 0;
    		mask = 0;
    	}
    	/* Open the session in promiscuous mode */
    	handle = pcap_open_live(dev, BUFSIZ, 1, 100, errbuf);
    	if (handle == NULL) {
    		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
     		return(2);
	    }
	    /* Compile and apply the filter */
	    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
	    	fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
	    	return(2);
	    }
	
        if (pcap_setfilter(handle, &fp) == -1) {
		    fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		    return(2);
	    }
	    
        /* Grab a packet */
	    packet = pcap_next(handle, &header);
	

        printf("Start [%d] grep packet.\n", count);
        print_packet(packet, header.len);
    
        count++;

        /* And close the session */
	    pcap_close(handle);
    }
	
    return(0);
}
