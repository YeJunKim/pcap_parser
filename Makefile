pcap_test: pcap_test.o
		gcc -o pcap_test pcap_test.o -lpcap

pcap_test.o: pcap_test.c
		gcc -c -o pcap_test.o pcap_test.c -lpcap

clean: 
		rm *.o pcap_test

