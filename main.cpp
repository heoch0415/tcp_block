#include <pcap.h>
#include <stdio.h>
#include <string.h>

char hostname[100];
char arr[6] = {'H', 'o', 's', 't', ':', ' '};
char temp[100];
void usage() {
	printf("syntax: pcap_test <interface> <host>\n");
	printf("sample: pcap_test wlan0 test.gilgil.net\n");
}

int main(int argc, char* argv[]) {
	if (argc != 3) {
		usage();
		return -1;
	}
	memcpy(hostname, argv[2], strlen(argv[2]);
  	char* dev = argv[1];
  	char errbuf[PCAP_ERRBUF_SIZE];
  	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  	if (handle == NULL) {
   		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    		return -1;
  	}

  	while (true) {
    	struct pcap_pkthdr* header;
    	const u_char* packet, f_packet, b_packet;
    	int res = pcap_next_ex(handle, &header, &packet);
	int size = strlen(packet)
    	if (res == 0) continue;
    	if (res == -1 || res == -2) break;
    	
    	if (packet[12] == 0x08 && packet[13] == 0x00){
		if (packet[23] == 0x06){
			packet = packet + 54;
	    		for(int i = 54; i < size - 6; i++){
				if(memcmp(packet, arr, 6) == 0){
					if(memcmp(packet + 6, hostname, strlen(hostname)) == 0){
						packet = packet - i;
						strcpy(f_packet, packet, 54);
						f_packet[45] = f_packet[45] + 0x36;
						f_packet[46] = 0x00;
						f_packet[47] = 0x04;
						pcap_sendpacket(handle, f_packet, 54);
						strcpy(b_packet, packet, 54);
						for(int j = 0; j < 6; j++){
							b_packet[j] = packet[j + 6];
							b_packet[j + 6] = packet[j]; 
						}
						for(int j = 26; j < 30; j++){
							b_packet[j] = packet[j + 4];
							b_packet[j + 4] = packet[j];
						}
						for(int j = 34; j < 36; j++){
							b_packet[j] = packet[j + 2];
							b_packet[j + 2] = packet[j];
						}
						for(int j = 38; j < 42; j++){
							b_packet[j] = f_packet[j + 4];
							b_packet[j + 4] = f_packet[j];
						}
						b_packet[46] = 0x00;
						b_packet[47] = 0x04;
						pcap_sendpacket(handle, b_packet, 54);
						break;
					}
				}
				packet++;
			}
			
    		}
  	}

  pcap_close(handle);
  return 0;
}
