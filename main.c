#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>

#include <pcap/pcap.h>

void packet_callback(u_char* args, const struct pcap_pkthdr* header, const u_char* buffer);

// thank you wireshark
// https://wiki.wireshark.org/Development/LibpcapFileFormat#:~:text=The%20value%20of%20N%2C%20in,be%20used%20in%20this%20case.

int main() {
    pcap_if_t*  alldevsp, *device;
    char        errbuf[BUFSIZ], devs[100][100];
    size_t      devcount;

    pcap_findalldevs(&alldevsp, errbuf);

    for (device = alldevsp; device != NULL; device = device->next) {
        if (device->name == NULL) continue;
        strcpy(devs[devcount++], device->name);
    }

    // all devices are in devs
   
    pcap_t* descriptor;
    descriptor = pcap_open_live(devs[0], 65536, 1, 0, errbuf);

    pcap_loop(descriptor, -1, packet_callback, NULL);

    return 0;
}

void packet_callback(u_char* user, const struct pcap_pkthdr* header, const u_char* bytes) {
    struct iphdr* ipheader = (struct iphdr*)(sizeof(struct ethhdr) + bytes);
}
