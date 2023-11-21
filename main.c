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

    if (pcap_findalldevs(&alldevsp, errbuf)) {
        printf("error finding device: %s\n", errbuf);
        exit(1);
    }

    printf("%-24s %-20s\n", "interface", "description");

    for (device = alldevsp; device != NULL; device = device->next) {
        printf("%2zu: %-20s %-20s\n", devcount, device->name, device->description);
        if (device->name == NULL) continue;
        strcpy(devs[devcount++], device->name);
    }

    // all devices are in devs
   
    pcap_t* descriptor;
    char*   devname = devs[0];

    descriptor = pcap_open_live(devname, 65536, 1, 0, errbuf);

    if (descriptor == NULL) {
        printf("opening device '%s' failed: %s\n", devname, errbuf);
        exit(1);
    }

    pcap_loop(descriptor, -1, packet_callback, NULL);

    return 0;
}

void packet_callback(u_char* user, const struct pcap_pkthdr* header, const u_char* bytes) {
    printf("packet_callback called\n");

//  struct ethhdr* etheader = (struct ethhdr*)(0);
    struct iphdr*  ipheader = (struct iphdr* )(sizeof(struct ethhdr) + bytes);

    printf("ipheader->protocol = %d\n", ipheader->protocol);

    // https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
    switch (ipheader->protocol) {
    case 0x01: // ICMP
        printf("ICMP\n");
        break;
    case 0x06: // TCP
        printf("TCP\n");
        break;
    case 0x11: // UDP
        printf("UDP\n");
        break;
    }
}
