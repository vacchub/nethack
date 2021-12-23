#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "nethack.h"

/***********************************************************
 * network_analysis()
 **********************************************************/
int network_analysis(handle *hand, char *interface, char *gateway, int mode)
{
	int fd;
	struct ifreq req;

	memset(hand, 0x00, sizeof(handle));

	hand->mode = 0;
	switch (mode)
	{
	case 0:
	default :
		hand->mode = MODE_NONE;
		break;
	case 1:
		hand->mode = MODE_ARP1;
		break;
	case 2:
		hand->mode = (MODE_ARP1 | MODE_ARP2);
		break;
	case 3:
		hand->mode = (MODE_ARP1 | MODE_ARP2 | MODE_PSND);
		break;
	case 4:
		hand->mode = MODE_SNIF;
		break;
	case 5:
		hand->mode = (MODE_ARP1 | MODE_FRAG | MODE_SNIF);
		break;
	}

	fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if(fd == -1) {
		perror("socket: ");
		return -1;
	}

	strcat(hand->interface, interface);
	hand->gateway.s_addr = inet_addr(gateway);

	bzero(&req, sizeof(struct ifreq));
	strcpy(req.ifr_ifrn.ifrn_name, interface);

	if(ioctl(fd, SIOCGIFADDR, &req) == -1) {
		perror("SIOCGIFADDR: ");
		return -1;
	}
	memcpy(&hand->host, req.ifr_ifru.ifru_addr.sa_data + 2, 4);

	if(ioctl(fd, SIOCGIFNETMASK, &req) == -1) {
		perror("SIOCGIFNETMASK: ");
		return -1;
	}
	memcpy(&hand->netmask, req.ifr_ifru.ifru_netmask.sa_data + 2, 4);

	/* C class */
	if (htonl(hand->netmask.s_addr) == 0xffffff00)
	{
		printf("ipscan_all\n");
		hand->ipscan = ipscan_all;
	}
	else
	{
		printf("ipscan_one\n");
		hand->ipscan = ipscan_one;
	}

	if(ioctl(fd, SIOCGIFHWADDR, &req) == -1) {
		perror("SIOCGIFHWADDR: ");
		return -1;
	}
	memcpy(hand->mac, req.ifr_ifru.ifru_hwaddr.sa_data, 6);

	close(fd);
	return 0;
}

