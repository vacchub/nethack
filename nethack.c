#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "nethack.h"

int delete_log();

void usage()
{
	printf("Usage : nethack interface gateway-ip mode\n");
	printf("mode\n");
	printf("    0 : non attack\n");
	printf("    1 : arpspoof (target)\n");
	printf("    2 : arpspoof (target + gateway)\n");
	printf("    3 : arpspoof (target + gateway) + packet attack\n");
	printf("    4 : sniff (monitor mode)\n");
	printf("    5 : sniff (arpspoof + fragraouter)\n");
}

/***********************************************************
 * main()
 **********************************************************/
int main(int argc, char *argv[])
{
	handle hand;
	char interface[12], gateway[16];
	int mode, retc;

	if (argc != 4)
	{
		usage();
		return 0;
	}

	memset(interface, 0x00, sizeof(interface));
	memcpy(interface, argv[1], strlen(argv[1]));
	memset(gateway, 0x00, sizeof(gateway));
	memcpy(gateway, argv[2], strlen(argv[2]));
	mode = atoi(argv[3]);

	retc = network_analysis(&hand, interface, gateway, mode);
	if (retc < 0)
	{
		printf("network_analysis() error\n");
		return -1;
	}

	printf("host [%s] [%08X]\n", inet_ntoa(hand.host), hand.host);
	printf("gateway [%s] [%08X]\n", inet_ntoa(hand.gateway), hand.gateway);
	printf("netmask [%s] [%08X]\n", inet_ntoa(hand.netmask), hand.netmask);
	printf("mac [%02x:%02x:%02x:%02x:%02x:%02x]\n", 
	hand.mac[0], hand.mac[1], hand.mac[2],
	hand.mac[3], hand.mac[4], hand.mac[5]);
	printf("-----------------------------------\n");

	delete_log();

	for (;;)
	{
		hand.ipscan(&hand);
		sleep(1);
	}

	return 0;
}

/***********************************************************
 * delete_log()
 **********************************************************/
int delete_log()
{
	char cmd[256];

	sprintf(cmd, "rm -f ./log/*");
	system(cmd);
	return 0;
}
