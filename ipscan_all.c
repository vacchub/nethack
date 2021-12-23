#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "nethack.h"

#define MAX_IPSCAN_THREAD 1000

static handle g_hand;
static char g_interface[12];

struct arp_packet
{
    unsigned char ap_dstmac[6];  //6
    unsigned char ap_srcmac[6];  //6
    unsigned short ap_frame;     //2
    //arp
    unsigned short ap_hwtype;    //2
    unsigned short ap_prototype; //2
    unsigned char  ap_hwlen;     //1
    unsigned char  ap_prolen;    //1
    unsigned short ap_op;        //2
    unsigned char  ap_frommac[6];//6
    unsigned char  ap_fromip[4]; //4
    unsigned char  ap_tomac[6];  //6
    unsigned char  ap_toip[4];   //4

    unsigned char  ap_padding[18];	//18
};

typedef struct {
	pthread_t tid;
} t_data_t;


pthread_mutex_t mutex;

int make_arp_packet(struct arp_packet *, uint8_t *, uint8_t *, uint8_t *, uint16_t); 
void *pthread_arp(void *pdata);


/***********************************************************
 * ipscan_all()
 **********************************************************/
int ipscan_all(handle *hand)
{
	unsigned char ip_client[4];
	unsigned char mac_client[6];
	unsigned char netmask_client[4];
	unsigned char ip_ser[4];
	uint32_t ip_n, netmask_n, ip_start_n, ip_stop_n;
	struct arp_packet ptr_packet[MAX_IPSCAN_THREAD];
	t_data_t ptr_t_data[MAX_IPSCAN_THREAD];
	int ii, tidx=0, nrec, result;
	struct in_addr ipaddr;

	pthread_mutex_init(&mutex, NULL);

	memcpy(&g_hand, hand, sizeof(handle));

	memset(g_interface, 0x00, sizeof(g_interface));
	memcpy(g_interface, hand->interface, strlen(hand->interface));

	for (ii = 0; ii < 4; ii++) 
	{
		ip_client[ii] = (htonl(hand->host.s_addr) >> ((3 - ii) * 8)) & 0xFF;
	}

	for (ii = 0; ii < 4; ii++) 
	{
		netmask_client[ii] = (htonl(hand->netmask.s_addr) >> ((3 - ii) * 8)) & 0xFF;
	}

	memcpy(mac_client, hand->mac, 6);

/*
	printf("my [%d.%d.%d.%d] [%02x:%02x:%02x:%02x:%02x:%02x] netmask[%d.%d.%d.%d]\n",
		ip_client[0], ip_client[1], ip_client[2], ip_client[3],
		mac_client[0], mac_client[1], mac_client[2],
		mac_client[3], mac_client[4], mac_client[5],
		netmask_client[0], netmask_client[1], netmask_client[2], netmask_client[3]);
*/

	ip_n = ntohl(*((uint32_t *)ip_client));
	netmask_n = ntohl(*((uint32_t *)netmask_client));

	ip_start_n = (ip_n & netmask_n) + 1;
	ip_stop_n = ((ip_n & netmask_n) | (~netmask_n));

	while (1) 
	{
		if(ip_start_n >= ip_stop_n)
			break;

		for (ii = 0; ii < 4; ii++) 
		{
			ip_ser[ii] = (ip_start_n >> ((3 - ii) * 8)) & 0xFF;
		}

//printf("1host[%d] s[%ld] e[%ld]\n", hand->host, ip_start_n, ip_stop_n);
//printf("2[%d.%d.%d.%d] [%d]\n", ip_ser[0], ip_ser[1], ip_ser[2], ip_ser[3], (ip_start_n));
//printf("1[%08X][%08X]\n", htonl(hand->host), ntohl(*((uint32_t *)ip_ser)));
		if (htonl(hand->host.s_addr) == ntohl(*((uint32_t *)ip_ser)))
		{
			ip_start_n++;
			continue;
		}

		if (htonl(hand->gateway.s_addr) == ntohl(*((uint32_t *)ip_ser)))
		{
			ip_start_n++;
			continue;
		}

		make_arp_packet(&ptr_packet[tidx], ip_client, ip_ser, mac_client, 0x0001);
		result = pthread_create(&(ptr_t_data[tidx].tid), NULL, 
			pthread_arp, &ptr_packet[tidx]);
		if(result) 
		{
			perror("create thread error");
			usleep(10000);
			continue;
		}

		tidx++;
		usleep(10000);

		ip_start_n++;
	}

	nrec = tidx;
	for (ii = 0; ii < nrec; ii++) 
	{
		pthread_join(ptr_t_data[ii].tid, (void *)&result);
		if (result == 0)
		{
			/* error */
		}
	}

	//printf("ip scan end\n");

	pthread_mutex_destroy(&mutex);
	return 0;
}

/***********************************************************
 * make_arp_packet()
 **********************************************************/
int make_arp_packet(arp_in, ip_cli, ip_ser, mac_cli, op)
struct arp_packet *arp_in; 
uint8_t *ip_cli; 
uint8_t *ip_ser;
uint8_t *mac_cli;
uint16_t op;
{
	bzero(arp_in,sizeof(struct arp_packet));

	memset(arp_in->ap_dstmac, 0xFF, 6);
	memcpy(arp_in->ap_srcmac, mac_cli, 6);

	arp_in->ap_frame = htons(ETH_P_ARP);
	arp_in->ap_hwtype = htons(0x0001);
	arp_in->ap_prototype = htons(ETH_P_IP);
	arp_in->ap_hwlen = 6;
	arp_in->ap_prolen = 4;
	arp_in->ap_op = htons(op);	//0x0001-ARP req 0x0002-ARP Reply

	memcpy(arp_in->ap_frommac, mac_cli, 6);
	memcpy(arp_in->ap_fromip, ip_cli, 4);
	memcpy(arp_in->ap_toip, ip_ser, 4);

	return 0;
}

/***********************************************************
 * pthread_arp()
 **********************************************************/
void *pthread_arp(void *pdata)
{
	int fd_socket;
	struct sockaddr_ll eth;
	socklen_t slen;
	struct timeval timeOut;
	int ret, cnt=0;
	struct arp_packet * arp_in, arp_rc;
	struct in_addr ipaddr;

	arp_in = (struct arp_packet *)pdata;

	fd_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (fd_socket < 0) 
	{
		perror("socket: ");
		pthread_exit((void *)0);
	}

	// set socket timeout: 2s
	timeOut.tv_sec = 2;
	timeOut.tv_usec = 0;
	if (setsockopt(fd_socket, SOL_SOCKET, SO_RCVTIMEO, 
			&timeOut, sizeof(struct timeval)) == -1) 
	{
		perror("setsockopt: ");
		close(fd_socket);
		pthread_exit((void *)0);
	}

	// make sockaddr
	bzero(&eth, sizeof(struct sockaddr_ll));
	eth.sll_family = PF_PACKET;
	eth.sll_ifindex = if_nametoindex(g_interface);

	// send ARP
	ret = sendto(fd_socket, arp_in, sizeof(struct arp_packet), 0, 
		(struct sockaddr *)&eth, sizeof(struct sockaddr_ll));
	if(ret == -1) {
		// perror("send arp: ");
		close(fd_socket);
		pthread_exit((void *)0);
	}

	// recv ARP
	for (cnt = 0; cnt < 5; cnt++)
	{
		slen = sizeof(struct sockaddr);
		bzero(&arp_rc, sizeof(struct arp_packet));
		ret = recvfrom(fd_socket, &arp_rc, sizeof(struct arp_packet), 0, 
			(struct sockaddr *)&eth, &slen);
		if(ret == -1) 
		{
			close(fd_socket);
			pthread_exit((void *)0);
		}

		if(ntohs(arp_rc.ap_op) == 0x0002)
		{
			if(memcmp(arp_in->ap_toip, arp_rc.ap_fromip, 4) == 0) 
			{
				pthread_mutex_lock(&mutex);
				ipaddr.s_addr = *((uint32_t *)arp_rc.ap_fromip);

				//printf("%s [%08X] alive\n", inet_ntoa(ipaddr), ipaddr.s_addr);
				attack_run(&g_hand, ipaddr);

				pthread_mutex_unlock(&mutex);

/*
printf("thread %d.%d.%d.%d [%08X] [%08X] [%08X]\n", 
arp_rc.ap_fromip[0], arp_rc.ap_fromip[1], arp_rc.ap_fromip[2], 
arp_rc.ap_fromip[3], ipaddr.s_addr, &ipaddr.s_addr, &ipaddr);
*/
				close(fd_socket);
				pthread_exit((void *)1);
			} 
			else
			{
				usleep(10000);
				continue;
			}
		}
	}

	close(fd_socket);
	pthread_exit((void *)0);
}


