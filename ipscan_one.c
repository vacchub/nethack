#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/ether.h>
#include<netinet/ip.h>
#include <unistd.h>
#include <errno.h>
#include <pcap.h>
#include "nethack.h"

struct arp_packet
{
	//ethernet
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

    unsigned char  ap_padding[18];  //18
};


pcap_t *ip_pd;

int ipscan_init(char *intf, char *ebuf);
void ipscan_loop(handle *hand);
int ipcmp(char *ip1, char *ip2);
void packet_print(unsigned char *pkt, int length);

/***********************************************************
 * ipscan_one()
 **********************************************************/
int ipscan_one(handle *hand)
{
	char ebuf[BUFSIZ];

	if (!ipscan_init(hand->interface, ebuf)) 
	{
		printf("ipscan_init failed: %s\n", ebuf);
		return -1;
	}
  
	ipscan_loop(hand);

	return 0;
}

/***********************************************************
 * ipscan_init()
 **********************************************************/
int ipscan_init(char *intf, char *ebuf)
{
	char filter[BUFSIZ];
	u_int net, mask;
	struct bpf_program fcode;

	snprintf(filter, sizeof(filter), "%s", "arp");

	/* don't set promiscuous mode. */
	if (pcap_lookupnet(intf, &net, &mask, ebuf) == -1)
		return 0;

	if (!(ip_pd = pcap_open_live(intf, BUFSIZ, 0, 1024, ebuf)))
		return 0;

	if (pcap_compile(ip_pd, &fcode, filter, 1, mask) < 0) {
		strcpy(ebuf, pcap_geterr(ip_pd));
		return 0;
	}
	if (pcap_setfilter(ip_pd, &fcode) == -1) {
		strcpy(ebuf, pcap_geterr(ip_pd));
		return 0;
	}

	return 1;
}

/***********************************************************
 * ipscan_loop()
 **********************************************************/
void ipscan_loop(handle *hand)
{
	struct in_addr ipaddr;
	struct arp_packet *arph;
	struct pcap_pkthdr pkthdr;
	char src[16], dst[16], gateway[16], host[16];
	u_char *pkt;

	memset(gateway, 0x00, sizeof(gateway));
	sprintf(gateway, "%s", inet_ntoa(hand->gateway));

	memset(host, 0x00, sizeof(host));
	sprintf(host, "%s", inet_ntoa(hand->host));

	for (;;) 
	{
		if ((pkt = (char *)pcap_next(ip_pd, &pkthdr)) != NULL) 
		{
    		arph = (struct arp_packet *)pkt;

			memset(src, 0x00, sizeof(src));
			sprintf(src, "%d.%d.%d.%d", arph->ap_fromip[0], 
				arph->ap_fromip[1], arph->ap_fromip[2], arph->ap_fromip[3]);

			memset(dst, 0x00, sizeof(dst));
			sprintf(dst, "%d.%d.%d.%d", arph->ap_toip[0], 
				arph->ap_toip[1], arph->ap_toip[2], arph->ap_toip[3]);

			if (arph->ap_fromip[0] != 0 && ipcmp(src, gateway) && ipcmp(src, host))
			{
				ipaddr.s_addr = *((uint32_t *)arph->ap_fromip);
				//printf("src[%s]%d\n", src, strlen(src));
				attack_run(hand, ipaddr);
			}
			if (arph->ap_toip[0] != 0 && ipcmp(dst, gateway) && ipcmp(dst, host))
			{
				ipaddr.s_addr = *((uint32_t *)arph->ap_toip);
				//printf("dst[%s]%d\n", dst, strlen(dst));
				attack_run(hand, ipaddr);
			}
		}
	}
}

/***********************************************************
 * ipcmp()
 **********************************************************/
int ipcmp(char *ip1, char *ip2)
{
	if (strlen(ip1) != strlen(ip2))
		return 1;

	if (memcmp(ip1, ip2, strlen(ip1)) != 0)
		return 1;

	return 0;
}

/***********************************************************
 * packet_print()
 **********************************************************/
void packet_print(unsigned char *str, int len)
{
	struct arp_packet *arph;
    struct tm *tm;
    time_t tt;
    int ii;

    arph = (struct arp_packet *)str;

    tt = time(NULL);
    tm = localtime(&tt);

    printf("[%02d:%02d:%02d] %d.%d.%d.%d > %d.%d.%d.%d\n", tm->tm_hour,
        tm->tm_min, tm->tm_sec, 
		arph->ap_fromip[0], arph->ap_fromip[1], 
		arph->ap_fromip[2], arph->ap_fromip[3], 
		arph->ap_toip[0], arph->ap_toip[1],
		arph->ap_toip[2], arph->ap_toip[3]);

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

