#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/ether.h>
#include<netinet/ip.h>
#include <unistd.h>
#include <errno.h>
#include <pcap.h>
#include <libnet.h>
#include "nethack.h"

/* global       */
char    interface[12];
char    host[16];

libnet_t *lnsock;
pcap_t *sniff_pd;
int sniff_ll_len;
static int raw_socket = -1;
static struct ipoption *sropt = NULL;
static int sroptlen = 0;

typedef void (*sniff_handler)(u_char *pkt, int len);
int sniff_init(char *ebuf);
void sniff_loop();
int send_init(char *ebuf);
int send_packet(u_char *pkt, int pktlen);
void print_ip(unsigned char *bp, int length);

int main(int argc, char *argv[])
{
	char ebuf[BUFSIZ];

	if (argc != 3)
	{
		printf("%s interface host (%d)\n", argv[0], argc);
		return 0;
	}

	memset(interface, 0x00, sizeof(interface));
	strcat(interface, argv[1]);
	memset(host, 0x00, sizeof(host));
	strcat(host, argv[2]);


	if (!sniff_init(ebuf)) {
		fprintf(stderr, "fragrouter: sniff_init failed: %s\n", ebuf);
		exit(1);
	}
	if (!send_init(ebuf)) {
		fprintf(stderr, "fragrouter: send_init failed: %s\n", ebuf);
		exit(1);
	}

	sniff_loop();

	exit(0);
}

int sniff_init(char *ebuf)
{
	char filter[BUFSIZ];
	libnet_t *ln;
	u_int32_t llip;
	struct libnet_ether_addr *llmac;
	u_int net, mask;
	struct bpf_program fcode;

	ln = libnet_init(LIBNET_LINK_ADV, interface, ebuf);
	if (ln == NULL)
		return 0;

	llip = libnet_get_ipaddr4(ln);
	llmac = libnet_get_hwaddr(ln);

	sniff_ll_len = 14; /* if libnet fails us here. */


	snprintf(filter, sizeof(filter),
		"ip and ether dst %x:%x:%x:%x:%x:%x and not dst %s and src %s and not ip broadcast",
		llmac->ether_addr_octet[0], llmac->ether_addr_octet[1],
		llmac->ether_addr_octet[2], llmac->ether_addr_octet[3],
		llmac->ether_addr_octet[4], llmac->ether_addr_octet[5],
		host, host);
		//printf("%s\n", filter);


	/* Open interface for sniffing, don't set promiscuous mode. */
	if (pcap_lookupnet(interface, &net, &mask, ebuf) == -1)
		return 0;

	if (!(sniff_pd = pcap_open_live(interface, BUFSIZ, 0, 1024, ebuf)))
		return 0;

	if (pcap_compile(sniff_pd, &fcode, filter, 1, mask) < 0) {
		strcpy(ebuf, pcap_geterr(sniff_pd));
		return 0;
	}
	if (pcap_setfilter(sniff_pd, &fcode) == -1) {
		strcpy(ebuf, pcap_geterr(sniff_pd));
		return 0;
	}

	return 1;
}

void sniff_loop()
{
	struct pcap_pkthdr pkthdr;
	struct ip *iph;
	u_char *pkt;
	int len;

	for (;;) {
		if ((pkt = (char *)pcap_next(sniff_pd, &pkthdr)) != NULL) {
			iph = (struct ip *)(pkt + sniff_ll_len);

			len = ntohs(iph->ip_len);
			if (len > pkthdr.len)
				len = pkthdr.len;

			send_packet(pkt + sniff_ll_len, len);
		}
	}
}

int send_init(char *ebuf)
{
	lnsock = libnet_init(LIBNET_RAW4_ADV, interface, ebuf);
	if (lnsock == NULL) {
		strcpy(ebuf, strerror(errno));
		return 0;
	}

	return 1;
}

int send_packet(u_char *pkt, int pktlen)
{
	static u_char opkt[IP_MAXPACKET];
	struct ip *iph = (struct ip *)pkt;
	int slen;

	/* Sanity checking. */
	if (pktlen < ntohs(iph->ip_len)) return 0;

	pktlen = ntohs(iph->ip_len);

	while ((slen = libnet_write_raw_ipv4(lnsock, pkt, pktlen)) != pktlen) {
		//perror("libnet_write_ip");
		//printf("send_packet failed: ");
		//printf("fail pktlen[%d] slen[%d]\n", pktlen, slen);
		return 0;
	}
	//print_ip(pkt, pktlen);

	return 1;
}

void print_ip(unsigned char *bp, int length)
{
	struct ip *iph;
	u_int ip_off, ip_hl, ip_len;

	iph = (struct ip *)bp;

	if (length < LIBNET_IPV4_H) {
		printf("truncated-ip %d", length);
		return;
	}
	ip_hl = iph->ip_hl * 4;
	ip_len = ntohs(iph->ip_len);

	if (length < ip_len) {
		printf("truncated-ip - %d bytes missing!", ip_len - length);
		return;
	}

	char src[16], dst[16], proto[16];
	strcpy(src, inet_ntoa(iph->ip_src));
	strcpy(dst, inet_ntoa(iph->ip_dst));
	switch (iph->ip_p)
	{
	case IPPROTO_TCP:  strcpy(proto, "TCP");  break;
	case IPPROTO_UDP:  strcpy(proto, "UDP");  break;
	case IPPROTO_ICMP: strcpy(proto, "ICMP"); break;
	default: strcpy(proto, "ETC"); break;
	}
	printf("[%d] %s > %s (%d bytes) %s\n", getpid(), src, dst, length, proto);
}

