#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap/pcap.h>
#include <pcre.h>
#include <assert.h>
#include "tls_api.h"
#include "http_api.h"
#include "nethack.h"

/* Ethernet */

#define ETH_ALEN 6

struct ether_header
{
  uint8_t  ether_dhost[ETH_ALEN];
  uint8_t  ether_shost[ETH_ALEN];
  uint16_t ether_type;
} __attribute__ ((__packed__));

#define ETHERTYPE_IP 0x0800 /* IP */
#define SIZE_ETHERNET sizeof(struct ether_header)


/* IP */

struct my_iphdr
{
  uint8_t  vhl;
#define IP_HL(ip) (((ip)->vhl) & 0x0F)
#define IP_V(ip)  (((ip)->vhl) >> 4)
  uint8_t  tos;
  uint16_t tot_len;
  uint16_t id;
  uint16_t frag_off;
  uint8_t  ttl;
  uint8_t  protocol;
  uint16_t check;
  uint32_t saddr;
  uint32_t daddr;
  /*The options start here. */
} __attribute__ ((__packed__));

#define MIN_SIZE_IP (sizeof(struct my_iphdr))
#define MAX_SIZE_IP (0xF * sizeof(uint32_t))

#define IPVERSION 4


/* TCP */

struct my_tcphdr
{
  uint16_t source;
  uint16_t dest;
  uint32_t seq;
  uint32_t ack_seq;
  uint8_t  res1doff;
#define TCP_OFF(th)      (((th)->res1doff & 0xF0) >> 4)
	uint8_t  flags;
#define TCP_FIN  (0x1 << 0)
#define TCP_SYN  (0x1 << 1)
#define TCP_RST  (0x1 << 2)
#define TCP_PUSH (0x1 << 3)
#define TCP_ACK  (0x1 << 4)
#define TCP_URG  (0x1 << 5)
#define TCP_ECE  (0x1 << 6)
#define TCP_CWR  (0x1 << 7)
  uint16_t window;
  uint16_t check;
  uint16_t urg_ptr;
} __attribute__ ((__packed__));

#define MIN_SIZE_TCP (sizeof(struct my_tcphdr))
#define MAX_SIZE_TCP (0xF * sizeof(uint32_t))

/* UDP */

struct udphdr
{
  uint16_t source;
  uint16_t dest;
  uint16_t len;
  uint16_t check;
} __attribute__ ((__packed__));

#define MIN_SIZE_UDP (sizeof(struct udphdr))


/* converts 16 bits in host byte order to 16 bits in network byte order */
#if !__BIG_ENDIAN__
#define h16ton16(n) \
((uint16_t) (((uint16_t) n) << 8) | (uint16_t) (((uint16_t) n) >> 8))
#else
#define h16ton16(n) (n)
#endif

#define n16toh16(n) h16ton16(n)

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)


pcap_t *pcap_handle;


struct my_iphdr *ip;

uint16_t src_port;
uint16_t dst_port;


uint8_t flag_sni_available;

int sni_handler (uint8_t *host_name, uint16_t host_name_length) {
	uint16_t i;
	char log_f[64], buff[512], logmsg[512];

	memset(buff, 0x00, sizeof(buff));
	memset(logmsg, 0x00, sizeof(logmsg));

#if 1
	sprintf(buff, "%u.%u.%u.%u:%u -> %u.%u.%u.%u:[%u] ",
		*(((uint8_t *)&(ip->saddr)) + 0),
		*(((uint8_t *)&(ip->saddr)) + 1),
		*(((uint8_t *)&(ip->saddr)) + 2),
		*(((uint8_t *)&(ip->saddr)) + 3),
		n16toh16(src_port),
		*(((uint8_t *)&(ip->daddr)) + 0),
		*(((uint8_t *)&(ip->daddr)) + 1),
		*(((uint8_t *)&(ip->daddr)) + 2),
		*(((uint8_t *)&(ip->daddr)) + 3),
		n16toh16(dst_port));
	strcat(logmsg, buff);
#else
	sprintf(buff, "%u.%u.%u.%u:[%u] ",
		*(((uint8_t *)&(ip->daddr)) + 0),
		*(((uint8_t *)&(ip->daddr)) + 1),
		*(((uint8_t *)&(ip->daddr)) + 2),
		*(((uint8_t *)&(ip->daddr)) + 3),
		n16toh16(dst_port));
	strcat(logmsg, buff);
#endif

	memset(buff, 0x00, sizeof(buff));
	//sprintf(buff, "%u:", host_name_length);
	//strcat(logmsg, buff);

	for (i = 0; i < host_name_length; i++) {
		sprintf(buff, "%c", host_name[i]);
		strcat(logmsg, buff);
	}
	sprintf(buff, "\n");
	strcat(logmsg, buff);

	memset(log_f, 0x00, sizeof(log_f));
	sprintf(log_f, "./%u.%u.%u.%u", 
		*(((uint8_t *)&(ip->saddr)) + 0),
        *(((uint8_t *)&(ip->saddr)) + 1),
        *(((uint8_t *)&(ip->saddr)) + 2),
        *(((uint8_t *)&(ip->saddr)) + 3));
	hacklog(log_f, logmsg, strlen(logmsg));

	flag_sni_available = 1;

	return 0;
}


void my_pcap_handler (uint8_t *user, const struct pcap_pkthdr *header,
	const uint8_t *packet)
{
	struct ether_header *ether;
	struct my_tcphdr *tcp;
	struct udphdr *udp;

	uint8_t *payload;
	uint16_t payload_length;

	uint16_t r;

	if (header->caplen < header->len) {
		return;
	}

	/* Process ethernet header */
	assert(header->caplen >= SIZE_ETHERNET);

	ether = (struct ether_header *) packet;
	if (unlikely(ether->ether_type != h16ton16(ETHERTYPE_IP))) {
		return;
	}

	/* Process IP header */
	assert(header->caplen >= SIZE_ETHERNET + MIN_SIZE_IP);

	ip = (struct my_iphdr *) (packet + SIZE_ETHERNET);
	if (unlikely(IP_V(ip) != IPVERSION)) {
		return;
	}

	switch(ip->protocol) {
	case IPPROTO_TCP: 
		/* Process TCP header */
		assert(header->caplen >=
			SIZE_ETHERNET + (IP_HL(ip) * sizeof(uint32_t)) + MIN_SIZE_TCP);

		tcp = (struct my_tcphdr *)
			(packet + SIZE_ETHERNET + (IP_HL(ip) * sizeof(uint32_t)));
		src_port = tcp->source;
		dst_port = tcp->dest;

		/* Make sure we have captured the entire packet. */
		assert(header->caplen >= SIZE_ETHERNET +
			(IP_HL(ip) * sizeof(uint32_t)) + (TCP_OFF(tcp) * sizeof(uint32_t)));

		/* Figure out payload. */
		payload = (uint8_t *)
			(packet + SIZE_ETHERNET + (IP_HL(ip) * sizeof(uint32_t)) +
			(TCP_OFF(tcp) * sizeof(uint32_t)));
		payload_length = header->caplen - SIZE_ETHERNET -
			(IP_HL(ip) * sizeof(uint32_t)) - (TCP_OFF(tcp) * sizeof(uint32_t));
		break;
	case IPPROTO_UDP:
		/* Process UDP header */
		assert(header->caplen >=
			SIZE_ETHERNET + (IP_HL(ip) * sizeof(uint32_t)) + MIN_SIZE_UDP);
		udp = (struct udphdr *)
			(packet + SIZE_ETHERNET + (IP_HL(ip) * sizeof(uint32_t)));
		src_port = udp->source;
		dst_port = udp->dest;

		/* Make sure we have captured the entire packet. */
		assert(header->caplen >= SIZE_ETHERNET +
			(IP_HL(ip) * sizeof(uint32_t)) + sizeof(struct udphdr));

		/* Figure out payload. */
		payload = (uint8_t *)
			(packet + SIZE_ETHERNET + (IP_HL(ip) * sizeof(uint32_t)) +
			sizeof(struct udphdr));
		payload_length = header->caplen - SIZE_ETHERNET -
			(IP_HL(ip) * sizeof(uint32_t)) - sizeof(struct udphdr);
		break;
	default:
		src_port = 0;
		dst_port = 0;
		payload = NULL;
		payload_length = 0;
		break;
	}

	if (payload_length == 0 || payload == NULL) {
		return;
	}

	/* Reset flag_sni_available. If it is set following any of the processing
	 * engines we know we have found the server's name and we can stop.
	 */
	flag_sni_available = 0;

	r = tls_process_record(payload, payload_length);

	/* If flag_sni_available then we have done. */
	/* If we have processed more than zero bytes then we are (probably) done. */
	if (flag_sni_available || r != 0) {
		return;
	}

	r = http_process_request(payload, payload_length);
	if (flag_sni_available || r != 0) {
		return;
	}

	return;
}


void signal_handler (int signum)
{
	switch(signum) {
	case SIGTERM:
	case SIGINT:
	case SIGSEGV:
		fprintf(stdout, "\n");
		pcap_breakloop(pcap_handle);
		break;
	default:
		break;
	}
}

#define SNAPLEN 65535
#define PCAP_TIMEOUT 1000

#define BPF_DEFAULT \
	"ip and tcp and (tcp[tcpflags] & tcp-push == tcp-push) and " \
	"(dst port 80 or dst port 443)"
#define BPF_OPTIMIZE 1

int main (int argc, char *argv[])
{
	char    interface[12];
	char    host[16];
	char errbuf[PCAP_ERRBUF_SIZE];
	char bpf_default[256];
	struct bpf_program bpf;
	struct pcap_stat ps;
	struct sigaction act;

	memset(errbuf, 0, PCAP_ERRBUF_SIZE);

	if (argc != 3)
    {
        printf("%s interface host\n", argv[0]);
        return 0;
    }

	memset(interface, 0x00, sizeof(interface));
	strcat(interface, argv[1]);

	memset(host, 0x00, sizeof(host));
	strcat(host, argv[2]);

	memset(bpf_default, 0, sizeof(bpf_default));
	sprintf(bpf_default, "ip and tcp and (tcp[tcpflags] & tcp-push == tcp-push) and (dst port 80 or dst port 443) and (src %s) ", host); 
	//printf("%s\n", bpf_default);


	/* 1 : promisc/monitor mode	*/
	if (!(pcap_handle = pcap_open_live(interface, SNAPLEN, 1, 
			PCAP_TIMEOUT, errbuf))) {
			fprintf(stderr, "[FATAL] %s\n", errbuf);
			return -1;
		}

	if (pcap_compile(pcap_handle, &bpf, bpf_default, BPF_OPTIMIZE,
		PCAP_NETMASK_UNKNOWN) == -1) {
		fprintf(stderr, "[FATAL] Couldn't parse filter. %s\n",
			pcap_geterr(pcap_handle));
		pcap_close(pcap_handle);
		return -1;
	}

	if (pcap_setfilter(pcap_handle, &bpf) == -1) {
		fprintf(stderr, "[FATAL] Couldn't install filter. %s\n",
			pcap_geterr(pcap_handle));
		pcap_close(pcap_handle);
		return -1;
	}

	pcap_freecode(&bpf);

	tls_set_callback_handshake_clienthello_servername(&sni_handler);
	http_set_callback_request_host(&sni_handler);

	http_init();

	act.sa_handler = signal_handler;
	sigemptyset (&act.sa_mask);
	act.sa_flags = 0;

	if (sigaction(SIGINT, &act, NULL)) {
		perror("sigaction");
		fprintf(stderr,
			"[WARNING] Failed to set signal handler for SIGINT.\n");
	}

	if (sigaction(SIGTERM, &act, NULL)) {
		perror("sigaction");
		fprintf(stderr,
			"[WARNING] Failed to set signal handler for SIGTERM.\n");
	}

	if (sigaction(SIGSEGV, &act, NULL)) {
		perror("sigaction");
		fprintf(stderr,
			"[WARNING] Failed to set signal handler for SIGSEGV.\n");
	}

	if (pcap_loop(pcap_handle, -1, &my_pcap_handler, NULL) == -1) {
		fprintf(stderr, "[FATAL] pcap_loop failed. %s\n",
			pcap_geterr(pcap_handle));
	}

	if (pcap_stats(pcap_handle, &ps) == -1) {
		fprintf(stderr, "pcap_stats failed. %s\n", pcap_geterr(pcap_handle));
	} 

	pcap_close(pcap_handle);
	http_cleanup();

	return 0;
}
