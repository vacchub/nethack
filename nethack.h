#ifndef NETHACK_H
#define NETHACK_H

#include <glib.h>
#include <arpa/inet.h>


#define MODE_NONE	0x01
#define MODE_ARP1	0x02
#define MODE_ARP2	0x04
#define MODE_PSND	0x08
#define MODE_FRAG	0x10
#define MODE_SNIF	0x20

/***********************************************************
 * handle
 **********************************************************/
struct handle {
    char interface[12];
    struct in_addr host;
    struct in_addr gateway;
    struct in_addr netmask;
    unsigned char mac[6];
	int mode;
	int (*ipscan)();
};
typedef struct handle handle;



/* network			*/
int network_analysis(handle *, char *, char *, int);

/* process			*/
int proc_add(struct in_addr);
int proc_chk(struct in_addr);

/* ipscan_all		*/
int ipscan_all(handle *);

/* ipscan_one		*/
int ipscan_one(handle *);

/* attack_run		*/
int attack_run(handle *, struct in_addr);

/* arpspoof		*/
int arpspoof(char *, char *, char *, char *);

/* hacklog		*/
int hacklog(char *, char *, ...);


#endif
