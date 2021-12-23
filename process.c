#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include "nethack.h"

char *ppath = "./log/proc_list";

/***********************************************************
 * proc_add()
 **********************************************************/
int proc_add(struct in_addr ipaddr)
{
	FILE *fp;
    char buff[32];

    fp = fopen(ppath, "a+");
    if (fp == NULL)
        return -1;

	memset(buff, 0x00, sizeof(buff));
	sprintf(buff, "%s\n", inet_ntoa(ipaddr));
    fprintf(fp, buff);
    fflush(fp);
    fclose(fp);
    return 0;
}

/***********************************************************
 * proc_chk()
 **********************************************************/
int proc_chk(struct in_addr ipaddr)
{
	FILE *fp;
    char buff[32];
	int cmplen;

    fp = fopen(ppath, "r");
    if (fp == NULL)
        return -1;

	cmplen = strlen(inet_ntoa(ipaddr));

	while (fgets(buff, sizeof(buff), fp) != NULL)
	{
		if (strlen(buff) - 1 == cmplen)
		{
			if (memcmp(buff, inet_ntoa(ipaddr), cmplen) == 0)
			{
				return 1;
			}
		}
	}
    fclose(fp);
	return 0;
}

