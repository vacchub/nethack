#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdarg.h>

int hacklog(char *fname, char* fmt, ...)
{
	FILE *fp;
	struct tm *tm;
	time_t tt;
	char path[256];
	char buf[4*1024];
	va_list ap;

	if (fname == NULL)
		return 0;

	if (strlen(fname) == 0)
		return 0;

	tt = time(NULL);
	tm = localtime(&tt);

	memset(buf, 0x00, sizeof(buf));
	sprintf(buf, "[%02d:%02d:%02d][%d] ", 
			tm->tm_hour, tm->tm_min, tm->tm_sec, getpid());

	va_start(ap, fmt);
	vsprintf(buf + strlen(buf), fmt, ap);
	va_end(ap);

	sprintf(path, "./log/%s", fname);
	fp = fopen(path, "a+");
	if (fp == NULL)
		return -1;
	
	fprintf(fp, buf);
	fflush(fp);
	fclose(fp);
	return 0;
}
