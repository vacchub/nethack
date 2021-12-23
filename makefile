CC      = gcc
CFLAGS  = -g -O2 -I/usr/include/glib-2.0 
LFLAGS  = -lpthread -lpcap -lpcre -lnet -lglib-2.0

OBJS1	= nethack.o network.o process.o ipscan_all.o ipscan_one.o attack_run.o hacklog.o
OBJS2	= attack.o arpspoof.o arp.o hacklog.o
OBJS3	= fragrouter.o hacklog.o
OBJS4	= sniff.o tls.o http.o arpspoof.o arp.o hacklog.o

all: nethack attack fragrouter sniff

nethack: $(OBJS1)
	$(CC) -o $@ $(OBJS1) $(CFLAGS) $(LFLAGS)

attack: $(OBJS2)
	$(CC) -o $@ $(OBJS2) $(CFLAGS) $(LFLAGS)

fragrouter: $(OBJS3)
	$(CC) -o $@ $(OBJS3) $(CFLAGS) $(LFLAGS)

sniff: $(OBJS4)
	$(CC) -o $@ $(OBJS4) $(CFLAGS) $(LFLAGS)

nethack.o: nethack.h nethack.c
network.o: nethack.h network.c
process.o: nethack.h process.c
ipscan_all.o: nethack.h ipscan_all.c
ipscan_one.o: nethack.h ipscan_one.c
attack_run.o: nethack.h attack_run.c
attack.o: nethack.h attack.c
fragrouter.o: nethack.h fragrouter.c
sniff.o: nethack.h sniff.c
tls.o: nethack.h tls.c
http.o: nethack.h http.c
arpspoof.o: arp.h nethack.h arpspoof.c
arp.o: arp.h nethack.h arp.c
hacklog.o: nethack.h hacklog.c

clean:
	rm -f *~ *.o
