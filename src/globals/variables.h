#ifndef GLOBALS_VARIABLES_H
#define GLOBALS_VARIABLES_H

#include <stdio.h>
#include <stdlib.h>
#include <net/if.h>
#include <linux/if_packet.h>

#define MTU 65536
#define LOGFILE_NAME "sniff.log"
#define IPV6_IDENTIFIER 56710

#ifndef GLOBALS_VARIABLES_IMPL
extern int sock_raw;
extern FILE *logfile;
extern struct ifreq INTERFACE;
extern struct sockaddr_ll sll;
extern unsigned char *buffer;
extern int tcp, udp, icmp, others, total, undefined;
#else
int sock_raw;
FILE *logfile;
struct ifreq INTERFACE;
struct sockaddr_ll sll;
unsigned char *buffer;
int tcp, udp, icmp, others, total, undefined;
#endif

#endif /* GLOBALS_VARIABLES_H */
