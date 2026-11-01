#ifndef MODULES_H
#define MODULES_H

#include "functions.h"
#include "variables.h"

// Check if given interface is wireless
static inline int CHECK_WIRELESS(const char* ifname, char* protocol)
{
    int sock = -1;
    struct iwreq pwrq;
    memset(&pwrq, 0, sizeof(pwrq));
    strncpy(pwrq.ifr_name, ifname, IFNAMSIZ - 1);
    
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) 
    {
        return 0;
    }

    if (ioctl(sock, SIOCGIWNAME, &pwrq) != -1)
    {
        if (protocol)
        {
            strncpy(protocol, pwrq.u.name, IFNAMSIZ - 1);
        }
        close(sock);
        return 1;
    }
    close(sock);
    return 0;
}

// List all available network interfaces
static inline int GET_INTERFACES(void)
{
    struct ifaddrs *addresses;
    struct ifaddrs *address;

    if (getifaddrs(&addresses) == -1)
    {
        fprintf(stderr,"[" RED("-") "]" RED("getifaddrs") "failed\n");
        return -1;
    }
    address = addresses;
    fprintf(stdout,CYAN("==========")MAGENTA(" Available Interfaces ")CYAN("==========")"\n");

    while(address)
    {
        char addr[INET6_ADDRSTRLEN]={};
        char protocol[IFNAMSIZ]={};

        if (address->ifa_addr)
        {
            int family = address->ifa_addr->sa_family;
            if (family == AF_INET || family == AF_INET6)
            {
                fprintf(stdout,GREEN("%s") "\t", address->ifa_name);
                if (family == AF_INET)
                {
                    fprintf(stdout,YELLOW("%s") "\t","IPv4");
                    struct sockaddr_in *in = (struct sockaddr_in*) address->ifa_addr;
                    inet_ntop(AF_INET, &in->sin_addr, addr, INET_ADDRSTRLEN);
                }
                else
                {
                    fprintf(stdout,YELLOW("%s") "\t","IPv6");
                    struct sockaddr_in6 *in6 = (struct sockaddr_in6*) address->ifa_addr;
                    inet_ntop(AF_INET6, &in6->sin6_addr, addr, sizeof(addr));
                }

                if (CHECK_WIRELESS(address->ifa_name,protocol))
                {
                    fprintf(stdout,RED("%s") " (%s)\n",addr,protocol);
                }
                else
                {
                    fprintf(stdout,RED("%s") "\n",addr);
                }
            }
        }
        address = address->ifa_next;
    }

    freeifaddrs(addresses);
    return 0;
}

// Init Socket
static inline int INIT_SOCKET(void)
{
    sock_raw = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
    if (sock_raw < 0)
    {
        fprintf(stderr,"[" RED("-") "] Failed Initializing " RED("Raw Socket") " (Check CAP_NET_RAW / sudo)\n");
        exit(EXIT_FAILURE); 
    }
    fprintf(stdout,"[" GREEN("+") "] Successfully Created " GREEN("Raw Socket") "\n" );
    return 0;
}

// Get Index Of The Interface
static inline int INIT_INTERFACE(char *name)
{
    memset(&INTERFACE,0,sizeof(INTERFACE));
    strncpy((char *)INTERFACE.ifr_name,name,IFNAMSIZ - 1);
    
    if ((ioctl(sock_raw,SIOCGIFINDEX,&INTERFACE))==-1)
    {
        fprintf(stderr,"[" RED("-") "] Error Fetching Interface: " RED("%s") "\n",name);
        GET_INTERFACES();
        exit(EXIT_FAILURE);
    }
    fprintf(stdout,"[" GREEN("+") "] Successfully Indexed " GREEN("%s") "\n",name);

    memset(&sll,0,sizeof(sll));
    sll.sll_family=AF_PACKET;
    sll.sll_ifindex=INTERFACE.ifr_ifindex;
    sll.sll_protocol=htons(ETH_P_ALL);

    return 0;
}

// Bind Socket To Interface
static inline int BIND_SOCKET(void)
{
    if ((bind(sock_raw,(struct  sockaddr *)&sll, sizeof(sll)))==-1)
    {
        fprintf(stderr,"[" RED("-") "] Cannot Bind " YELLOW("Raw Socket") " to " RED("%s") "\n",INTERFACE.ifr_name);
        return -1;
    }
    return 0;
}

// Initiate Logs
static inline int INIT_LOGS(void)
{
    logfile = fopen(LOGFILE_NAME,"w");
    if(logfile==NULL)
    {
        fprintf(stderr,"[" RED("-") "] Could Not Open " RED("%s") " For Writing\n",LOGFILE_NAME);
        return -1;
    }
    else
    {
        fprintf(stdout,"[" GREEN("+") "] Log File " CYAN("%s") "\n",LOGFILE_NAME);
        return 0;
    }
}

// Cleanup after done
static inline void CLEANUP(void)
{
    if (logfile) {
        fprintf(logfile,"\n================= Result =================\n");
        fprintf(logfile,"|- TCP: %d\n|- UDP: %d\n|- ICMP: %d\n|- Others : %d\n|- Undefined: %d\n|- Total : %d\n",tcp,udp,icmp,others,undefined,total);
        fprintf(logfile,"==========================================\n");
        fclose(logfile);
        logfile = NULL;
    }

    fprintf(stdout,"\n"CYAN("=================")MAGENTA(" RESULT ")CYAN("=================")"\n");
    fprintf(stdout,CYAN("|-")" " YELLOW("TCP") ": " GREEN("%d") "\n" CYAN("|-")" "YELLOW("UDP") ": " GREEN("%d")"\n" CYAN("|-")" " YELLOW("ICMP")": " GREEN("%d") "\n" CYAN("|-")" "YELLOW("Others")": " GREEN("%d") "\n" CYAN("|-")" " YELLOW("Undefined") ": " GREEN("%d") "\n" CYAN("|-")" " GREEN("Total") ": " GREEN("%d")"\n",tcp,udp,icmp,others,undefined,total);
    fprintf(stdout,CYAN("==========================================\n"));
    fprintf(stdout,"[" GREEN("+") "] Wrote Logs To " BLUE("%s") "\n",LOGFILE_NAME);

    if (buffer) {
        free(buffer);
        buffer = NULL;
    }
    if (sock_raw >= 0) {
        close(sock_raw);
        sock_raw = -1;
    }
}

static volatile sig_atomic_t g_legacy_stop = 0;

static inline void SIGNINT_HANDLER(int dummy)
{
    (void)dummy;
    g_legacy_stop = 1;
}

#endif /* MODULES_H */
