#ifndef PACKETINFO_H
#define PACKETINFO_H

#include "modules.h"
#include "miscellaneous.h"

// Print UDP Packet
static inline void PRINT_UDP_PACKET(unsigned char *buf, int len, int ip_hdr_len)
{
    int offset = sizeof(struct ethhdr) + ip_hdr_len;
    if (len < offset + (int)sizeof(struct udphdr)) 
    {
        INVALID_CAPTURE("UDP", logfile, stdout);
        return;
    }

    struct udphdr udph;
    memcpy(&udph, buf + offset, sizeof(udph));

    fprintf(stdout,CYAN("---------------")" " MAGENTA("UDP Packet")" " CYAN("---------------")"\n");
    if (logfile) fprintf(logfile,"--------------- UDP Packet ---------------\n");

    fprintf(stdout,CYAN("|-") " " YELLOW("Source Port") ": " GREEN("%u")"\n", ntohs(udph.source));
    if (logfile) fprintf(logfile,"|- Source Port: %u\n", ntohs(udph.source));
    
    fprintf(stdout,CYAN("|-") " " YELLOW("Destination Port") ": " GREEN("%u")"\n", ntohs(udph.dest));
    if (logfile) fprintf(logfile,"|- Destination Port: %u\n", ntohs(udph.dest));

    fprintf(stdout,CYAN("|-") " " YELLOW("UDP Length") ": " GREEN("%u") "\n",ntohs(udph.len));
    if (logfile) fprintf(logfile,"|- UDP Length: %u\n",ntohs(udph.len));
    
    fprintf(stdout,CYAN("|-") " " YELLOW("UDP Checksum") ": " GREEN("%u")"\n",ntohs(udph.check));
    if (logfile) fprintf(logfile,"|- UDP Checksum: %u\n",ntohs(udph.check));

    int payload_offset = offset + sizeof(struct udphdr);
    int payload_len = len - payload_offset;
    if (payload_len > 0)
    {
        HEX_P(stdout,CYAN("|-") " "YELLOW("Payload") ": \n", buf + payload_offset, payload_len);
        if (logfile) HEX_P(logfile,"|- Payload:\n", buf + payload_offset, payload_len);
    }
}

// Print TCP Packet
static inline void PRINT_TCP_PACKET(unsigned char *buf, int len, int ip_hdr_len)
{
    int offset = sizeof(struct ethhdr) + ip_hdr_len;
    if (len < offset + (int)sizeof(struct tcphdr)) 
    {
        INVALID_CAPTURE("TCP", logfile, stdout);
        return;
    }

    struct tcphdr tcph;
    memcpy(&tcph, buf + offset, sizeof(tcph));

    int tcp_hdr_len = tcph.doff * 4;
    if (tcp_hdr_len < 20 || len < offset + tcp_hdr_len)
    {
        INVALID_CAPTURE("TCP Options", logfile, stdout);
        return;
    }

    fprintf(stdout,CYAN("---------------")" " MAGENTA("TCP Packet")" " CYAN("---------------")"\n");
    if (logfile) fprintf(logfile,"--------------- TCP Packet ---------------\n");

    fprintf(stdout,CYAN("|-") " " YELLOW("Source Port") ": " GREEN("%u")"\n", ntohs(tcph.source));
    if (logfile) fprintf(logfile,"|- Source Port: %u\n", ntohs(tcph.source));
    
    fprintf(stdout,CYAN("|-") " " YELLOW("Destination Port") ": " GREEN("%u")"\n", ntohs(tcph.dest));
    if (logfile) fprintf(logfile,"|- Destination Port: %u\n", ntohs(tcph.dest));

    fprintf(stdout,CYAN("|-") " " YELLOW("Sequence Number") ": " GREEN("%u") "\n",ntohl(tcph.seq));
    if (logfile) fprintf(logfile,"|- Sequence Number: %u\n",ntohl(tcph.seq));
    
    fprintf(stdout,CYAN("|-") " " YELLOW("Acknowledge Number") ": " GREEN("%u")"\n",ntohl(tcph.ack_seq));
    if (logfile) fprintf(logfile,"|- Acknowledge Number: %u\n",ntohl(tcph.ack_seq));

    fprintf(stdout,CYAN("|-")" " YELLOW("TCP Header Length") ": " GREEN("%d") " " BLUE("DWORDS") " " YELLOW("or") " " GREEN("%d") " " BLUE("Bytes") "\n",(unsigned int)tcph.doff,(unsigned int)tcph.doff*4);
    if (logfile) fprintf(logfile,"|- TCP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)tcph.doff,(unsigned int)tcph.doff*4);  

    fprintf(stdout,CYAN("|-") " " YELLOW("CWR Flag") ":    "GREEN("%d")"\n",(unsigned int)tcph.cwr);
    if (logfile) fprintf(logfile,"|- CWR Flag:    %d\n",(unsigned int)tcph.cwr);

    fprintf(stdout,CYAN("|-") " " YELLOW("ECN Flag") ":    "GREEN("%d")"\n",(unsigned int)tcph.ece);
    if (logfile) fprintf(logfile,"|- ECN Flag:    %d\n",(unsigned int)tcph.ece);

    fprintf(stdout,CYAN("|-") " "YELLOW("Urgent Flag") ": "GREEN("%d")"\n",(unsigned int)tcph.urg);
    if (logfile) fprintf(logfile,"|- Urgent Flag: %d\n",(unsigned int)tcph.urg);

    fprintf(stdout,CYAN("|-") " "YELLOW("Ack Flag") ":    "GREEN("%d")"\n",(unsigned int)tcph.ack);
    if (logfile) fprintf(logfile,"|- Ack Flag:    %d\n",(unsigned int)tcph.ack);

    fprintf(stdout,CYAN("|-") " "YELLOW("Push Flag") ":   "GREEN("%d")"\n",(unsigned int)tcph.psh);
    if (logfile) fprintf(logfile,"|- Push Flag:   %d\n",(unsigned int)tcph.psh);

    fprintf(stdout,CYAN("|-") " "YELLOW("Reset Flag") ":  "GREEN("%d")"\n",(unsigned int)tcph.rst);
    if (logfile) fprintf(logfile,"|- Reset Flag:  %d\n",(unsigned int)tcph.rst);

    fprintf(stdout,CYAN("|-") " "YELLOW("Syn Flag") ":    "GREEN("%d")"\n",(unsigned int)tcph.syn);
    if (logfile) fprintf(logfile,"|- Syn Flag:    %d\n",(unsigned int)tcph.syn);

    fprintf(stdout,CYAN("|-") " "YELLOW("Fin Flag") ":    "GREEN("%d")"\n",(unsigned int)tcph.fin);
    if (logfile) fprintf(logfile,"|- Fin Flag:    %d\n",(unsigned int)tcph.fin);

    fprintf(stdout,CYAN("|-") " "YELLOW("Window") ": "GREEN("%d")"\n",ntohs(tcph.window));
    if (logfile) fprintf(logfile,"|- Window: %d\n",ntohs(tcph.window));

    fprintf(stdout,CYAN("|-") " "YELLOW("Checksum") ": "GREEN("%d")"\n",ntohs(tcph.check));
    if (logfile) fprintf(logfile,"|- Checksum: %d\n",ntohs(tcph.check));

    fprintf(stdout,CYAN("|-") " "YELLOW("Urgent Pointer") ": "GREEN("%d")"\n",ntohs(tcph.urg_ptr));
    if (logfile) fprintf(logfile,"|- Urgent Pointer: %d\n",ntohs(tcph.urg_ptr));

    int payload_offset = offset + tcp_hdr_len;
    int payload_len = len - payload_offset;
    if (payload_len > 0)
    {
        HEX_P(stdout,CYAN("|-") " "YELLOW("Payload") ": \n", buf + payload_offset, payload_len);
        if (logfile) HEX_P(logfile,"|- Payload:\n", buf + payload_offset, payload_len);
    }
}

// Print ICMP Packet
static inline void PRINT_ICMP_PACKET(unsigned char *buf, int len, int ip_hdr_len)
{
    int offset = sizeof(struct ethhdr) + ip_hdr_len;
    if (len < offset + (int)sizeof(struct icmphdr))
    {
        INVALID_CAPTURE("ICMP", logfile, stdout);
        return;
    }

    struct icmphdr icmph;
    memcpy(&icmph, buf + offset, sizeof(icmph));

    fprintf(stdout,CYAN("------------------")" " MAGENTA("ICMP")" " CYAN("------------------")"\n");
    if (logfile) fprintf(logfile,"------------------ ICMP ------------------\n");

    fprintf(stdout,CYAN("|-") " " YELLOW("Type") ": " GREEN("%d") " (" BLUE("%s") ")" "\n",(unsigned int)(icmph.type),GET_ICMP_PROTO((unsigned int)(icmph.type)));
    if (logfile) fprintf(logfile,"|- Type: %d (%s)\n",(unsigned int)(icmph.type),GET_ICMP_PROTO((unsigned int)(icmph.type)));

    fprintf(stdout,CYAN("|-") " "YELLOW("Code") ": " GREEN("%d") "\n", (unsigned int)(icmph.code));
    if (logfile) fprintf(logfile,"|- Code: %d\n", (unsigned int)(icmph.code));        

    fprintf(stdout,CYAN("|-") " " YELLOW("Checksum") ": " GREEN("%d") "\n",ntohs(icmph.checksum));
    if (logfile) fprintf(logfile,"|- Checksum : %d\n",ntohs(icmph.checksum));

    int payload_offset = offset + sizeof(struct icmphdr);
    int payload_len = len - payload_offset;
    if (payload_len > 0)
    {
        HEX_P(stdout,CYAN("|-") " "YELLOW("Packet Dump") ": \n", buf + payload_offset, payload_len);
        if (logfile) HEX_P(logfile,"|- Packet Dump :\n", buf + payload_offset, payload_len);
    }
}

// Print IP Header
static inline unsigned int PRINT_IP_PACKET(unsigned char *buf, int len, int *out_ip_hdr_len)
{
    struct sockaddr_in source, dest;
    memset(&source, 0, sizeof(source));
    struct iphdr iph;
    memcpy(&iph, buf + sizeof(struct ethhdr), sizeof(iph));
    
    source.sin_addr.s_addr = iph.saddr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph.daddr;

    int ip_len = iph.ihl * 4;
    if (out_ip_hdr_len) *out_ip_hdr_len = ip_len;

    fprintf(stdout, CYAN("|-") " " YELLOW("Version") ": " GREEN("IPv%d")"\n",(unsigned int)iph.version);   
    if (logfile) fprintf(logfile, "|- Version: IPv%d\n",(unsigned int)iph.version);       
    
    fprintf(stdout,CYAN("|-")" " YELLOW("IP Header Length") ": " GREEN("%d") " " BLUE("DWORDS") " " YELLOW("or") " " GREEN("%d") " " BLUE("Bytes") "\n",(unsigned int)iph.ihl, ip_len);
    if (logfile) fprintf(logfile,"|- IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph.ihl, ip_len);
  
    fprintf(stdout,CYAN("|-") " " YELLOW("Type Of Service") ": " GREEN("%d") "\n",(unsigned int)iph.tos);
    if (logfile) fprintf(logfile,"|- Type Of Service   : %d\n",(unsigned int)iph.tos);

    fprintf(stdout,CYAN("|-") " " YELLOW("Total Length") ": " GREEN("%d") " " BLUE("Bytes") YELLOW("(Size of Packet)") "\n",ntohs(iph.tot_len));
    if (logfile) fprintf(logfile,"|- Total Length: %d  Bytes(Size of Packet)\n",ntohs(iph.tot_len));

    fprintf(stdout,CYAN("|-") " " YELLOW("Identification") ": " GREEN("%d") "\n",ntohs(iph.id));
    if (logfile) fprintf(logfile,"|- Identification: %d\n",ntohs(iph.id));
    
    fprintf(stdout,CYAN("|-") " " YELLOW("TTL")": " GREEN("%d")"\n",(unsigned int)iph.ttl);
    if (logfile) fprintf(logfile,"|- TTL: %d\n",(unsigned int)iph.ttl);

    fprintf(stdout,CYAN("|-") " " YELLOW("Protocol") ": " GREEN("%d") " (" BLUE("%s") ")" "\n",(unsigned int)iph.protocol,GET_IP_PROTO((unsigned int)iph.protocol));
    if (logfile) fprintf(logfile,"|- Protocol: %d (%s)\n",(unsigned int)iph.protocol,GET_IP_PROTO((unsigned int)iph.protocol));
    
    fprintf(stdout,CYAN("|-") " " YELLOW("Checksum") ": " GREEN("%d") "\n",ntohs(iph.check));
    if (logfile) fprintf(logfile,"|- Checksum: %d\n",ntohs(iph.check));
    
    fprintf(stdout,CYAN("|-") " " YELLOW("Source IP")": "GREEN("%s") "\n",inet_ntoa(source.sin_addr));
    if (logfile) fprintf(logfile,"|- Source IP: %s\n",inet_ntoa(source.sin_addr));
    
    fprintf(stdout,CYAN("|-") " " YELLOW("Destination IP")": "GREEN("%s") "\n",inet_ntoa(dest.sin_addr));
    if (logfile) fprintf(logfile,"|- Destination IP: %s\n",inet_ntoa(dest.sin_addr));

    return (unsigned int)iph.protocol;
}

// Print Information About The Packet
static inline void PRINT_PACKET_INFO(unsigned char* buf, int size)
{
    ++total;
    if(size >= (int)sizeof(struct ethhdr))
    {
        if (logfile) fprintf(logfile,"\n================= Packet =================\n");
        fprintf(stdout,"\n"CYAN("=================")MAGENTA(" Packet ")CYAN("=================")"\n");
        
        struct ethhdr ethernet_header;
        memcpy(&ethernet_header, buf, sizeof(ethernet_header));
        uint16_t proto = ntohs(ethernet_header.h_proto);

        fprintf(stdout,CYAN("----------------")" " MAGENTA("Ethernet")" " CYAN("----------------")"\n");
        if (logfile) fprintf(logfile,"---------------- Ethernet ----------------\n");
        fprintf(stdout,CYAN("|- ") YELLOW("Source Address") ": " GREEN("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X") "\n",ethernet_header.h_source[0],ethernet_header.h_source[1],ethernet_header.h_source[2],ethernet_header.h_source[3],ethernet_header.h_source[4],ethernet_header.h_source[5]);
        fprintf(stdout,CYAN("|- ") YELLOW("Destination Address") ": " GREEN("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X") "\n",ethernet_header.h_dest[0],ethernet_header.h_dest[1],ethernet_header.h_dest[2],ethernet_header.h_dest[3],ethernet_header.h_dest[4],ethernet_header.h_dest[5]);
        fprintf(stdout,CYAN("|- ") YELLOW("Protocol") ": " GREEN("%d") " ("BLUE("%s")")" "\n", proto, GET_ETHER_PROTO(proto));

        if (logfile) {
            fprintf(logfile,"|- Source Address : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",ethernet_header.h_source[0],ethernet_header.h_source[1],ethernet_header.h_source[2],ethernet_header.h_source[3],ethernet_header.h_source[4],ethernet_header.h_source[5]);
            fprintf(logfile,"|- Destination Address : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",ethernet_header.h_dest[0],ethernet_header.h_dest[1],ethernet_header.h_dest[2],ethernet_header.h_dest[3],ethernet_header.h_dest[4],ethernet_header.h_dest[5]);
            fprintf(logfile,"|- Protocol : %d (%s)\n", proto, GET_ETHER_PROTO(proto));
        }

        if (proto == ETH_P_IP && size >= (int)(sizeof(struct ethhdr) + sizeof(struct iphdr)))
        {
            int ip_hdr_len = 20;
            fprintf(stdout,CYAN("-------------------")" " MAGENTA("IP")" " CYAN("-------------------")"\n");
            if (logfile) fprintf(logfile,"------------------- IP -------------------\n");
            unsigned int IP_PROTO = PRINT_IP_PACKET(buf, size, &ip_hdr_len);
            switch(IP_PROTO)
            {
                case IPPROTO_ICMP:
                    ++icmp;
                    PRINT_ICMP_PACKET(buf, size, ip_hdr_len);
                    break;
                case IPPROTO_TCP:
                    ++tcp;
                    PRINT_TCP_PACKET(buf, size, ip_hdr_len);
                    break;
                case IPPROTO_UDP:
                    ++udp;
                    PRINT_UDP_PACKET(buf, size, ip_hdr_len);
                    break;
                default:
                    ++others;
                    fprintf(stdout,CYAN("|-") " " YELLOW("Unsupported Protocol")" " MAGENTA(":(")"\n");
                    if (logfile) fprintf(logfile,"|- Unsupported Protocol :(\n");
                    HEX_P(stdout,YELLOW("|-") " " RED("Complete Packet Dump") "\n", buf + sizeof(struct ethhdr) + ip_hdr_len, size - sizeof(struct ethhdr) - ip_hdr_len);
                    if (logfile) HEX_P(logfile,"|- Complete Packet Dump\n", buf + sizeof(struct ethhdr) + ip_hdr_len, size - sizeof(struct ethhdr) - ip_hdr_len);
                    break;
            }
        }
        else if (proto != ETH_P_IP && size >= (int)sizeof(struct ethhdr))
        {
            ++others;
            fprintf(stdout,CYAN("|-") " " YELLOW("Protocol Not IPv4")" " MAGENTA(":(")"\n");
            if (logfile) fprintf(logfile,"|- Protocol Not IPv4 :(\n");
            HEX_P(stdout,YELLOW("|-") " " RED("Complete Packet Dump") "\n", buf + sizeof(struct ethhdr), size - sizeof(struct ethhdr));
            if (logfile) HEX_P(logfile,"|- Complete Packet Dump\n", buf + sizeof(struct ethhdr), size - sizeof(struct ethhdr));
        }
        else
        {
            ++undefined;
            INVALID_CAPTURE("IP", logfile, stdout);
        }        
    }
    else
    {
        ++undefined;
        INVALID_CAPTURE("Ethernet", logfile, stdout);
    }
}

#endif /* PACKETINFO_H */
