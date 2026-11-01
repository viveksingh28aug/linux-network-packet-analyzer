#include "sniffer/capture.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

int capture_open(capture_handle_t *cap, const char *interface, int snaplen, bool promisc)
{
    if (!cap) return -1;
    memset(cap, 0, sizeof(*cap));
    cap->sock_fd = -1;
    cap->snaplen = (snaplen > 0) ? snaplen : SNIFFER_DEFAULT_SNAPLEN;

    /* Create raw socket capturing all Ethernet protocols */
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        if (errno == EPERM || errno == EACCES) {
            fprintf(stderr,
                    "%s[-] Permission Denied:%s Raw socket creation requires CAP_NET_RAW capability or root privileges.\n"
                    "    Run with sudo: sudo ./sniffer -i <interface>\n"
                    "    Or set capability: sudo setcap cap_net_raw+ep ./sniffer\n",
                    COLOR_RED, COLOR_RESET);
        } else {
            fprintf(stderr, "%s[-] Failed to create raw socket:%s %s\n",
                    COLOR_RED, COLOR_RESET, strerror(errno));
        }
        return -1;
    }

    /* Enlarge socket receive buffer to prevent packet drops at high traffic */
    int rcvbuf = 4 * 1024 * 1024; /* 4 MB buffer */
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &rcvbuf, sizeof(rcvbuf)) < 0) {
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    }

    /* Set socket receive timeout so capture loop can periodically check for termination */
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 250000; /* 250 ms */
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt(SO_RCVTIMEO)");
    }

    /* Bind to specific interface if requested */
    int ifindex = 0;
    if (interface && strlen(interface) > 0 && strcmp(interface, "any") != 0) {
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

        if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
            fprintf(stderr, "%s[-] Failed to get interface index for '%s':%s %s\n",
                    COLOR_RED, interface, COLOR_RESET, strerror(errno));
            close(fd);
            return -2;
        }

        ifindex = ifr.ifr_ifindex;
        strncpy(cap->ifname, interface, sizeof(cap->ifname) - 1);
    } else {
        strncpy(cap->ifname, "any", sizeof(cap->ifname) - 1);
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ifindex;

    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        fprintf(stderr, "%s[-] Failed to bind socket to interface '%s':%s %s\n",
                COLOR_RED, cap->ifname, COLOR_RESET, strerror(errno));
        close(fd);
        return -3;
    }

    /* Enable Promiscuous Mode if requested and interface is specific */
    if (promisc && ifindex != 0) {
        struct packet_mreq mreq;
        memset(&mreq, 0, sizeof(mreq));
        mreq.mr_ifindex = ifindex;
        mreq.mr_type = PACKET_MR_PROMISC;

        if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) == 0) {
            cap->promisc_enabled = true;
        } else {
            fprintf(stderr, "%s[!] Warning: Failed to enable promiscuous mode:%s %s\n",
                    COLOR_YELLOW, COLOR_RESET, strerror(errno));
        }
    }

    cap->sock_fd = fd;
    cap->ifindex = ifindex;
    return 0;
}

int capture_next(capture_handle_t *cap, uint8_t *buf, size_t buflen, size_t *caplen, size_t *wirelen)
{
    if (!cap || cap->sock_fd < 0 || !buf || !caplen || !wirelen) return -1;

    struct sockaddr_ll sll;
    socklen_t sll_len = sizeof(sll);

    ssize_t n = recvfrom(cap->sock_fd, buf, buflen, 0, (struct sockaddr *)&sll, &sll_len);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            return 0; /* Timeout / interrupted, caller should retry or check termination */
        }
        return -1; /* Socket error */
    }

    *caplen = (size_t)n;
    *wirelen = (size_t)n;
    cap->packets_received++;
    return 1;
}

int capture_get_stats(capture_handle_t *cap, uint64_t *received, uint64_t *dropped)
{
    if (!cap || cap->sock_fd < 0) return -1;

    struct tpacket_stats stats;
    socklen_t len = sizeof(stats);

    if (getsockopt(cap->sock_fd, SOL_PACKET, PACKET_STATISTICS, &stats, &len) < 0) {
        return -1;
    }

    if (received) *received = stats.tp_packets;
    if (dropped) *dropped = stats.tp_drops;

    cap->packets_dropped = stats.tp_drops;
    return 0;
}

void capture_close(capture_handle_t *cap)
{
    if (!cap || cap->sock_fd < 0) return;

    if (cap->promisc_enabled && cap->ifindex != 0) {
        struct packet_mreq mreq;
        memset(&mreq, 0, sizeof(mreq));
        mreq.mr_ifindex = cap->ifindex;
        mreq.mr_type = PACKET_MR_PROMISC;
        setsockopt(cap->sock_fd, SOL_PACKET, PACKET_DROP_MEMBERSHIP, &mreq, sizeof(mreq));
        cap->promisc_enabled = false;
    }

    close(cap->sock_fd);
    cap->sock_fd = -1;
}
