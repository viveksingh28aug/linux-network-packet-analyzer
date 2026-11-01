#include "sniffer/checksum.h"
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>

void checksum_accumulate(uint32_t *acc, const void *buf, size_t len)
{
    const uint8_t *ptr = (const uint8_t *)buf;
    size_t count = len;

    /*
     * Process 16-bit words safely. Using memcpy prevents unaligned pointer
     * dereferences and strict aliasing violations under aggressive compiler optimization (-O3).
     */
    while (count > 1) {
        uint16_t word;
        memcpy(&word, ptr, sizeof(word));
        *acc += word;
        ptr += 2;
        count -= 2;
    }

    /* Handle odd trailing byte (padded with 0 to 16 bits per RFC 1071) */
    if (count > 0) {
        uint8_t odd_buf[2] = { *ptr, 0 };
        uint16_t odd;
        memcpy(&odd, odd_buf, sizeof(odd));
        *acc += odd;
    }
}

uint16_t checksum_finalize(uint32_t acc)
{
    while (acc >> 16) {
        acc = (acc & 0xFFFF) + (acc >> 16);
    }
    return (uint16_t)(~acc);
}

uint16_t checksum_compute(const void *buf, size_t len)
{
    uint32_t acc = 0;
    checksum_accumulate(&acc, buf, len);
    return checksum_finalize(acc);
}

bool verify_ipv4_checksum(const void *ip_hdr_buf, size_t hdr_len)
{
    if (!ip_hdr_buf || hdr_len < sizeof(struct iphdr)) return false;
    return (checksum_compute(ip_hdr_buf, hdr_len) == 0);
}

bool verify_icmp_checksum(const void *icmp_buf, size_t len)
{
    if (!icmp_buf || len < sizeof(struct icmphdr)) return false;
    return (checksum_compute(icmp_buf, len) == 0);
}

/* IPv4 Pseudo-header for TCP/UDP (12 bytes) */
struct ipv4_pseudo_header {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t  reserved;
    uint8_t  protocol;
    uint16_t length;
} __attribute__((packed));

bool verify_tcp_checksum_ipv4(const struct in_addr *src, const struct in_addr *dst,
                              uint8_t protocol, const void *tcp_buf, size_t tcp_len)
{
    if (!src || !dst || !tcp_buf || tcp_len < sizeof(struct tcphdr)) return false;

    struct ipv4_pseudo_header ph;
    memset(&ph, 0, sizeof(ph));
    memcpy(&ph.src_ip, src, sizeof(uint32_t));
    memcpy(&ph.dst_ip, dst, sizeof(uint32_t));
    ph.reserved = 0;
    ph.protocol = protocol;
    ph.length = htons((uint16_t)tcp_len);

    uint32_t acc = 0;
    checksum_accumulate(&acc, &ph, sizeof(ph));
    checksum_accumulate(&acc, tcp_buf, tcp_len);

    return (checksum_finalize(acc) == 0);
}

bool verify_udp_checksum_ipv4(const struct in_addr *src, const struct in_addr *dst,
                              uint8_t protocol, uint16_t udp_check,
                              const void *udp_buf, size_t udp_len)
{
    if (!src || !dst || !udp_buf || udp_len < sizeof(struct udphdr)) return false;

    /* In IPv4, a UDP checksum of 0 means no checksum was computed by sender */
    if (udp_check == 0) {
        return true;
    }

    struct ipv4_pseudo_header ph;
    memset(&ph, 0, sizeof(ph));
    memcpy(&ph.src_ip, src, sizeof(uint32_t));
    memcpy(&ph.dst_ip, dst, sizeof(uint32_t));
    ph.reserved = 0;
    ph.protocol = protocol;
    ph.length = htons((uint16_t)udp_len);

    uint32_t acc = 0;
    checksum_accumulate(&acc, &ph, sizeof(ph));
    checksum_accumulate(&acc, udp_buf, udp_len);

    return (checksum_finalize(acc) == 0);
}

/* IPv6 Pseudo-header for TCP/UDP (40 bytes per RFC 8200) */
struct ipv6_pseudo_header {
    struct in6_addr src_ip;
    struct in6_addr dst_ip;
    uint32_t length;
    uint8_t  zeros[3];
    uint8_t  next_header;
} __attribute__((packed));

bool verify_tcp_checksum_ipv6(const struct in6_addr *src, const struct in6_addr *dst,
                              const void *tcp_buf, size_t tcp_len)
{
    if (!src || !dst || !tcp_buf || tcp_len < sizeof(struct tcphdr)) return false;

    struct ipv6_pseudo_header ph;
    memset(&ph, 0, sizeof(ph));
    memcpy(&ph.src_ip, src, sizeof(struct in6_addr));
    memcpy(&ph.dst_ip, dst, sizeof(struct in6_addr));
    ph.length = htonl((uint32_t)tcp_len);
    ph.next_header = IPPROTO_TCP;

    uint32_t acc = 0;
    checksum_accumulate(&acc, &ph, sizeof(ph));
    checksum_accumulate(&acc, tcp_buf, tcp_len);

    return (checksum_finalize(acc) == 0);
}

bool verify_udp_checksum_ipv6(const struct in6_addr *src, const struct in6_addr *dst,
                              const void *udp_buf, size_t udp_len)
{
    if (!src || !dst || !udp_buf || udp_len < sizeof(struct udphdr)) return false;

    struct ipv6_pseudo_header ph;
    memset(&ph, 0, sizeof(ph));
    memcpy(&ph.src_ip, src, sizeof(struct in6_addr));
    memcpy(&ph.dst_ip, dst, sizeof(struct in6_addr));
    ph.length = htonl((uint32_t)udp_len);
    ph.next_header = IPPROTO_UDP;

    uint32_t acc = 0;
    checksum_accumulate(&acc, &ph, sizeof(ph));
    checksum_accumulate(&acc, udp_buf, udp_len);

    return (checksum_finalize(acc) == 0);
}
