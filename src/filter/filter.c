#include "sniffer/filter.h"
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>

void filter_init(packet_filter_t *filter)
{
    if (!filter) return;
    memset(filter, 0, sizeof(*filter));
    filter->protocol = -1;
    filter->src_port_min = -1;
    filter->src_port_max = -1;
    filter->dst_port_min = -1;
    filter->dst_port_max = -1;
}

int filter_set_protocol(packet_filter_t *filter, const char *proto_name)
{
    if (!filter || !proto_name) return -1;

    if (strcasecmp(proto_name, "tcp") == 0) {
        filter->protocol = IPPROTO_TCP;
    } else if (strcasecmp(proto_name, "udp") == 0) {
        filter->protocol = IPPROTO_UDP;
    } else if (strcasecmp(proto_name, "icmp") == 0) {
        filter->protocol = IPPROTO_ICMP;
    } else if (strcasecmp(proto_name, "icmpv6") == 0 || strcasecmp(proto_name, "icmp6") == 0) {
        filter->protocol = IPPROTO_ICMPV6;
    } else if (strcasecmp(proto_name, "ipv4") == 0 || strcasecmp(proto_name, "ip") == 0) {
        filter->filter_ipv4_only = true;
    } else if (strcasecmp(proto_name, "ipv6") == 0 || strcasecmp(proto_name, "ip6") == 0) {
        filter->filter_ipv6_only = true;
    } else if (strcasecmp(proto_name, "arp") == 0) {
        filter->protocol = ETH_P_ARP;
    } else if (strcasecmp(proto_name, "vlan") == 0) {
        filter->filter_vlan_only = true;
    } else {
        return -1;
    }
    return 0;
}

static int parse_ip_cidr(const char *ip_str, bool *is_v6,
                         uint32_t *ip4, uint32_t *mask4,
                         struct in6_addr *ip6, uint8_t *prefix6)
{
    char buf[128];
    strncpy(buf, ip_str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *slash = strchr(buf, '/');
    int prefix = -1;
    if (slash) {
        *slash = '\0';
        prefix = atoi(slash + 1);
    }

    struct in_addr addr4;
    if (inet_pton(AF_INET, buf, &addr4) == 1) {
        *is_v6 = false;
        *ip4 = addr4.s_addr;
        if (prefix < 0) prefix = 32;
        if (prefix > 32) prefix = 32;
        if (prefix == 0) {
            *mask4 = 0;
        } else {
            *mask4 = htonl(~((1ULL << (32 - prefix)) - 1));
        }
        *ip4 &= *mask4;
        return 0;
    }

    struct in6_addr addr6;
    if (inet_pton(AF_INET6, buf, &addr6) == 1) {
        *is_v6 = true;
        memcpy(ip6, &addr6, sizeof(struct in6_addr));
        if (prefix < 0) prefix = 128;
        if (prefix > 128) prefix = 128;
        *prefix6 = (uint8_t)prefix;
        return 0;
    }

    return -1;
}

int filter_set_src_ip(packet_filter_t *filter, const char *ip_str)
{
    if (!filter || !ip_str) return -1;
    bool is_v6 = false;
    uint32_t ip4 = 0, mask4 = 0;
    struct in6_addr ip6;
    uint8_t prefix6 = 128;

    if (parse_ip_cidr(ip_str, &is_v6, &ip4, &mask4, &ip6, &prefix6) != 0) {
        return -1;
    }

    if (is_v6) {
        filter->has_src_ip6 = true;
        memcpy(&filter->src_ip6, &ip6, sizeof(struct in6_addr));
        filter->src_ip6_prefix = prefix6;
    } else {
        filter->has_src_ip4 = true;
        filter->src_ip4 = ip4;
        filter->src_ip4_mask = mask4;
    }
    return 0;
}

int filter_set_dst_ip(packet_filter_t *filter, const char *ip_str)
{
    if (!filter || !ip_str) return -1;
    bool is_v6 = false;
    uint32_t ip4 = 0, mask4 = 0;
    struct in6_addr ip6;
    uint8_t prefix6 = 128;

    if (parse_ip_cidr(ip_str, &is_v6, &ip4, &mask4, &ip6, &prefix6) != 0) {
        return -1;
    }

    if (is_v6) {
        filter->has_dst_ip6 = true;
        memcpy(&filter->dst_ip6, &ip6, sizeof(struct in6_addr));
        filter->dst_ip6_prefix = prefix6;
    } else {
        filter->has_dst_ip4 = true;
        filter->dst_ip4 = ip4;
        filter->dst_ip4_mask = mask4;
    }
    return 0;
}

int filter_set_src_port(packet_filter_t *filter, int port)
{
    return filter_set_src_port_range(filter, port, port);
}

int filter_set_dst_port(packet_filter_t *filter, int port)
{
    return filter_set_dst_port_range(filter, port, port);
}

int filter_set_src_port_range(packet_filter_t *filter, int min_port, int max_port)
{
    if (!filter || min_port < 0 || max_port < min_port || max_port > 65535) return -1;
    filter->src_port_min = min_port;
    filter->src_port_max = max_port;
    return 0;
}

int filter_set_dst_port_range(packet_filter_t *filter, int min_port, int max_port)
{
    if (!filter || min_port < 0 || max_port < min_port || max_port > 65535) return -1;
    filter->dst_port_min = min_port;
    filter->dst_port_max = max_port;
    return 0;
}

int filter_set_interface(packet_filter_t *filter, const char *ifname)
{
    if (!filter || !ifname) return -1;
    strncpy(filter->interface, ifname, IFNAMSIZ - 1);
    filter->interface[IFNAMSIZ - 1] = '\0';
    return 0;
}

static bool match_ipv6_prefix(const struct in6_addr *a1, const struct in6_addr *a2, uint8_t prefix)
{
    int bytes = prefix / 8;
    int rem_bits = prefix % 8;

    if (bytes > 0 && memcmp(a1->s6_addr, a2->s6_addr, bytes) != 0) {
        return false;
    }

    if (rem_bits > 0) {
        uint8_t mask = (uint8_t)(~((1 << (8 - rem_bits)) - 1));
        if ((a1->s6_addr[bytes] & mask) != (a2->s6_addr[bytes] & mask)) {
            return false;
        }
    }

    return true;
}

bool filter_matches(const packet_filter_t *filter, const parsed_packet_t *pkt)
{
    if (!filter || !pkt) return true;

    /* Check VLAN filter */
    if (filter->filter_vlan_only && !pkt->has_vlan) {
        return false;
    }

    /* Check IPv4 / IPv6 only flags */
    if (filter->filter_ipv4_only && pkt->ip_version != 4) {
        return false;
    }
    if (filter->filter_ipv6_only && pkt->ip_version != 6) {
        return false;
    }

    /* Check protocol filter */
    if (filter->protocol >= 0) {
        if (filter->protocol == ETH_P_ARP) {
            if (pkt->ether_type != ETH_P_ARP) return false;
        } else {
            if (pkt->l4_proto != (uint8_t)filter->protocol) return false;
        }
    }

    /* Check Source IPv4 filter */
    if (filter->has_src_ip4) {
        if (pkt->ip_version != 4) return false;
        if ((pkt->l3.ipv4.src.s_addr & filter->src_ip4_mask) != filter->src_ip4) {
            return false;
        }
    }

    /* Check Destination IPv4 filter */
    if (filter->has_dst_ip4) {
        if (pkt->ip_version != 4) return false;
        if ((pkt->l3.ipv4.dst.s_addr & filter->dst_ip4_mask) != filter->dst_ip4) {
            return false;
        }
    }

    /* Check Source IPv6 filter */
    if (filter->has_src_ip6) {
        if (pkt->ip_version != 6) return false;
        if (!match_ipv6_prefix(&pkt->l3.ipv6.src, &filter->src_ip6, filter->src_ip6_prefix)) {
            return false;
        }
    }

    /* Check Destination IPv6 filter */
    if (filter->has_dst_ip6) {
        if (pkt->ip_version != 6) return false;
        if (!match_ipv6_prefix(&pkt->l3.ipv6.dst, &filter->dst_ip6, filter->dst_ip6_prefix)) {
            return false;
        }
    }

    /* Check Port Filters (only applicable if packet has TCP or UDP) */
    if (filter->src_port_min >= 0 || filter->dst_port_min >= 0) {
        uint16_t src_p = 0;
        uint16_t dst_p = 0;
        bool has_ports = false;

        if (pkt->l4_proto == IPPROTO_TCP) {
            src_p = pkt->l4.tcp.src_port;
            dst_p = pkt->l4.tcp.dst_port;
            has_ports = true;
        } else if (pkt->l4_proto == IPPROTO_UDP) {
            src_p = pkt->l4.udp.src_port;
            dst_p = pkt->l4.udp.dst_port;
            has_ports = true;
        }

        if (!has_ports) return false;

        if (filter->src_port_min >= 0) {
            if (src_p < filter->src_port_min || src_p > filter->src_port_max) {
                return false;
            }
        }

        if (filter->dst_port_min >= 0) {
            if (dst_p < filter->dst_port_min || dst_p > filter->dst_port_max) {
                return false;
            }
        }
    }

    return true;
}
