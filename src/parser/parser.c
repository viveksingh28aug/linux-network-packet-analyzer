#include "sniffer/parser.h"
#include "sniffer/checksum.h"
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

const char *get_ether_proto_name(uint16_t ether_type)
{
    switch (ether_type) {
        case ETH_P_IP:       return "IPv4 (Internet Protocol v4)";
        case ETH_P_IPV6:     return "IPv6 (Internet Protocol v6)";
        case ETH_P_ARP:      return "ARP (Address Resolution Protocol)";
        case ETH_P_RARP:     return "RARP (Reverse ARP)";
        case ETH_P_8021Q:    return "802.1Q (VLAN Tagged Frame)";
        case ETH_P_8021AD:   return "802.1ad (Provider Bridging / QinQ)";
        case ETH_P_PPP_DISC: return "PPPoE Discovery";
        case ETH_P_PPP_SES:  return "PPPoE Session";
        case ETH_P_MPLS_UC:  return "MPLS Unicast";
        case ETH_P_MPLS_MC:  return "MPLS Multicast";
        case ETH_P_LLDP:     return "LLDP (Link Layer Discovery Protocol)";
        case ETH_P_1588:     return "PTP / IEEE 1588 (Precision Time Protocol)";
        case ETH_P_LOOP:     return "Ethernet Loopback";
        default:             return "Unknown / Proprietary EtherType";
    }
}

const char *get_ip_proto_name(uint8_t proto)
{
    switch (proto) {
        case IPPROTO_ICMP:   return "ICMP (Internet Control Message Protocol)";
        case IPPROTO_IGMP:   return "IGMP (Internet Group Management)";
        case IPPROTO_TCP:    return "TCP (Transmission Control Protocol)";
        case IPPROTO_UDP:    return "UDP (User Datagram Protocol)";
        case IPPROTO_IPV6:   return "IPv6 Encapsulation";
        case IPPROTO_GRE:    return "GRE (Generic Routing Encapsulation)";
        case IPPROTO_ESP:    return "IPsec ESP";
        case IPPROTO_AH:     return "IPsec AH";
        case IPPROTO_ICMPV6: return "ICMPv6";
        case IPPROTO_SCTP:   return "SCTP (Stream Control Transmission)";
        case IPPROTO_RAW:    return "RAW Socket Protocol";
        default:             return "Unknown L4 Protocol";
    }
}

const char *get_icmp_type_name(uint8_t type)
{
    switch (type) {
        case ICMP_ECHOREPLY:      return "Echo Reply";
        case ICMP_DEST_UNREACH:   return "Destination Unreachable";
        case ICMP_SOURCE_QUENCH:  return "Source Quench";
        case ICMP_REDIRECT:       return "Redirect (change route)";
        case ICMP_ECHO:           return "Echo Request";
        case ICMP_TIME_EXCEEDED:  return "Time Exceeded (TTL Expired)";
        case ICMP_PARAMETERPROB:  return "Parameter Problem";
        case ICMP_TIMESTAMP:      return "Timestamp Request";
        case ICMP_TIMESTAMPREPLY: return "Timestamp Reply";
        case ICMP_INFO_REQUEST:   return "Information Request";
        case ICMP_INFO_REPLY:     return "Information Reply";
        case ICMP_ADDRESS:        return "Address Mask Request";
        case ICMP_ADDRESSREPLY:   return "Address Mask Reply";
        default:                  return "Unknown ICMP Type";
    }
}

const char *get_icmpv6_type_name(uint8_t type)
{
    switch (type) {
        case ICMP6_DST_UNREACH:     return "Destination Unreachable";
        case ICMP6_PACKET_TOO_BIG:  return "Packet Too Big";
        case ICMP6_TIME_EXCEEDED:   return "Time Exceeded";
        case ICMP6_PARAM_PROB:      return "Parameter Problem";
        case ICMP6_ECHO_REQUEST:    return "Echo Request";
        case ICMP6_ECHO_REPLY:      return "Echo Reply";
        case 133:                   return "Router Solicitation";
        case 134:                   return "Router Advertisement";
        case 135:                   return "Neighbor Solicitation";
        case 136:                   return "Neighbor Advertisement";
        case 137:                   return "Redirect Message";
        default:                    return "Unknown ICMPv6 Type";
    }
}

int parse_packet(const uint8_t *buffer, size_t caplen, size_t wirelen, parsed_packet_t *pkt)
{
    if (!buffer || !pkt) return PARSE_ERR_MALFORMED;

    memset(pkt, 0, sizeof(*pkt));
    pkt->raw_data = buffer;
    pkt->caplen = caplen;
    pkt->wirelen = (wirelen > 0) ? wirelen : caplen;

    size_t offset = 0;

    /* Layer 2: Ethernet Header (14 bytes) */
    if (caplen < sizeof(struct ethhdr)) {
        pkt->is_truncated = true;
        pkt->is_malformed = true;
        snprintf(pkt->error_msg, sizeof(pkt->error_msg),
                 "Packet length (%zu) < Ethernet header (14 bytes)", caplen);
        return PARSE_ERR_TRUNCATED;
    }

    struct ethhdr eth;
    memcpy(&eth, buffer, sizeof(eth));
    pkt->has_eth = true;
    memcpy(pkt->eth_src, eth.h_source, ETH_ALEN);
    memcpy(pkt->eth_dst, eth.h_dest, ETH_ALEN);

    uint16_t eth_proto = ntohs(eth.h_proto);
    offset = sizeof(struct ethhdr);
    pkt->l2_offset = 0;

    /* Handle 802.1Q or 802.1ad VLAN tags */
    if (eth_proto == ETH_P_8021Q || eth_proto == ETH_P_8021AD) {
        if (caplen < offset + sizeof(struct vlan_hdr)) {
            pkt->is_truncated = true;
            pkt->is_malformed = true;
            snprintf(pkt->error_msg, sizeof(pkt->error_msg),
                     "Truncated 802.1Q/802.1ad VLAN header");
            return PARSE_ERR_TRUNCATED;
        }

        struct vlan_hdr vlan;
        memcpy(&vlan, buffer + offset, sizeof(vlan));
        uint16_t tci = ntohs(vlan.vlan_tci);
        pkt->has_vlan = true;
        pkt->vlan_id = tci & 0x0FFF;
        pkt->vlan_pcp = (tci >> 13) & 0x07;
        pkt->vlan_dei = (tci >> 12) & 0x01;
        eth_proto = ntohs(vlan.eth_proto);
        offset += sizeof(struct vlan_hdr);

        /* Handle double-tagging (QinQ / 802.1ad inner VLAN) */
        if (eth_proto == ETH_P_8021Q) {
            if (caplen < offset + sizeof(struct vlan_hdr)) {
                pkt->is_truncated = true;
                pkt->is_malformed = true;
                snprintf(pkt->error_msg, sizeof(pkt->error_msg),
                         "Truncated inner 802.1Q VLAN header");
                return PARSE_ERR_TRUNCATED;
            }
            struct vlan_hdr inner_vlan;
            memcpy(&inner_vlan, buffer + offset, sizeof(inner_vlan));
            uint16_t inner_tci = ntohs(inner_vlan.vlan_tci);
            pkt->has_inner_vlan = true;
            pkt->inner_vlan_id = inner_tci & 0x0FFF;
            pkt->inner_vlan_pcp = (inner_tci >> 13) & 0x07;
            eth_proto = ntohs(inner_vlan.eth_proto);
            offset += sizeof(struct vlan_hdr);
        }
    }

    pkt->ether_type = eth_proto;
    pkt->l2_len = offset;
    pkt->l3_offset = offset;

    /* Layer 3: IPv4, IPv6, or Other */
    if (eth_proto == ETH_P_IP) {
        pkt->ip_version = 4;

        if (caplen < offset + sizeof(struct iphdr)) {
            pkt->is_truncated = true;
            pkt->is_malformed = true;
            snprintf(pkt->error_msg, sizeof(pkt->error_msg),
                     "Packet truncated before IPv4 base header");
            return PARSE_ERR_TRUNCATED;
        }

        struct iphdr iph;
        memcpy(&iph, buffer + offset, sizeof(iph));

        if (iph.version != 4) {
            pkt->is_malformed = true;
            snprintf(pkt->error_msg, sizeof(pkt->error_msg),
                     "Invalid IP version %u in IPv4 packet", iph.version);
            return PARSE_ERR_MALFORMED;
        }

        size_t ihl_bytes = (size_t)iph.ihl * 4;
        if (iph.ihl < 5) {
            pkt->is_malformed = true;
            snprintf(pkt->error_msg, sizeof(pkt->error_msg),
                     "Malformed IPv4 header: IHL %u < 5 (less than 20 bytes)", iph.ihl);
            return PARSE_ERR_MALFORMED;
        }

        if (caplen < offset + ihl_bytes) {
            pkt->is_truncated = true;
            pkt->is_malformed = true;
            snprintf(pkt->error_msg, sizeof(pkt->error_msg),
                     "IPv4 options truncated (IHL=%zu bytes, available=%zu)",
                     ihl_bytes, caplen - offset);
            return PARSE_ERR_TRUNCATED;
        }

        uint16_t tot_len = ntohs(iph.tot_len);
        if (tot_len < ihl_bytes) {
            pkt->is_malformed = true;
            snprintf(pkt->error_msg, sizeof(pkt->error_msg),
                     "Malformed IPv4 total length %u < header length %zu", tot_len, ihl_bytes);
            return PARSE_ERR_MALFORMED;
        }

        if (caplen < offset + tot_len) {
            pkt->is_truncated = true;
        }

        pkt->l3.ipv4.src.s_addr = iph.saddr;
        pkt->l3.ipv4.dst.s_addr = iph.daddr;
        pkt->l3.ipv4.ihl = iph.ihl;
        pkt->l3.ipv4.tos = iph.tos;
        pkt->l3.ipv4.dscp = iph.tos >> 2;
        pkt->l3.ipv4.ecn = iph.tos & 0x03;
        pkt->l3.ipv4.total_len = tot_len;
        pkt->l3.ipv4.id = ntohs(iph.id);

        uint16_t frag_field = ntohs(iph.frag_off);
        pkt->l3.ipv4.flags_offset = frag_field;
        pkt->l3.ipv4.df = (frag_field & 0x4000) != 0;
        pkt->l3.ipv4.mf = (frag_field & 0x2000) != 0;
        pkt->l3.ipv4.frag_offset = (frag_field & 0x1FFF) * 8;
        pkt->l3.ipv4.ttl = iph.ttl;
        pkt->l3.ipv4.protocol = iph.protocol;
        pkt->l3.ipv4.checksum = ntohs(iph.check);
        pkt->l3.ipv4.checksum_valid = verify_ipv4_checksum(buffer + offset, ihl_bytes);

        pkt->l3_len = ihl_bytes;
        offset += ihl_bytes;
        pkt->l4_offset = offset;
        pkt->l4_proto = iph.protocol;

        /* If this is a subsequent fragment (offset > 0), transport headers are not present */
        if (pkt->l3.ipv4.frag_offset > 0) {
            pkt->payload_offset = offset;
            pkt->payload_len = (caplen > offset) ? (caplen - offset) : 0;
            pkt->payload = (pkt->payload_len > 0) ? (buffer + offset) : NULL;
            return PARSE_OK;
        }

    } else if (eth_proto == ETH_P_IPV6) {
        pkt->ip_version = 6;

        if (caplen < offset + sizeof(struct ip6_hdr)) {
            pkt->is_truncated = true;
            pkt->is_malformed = true;
            snprintf(pkt->error_msg, sizeof(pkt->error_msg),
                     "Packet truncated before IPv6 base header (40 bytes)");
            return PARSE_ERR_TRUNCATED;
        }

        struct ip6_hdr ip6h;
        memcpy(&ip6h, buffer + offset, sizeof(ip6h));

        uint8_t version = (ip6h.ip6_vfc >> 4) & 0x0F;
        if (version != 6) {
            pkt->is_malformed = true;
            snprintf(pkt->error_msg, sizeof(pkt->error_msg),
                     "Invalid IP version %u in IPv6 packet", version);
            return PARSE_ERR_MALFORMED;
        }

        uint32_t flow_word = ntohl(ip6h.ip6_flow);
        pkt->l3.ipv6.traffic_class = (flow_word >> 20) & 0xFF;
        pkt->l3.ipv6.flow_label = flow_word & 0x000FFFFF;
        pkt->l3.ipv6.payload_len = ntohs(ip6h.ip6_plen);
        pkt->l3.ipv6.next_header = ip6h.ip6_nxt;
        pkt->l3.ipv6.hop_limit = ip6h.ip6_hlim;
        memcpy(&pkt->l3.ipv6.src, &ip6h.ip6_src, sizeof(struct in6_addr));
        memcpy(&pkt->l3.ipv6.dst, &ip6h.ip6_dst, sizeof(struct in6_addr));

        size_t ipv6_total_expected = sizeof(struct ip6_hdr) + pkt->l3.ipv6.payload_len;
        if (caplen < offset + ipv6_total_expected) {
            pkt->is_truncated = true;
        }

        pkt->l3_len = sizeof(struct ip6_hdr);
        offset += sizeof(struct ip6_hdr);

        /* Parse IPv6 Extension Headers safely */
        uint8_t curr_nh = ip6h.ip6_nxt;
        uint8_t ext_count = 0;

        while (ext_count < 8) {
            if (curr_nh == IPPROTO_HOPOPTS || curr_nh == IPPROTO_ROUTING ||
                curr_nh == IPPROTO_DSTOPTS) {
                if (caplen < offset + 2) {
                    pkt->is_truncated = true;
                    break;
                }
                const uint8_t *ext_ptr = buffer + offset;
                curr_nh = ext_ptr[0];
                size_t ext_len = ((size_t)ext_ptr[1] + 1) * 8;
                if (caplen < offset + ext_len) {
                    pkt->is_truncated = true;
                    break;
                }
                offset += ext_len;
                pkt->l3_len += ext_len;
                ext_count++;
            } else if (curr_nh == IPPROTO_FRAGMENT) {
                if (caplen < offset + 8) {
                    pkt->is_truncated = true;
                    break;
                }
                const uint8_t *ext_ptr = buffer + offset;
                curr_nh = ext_ptr[0];
                offset += 8;
                pkt->l3_len += 8;
                ext_count++;
            } else if (curr_nh == IPPROTO_AH) {
                if (caplen < offset + 2) {
                    pkt->is_truncated = true;
                    break;
                }
                const uint8_t *ext_ptr = buffer + offset;
                curr_nh = ext_ptr[0];
                size_t ext_len = ((size_t)ext_ptr[1] + 2) * 4;
                if (caplen < offset + ext_len) {
                    pkt->is_truncated = true;
                    break;
                }
                offset += ext_len;
                pkt->l3_len += ext_len;
                ext_count++;
            } else {
                /* Reached terminal upper-layer protocol or unknown */
                break;
            }
        }

        pkt->l3.ipv6.ext_hdr_count = ext_count;
        pkt->l3.ipv6.final_protocol = curr_nh;
        pkt->l4_offset = offset;
        pkt->l4_proto = curr_nh;

    } else {
        /* Non-IP Frame (e.g. ARP, MPLS, LLDP) */
        pkt->ip_version = 0;
        pkt->l4_proto = 0;
        pkt->payload_offset = offset;
        pkt->payload_len = (caplen > offset) ? (caplen - offset) : 0;
        pkt->payload = (pkt->payload_len > 0) ? (buffer + offset) : NULL;
        return PARSE_OK;
    }

    /* Layer 4: TCP, UDP, ICMP, ICMPv6 */
    uint8_t proto = pkt->l4_proto;

    if (proto == IPPROTO_TCP) {
        if (caplen < offset + sizeof(struct tcphdr)) {
            pkt->is_truncated = true;
            snprintf(pkt->error_msg, sizeof(pkt->error_msg),
                     "TCP header truncated: need %zu bytes, have %zu",
                     sizeof(struct tcphdr), (caplen > offset) ? caplen - offset : 0);
            return PARSE_ERR_TRUNCATED;
        }

        struct tcphdr tcph;
        memcpy(&tcph, buffer + offset, sizeof(tcph));

        size_t doff_bytes = (size_t)tcph.doff * 4;
        if (tcph.doff < 5) {
            pkt->is_malformed = true;
            snprintf(pkt->error_msg, sizeof(pkt->error_msg),
                     "Malformed TCP header: Data Offset %u < 5", tcph.doff);
            return PARSE_ERR_MALFORMED;
        }

        if (caplen < offset + doff_bytes) {
            pkt->is_truncated = true;
            snprintf(pkt->error_msg, sizeof(pkt->error_msg),
                     "TCP options truncated (doff=%zu bytes)", doff_bytes);
            return PARSE_ERR_TRUNCATED;
        }

        pkt->l4.tcp.src_port = ntohs(tcph.source);
        pkt->l4.tcp.dst_port = ntohs(tcph.dest);
        pkt->l4.tcp.seq = ntohl(tcph.seq);
        pkt->l4.tcp.ack = ntohl(tcph.ack_seq);
        pkt->l4.tcp.data_offset = tcph.doff;

        uint16_t flags_byte = ((const uint8_t *)&tcph)[13];
        pkt->l4.tcp.flags = flags_byte;
        pkt->l4.tcp.fin = (flags_byte & TCP_FLAG_FIN) != 0;
        pkt->l4.tcp.syn = (flags_byte & TCP_FLAG_SYN) != 0;
        pkt->l4.tcp.rst = (flags_byte & TCP_FLAG_RST) != 0;
        pkt->l4.tcp.psh = (flags_byte & TCP_FLAG_PSH) != 0;
        pkt->l4.tcp.ack_flag = (flags_byte & TCP_FLAG_ACK) != 0;
        pkt->l4.tcp.urg = (flags_byte & TCP_FLAG_URG) != 0;
        pkt->l4.tcp.ece = (flags_byte & TCP_FLAG_ECE) != 0;
        pkt->l4.tcp.cwr = (flags_byte & TCP_FLAG_CWR) != 0;

        pkt->l4.tcp.window = ntohs(tcph.window);
        pkt->l4.tcp.checksum = ntohs(tcph.check);
        pkt->l4.tcp.urg_ptr = ntohs(tcph.urg_ptr);

        /* Verify TCP Checksum if full L4 packet is present */
        size_t tcp_total_len = 0;
        if (pkt->ip_version == 4) {
            size_t ip_len = pkt->l3.ipv4.total_len;
            if (ip_len >= pkt->l3_len) {
                tcp_total_len = ip_len - pkt->l3_len;
            }
            if (tcp_total_len > 0 && caplen >= offset + tcp_total_len) {
                pkt->l4.tcp.checksum_valid = verify_tcp_checksum_ipv4(
                    &pkt->l3.ipv4.src, &pkt->l3.ipv4.dst, pkt->l3.ipv4.protocol,
                    buffer + offset, tcp_total_len);
            }
        } else if (pkt->ip_version == 6) {
            tcp_total_len = pkt->l3.ipv6.payload_len;
            if (tcp_total_len > 0 && caplen >= offset + tcp_total_len) {
                pkt->l4.tcp.checksum_valid = verify_tcp_checksum_ipv6(
                    &pkt->l3.ipv6.src, &pkt->l3.ipv6.dst,
                    buffer + offset, tcp_total_len);
            }
        }

        pkt->l4_len = doff_bytes;
        offset += doff_bytes;
        pkt->payload_offset = offset;
        pkt->payload_len = (caplen > offset) ? (caplen - offset) : 0;
        pkt->payload = (pkt->payload_len > 0) ? (buffer + offset) : NULL;

    } else if (proto == IPPROTO_UDP) {
        if (caplen < offset + sizeof(struct udphdr)) {
            pkt->is_truncated = true;
            snprintf(pkt->error_msg, sizeof(pkt->error_msg),
                     "UDP header truncated: need %zu bytes", sizeof(struct udphdr));
            return PARSE_ERR_TRUNCATED;
        }

        struct udphdr udph;
        memcpy(&udph, buffer + offset, sizeof(udph));

        uint16_t ulen = ntohs(udph.len);
        if (ulen < sizeof(struct udphdr)) {
            pkt->is_malformed = true;
            snprintf(pkt->error_msg, sizeof(pkt->error_msg),
                     "Malformed UDP length %u < 8", ulen);
            return PARSE_ERR_MALFORMED;
        }

        pkt->l4.udp.src_port = ntohs(udph.source);
        pkt->l4.udp.dst_port = ntohs(udph.dest);
        pkt->l4.udp.len = ulen;
        pkt->l4.udp.checksum = ntohs(udph.check);

        /* Verify UDP Checksum */
        if (caplen >= offset + ulen) {
            if (pkt->ip_version == 4) {
                pkt->l4.udp.checksum_valid = verify_udp_checksum_ipv4(
                    &pkt->l3.ipv4.src, &pkt->l3.ipv4.dst, pkt->l3.ipv4.protocol,
                    udph.check, buffer + offset, ulen);
            } else if (pkt->ip_version == 6) {
                pkt->l4.udp.checksum_valid = verify_udp_checksum_ipv6(
                    &pkt->l3.ipv6.src, &pkt->l3.ipv6.dst,
                    buffer + offset, ulen);
            }
        }

        pkt->l4_len = sizeof(struct udphdr);
        offset += sizeof(struct udphdr);
        pkt->payload_offset = offset;

        size_t available = (caplen > offset) ? (caplen - offset) : 0;
        size_t udp_data_len = (ulen >= sizeof(struct udphdr)) ? (ulen - sizeof(struct udphdr)) : 0;
        pkt->payload_len = (available < udp_data_len) ? available : udp_data_len;
        pkt->payload = (pkt->payload_len > 0) ? (buffer + offset) : NULL;

    } else if (proto == IPPROTO_ICMP) {
        if (caplen < offset + sizeof(struct icmphdr)) {
            pkt->is_truncated = true;
            snprintf(pkt->error_msg, sizeof(pkt->error_msg),
                     "ICMP header truncated");
            return PARSE_ERR_TRUNCATED;
        }

        struct icmphdr icmph;
        memcpy(&icmph, buffer + offset, sizeof(icmph));

        pkt->l4.icmp.type = icmph.type;
        pkt->l4.icmp.code = icmph.code;
        pkt->l4.icmp.checksum = ntohs(icmph.checksum);

        size_t icmp_len = (caplen > offset) ? (caplen - offset) : 0;
        pkt->l4.icmp.checksum_valid = verify_icmp_checksum(buffer + offset, icmp_len);

        if (icmph.type == ICMP_ECHO || icmph.type == ICMP_ECHOREPLY) {
            pkt->l4.icmp.id = ntohs(icmph.un.echo.id);
            pkt->l4.icmp.sequence = ntohs(icmph.un.echo.sequence);
        }

        pkt->l4_len = sizeof(struct icmphdr);
        offset += sizeof(struct icmphdr);
        pkt->payload_offset = offset;
        pkt->payload_len = (caplen > offset) ? (caplen - offset) : 0;
        pkt->payload = (pkt->payload_len > 0) ? (buffer + offset) : NULL;

    } else if (proto == IPPROTO_ICMPV6) {
        if (caplen < offset + sizeof(struct icmp6_hdr)) {
            pkt->is_truncated = true;
            snprintf(pkt->error_msg, sizeof(pkt->error_msg),
                     "ICMPv6 header truncated");
            return PARSE_ERR_TRUNCATED;
        }

        struct icmp6_hdr icmp6h;
        memcpy(&icmp6h, buffer + offset, sizeof(icmp6h));

        pkt->l4.icmpv6.type = icmp6h.icmp6_type;
        pkt->l4.icmpv6.code = icmp6h.icmp6_code;
        pkt->l4.icmpv6.checksum = ntohs(icmp6h.icmp6_cksum);

        pkt->l4_len = sizeof(struct icmp6_hdr);
        offset += sizeof(struct icmp6_hdr);
        pkt->payload_offset = offset;
        pkt->payload_len = (caplen > offset) ? (caplen - offset) : 0;
        pkt->payload = (pkt->payload_len > 0) ? (buffer + offset) : NULL;

    } else {
        /* Other L4 protocols */
        pkt->l4_len = 0;
        pkt->payload_offset = offset;
        pkt->payload_len = (caplen > offset) ? (caplen - offset) : 0;
        pkt->payload = (pkt->payload_len > 0) ? (buffer + offset) : NULL;
    }

    return PARSE_OK;
}
