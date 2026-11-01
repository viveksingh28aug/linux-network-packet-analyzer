#include "sniffer/printer.h"
#include "sniffer/parser.h"
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <linux/wireless.h>
#include <string.h>

void print_hex_dump(FILE *out, const uint8_t *data, size_t len)
{
    if (!out || !data || len == 0) return;

    for (size_t i = 0; i < len; i += 16) {
        fprintf(out, "  %04zx: ", i);

        /* Hex bytes */
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len) {
                fprintf(out, "%02X ", data[i + j]);
            } else {
                fprintf(out, "   ");
            }
            if (j == 7) fprintf(out, " ");
        }

        fprintf(out, " |");

        /* ASCII characters */
        for (size_t j = 0; j < 16 && (i + j) < len; j++) {
            uint8_t c = data[i + j];
            fprintf(out, "%c", (c >= 32 && c <= 126) ? (char)c : '.');
        }

        fprintf(out, "|\n");
    }
}

void print_packet_details(FILE *out, const parsed_packet_t *pkt, bool use_color)
{
    if (!out || !pkt) return;

    const char *c_red = use_color ? COLOR_RED : "";
    const char *c_grn = use_color ? COLOR_GREEN : "";
    const char *c_ylw = use_color ? COLOR_YELLOW : "";
    const char *c_blu = use_color ? COLOR_BLUE : "";
    const char *c_mag = use_color ? COLOR_MAGENTA : "";
    const char *c_cyn = use_color ? COLOR_CYAN : "";
    const char *c_rst = use_color ? COLOR_RESET : "";

    fprintf(out, "\n%s=================%s %sPacket (Cap: %zu B, Wire: %zu B)%s %s=================%s\n",
            c_cyn, c_rst, c_mag, pkt->caplen, pkt->wirelen, c_rst, c_cyn, c_rst);

    if (pkt->is_malformed) {
        fprintf(out, "%s[!] MALFORMED PACKET:%s %s\n", c_red, c_rst, pkt->error_msg);
    }
    if (pkt->is_truncated) {
        fprintf(out, "%s[!] TRUNCATED PACKET%s\n", c_ylw, c_rst);
    }

    /* Layer 2: Ethernet */
    if (pkt->has_eth) {
        fprintf(out, "%s---------------- Ethernet ----------------%s\n", c_cyn, c_rst);
        fprintf(out, "|- %sSource MAC%s      : %s%02X:%02X:%02X:%02X:%02X:%02X%s\n",
                c_ylw, c_rst, c_grn,
                pkt->eth_src[0], pkt->eth_src[1], pkt->eth_src[2],
                pkt->eth_src[3], pkt->eth_src[4], pkt->eth_src[5], c_rst);
        fprintf(out, "|- %sDestination MAC%s : %s%02X:%02X:%02X:%02X:%02X:%02X%s\n",
                c_ylw, c_rst, c_grn,
                pkt->eth_dst[0], pkt->eth_dst[1], pkt->eth_dst[2],
                pkt->eth_dst[3], pkt->eth_dst[4], pkt->eth_dst[5], c_rst);
        fprintf(out, "|- %sEtherType%s       : %s0x%04X%s (%s%s%s)\n",
                c_ylw, c_rst, c_grn, pkt->ether_type, c_rst,
                c_blu, get_ether_proto_name(pkt->ether_type), c_rst);

        if (pkt->has_vlan) {
            fprintf(out, "|- %sVLAN Tag (802.1Q)%s: VID=%s%u%s, PCP=%u, DEI=%u\n",
                    c_ylw, c_rst, c_grn, pkt->vlan_id, c_rst, pkt->vlan_pcp, pkt->vlan_dei);
        }
        if (pkt->has_inner_vlan) {
            fprintf(out, "|- %sInner VLAN (QinQ)%s: VID=%s%u%s, PCP=%u\n",
                    c_ylw, c_rst, c_grn, pkt->inner_vlan_id, c_rst, pkt->inner_vlan_pcp);
        }
    }

    /* Layer 3: IPv4 */
    if (pkt->ip_version == 4) {
        char src_str[INET_ADDRSTRLEN], dst_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &pkt->l3.ipv4.src, src_str, sizeof(src_str));
        inet_ntop(AF_INET, &pkt->l3.ipv4.dst, dst_str, sizeof(dst_str));

        fprintf(out, "%s------------------- IPv4 -------------------%s\n", c_cyn, c_rst);
        fprintf(out, "|- %sVersion%s         : %sIPv4%s\n", c_ylw, c_rst, c_grn, c_rst);
        fprintf(out, "|- %sHeader Length%s   : %s%u DWORDS (%u Bytes)%s\n",
                c_ylw, c_rst, c_grn, pkt->l3.ipv4.ihl, pkt->l3.ipv4.ihl * 4, c_rst);
        fprintf(out, "|- %sTOS / DSCP / ECN%s: %s0x%02X%s (DSCP: %u, ECN: %u)\n",
                c_ylw, c_rst, c_grn, pkt->l3.ipv4.tos, c_rst, pkt->l3.ipv4.dscp, pkt->l3.ipv4.ecn);
        fprintf(out, "|- %sTotal Length%s    : %s%u Bytes%s\n",
                c_ylw, c_rst, c_grn, pkt->l3.ipv4.total_len, c_rst);
        fprintf(out, "|- %sIdentification%s  : %s%u%s\n",
                c_ylw, c_rst, c_grn, pkt->l3.ipv4.id, c_rst);
        fprintf(out, "|- %sFlags / Frag Off%s : DF=%s%d%s, MF=%s%d%s, Offset=%s%u%s Bytes\n",
                c_ylw, c_rst, c_grn, pkt->l3.ipv4.df ? 1 : 0, c_rst,
                c_grn, pkt->l3.ipv4.mf ? 1 : 0, c_rst,
                c_grn, pkt->l3.ipv4.frag_offset, c_rst);
        fprintf(out, "|- %sTTL%s             : %s%u%s\n",
                c_ylw, c_rst, c_grn, pkt->l3.ipv4.ttl, c_rst);
        fprintf(out, "|- %sProtocol%s        : %s%u%s (%s%s%s)\n",
                c_ylw, c_rst, c_grn, pkt->l3.ipv4.protocol, c_rst,
                c_blu, get_ip_proto_name(pkt->l3.ipv4.protocol), c_rst);
        fprintf(out, "|- %sChecksum%s        : %s0x%04X%s (%s%s%s)\n",
                c_ylw, c_rst, c_grn, pkt->l3.ipv4.checksum, c_rst,
                pkt->l3.ipv4.checksum_valid ? c_grn : c_red,
                pkt->l3.ipv4.checksum_valid ? "VALID" : "INVALID / CORRUPT", c_rst);
        fprintf(out, "|- %sSource IP%s       : %s%s%s\n",
                c_ylw, c_rst, c_grn, src_str, c_rst);
        fprintf(out, "|- %sDestination IP%s  : %s%s%s\n",
                c_ylw, c_rst, c_grn, dst_str, c_rst);

    } else if (pkt->ip_version == 6) {
        char src_str[INET6_ADDRSTRLEN], dst_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &pkt->l3.ipv6.src, src_str, sizeof(src_str));
        inet_ntop(AF_INET6, &pkt->l3.ipv6.dst, dst_str, sizeof(dst_str));

        fprintf(out, "%s------------------- IPv6 -------------------%s\n", c_cyn, c_rst);
        fprintf(out, "|- %sVersion%s         : %sIPv6%s\n", c_ylw, c_rst, c_grn, c_rst);
        fprintf(out, "|- %sTraffic Class%s   : %s0x%02X%s\n",
                c_ylw, c_rst, c_grn, pkt->l3.ipv6.traffic_class, c_rst);
        fprintf(out, "|- %sFlow Label%s      : %s0x%05X%s\n",
                c_ylw, c_rst, c_grn, pkt->l3.ipv6.flow_label, c_rst);
        fprintf(out, "|- %sPayload Length%s  : %s%u Bytes%s\n",
                c_ylw, c_rst, c_grn, pkt->l3.ipv6.payload_len, c_rst);
        fprintf(out, "|- %sNext Header%s     : %s%u%s (%s%s%s)\n",
                c_ylw, c_rst, c_grn, pkt->l3.ipv6.next_header, c_rst,
                c_blu, get_ip_proto_name(pkt->l3.ipv6.next_header), c_rst);
        fprintf(out, "|- %sHop Limit%s       : %s%u%s\n",
                c_ylw, c_rst, c_grn, pkt->l3.ipv6.hop_limit, c_rst);
        fprintf(out, "|- %sExt Headers Count%s: %s%u%s\n",
                c_ylw, c_rst, c_grn, pkt->l3.ipv6.ext_hdr_count, c_rst);
        fprintf(out, "|- %sSource IPv6%s     : %s%s%s\n",
                c_ylw, c_rst, c_grn, src_str, c_rst);
        fprintf(out, "|- %sDestination IPv6%s: %s%s%s\n",
                c_ylw, c_rst, c_grn, dst_str, c_rst);
    }

    /* Layer 4: TCP */
    if (pkt->l4_proto == IPPROTO_TCP) {
        fprintf(out, "%s------------------- TCP -------------------%s\n", c_cyn, c_rst);
        fprintf(out, "|- %sSource Port%s     : %s%u%s\n",
                c_ylw, c_rst, c_grn, pkt->l4.tcp.src_port, c_rst);
        fprintf(out, "|- %sDestination Port%s: %s%u%s\n",
                c_ylw, c_rst, c_grn, pkt->l4.tcp.dst_port, c_rst);
        fprintf(out, "|- %sSequence Number%s : %s%u%s\n",
                c_ylw, c_rst, c_grn, pkt->l4.tcp.seq, c_rst);
        fprintf(out, "|- %sAck Number%s      : %s%u%s\n",
                c_ylw, c_rst, c_grn, pkt->l4.tcp.ack, c_rst);
        fprintf(out, "|- %sHeader Length%s   : %s%u DWORDS (%u Bytes)%s\n",
                c_ylw, c_rst, c_grn, pkt->l4.tcp.data_offset, pkt->l4.tcp.data_offset * 4, c_rst);
        fprintf(out, "|- %sFlags%s           : %s[ %s%s%s%s%s%s%s%s]%s (0x%02X)\n",
                c_ylw, c_rst, c_mag,
                pkt->l4.tcp.cwr ? "CWR " : "",
                pkt->l4.tcp.ece ? "ECE " : "",
                pkt->l4.tcp.urg ? "URG " : "",
                pkt->l4.tcp.ack_flag ? "ACK " : "",
                pkt->l4.tcp.psh ? "PSH " : "",
                pkt->l4.tcp.rst ? "RST " : "",
                pkt->l4.tcp.syn ? "SYN " : "",
                pkt->l4.tcp.fin ? "FIN " : "",
                c_rst, pkt->l4.tcp.flags);
        fprintf(out, "|- %sWindow Size%s     : %s%u%s\n",
                c_ylw, c_rst, c_grn, pkt->l4.tcp.window, c_rst);
        fprintf(out, "|- %sChecksum%s        : %s0x%04X%s (%s%s%s)\n",
                c_ylw, c_rst, c_grn, pkt->l4.tcp.checksum, c_rst,
                pkt->l4.tcp.checksum_valid ? c_grn : c_red,
                pkt->l4.tcp.checksum_valid ? "VALID" : "UNVERIFIED / INVALID", c_rst);
        fprintf(out, "|- %sUrgent Pointer%s  : %s%u%s\n",
                c_ylw, c_rst, c_grn, pkt->l4.tcp.urg_ptr, c_rst);

    } else if (pkt->l4_proto == IPPROTO_UDP) {
        fprintf(out, "%s------------------- UDP -------------------%s\n", c_cyn, c_rst);
        fprintf(out, "|- %sSource Port%s     : %s%u%s\n",
                c_ylw, c_rst, c_grn, pkt->l4.udp.src_port, c_rst);
        fprintf(out, "|- %sDestination Port%s: %s%u%s\n",
                c_ylw, c_rst, c_grn, pkt->l4.udp.dst_port, c_rst);
        fprintf(out, "|- %sUDP Length%s      : %s%u Bytes%s\n",
                c_ylw, c_rst, c_grn, pkt->l4.udp.len, c_rst);
        fprintf(out, "|- %sChecksum%s        : %s0x%04X%s (%s%s%s)\n",
                c_ylw, c_rst, c_grn, pkt->l4.udp.checksum, c_rst,
                pkt->l4.udp.checksum_valid ? c_grn : c_red,
                pkt->l4.udp.checksum_valid ? "VALID" : "UNVERIFIED / INVALID", c_rst);

    } else if (pkt->l4_proto == IPPROTO_ICMP) {
        fprintf(out, "%s------------------- ICMP -------------------%s\n", c_cyn, c_rst);
        fprintf(out, "|- %sType%s            : %s%u%s (%s%s%s)\n",
                c_ylw, c_rst, c_grn, pkt->l4.icmp.type, c_rst,
                c_blu, get_icmp_type_name(pkt->l4.icmp.type), c_rst);
        fprintf(out, "|- %sCode%s            : %s%u%s\n",
                c_ylw, c_rst, c_grn, pkt->l4.icmp.code, c_rst);
        fprintf(out, "|- %sChecksum%s        : %s0x%04X%s (%s%s%s)\n",
                c_ylw, c_rst, c_grn, pkt->l4.icmp.checksum, c_rst,
                pkt->l4.icmp.checksum_valid ? c_grn : c_red,
                pkt->l4.icmp.checksum_valid ? "VALID" : "INVALID", c_rst);
        if (pkt->l4.icmp.type == ICMP_ECHO || pkt->l4.icmp.type == ICMP_ECHOREPLY) {
            fprintf(out, "|- %sIdentifier / Seq%s : ID=%u, Sequence=%u\n",
                    c_ylw, c_rst, pkt->l4.icmp.id, pkt->l4.icmp.sequence);
        }

    } else if (pkt->l4_proto == IPPROTO_ICMPV6) {
        fprintf(out, "%s------------------ ICMPv6 ------------------%s\n", c_cyn, c_rst);
        fprintf(out, "|- %sType%s            : %s%u%s (%s%s%s)\n",
                c_ylw, c_rst, c_grn, pkt->l4.icmpv6.type, c_rst,
                c_blu, get_icmpv6_type_name(pkt->l4.icmpv6.type), c_rst);
        fprintf(out, "|- %sCode%s            : %s%u%s\n",
                c_ylw, c_rst, c_grn, pkt->l4.icmpv6.code, c_rst);
        fprintf(out, "|- %sChecksum%s        : %s0x%04X%s\n",
                c_ylw, c_rst, c_grn, pkt->l4.icmpv6.checksum, c_rst);
    }

    /* Payload Hex Dump */
    if (pkt->payload && pkt->payload_len > 0) {
        fprintf(out, "|- %sPayload Dump (%zu Bytes)%s:\n", c_ylw, pkt->payload_len, c_rst);
        print_hex_dump(out, pkt->payload, pkt->payload_len);
    }
}

void print_analytics_summary(FILE *out, const sniffer_analytics_t *a, bool use_color)
{
    if (!out || !a) return;

    const char *c_red = use_color ? COLOR_RED : "";
    const char *c_grn = use_color ? COLOR_GREEN : "";
    const char *c_ylw = use_color ? COLOR_YELLOW : "";
    const char *c_cyn = use_color ? COLOR_CYAN : "";
    const char *c_mag = use_color ? COLOR_MAGENTA : "";
    const char *c_rst = use_color ? COLOR_RESET : "";

    fprintf(out, "\n%s=======================================================%s\n", c_cyn, c_rst);
    fprintf(out, "%s              NETWORK TRAFFIC ANALYTICS SUMMARY         %s\n", c_mag, c_rst);
    fprintf(out, "%s=======================================================%s\n", c_cyn, c_rst);

    fprintf(out, "|- %sTotal Packets Processed%s: %s%lu%s\n", c_ylw, c_rst, c_grn, a->total_packets, c_rst);
    fprintf(out, "|- %sTotal Bytes Processed%s  : %s%lu%s\n", c_ylw, c_rst, c_grn, a->total_bytes, c_rst);
    fprintf(out, "|- %sAverage Packet Size%s    : %s%.2f Bytes%s\n",
            c_ylw, c_rst, c_grn, analytics_get_average_packet_size(a), c_rst);

    fprintf(out, "\n%s--- Protocol Distribution ---%s\n", c_cyn, c_rst);
    fprintf(out, "|- %sIPv4 Packets%s           : %s%lu%s (%.1f%%)\n",
            c_ylw, c_rst, c_grn, a->ipv4_packets, c_rst,
            a->total_packets ? ((double)a->ipv4_packets * 100.0 / a->total_packets) : 0.0);
    fprintf(out, "|- %sIPv6 Packets%s           : %s%lu%s (%.1f%%)\n",
            c_ylw, c_rst, c_grn, a->ipv6_packets, c_rst,
            a->total_packets ? ((double)a->ipv6_packets * 100.0 / a->total_packets) : 0.0);
    fprintf(out, "|- %sNon-IP / Other Packets%s : %s%lu%s\n", c_ylw, c_rst, c_grn, a->non_ip_packets, c_rst);
    fprintf(out, "|- %sVLAN Tagged Frames%s     : %s%lu%s\n", c_ylw, c_rst, c_grn, a->vlan_packets, c_rst);
    fprintf(out, "|- %sARP Packets%s            : %s%lu%s\n", c_ylw, c_rst, c_grn, a->arp_packets, c_rst);
    fprintf(out, "|- %sTCP Packets%s            : %s%lu%s (%.1f%%)\n",
            c_ylw, c_rst, c_grn, a->tcp_packets, c_rst,
            a->total_packets ? ((double)a->tcp_packets * 100.0 / a->total_packets) : 0.0);
    fprintf(out, "|- %sUDP Packets%s            : %s%lu%s (%.1f%%)\n",
            c_ylw, c_rst, c_grn, a->udp_packets, c_rst,
            a->total_packets ? ((double)a->udp_packets * 100.0 / a->total_packets) : 0.0);
    fprintf(out, "|- %sICMP / ICMPv6 Packets%s  : %s%lu%s (%.1f%%)\n",
            c_ylw, c_rst, c_grn, a->icmp_packets, c_rst,
            a->total_packets ? ((double)a->icmp_packets * 100.0 / a->total_packets) : 0.0);
    fprintf(out, "|- %sOther L4 Packets%s       : %s%lu%s\n", c_ylw, c_rst, c_grn, a->other_l4_packets, c_rst);

    fprintf(out, "\n%s--- Packet Validation & Anomalies ---%s\n", c_cyn, c_rst);
    fprintf(out, "|- %sMalformed Packets%s      : %s%lu%s\n",
            c_ylw, c_rst, a->malformed_packets ? c_red : c_grn, a->malformed_packets, c_rst);
    fprintf(out, "|- %sTruncated Packets%s      : %s%lu%s\n",
            c_ylw, c_rst, a->truncated_packets ? c_red : c_grn, a->truncated_packets, c_rst);
    fprintf(out, "|- %sKernel Dropped Packets%s : %s%lu%s\n",
            c_ylw, c_rst, a->kernel_dropped ? c_red : c_grn, a->kernel_dropped, c_rst);

    /* Top Source IP Addresses */
    top_ip_record_t top_src[MAX_TOP_IPS];
    size_t num_src = analytics_get_top_src_ips(a, top_src, MAX_TOP_IPS);
    fprintf(out, "\n%s--- Top %zu Source IP Addresses ---%s\n", c_cyn, num_src, c_rst);
    for (size_t i = 0; i < num_src; i++) {
        fprintf(out, "  [%zu] %-25s : %lu packets (%lu bytes, %.1f%%)\n",
                i + 1, top_src[i].ip_str, top_src[i].count, top_src[i].bytes, top_src[i].percentage);
    }

    /* Top Destination IP Addresses */
    top_ip_record_t top_dst[MAX_TOP_IPS];
    size_t num_dst = analytics_get_top_dst_ips(a, top_dst, MAX_TOP_IPS);
    fprintf(out, "\n%s--- Top %zu Destination IP Addresses ---%s\n", c_cyn, num_dst, c_rst);
    for (size_t i = 0; i < num_dst; i++) {
        fprintf(out, "  [%zu] %-25s : %lu packets (%lu bytes, %.1f%%)\n",
                i + 1, top_dst[i].ip_str, top_dst[i].count, top_dst[i].bytes, top_dst[i].percentage);
    }

    fprintf(out, "%s=======================================================%s\n\n", c_cyn, c_rst);
}

void print_available_interfaces(FILE *out)
{
    if (!out) return;

    struct ifaddrs *ifaddr = NULL;
    if (getifaddrs(&ifaddr) == -1) {
        fprintf(stderr, "%s[-] Failed to query network interfaces%s\n", COLOR_RED, COLOR_RESET);
        return;
    }

    fprintf(out, "%s========== Available Network Interfaces ==========%s\n", COLOR_CYAN, COLOR_RESET);

    for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;

        int family = ifa->ifa_addr->sa_family;
        if (family == AF_INET || family == AF_INET6) {
            char addr_str[INET6_ADDRSTRLEN] = {0};

            if (family == AF_INET) {
                struct sockaddr_in *s4 = (struct sockaddr_in *)ifa->ifa_addr;
                inet_ntop(AF_INET, &s4->sin_addr, addr_str, sizeof(addr_str));
                fprintf(out, "  %s%-12s%s \t%sIPv4%s \t%s\n",
                        COLOR_GREEN, ifa->ifa_name, COLOR_RESET,
                        COLOR_YELLOW, COLOR_RESET, addr_str);
            } else {
                struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)ifa->ifa_addr;
                inet_ntop(AF_INET6, &s6->sin6_addr, addr_str, sizeof(addr_str));
                fprintf(out, "  %s%-12s%s \t%sIPv6%s \t%s\n",
                        COLOR_GREEN, ifa->ifa_name, COLOR_RESET,
                        COLOR_YELLOW, COLOR_RESET, addr_str);
            }
        }
    }

    fprintf(out, "%s==================================================%s\n", COLOR_CYAN, COLOR_RESET);
    freeifaddrs(ifaddr);
}
