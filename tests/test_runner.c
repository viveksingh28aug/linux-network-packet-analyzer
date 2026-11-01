#include "sniffer/types.h"
#include "sniffer/parser.h"
#include "sniffer/filter.h"
#include "sniffer/analytics.h"
#include "sniffer/checksum.h"
#include "sniffer/pcap.h"
#include "test_packets.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static int g_tests_run = 0;
static int g_tests_passed = 0;

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  %s[FAIL]%s %s (Line %d): %s\n", COLOR_RED, COLOR_RESET, __func__, __LINE__, msg); \
        return 1; \
    } \
} while(0)

#define RUN_TEST(fn) do { \
    g_tests_run++; \
    printf("[TEST %d] Running %s...", g_tests_run, #fn); \
    if (fn() == 0) { \
        g_tests_passed++; \
        printf(" %sPASSED%s\n", COLOR_GREEN, COLOR_RESET); \
    } else { \
        printf(" %sFAILED%s\n", COLOR_RED, COLOR_RESET); \
    } \
} while(0)

static int test_ethernet_arp(void)
{
    parsed_packet_t pkt;
    int res = parse_packet(pkt_arp, pkt_arp_len, pkt_arp_len, &pkt);
    TEST_ASSERT(res == PARSE_OK, "parse_packet should return PARSE_OK");
    TEST_ASSERT(pkt.has_eth == true, "has_eth must be true");
    TEST_ASSERT(pkt.ether_type == ETH_P_ARP, "ether_type must be ARP (0x0806)");
    TEST_ASSERT(pkt.ip_version == 0, "ARP frame must have ip_version == 0");
    TEST_ASSERT(pkt.eth_dst[0] == 0xff && pkt.eth_dst[5] == 0xff, "Broadcast MAC expected");
    return 0;
}

static int test_8021q_vlan_ipv4_tcp(void)
{
    parsed_packet_t pkt;
    int res = parse_packet(pkt_vlan_tcp, pkt_vlan_tcp_len, pkt_vlan_tcp_len, &pkt);
    TEST_ASSERT(res == PARSE_OK, "parse_packet should return PARSE_OK");
    TEST_ASSERT(pkt.has_vlan == true, "has_vlan must be true");
    TEST_ASSERT(pkt.vlan_id == 100, "VLAN ID must be 100");
    TEST_ASSERT(pkt.vlan_pcp == 3, "VLAN PCP must be 3");
    TEST_ASSERT(pkt.ip_version == 4, "ip_version must be 4");

    char src_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &pkt.l3.ipv4.src, src_ip, sizeof(src_ip));
    TEST_ASSERT(strcmp(src_ip, "192.168.1.100") == 0, "Source IP mismatch");
    TEST_ASSERT(pkt.l3.ipv4.checksum_valid == true, "IPv4 checksum must be valid");
    TEST_ASSERT(pkt.l3.ipv4.df == true, "DF flag must be set");

    TEST_ASSERT(pkt.l4_proto == IPPROTO_TCP, "L4 proto must be TCP");
    TEST_ASSERT(pkt.l4.tcp.src_port == 443, "TCP src port must be 443");
    TEST_ASSERT(pkt.l4.tcp.dst_port == 54321, "TCP dst port must be 54321");
    TEST_ASSERT(pkt.l4.tcp.syn == true, "SYN flag must be set");
    TEST_ASSERT(pkt.l4.tcp.ack_flag == true, "ACK flag must be set");
    TEST_ASSERT(pkt.l4.tcp.fin == false, "FIN flag must NOT be set");
    TEST_ASSERT(pkt.l4.tcp.checksum_valid == true, "TCP checksum must be valid");

    TEST_ASSERT(pkt.payload != NULL, "TCP payload must exist");
    TEST_ASSERT(memcmp(pkt.payload, "HELLO SILICON", 13) == 0, "Payload content mismatch");
    return 0;
}

static int test_qinq_vlan_udp(void)
{
    parsed_packet_t pkt;
    int res = parse_packet(pkt_qinq_udp, pkt_qinq_udp_len, pkt_qinq_udp_len, &pkt);
    TEST_ASSERT(res == PARSE_OK, "parse_packet should return PARSE_OK");
    TEST_ASSERT(pkt.has_vlan == true, "Outer 802.1ad VLAN must be detected");
    TEST_ASSERT(pkt.vlan_id == 200, "Outer VLAN ID must be 200");
    TEST_ASSERT(pkt.has_inner_vlan == true, "Inner 802.1Q VLAN must be detected");
    TEST_ASSERT(pkt.inner_vlan_id == 10, "Inner VLAN ID must be 10");

    TEST_ASSERT(pkt.ip_version == 4, "ip_version must be 4");
    TEST_ASSERT(pkt.l4_proto == IPPROTO_UDP, "L4 proto must be UDP");
    TEST_ASSERT(pkt.l4.udp.src_port == 53, "UDP src port must be 53");
    TEST_ASSERT(pkt.l4.udp.dst_port == 49152, "UDP dst port must be 49152");
    TEST_ASSERT(pkt.l4.udp.checksum_valid == true, "UDP checksum must be valid");
    TEST_ASSERT(pkt.payload_len == 14, "UDP payload length mismatch");
    return 0;
}

static int test_ipv4_options_icmp(void)
{
    parsed_packet_t pkt;
    int res = parse_packet(pkt_ip_opt_icmp, pkt_ip_opt_icmp_len, pkt_ip_opt_icmp_len, &pkt);
    TEST_ASSERT(res == PARSE_OK, "parse_packet should return PARSE_OK");
    TEST_ASSERT(pkt.l3.ipv4.ihl == 6, "IHL must be 6 (24 bytes IP header with options)");
    TEST_ASSERT(pkt.l3.ipv4.checksum_valid == true, "IPv4 checksum with options must be valid");

    TEST_ASSERT(pkt.l4_proto == IPPROTO_ICMP, "L4 proto must be ICMP");
    TEST_ASSERT(pkt.l4.icmp.type == ICMP_ECHO, "ICMP type must be Echo Request (8)");
    TEST_ASSERT(pkt.l4.icmp.code == 0, "ICMP code must be 0");
    TEST_ASSERT(pkt.l4.icmp.id == 0x1234, "ICMP Echo ID mismatch");
    TEST_ASSERT(pkt.l4.icmp.sequence == 1, "ICMP Echo sequence mismatch");
    TEST_ASSERT(pkt.l4.icmp.checksum_valid == true, "ICMP checksum must be valid");
    TEST_ASSERT(pkt.payload != NULL, "ICMP payload must exist");
    TEST_ASSERT(memcmp(pkt.payload, "PINGPONG123456", 14) == 0, "ICMP payload data mismatch");
    return 0;
}

static int test_ipv6_tcp(void)
{
    parsed_packet_t pkt;
    int res = parse_packet(pkt_ipv6_tcp, pkt_ipv6_tcp_len, pkt_ipv6_tcp_len, &pkt);
    TEST_ASSERT(res == PARSE_OK, "parse_packet should return PARSE_OK");
    TEST_ASSERT(pkt.ip_version == 6, "ip_version must be 6");

    char src_ip6[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &pkt.l3.ipv6.src, src_ip6, sizeof(src_ip6));
    TEST_ASSERT(strcmp(src_ip6, "2001:db8::1") == 0, "IPv6 source IP mismatch");

    TEST_ASSERT(pkt.l4_proto == IPPROTO_TCP, "L4 proto must be TCP");
    TEST_ASSERT(pkt.l4.tcp.src_port == 80, "TCP port must be 80");
    TEST_ASSERT(pkt.l4.tcp.dst_port == 60000, "TCP port must be 60000");
    TEST_ASSERT(pkt.l4.tcp.checksum_valid == true, "IPv6 TCP pseudo-header checksum must be valid");
    return 0;
}

static int test_ipv6_extension_headers(void)
{
    parsed_packet_t pkt;
    int res = parse_packet(pkt_ipv6_ext_udp, pkt_ipv6_ext_udp_len, pkt_ipv6_ext_udp_len, &pkt);
    TEST_ASSERT(res == PARSE_OK, "parse_packet should return PARSE_OK");
    TEST_ASSERT(pkt.ip_version == 6, "ip_version must be 6");
    TEST_ASSERT(pkt.l3.ipv6.ext_hdr_count == 1, "Should parse 1 extension header (Hop-by-Hop)");
    TEST_ASSERT(pkt.l3.ipv6.final_protocol == IPPROTO_UDP, "Final protocol must be UDP");
    TEST_ASSERT(pkt.l4_proto == IPPROTO_UDP, "L4 protocol must be UDP");
    TEST_ASSERT(pkt.l4.udp.src_port == 5000, "UDP src port 5000");
    TEST_ASSERT(pkt.l4.udp.checksum_valid == true, "IPv6 UDP pseudo-header checksum must be valid");
    return 0;
}

static int test_ipv4_fragmentation(void)
{
    parsed_packet_t pkt;
    int res = parse_packet(pkt_ipv4_frag, pkt_ipv4_frag_len, pkt_ipv4_frag_len, &pkt);
    TEST_ASSERT(res == PARSE_OK, "parse_packet should return PARSE_OK");
    TEST_ASSERT(pkt.l3.ipv4.mf == true, "More Fragments (MF) flag must be true");
    TEST_ASSERT(pkt.l3.ipv4.frag_offset == 0, "Fragment offset must be 0");
    TEST_ASSERT(pkt.l3.ipv4.checksum_valid == true, "IPv4 fragment checksum must be valid");
    return 0;
}

static int test_malformed_packets(void)
{
    parsed_packet_t pkt1;
    int res1 = parse_packet(pkt_mal_ihl, pkt_mal_ihl_len, pkt_mal_ihl_len, &pkt1);
    TEST_ASSERT(res1 == PARSE_ERR_MALFORMED, "IHL < 5 must return PARSE_ERR_MALFORMED");
    TEST_ASSERT(pkt1.is_malformed == true, "is_malformed must be true");

    parsed_packet_t pkt2;
    int res2 = parse_packet(pkt_mal_totlen, pkt_mal_totlen_len, pkt_mal_totlen_len, &pkt2);
    TEST_ASSERT(res2 == PARSE_ERR_MALFORMED, "Total length < Header length must return PARSE_ERR_MALFORMED");
    TEST_ASSERT(pkt2.is_malformed == true, "is_malformed must be true");
    return 0;
}

static int test_truncated_packets(void)
{
    parsed_packet_t pkt;
    int res = parse_packet(pkt_trunc_eth, pkt_trunc_eth_len, pkt_trunc_eth_len, &pkt);
    TEST_ASSERT(res == PARSE_ERR_TRUNCATED, "Short frame must return PARSE_ERR_TRUNCATED");
    TEST_ASSERT(pkt.is_truncated == true, "is_truncated must be true");
    return 0;
}

static int test_checksum_validation(void)
{
    parsed_packet_t pkt;
    parse_packet(pkt_bad_ck, pkt_bad_ck_len, pkt_bad_ck_len, &pkt);
    TEST_ASSERT(pkt.l3.ipv4.checksum_valid == false, "Corrupted checksum must be marked invalid");
    return 0;
}

static int test_packet_filtering(void)
{
    parsed_packet_t pkt_tcp, pkt_udp;
    parse_packet(pkt_vlan_tcp, pkt_vlan_tcp_len, pkt_vlan_tcp_len, &pkt_tcp);
    parse_packet(pkt_qinq_udp, pkt_qinq_udp_len, pkt_qinq_udp_len, &pkt_udp);

    /* Protocol Filter */
    packet_filter_t f_tcp;
    filter_init(&f_tcp);
    filter_set_protocol(&f_tcp, "tcp");
    TEST_ASSERT(filter_matches(&f_tcp, &pkt_tcp) == true, "Filter TCP should match TCP packet");
    TEST_ASSERT(filter_matches(&f_tcp, &pkt_udp) == false, "Filter TCP should reject UDP packet");

    /* Port Filter */
    packet_filter_t f_port;
    filter_init(&f_port);
    filter_set_src_port(&f_port, 443);
    TEST_ASSERT(filter_matches(&f_port, &pkt_tcp) == true, "Filter port 443 should match");
    TEST_ASSERT(filter_matches(&f_port, &pkt_udp) == false, "Filter port 443 should reject port 53");

    /* CIDR Subnet Filter */
    packet_filter_t f_cidr;
    filter_init(&f_cidr);
    filter_set_src_ip(&f_cidr, "192.168.1.0/24");
    TEST_ASSERT(filter_matches(&f_cidr, &pkt_tcp) == true, "192.168.1.100 must match 192.168.1.0/24");
    TEST_ASSERT(filter_matches(&f_cidr, &pkt_udp) == false, "172.16.0.5 must reject 192.168.1.0/24");

    /* VLAN Filter */
    packet_filter_t f_vlan;
    filter_init(&f_vlan);
    filter_set_protocol(&f_vlan, "vlan");
    TEST_ASSERT(filter_matches(&f_vlan, &pkt_tcp) == true, "VLAN packet must match");

    parsed_packet_t pkt_non_vlan;
    parse_packet(pkt_ip_opt_icmp, pkt_ip_opt_icmp_len, pkt_ip_opt_icmp_len, &pkt_non_vlan);
    TEST_ASSERT(filter_matches(&f_vlan, &pkt_non_vlan) == false, "Non-VLAN packet must reject");

    return 0;
}

static int test_analytics_and_pcap(void)
{
    const char *test_pcap_path = "/tmp/sniffer_test.pcap";
    pcap_dumper_t dumper;
    int rc = pcap_dumper_open(&dumper, test_pcap_path, 65536, DLT_EN10MB);
    TEST_ASSERT(rc == 0, "pcap_dumper_open failed");

    pcap_dumper_write(&dumper, pkt_vlan_tcp, pkt_vlan_tcp_len, pkt_vlan_tcp_len, NULL);
    pcap_dumper_write(&dumper, pkt_qinq_udp, pkt_qinq_udp_len, pkt_qinq_udp_len, NULL);
    pcap_dumper_write(&dumper, pkt_ip_opt_icmp, pkt_ip_opt_icmp_len, pkt_ip_opt_icmp_len, NULL);
    pcap_dumper_write(&dumper, pkt_ipv6_tcp, pkt_ipv6_tcp_len, pkt_ipv6_tcp_len, NULL);
    pcap_dumper_close(&dumper);

    /* Read back with PCAP reader */
    pcap_reader_t reader;
    rc = pcap_reader_open(&reader, test_pcap_path);
    TEST_ASSERT(rc == 0, "pcap_reader_open failed");

    sniffer_analytics_t a;
    analytics_init(&a);

    uint8_t buf[2048];
    size_t caplen = 0, wirelen = 0;
    parsed_packet_t pkt;
    int count = 0;

    while (pcap_reader_next(&reader, buf, sizeof(buf), &caplen, &wirelen, NULL) > 0) {
        parse_packet(buf, caplen, wirelen, &pkt);
        analytics_update(&a, &pkt);
        count++;
    }
    pcap_reader_close(&reader);
    remove(test_pcap_path);

    TEST_ASSERT(count == 4, "PCAP must contain 4 packets");
    TEST_ASSERT(a.total_packets == 4, "Analytics total packets must be 4");
    TEST_ASSERT(a.tcp_packets == 2, "Analytics TCP packets must be 2");
    TEST_ASSERT(a.udp_packets == 1, "Analytics UDP packets must be 1");
    TEST_ASSERT(a.icmp_packets == 1, "Analytics ICMP packets must be 1");
    TEST_ASSERT(a.ipv4_packets == 3, "Analytics IPv4 packets must be 3");
    TEST_ASSERT(a.ipv6_packets == 1, "Analytics IPv6 packets must be 1");
    TEST_ASSERT(analytics_get_average_packet_size(&a) > 0.0, "Average packet size must be > 0");

    top_ip_record_t top_src[5];
    size_t n = analytics_get_top_src_ips(&a, top_src, 5);
    TEST_ASSERT(n >= 1, "Must have top source IPs");

    return 0;
}

static int test_unaligned_ipv4_tcp(void)
{
    /*
     * In networking, Ethernet frames (14 bytes) inherently cause subsequent
     * L3/L4 headers to begin at a 2-byte offset (14 % 4 == 2). Furthermore,
     * variable encapsulation (QinQ, MPLS, GRE) can place packet buffers at arbitrary
     * odd byte boundaries in memory.
     * We stress-test parsing at offsets 1, 3, 5, and 7 to guarantee zero misaligned
     * memory accesses or UBSan violations.
     */
    uint8_t buffer[1024];
    const size_t offsets[] = { 1, 3, 5, 7 };

    for (size_t i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
        size_t off = offsets[i];
        memset(buffer, 0xAA, sizeof(buffer));
        memcpy(buffer + off, pkt_vlan_tcp, pkt_vlan_tcp_len);

        parsed_packet_t pkt;
        int res = parse_packet(buffer + off, pkt_vlan_tcp_len, pkt_vlan_tcp_len, &pkt);
        TEST_ASSERT(res == PARSE_OK, "parse_packet on unaligned IPv4 TCP failed");
        TEST_ASSERT(pkt.has_vlan == true, "Unaligned VLAN flag mismatch");
        TEST_ASSERT(pkt.vlan_id == 100, "Unaligned VLAN ID mismatch");
        TEST_ASSERT(pkt.ip_version == 4, "Unaligned IP version mismatch");
        TEST_ASSERT(pkt.l3.ipv4.checksum_valid == true, "Unaligned IPv4 checksum must be valid");
        TEST_ASSERT(pkt.l4_proto == IPPROTO_TCP, "Unaligned L4 proto must be TCP");
        TEST_ASSERT(pkt.l4.tcp.src_port == 443, "Unaligned TCP src port mismatch");
        TEST_ASSERT(pkt.l4.tcp.dst_port == 54321, "Unaligned TCP dst port mismatch");
        TEST_ASSERT(pkt.l4.tcp.syn == true && pkt.l4.tcp.ack_flag == true, "Unaligned TCP flags mismatch");
        TEST_ASSERT(pkt.l4.tcp.checksum_valid == true, "Unaligned TCP checksum must be valid");
        TEST_ASSERT(pkt.payload != NULL, "Unaligned TCP payload must be non-null");
        TEST_ASSERT(memcmp(pkt.payload, "HELLO SILICON", 13) == 0, "Unaligned TCP payload mismatch");
    }
    return 0;
}

static int test_unaligned_ipv6_tcp(void)
{
    uint8_t buffer[1024];
    const size_t offsets[] = { 1, 3, 5, 7 };

    for (size_t i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
        size_t off = offsets[i];
        memset(buffer, 0xBB, sizeof(buffer));
        memcpy(buffer + off, pkt_ipv6_tcp, pkt_ipv6_tcp_len);

        parsed_packet_t pkt;
        int res = parse_packet(buffer + off, pkt_ipv6_tcp_len, pkt_ipv6_tcp_len, &pkt);
        TEST_ASSERT(res == PARSE_OK, "parse_packet on unaligned IPv6 TCP failed");
        TEST_ASSERT(pkt.ip_version == 6, "Unaligned IPv6 version mismatch");
        TEST_ASSERT(pkt.l4_proto == IPPROTO_TCP, "Unaligned IPv6 L4 proto must be TCP");
        TEST_ASSERT(pkt.l4.tcp.src_port == 80, "Unaligned IPv6 TCP src port mismatch");
        TEST_ASSERT(pkt.l4.tcp.dst_port == 60000, "Unaligned IPv6 TCP dst port mismatch");
        TEST_ASSERT(pkt.l4.tcp.checksum_valid == true, "Unaligned IPv6 TCP checksum must be valid");
    }
    return 0;
}

static int test_unaligned_qinq_udp(void)
{
    uint8_t buffer[1024];
    const size_t offsets[] = { 1, 3, 5, 7 };

    for (size_t i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
        size_t off = offsets[i];
        memset(buffer, 0xCC, sizeof(buffer));
        memcpy(buffer + off, pkt_qinq_udp, pkt_qinq_udp_len);

        parsed_packet_t pkt;
        int res = parse_packet(buffer + off, pkt_qinq_udp_len, pkt_qinq_udp_len, &pkt);
        TEST_ASSERT(res == PARSE_OK, "parse_packet on unaligned QinQ UDP failed");
        TEST_ASSERT(pkt.has_vlan == true && pkt.vlan_id == 200, "Unaligned outer VLAN mismatch");
        TEST_ASSERT(pkt.has_inner_vlan == true && pkt.inner_vlan_id == 10, "Unaligned inner VLAN mismatch");
        TEST_ASSERT(pkt.ip_version == 4, "Unaligned QinQ IP version mismatch");
        TEST_ASSERT(pkt.l4_proto == IPPROTO_UDP, "Unaligned QinQ L4 proto must be UDP");
        TEST_ASSERT(pkt.l4.udp.src_port == 53, "Unaligned UDP src port mismatch");
        TEST_ASSERT(pkt.l4.udp.dst_port == 49152, "Unaligned UDP dst port mismatch");
        TEST_ASSERT(pkt.l4.udp.checksum_valid == true, "Unaligned UDP checksum must be valid");
    }
    return 0;
}

static int test_unaligned_ipv6_extension_headers(void)
{
    uint8_t buffer[1024];
    const size_t offsets[] = { 1, 3, 5, 7 };

    for (size_t i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
        size_t off = offsets[i];
        memset(buffer, 0xDD, sizeof(buffer));
        memcpy(buffer + off, pkt_ipv6_ext_udp, pkt_ipv6_ext_udp_len);

        parsed_packet_t pkt;
        int res = parse_packet(buffer + off, pkt_ipv6_ext_udp_len, pkt_ipv6_ext_udp_len, &pkt);
        TEST_ASSERT(res == PARSE_OK, "parse_packet on unaligned IPv6 ext headers failed");
        TEST_ASSERT(pkt.ip_version == 6, "Unaligned IPv6 ext version mismatch");
        TEST_ASSERT(pkt.l3.ipv6.ext_hdr_count == 1, "Unaligned ext hdr count mismatch");
        TEST_ASSERT(pkt.l3.ipv6.final_protocol == IPPROTO_UDP, "Unaligned final protocol mismatch");
        TEST_ASSERT(pkt.l4_proto == IPPROTO_UDP, "Unaligned L4 protocol mismatch");
        TEST_ASSERT(pkt.l4.udp.src_port == 5000, "Unaligned UDP port mismatch");
        TEST_ASSERT(pkt.l4.udp.checksum_valid == true, "Unaligned UDP checksum must be valid");
    }
    return 0;
}

int main(void)
{
    printf("\n%s================================================================%s\n", COLOR_CYAN, COLOR_RESET);
    printf("%s   RUNNING NETWORK PACKET SNIFFER PROTOCOL & SANITIZER TESTS   %s\n", COLOR_MAGENTA, COLOR_RESET);
    printf("%s================================================================%s\n\n", COLOR_CYAN, COLOR_RESET);

    /* Original 12 Baseline Test Cases */
    RUN_TEST(test_ethernet_arp);
    RUN_TEST(test_8021q_vlan_ipv4_tcp);
    RUN_TEST(test_qinq_vlan_udp);
    RUN_TEST(test_ipv4_options_icmp);
    RUN_TEST(test_ipv6_tcp);
    RUN_TEST(test_ipv6_extension_headers);
    RUN_TEST(test_ipv4_fragmentation);
    RUN_TEST(test_malformed_packets);
    RUN_TEST(test_truncated_packets);
    RUN_TEST(test_checksum_validation);
    RUN_TEST(test_packet_filtering);
    RUN_TEST(test_analytics_and_pcap);

    /* Deliberately Unaligned Packet Buffers Test Suite */
    printf("\n%s--- Unaligned Memory Stress Tests (Off-by-1, 3, 5, 7 bytes) ---%s\n", COLOR_YELLOW, COLOR_RESET);
    RUN_TEST(test_unaligned_ipv4_tcp);
    RUN_TEST(test_unaligned_ipv6_tcp);
    RUN_TEST(test_unaligned_qinq_udp);
    RUN_TEST(test_unaligned_ipv6_extension_headers);

    printf("\n%s----------------------------------------------------------------%s\n", COLOR_CYAN, COLOR_RESET);
    printf("Total Tests: %d | Passed: %s%d%s | Failed: %s%d%s\n",
           g_tests_run,
           COLOR_GREEN, g_tests_passed, COLOR_RESET,
           (g_tests_run - g_tests_passed > 0) ? COLOR_RED : COLOR_GREEN,
           g_tests_run - g_tests_passed, COLOR_RESET);
    printf("%s----------------------------------------------------------------%s\n\n", COLOR_CYAN, COLOR_RESET);

    return (g_tests_run == g_tests_passed) ? EXIT_SUCCESS : EXIT_FAILURE;
}
