#include "sniffer/types.h"
#include "sniffer/parser.h"
#include "sniffer/filter.h"
#include "sniffer/checksum.h"
#include "../tests/test_packets.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <inttypes.h>

#define NUM_ITERATIONS 5000000ULL /* 5 million packets */

static double get_time_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

static void run_benchmark(const char *label, const uint8_t *packet, size_t pkt_len, uint64_t iterations)
{
    parsed_packet_t pkt;
    packet_filter_t filter;
    filter_init(&filter);
    filter_set_protocol(&filter, "tcp");

    /* Warm-up cache */
    for (int i = 0; i < 10000; i++) {
        parse_packet(packet, pkt_len, pkt_len, &pkt);
    }

    double t_start = get_time_sec();

    uint64_t match_count = 0;
    for (uint64_t i = 0; i < iterations; i++) {
        parse_packet(packet, pkt_len, pkt_len, &pkt);
        if (filter_matches(&filter, &pkt)) {
            match_count++;
        }
    }

    double t_end = get_time_sec();
    double duration = t_end - t_start;

    double pps = (double)iterations / duration;
    double mpps = pps / 1e6;
    double total_bytes = (double)iterations * (double)pkt_len;
    double gbps = (total_bytes * 8.0) / (duration * 1e9);
    double mb_per_sec = (total_bytes / (1024.0 * 1024.0)) / duration;
    double avg_ns = (duration * 1e9) / (double)iterations;

    printf("\n%s--- Benchmark: %s ---%s\n", COLOR_CYAN, label, COLOR_RESET);
    printf("  Iterations       : %" PRIu64 " packets\n", iterations);
    printf("  Packet Size      : %zu bytes\n", pkt_len);
    printf("  Elapsed Time     : %.4f seconds\n", duration);
    printf("  Parsing Rate     : %s%.2f Mpps%s (Million packets/sec)\n", COLOR_GREEN, mpps, COLOR_RESET);
    printf("  Throughput       : %s%.2f Gbps%s (%.2f MB/s)\n", COLOR_GREEN, gbps, COLOR_RESET, mb_per_sec);
    printf("  Avg Latency      : %s%.2f ns%s per packet\n", COLOR_YELLOW, avg_ns, COLOR_RESET);
    printf("  Filter Matches   : %" PRIu64 " packets\n", match_count);
}

int main(int argc, char *argv[])
{
    uint64_t n = NUM_ITERATIONS;
    if (argc > 1) {
        n = strtoull(argv[1], NULL, 10);
        if (n == 0) n = NUM_ITERATIONS;
    }

    printf("\n%s=======================================================%s\n", COLOR_CYAN, COLOR_RESET);
    printf("%s   CISCO SILICON ONE PACKET PARSER THROUGHPUT BENCHMARK  %s\n", COLOR_MAGENTA, COLOR_RESET);
    printf("%s=======================================================%s\n", COLOR_CYAN, COLOR_RESET);
    printf("Benchmarking zero-allocation L2/L3/L4 parser and filter engine on Ubuntu Linux.\n");

    run_benchmark("VLAN 802.1Q + IPv4 + TCP Frame", pkt_vlan_tcp, pkt_vlan_tcp_len, n);
    run_benchmark("QinQ 802.1ad/802.1Q + IPv4 + UDP Frame", pkt_qinq_udp, pkt_qinq_udp_len, n);
    run_benchmark("IPv6 + TCP Frame", pkt_ipv6_tcp, pkt_ipv6_tcp_len, n);
    run_benchmark("IPv4 Options + ICMP Frame", pkt_ip_opt_icmp, pkt_ip_opt_icmp_len, n);

    printf("\n%s=======================================================%s\n\n", COLOR_CYAN, COLOR_RESET);
    return 0;
}
