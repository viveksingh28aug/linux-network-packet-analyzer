#include "sniffer/types.h"
#include "sniffer/capture.h"
#include "sniffer/parser.h"
#include "sniffer/filter.h"
#include "sniffer/analytics.h"
#include "sniffer/printer.h"
#include "sniffer/pcap.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <unistd.h>

/* Global termination flag for async-signal safety */
static volatile sig_atomic_t g_running = 1;

static void handle_signal(int sig)
{
    (void)sig;
    g_running = 0;
}

static void print_banner(FILE *out)
{
    fprintf(out, "%s[%s+%s] %sLinux Raw Socket Network Packet Analyzer%s (Cisco Silicon One Edition)\n",
            COLOR_CYAN, COLOR_GREEN, COLOR_CYAN, COLOR_BOLD, COLOR_RESET);
}

static void print_usage(const char *prog)
{
    printf("\nUsage: %s [OPTIONS]\n", prog);
    printf("Options:\n");
    printf("  -i, --interface <ifname>  Network interface (e.g. eth0, lo, any)\n");
    printf("  -r, --read <pcap_file>    Read packets from offline PCAP file (no root needed)\n");
    printf("  -w, --write <pcap_file>   Save captured packets to PCAP file\n");
    printf("  -l, --log <file>          Save formatted text analysis to file (default: sniff.log)\n");
    printf("  -c, --count <num>         Exit after processing <num> matching packets\n");
    printf("  -p, --proto <protocol>    Filter protocol (tcp, udp, icmp, icmpv6, ipv4, ipv6, arp, vlan)\n");
    printf("      --src-ip <ip[/cidr]>  Filter source IP (IPv4 CIDR or IPv6)\n");
    printf("      --dst-ip <ip[/cidr]>  Filter destination IP (IPv4 CIDR or IPv6)\n");
    printf("      --sport <port[-range]> Filter source port or port range\n");
    printf("      --dport <port[-range]> Filter destination port or port range\n");
    printf("  -q, --quiet               Quiet mode: suppress per-packet output, show summary only\n");
    printf("      --no-color            Disable ANSI terminal colors\n");
    printf("  -L, --list-interfaces     List available network interfaces and exit\n");
    printf("  -h, --help                Show this help screen and exit\n\n");
}

int main(int argc, char *argv[])
{
    char ifname[IFNAMSIZ] = "";
    char pcap_in[256] = "";
    char pcap_out[256] = "";
    char log_filename[256] = "sniff.log";
    uint64_t max_packets = 0;
    bool quiet = false;
    bool use_color = isatty(fileno(stdout));

    packet_filter_t filter;
    filter_init(&filter);

    static struct option long_options[] = {
        {"interface",       required_argument, 0, 'i'},
        {"read",            required_argument, 0, 'r'},
        {"write",           required_argument, 0, 'w'},
        {"log",             required_argument, 0, 'l'},
        {"count",           required_argument, 0, 'c'},
        {"proto",           required_argument, 0, 'p'},
        {"src-ip",          required_argument, 0, 1001},
        {"dst-ip",          required_argument, 0, 1002},
        {"sport",           required_argument, 0, 1003},
        {"dport",           required_argument, 0, 1004},
        {"quiet",           no_argument,       0, 'q'},
        {"no-color",        no_argument,       0, 1005},
        {"list-interfaces", no_argument,       0, 'L'},
        {"help",            no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt = 0;
    int option_index = 0;

    while ((opt = getopt_long(argc, argv, "i:r:w:l:c:p:qLh", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'i':
                strncpy(ifname, optarg, sizeof(ifname) - 1);
                break;
            case 'r':
                strncpy(pcap_in, optarg, sizeof(pcap_in) - 1);
                break;
            case 'w':
                strncpy(pcap_out, optarg, sizeof(pcap_out) - 1);
                break;
            case 'l':
                strncpy(log_filename, optarg, sizeof(log_filename) - 1);
                break;
            case 'c':
                max_packets = (uint64_t)strtoull(optarg, NULL, 10);
                break;
            case 'p':
                if (filter_set_protocol(&filter, optarg) != 0) {
                    fprintf(stderr, "[-] Unknown protocol filter: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            case 1001: /* --src-ip */
                if (filter_set_src_ip(&filter, optarg) != 0) {
                    fprintf(stderr, "[-] Invalid source IP filter: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            case 1002: /* --dst-ip */
                if (filter_set_dst_ip(&filter, optarg) != 0) {
                    fprintf(stderr, "[-] Invalid destination IP filter: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            case 1003: { /* --sport */
                char *dash = strchr(optarg, '-');
                if (dash) {
                    *dash = '\0';
                    int p1 = atoi(optarg);
                    int p2 = atoi(dash + 1);
                    filter_set_src_port_range(&filter, p1, p2);
                } else {
                    filter_set_src_port(&filter, atoi(optarg));
                }
                break;
            }
            case 1004: { /* --dport */
                char *dash = strchr(optarg, '-');
                if (dash) {
                    *dash = '\0';
                    int p1 = atoi(optarg);
                    int p2 = atoi(dash + 1);
                    filter_set_dst_port_range(&filter, p1, p2);
                } else {
                    filter_set_dst_port(&filter, atoi(optarg));
                }
                break;
            }
            case 'q':
                quiet = true;
                break;
            case 1005: /* --no-color */
                use_color = false;
                break;
            case 'L':
                print_banner(stdout);
                print_available_interfaces(stdout);
                exit(EXIT_SUCCESS);
            case 'h':
                print_banner(stdout);
                print_usage(argv[0]);
                exit(EXIT_SUCCESS);
            default:
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    /* Fallback positional argument if interface not supplied via flag */
    if (strlen(ifname) == 0 && strlen(pcap_in) == 0 && optind < argc) {
        strncpy(ifname, argv[optind], sizeof(ifname) - 1);
    }

    /* If neither interface nor offline pcap specified, show interfaces and usage */
    if (strlen(ifname) == 0 && strlen(pcap_in) == 0) {
        print_banner(stdout);
        fprintf(stderr, "%s[-] No capture interface or PCAP input file specified.%s\n", COLOR_RED, COLOR_RESET);
        print_usage(argv[0]);
        print_available_interfaces(stdout);
        exit(EXIT_FAILURE);
    }

    /* Register POSIX signal handlers */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    print_banner(stdout);

    /* Open log file */
    FILE *log_fp = NULL;
    if (strlen(log_filename) > 0) {
        log_fp = fopen(log_filename, "w");
        if (log_fp) {
            fprintf(stdout, "[%s+%s] Logging detailed analysis to: %s%s%s\n",
                    COLOR_GREEN, COLOR_RESET, COLOR_CYAN, log_filename, COLOR_RESET);
        } else {
            fprintf(stderr, "%s[!] Warning: Failed to open log file '%s'%s\n",
                    COLOR_YELLOW, log_filename, COLOR_RESET);
        }
    }

    /* Open PCAP writer if requested */
    pcap_dumper_t dumper;
    bool dump_pcap = false;
    if (strlen(pcap_out) > 0) {
        if (pcap_dumper_open(&dumper, pcap_out, SNIFFER_MAX_PACKET_SIZE, DLT_EN10MB) == 0) {
            dump_pcap = true;
            fprintf(stdout, "[%s+%s] Writing matching packets to PCAP: %s%s%s\n",
                    COLOR_GREEN, COLOR_RESET, COLOR_CYAN, pcap_out, COLOR_RESET);
        } else {
            fprintf(stderr, "%s[-] Failed to open PCAP output file '%s'%s\n",
                    COLOR_RED, pcap_out, COLOR_RESET);
        }
    }

    /* Preallocated zero-copy packet buffer (avoid heap allocations in fast path) */
    static uint8_t packet_buffer[SNIFFER_MAX_PACKET_SIZE];
    parsed_packet_t parsed_pkt;
    sniffer_analytics_t analytics;
    analytics_init(&analytics);

    uint64_t processed_count = 0;

    if (strlen(pcap_in) > 0) {
        /* Offline PCAP Replay Mode */
        fprintf(stdout, "[%s+%s] Reading from offline PCAP: %s%s%s\n",
                COLOR_GREEN, COLOR_RESET, COLOR_CYAN, pcap_in, COLOR_RESET);

        pcap_reader_t reader;
        if (pcap_reader_open(&reader, pcap_in) != 0) {
            fprintf(stderr, "%s[-] Failed to open PCAP file: %s%s\n",
                    COLOR_RED, pcap_in, COLOR_RESET);
            if (log_fp) fclose(log_fp);
            if (dump_pcap) pcap_dumper_close(&dumper);
            exit(EXIT_FAILURE);
        }

        size_t caplen = 0, wirelen = 0;
        struct timeval ts;

        while (g_running) {
            int ret = pcap_reader_next(&reader, packet_buffer, sizeof(packet_buffer), &caplen, &wirelen, &ts);
            if (ret <= 0) break; /* End of file */

            parse_packet(packet_buffer, caplen, wirelen, &parsed_pkt);

            if (!filter_matches(&filter, &parsed_pkt)) {
                continue;
            }

            analytics_update(&analytics, &parsed_pkt);
            processed_count++;

            if (dump_pcap) {
                pcap_dumper_write(&dumper, packet_buffer, caplen, wirelen, &ts);
            }

            if (!quiet) {
                print_packet_details(stdout, &parsed_pkt, use_color);
            }
            if (log_fp) {
                print_packet_details(log_fp, &parsed_pkt, false);
            }

            if (max_packets > 0 && processed_count >= max_packets) {
                break;
            }
        }

        pcap_reader_close(&reader);

    } else {
        /* Live Raw Socket Capture Mode */
        fprintf(stdout, "[%s+%s] Initializing live capture on interface: %s%s%s\n",
                COLOR_GREEN, COLOR_RESET, COLOR_CYAN, ifname, COLOR_RESET);

        capture_handle_t cap;
        if (capture_open(&cap, ifname, SNIFFER_MAX_PACKET_SIZE, true) != 0) {
            if (log_fp) fclose(log_fp);
            if (dump_pcap) pcap_dumper_close(&dumper);
            exit(EXIT_FAILURE);
        }

        fprintf(stdout, "[%s+%s] Raw socket successfully bound. Capturing frames... (Press Ctrl+C to terminate)\n",
                COLOR_GREEN, COLOR_RESET);

        size_t caplen = 0, wirelen = 0;

        while (g_running) {
            int ret = capture_next(&cap, packet_buffer, sizeof(packet_buffer), &caplen, &wirelen);
            if (ret < 0) {
                fprintf(stderr, "%s[-] Socket error encountered%s\n", COLOR_RED, COLOR_RESET);
                break;
            }
            if (ret == 0) {
                /* Timeout expired, loop back to check g_running */
                continue;
            }

            parse_packet(packet_buffer, caplen, wirelen, &parsed_pkt);

            if (!filter_matches(&filter, &parsed_pkt)) {
                continue;
            }

            analytics_update(&analytics, &parsed_pkt);
            processed_count++;

            if (dump_pcap) {
                pcap_dumper_write(&dumper, packet_buffer, caplen, wirelen, NULL);
            }

            if (!quiet) {
                print_packet_details(stdout, &parsed_pkt, use_color);
            }
            if (log_fp) {
                print_packet_details(log_fp, &parsed_pkt, false);
            }

            if (max_packets > 0 && processed_count >= max_packets) {
                break;
            }
        }

        /* Fetch kernel drop statistics */
        uint64_t rx_pkts = 0, drop_pkts = 0;
        if (capture_get_stats(&cap, &rx_pkts, &drop_pkts) == 0) {
            analytics_set_kernel_drops(&analytics, drop_pkts, 0);
        }

        capture_close(&cap);
    }

    /* Print Final Analytics Summary */
    print_analytics_summary(stdout, &analytics, use_color);
    if (log_fp) {
        print_analytics_summary(log_fp, &analytics, false);
        fclose(log_fp);
    }

    if (dump_pcap) {
        pcap_dumper_close(&dumper);
    }

    fprintf(stdout, "[%s+%s] Session cleanly terminated. Total matching packets: %lu\n",
            COLOR_GREEN, COLOR_RESET, processed_count);

    return 0;
}
