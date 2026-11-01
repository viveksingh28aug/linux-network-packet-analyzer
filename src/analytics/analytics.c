#include "sniffer/analytics.h"
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

void analytics_init(sniffer_analytics_t *a)
{
    if (!a) return;
    memset(a, 0, sizeof(*a));
}

void analytics_reset(sniffer_analytics_t *a)
{
    analytics_init(a);
}

void analytics_set_kernel_drops(sniffer_analytics_t *a, uint64_t dropped, uint64_t freeze)
{
    if (!a) return;
    a->kernel_dropped = dropped;
    a->kernel_freeze = freeze;
}

static uint32_t fnv1a_hash(const uint8_t *data, size_t len)
{
    uint32_t hash = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= 16777619u;
    }
    return hash;
}

static void record_ip(ip_entry_t *table, size_t *unique_count,
                      const void *ip_bytes, bool is_v6, size_t pkt_len)
{
    size_t ip_len = is_v6 ? 16 : 4;
    uint32_t hash = fnv1a_hash((const uint8_t *)ip_bytes, ip_len);
    size_t idx = hash % IP_HASH_TABLE_SIZE;

    for (size_t probe = 0; probe < 64; probe++) {
        size_t pos = (idx + probe) % IP_HASH_TABLE_SIZE;
        ip_entry_t *entry = &table[pos];

        if (!entry->in_use) {
            entry->in_use = true;
            entry->is_ipv6 = is_v6;
            memcpy(entry->addr, ip_bytes, ip_len);
            entry->count = 1;
            entry->bytes = pkt_len;

            if (is_v6) {
                inet_ntop(AF_INET6, ip_bytes, entry->ip_str, sizeof(entry->ip_str));
            } else {
                inet_ntop(AF_INET, ip_bytes, entry->ip_str, sizeof(entry->ip_str));
            }

            (*unique_count)++;
            return;
        }

        if (entry->is_ipv6 == is_v6 && memcmp(entry->addr, ip_bytes, ip_len) == 0) {
            entry->count++;
            entry->bytes += pkt_len;
            return;
        }
    }
}

void analytics_update(sniffer_analytics_t *a, const parsed_packet_t *pkt)
{
    if (!a || !pkt) return;

    a->total_packets++;
    a->total_bytes += pkt->caplen;

    if (pkt->is_malformed) {
        a->malformed_packets++;
    }
    if (pkt->is_truncated) {
        a->truncated_packets++;
    }
    if (pkt->has_vlan) {
        a->vlan_packets++;
    }
    if (pkt->ether_type == ETH_P_ARP) {
        a->arp_packets++;
    }

    /* Layer 3 analytics */
    if (pkt->ip_version == 4) {
        a->ipv4_packets++;
        record_ip(a->src_ip_table, &a->unique_src_ips,
                  &pkt->l3.ipv4.src.s_addr, false, pkt->caplen);
        record_ip(a->dst_ip_table, &a->unique_dst_ips,
                  &pkt->l3.ipv4.dst.s_addr, false, pkt->caplen);
    } else if (pkt->ip_version == 6) {
        a->ipv6_packets++;
        record_ip(a->src_ip_table, &a->unique_src_ips,
                  &pkt->l3.ipv6.src, true, pkt->caplen);
        record_ip(a->dst_ip_table, &a->unique_dst_ips,
                  &pkt->l3.ipv6.dst, true, pkt->caplen);
    } else {
        a->non_ip_packets++;
    }

    /* Layer 4 analytics */
    if (pkt->l4_proto == IPPROTO_TCP) {
        a->tcp_packets++;
    } else if (pkt->l4_proto == IPPROTO_UDP) {
        a->udp_packets++;
    } else if (pkt->l4_proto == IPPROTO_ICMP || pkt->l4_proto == IPPROTO_ICMPV6) {
        a->icmp_packets++;
    } else if (pkt->l4_proto != 0) {
        a->other_l4_packets++;
    }
}

double analytics_get_average_packet_size(const sniffer_analytics_t *a)
{
    if (!a || a->total_packets == 0) return 0.0;
    return (double)a->total_bytes / (double)a->total_packets;
}

static int compare_ip_entries(const void *p1, const void *p2)
{
    const ip_entry_t *e1 = *(const ip_entry_t **)p1;
    const ip_entry_t *e2 = *(const ip_entry_t **)p2;
    if (e2->count > e1->count) return 1;
    if (e2->count < e1->count) return -1;
    return 0;
}

static size_t get_top_ips(const ip_entry_t *table, uint64_t total_packets,
                          top_ip_record_t *records, size_t max_records)
{
    const ip_entry_t *active[IP_HASH_TABLE_SIZE];
    size_t active_count = 0;

    for (size_t i = 0; i < IP_HASH_TABLE_SIZE; i++) {
        if (table[i].in_use) {
            active[active_count++] = &table[i];
        }
    }

    if (active_count == 0) return 0;

    qsort(active, active_count, sizeof(const ip_entry_t *), compare_ip_entries);

    size_t out_count = (active_count < max_records) ? active_count : max_records;
    for (size_t i = 0; i < out_count; i++) {
        snprintf(records[i].ip_str, sizeof(records[i].ip_str), "%s", active[i]->ip_str);
        records[i].count = active[i]->count;
        records[i].bytes = active[i]->bytes;
        records[i].percentage = (total_packets > 0)
            ? ((double)active[i]->count * 100.0 / (double)total_packets)
            : 0.0;
    }

    return out_count;
}

size_t analytics_get_top_src_ips(const sniffer_analytics_t *a, top_ip_record_t *records, size_t max_records)
{
    if (!a || !records || max_records == 0) return 0;
    return get_top_ips(a->src_ip_table, a->total_packets, records, max_records);
}

size_t analytics_get_top_dst_ips(const sniffer_analytics_t *a, top_ip_record_t *records, size_t max_records)
{
    if (!a || !records || max_records == 0) return 0;
    return get_top_ips(a->dst_ip_table, a->total_packets, records, max_records);
}
