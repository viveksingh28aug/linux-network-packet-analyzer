# Testing Guide & Verification Suite

This document describes the automated testing framework, test fixtures, and validation methodology implemented in `tests/test_runner.c`.

---

## 1. Testing Philosophy

In carrier-grade network software engineering (such as Cisco Silicon One OS development), automated testing must satisfy three core requirements:
1. **Determinism:** Tests must produce identical, byte-exact results across all architectures and environments without dependency on live network traffic.
2. **Zero-Privilege Execution:** Unit tests must execute entirely in userspace without requiring root privileges or `CAP_NET_RAW` capabilities.
3. **Fault Injection & Edge Cases:** Must deliberately inject malformed headers, illegal lengths, buffer truncations, and checksum corruptions to prove boundary resilience.

---

## 2. Test Cases Overview

The test runner implements 16 distinct test cases covering 100% of the required protocol layers, validation checks, and memory alignment guarantees:

| # | Test Function | Purpose / Coverage | Validation Criteria |
|---|---|---|---|
| **1** | `test_ethernet_arp` | L2 Ethernet parsing, ARP frame detection | `has_eth == true`, `ether_type == 0x0806`, `ip_version == 0`, Broadcast MAC verified. |
| **2** | `test_8021q_vlan_ipv4_tcp` | 802.1Q VLAN peeling, IPv4 header, TCP flags, payload | `vlan_id == 100`, `vlan_pcp == 3`, `SYN+ACK` flags set, valid IPv4 & TCP checksums, payload extracted safely. |
| **3** | `test_qinq_vlan_udp` | Stacked 802.1ad (outer) + 802.1Q (inner) VLANs, UDP | Outer VID 200, Inner VID 10, UDP ports 53 -> 49152, valid UDP checksum, payload length verified. |
| **4** | `test_ipv4_options_icmp` | Variable IPv4 header length (IHL=6, 24 bytes), ICMP Echo | `ihl == 6`, ICMP Echo Request type 8, valid ICMP checksum, payload offset adjusted past IP options without memory corruption. |
| **5** | `test_ipv6_tcp` | Base IPv6 40-byte header, 128-bit addresses, TCP | `version == 6`, IPv6 address matches `2001:db8::1`, TCP ports 80 -> 60000, RFC 8200 pseudo-header checksum valid. |
| **6** | `test_ipv6_extension_headers` | IPv6 Hop-by-Hop options chain traversal, UDP | Extension header count == 1, resolves terminal protocol UDP (17), UDP checksum valid. |
| **7** | `test_ipv4_fragmentation` | IPv4 fragmentation flags (`MF`, fragment offset) | `mf == true`, `frag_offset == 0`, confirms no erroneous L4 transport parsing on fragmented payloads. |
| **8** | `test_malformed_packets` | Fault injection: illegal IHL < 5, total_len < ihl_bytes | Parser returns `PARSE_ERR_MALFORMED`, sets `is_malformed = true`, prevents buffer over-reads. |
| **9** | `test_truncated_packets` | Fault injection: truncated Ethernet frames (< 14 bytes) | Parser returns `PARSE_ERR_TRUNCATED`, sets `is_truncated = true`. |
| **10** | `test_checksum_validation` | Bit flip injection on IPv4 header checksum | Parser flags `pkt.l3.ipv4.checksum_valid == false`. |
| **11** | `test_packet_filtering` | Protocol, CIDR subnet, port range, and VLAN filtering | Positive matches on `tcp`, `192.168.1.0/24`, port `443`, VLAN tags. Negative matches on mismatched traffic. |
| **12** | `test_analytics_and_pcap` | PCAP dumper writing, PCAP reading, analytics rollup | Writes 4 packets to PCAP, reads back, validates packet counts, byte totals, average packet size, and top talkers. |
| **13** | `test_unaligned_ipv4_tcp` | Deliberately unaligned buffer offsets (1, 3, 5, 7 bytes) | IPv4/TCP header members parsed via safe `memcpy` into aligned stack structures; zero UBSan alignment faults. |
| **14** | `test_unaligned_ipv6_tcp` | Deliberately unaligned IPv6 buffer offsets (1, 3, 5, 7 bytes) | 128-bit IPv6 addresses, flow label, and TCP ports parsed cleanly with zero unaligned dereferences. |
| **15** | `test_unaligned_qinq_udp` | Deliberately unaligned QinQ UDP offsets (1, 3, 5, 7 bytes) | Stacked VLAN tags and UDP datagram parsed cleanly at odd memory boundaries. |
| **16** | `test_unaligned_ipv6_extension_headers` | Deliberately unaligned IPv6 ext headers (1, 3, 5, 7 bytes) | Hop-by-Hop extension header chain parsed cleanly on odd byte boundaries. |

---

## 3. Running the Test Suite

### Standard Build
```bash
make test
```

### Strict ASan & UBSan Alignment Verification
```bash
make test-sanitizers
```

Or manually:
```bash
gcc -Wall -Wextra -Werror -O2 -g -fsanitize=address,undefined \
    -fno-omit-frame-pointer -fno-sanitize-recover=all \
    -I include -I src/headers -I src/globals -D_GNU_SOURCE \
    src/core/capture.c src/parser/parser.c src/parser/checksum.c \
    src/filter/filter.c src/analytics/analytics.c src/printer/printer.c \
    src/pcap/pcap.c tests/test_runner.c -o test_runner_sanitized

./test_runner_sanitized
```

All 16 tests pass with 0 AddressSanitizer and 0 UndefinedBehaviorSanitizer errors.
