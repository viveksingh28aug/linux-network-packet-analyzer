# Linux Raw Socket Network Packet Analyzer
### High-Performance L2/L3/L4 Network Traffic Analyzer & Packet Parsing Engine

[![Language](https://img.shields.io/badge/Language-C11%20%2F%20C%2B%2B-blue.svg)](#)
[![Platform](https://img.shields.io/badge/Platform-Linux%20Ubuntu-orange.svg)](#)
[![Build](https://img.shields.io/badge/Build-Makefile%20%7C%20CMake-green.svg)](#)
[![Performance](https://img.shields.io/badge/Throughput-29.67%20Mpps%20%7C%2021.6%20Gbps-brightgreen.svg)](#)
[![License](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](LICENSE.md)

---

## 1. Project Overview

The **Linux Raw Socket Network Packet Analyzer** is a production-grade, low-level network diagnostic and packet inspection tool designed for systems and network software engineers. Operating directly on top of the Linux network stack using `AF_PACKET` raw sockets, the analyzer captures raw Ethernet frames, performs deterministic, zero-allocation protocol parsing across Layers 2, 3, and 4, evaluates real-time packet filters, verifies RFC 1071 Internet checksums, and aggregates telemetry and top-talker frequency distributions.

The project is structured to demonstrate low-level systems programming concepts critical for **Cisco Silicon One** software engineering, including zero-copy architectures, strict-aliasing and memory alignment safety, kernel drop telemetry, bitwise protocol extraction, and deterministic offline verification.

---

## 2. OSI Model Explanation

The packet analyzer decapsulates frames traversing the first four layers of the Open Systems Interconnection (OSI) reference model:

```
+------------------------------------+-----------------------------------------------+
| OSI Layer                          | Packet Analyzer Implementation / Support      |
+------------------------------------+-----------------------------------------------+
| Layer 4: Transport Layer           | TCP (Flags, Ports, Seq/Ack, Checksum)         |
|                                    | UDP (Ports, Length, Checksum, Padding)        |
|                                    | ICMPv4 & ICMPv6 (Type, Code, Echo ID/Seq)     |
+------------------------------------+-----------------------------------------------+
| Layer 3: Network Layer             | IPv4 (IHL, TOS/DSCP/ECN, Frag Flags, Checksum)|
|                                    | IPv6 (Traffic Class, Flow Label, Ext Headers) |
+------------------------------------+-----------------------------------------------+
| Layer 2: Data Link Layer           | Ethernet II (MAC Addresses, EtherType)        |
|                                    | IEEE 802.1Q Single VLAN Tagging (PCP, DEI, VID)|
|                                    | IEEE 802.1ad QinQ Provider Bridging (Double)  |
|                                    | ARP (Address Resolution Protocol)             |
+------------------------------------+-----------------------------------------------+
| Layer 1: Physical Layer            | Handled by physical PHY, MAC SerDes, and NIC  |
+------------------------------------+-----------------------------------------------+
```

---

## 3. Packet Processing Architecture

The analyzer processes packets through a decoupled, pipelined architecture:

1. **Ingestion Layer (`src/core/capture.c`):**
   - Creates an `AF_PACKET` raw socket with `SOCK_RAW` and `htons(ETH_P_ALL)`.
   - Binds to a specific network interface via `struct sockaddr_ll` or captures on all interfaces.
   - Dynamically configures socket receive buffers (`SO_RCVBUFFORCE` / `SO_RCVBUF` up to 4 MB) to prevent kernel buffer drops.
   - Monitors kernel drop counters using `getsockopt(SOL_PACKET, PACKET_STATISTICS)`.
2. **Parser Pipeline (`src/parser/parser.c`):**
   - Zero-allocation design: all state is contained in a caller-allocated `parsed_packet_t` structure.
   - Recursive header peeling: decodes L2 Ethernet and VLAN tags, routes to L3 (IPv4/IPv6), processes IPv6 extension header chains, and inspects L4 transport headers.
   - Thorough boundary checking: ensures `offset + header_len <= caplen` before any header dereference, completely preventing buffer over-reads.
3. **Checksum Engine (`src/parser/checksum.c`):**
   - Implements RFC 1071 16-bit 1's complement accumulator.
   - Uses alignment-safe, strict-aliasing-safe `memcpy` access to avoid compiler misoptimizations under `-O3`.
   - Validates IPv4 header checksums, ICMP checksums, and L4 IPv4/IPv6 pseudo-header checksums.
4. **Filtering Engine (`src/filter/filter.c`):**
   - High-speed bitmask and range matching for Protocol, CIDR Subnets (IPv4 and IPv6), Port Ranges, and VLAN IDs.
5. **Analytics & IP Frequency (`src/analytics/analytics.c`):**
   - Bounded-memory hash table (4,096 buckets) using FNV-1a hashing and linear probing.
   - Eliminates dynamic memory allocations in the packet capture loop.
   - Calculates total packets/bytes, average packet size, and ranks Top 10 IP talkers.
6. **Telemetry & Output (`src/printer/printer.c`, `src/pcap/pcap.c`):**
   - ANSI color formatting for terminal diagnostics.
   - Boundary-safe hex/ASCII payload dumps.
   - Standard libpcap file (`.pcap`) generation and offline replay.

---

## 4. Supported Protocols

- **Layer 2:** Ethernet II (DIX), IEEE 802.1Q VLAN, IEEE 802.1ad QinQ (Stacked VLANs), ARP, Loopback.
- **Layer 3:** 
  - **IPv4:** Full base header, variable IP options (IHL 20 to 60 bytes), DiffServ/DSCP (6 bits), ECN (2 bits), Fragmentation (`DF`, `MF`, 13-bit Fragment Offset), Header Checksum verification.
  - **IPv6:** Full 40-byte base header, Traffic Class, 20-bit Flow Label (ECMP/LAG hashing), Hop Limit, Extension Headers (Hop-by-Hop, Routing, Fragment, Authentication Header, Destination Options).
- **Layer 4:**
  - **TCP:** Ports, 32-bit Seq/Ack numbers, Data Offset (TCP options), 8 Flags (`FIN`, `SYN`, `RST`, `PSH`, `ACK`, `URG`, `ECE`, `CWR`), Window size, Urgent pointer, Pseudo-header checksum verification.
  - **UDP:** Ports, Length, Pseudo-header checksum verification, padding handling.
  - **ICMPv4:** Type, Code, Checksum, Echo Request/Reply ID & Sequence numbers.
  - **ICMPv6:** Type, Code, Checksum.

---

## 5. Installation Instructions

### Prerequisites (Ubuntu Linux)
```bash
sudo apt-get update
sudo apt-get install -y build-essential gcc make cmake libpcap-dev
```

---

## 6. Build Instructions

### Building with GNU Make
```bash
# Build sniffer, test_runner, and benchmark
make all

# Build and execute automated unit tests
make test

# Build and execute performance benchmarks
make run-benchmark

# Clean build artifacts
make clean
```

### Building with CMake
```bash
mkdir -p build && cd build
cmake ..
make -j$(nproc)
ctest --output-on-failure
```

---

## 7. Execution Examples

### A. Inspect Available Interfaces
```bash
./sniffer -L
```

### B. Live Capture on Interface (Requires Root or CAP_NET_RAW)
```bash
# Capture on loopback interface
sudo ./sniffer -i lo

# Capture on Ethernet/WiFi interface
sudo ./sniffer -i wlp1s0

# Capture with setcap capability (run without sudo):
sudo setcap cap_net_raw+ep ./sniffer
./sniffer -i lo
```

### C. Live Capture with Filters and Packet Count Limit
```bash
# Capture 10 TCP packets on interface wlp1s0 and save to output.pcap
sudo ./sniffer -i wlp1s0 -p tcp -c 10 -w output.pcap

# Capture UDP traffic on port 53 (DNS)
sudo ./sniffer -i wlp1s0 -p udp --dport 53

# Capture traffic to a specific IPv4 CIDR subnet
sudo ./sniffer -i wlp1s0 --dst-ip 192.168.1.0/24
```

### D. Offline Analysis of PCAP Traces (No Root Required!)
```bash
# Analyze captured PCAP file
./sniffer -r sample.pcap

# Filter offline PCAP by protocol
./sniffer -r sample.pcap -p udp
```

---

## 8. Sample Output

### Packet Decapsulation Output
```
================= Packet (Cap: 103 B, Wire: 103 B) =================
---------------- Ethernet ----------------
|- Source MAC      : 66:77:88:99:AA:BB
|- Destination MAC : 00:11:22:33:44:55
|- EtherType       : 0x0800 (IPv4 (Internet Protocol v4))
|- VLAN Tag (802.1Q): VID=100, PCP=3, DEI=0
------------------- IPv4 -------------------
|- Version         : IPv4
|- Header Length   : 5 DWORDS (20 Bytes)
|- TOS / DSCP / ECN: 0x00 (DSCP: 0, ECN: 0)
|- Total Length    : 85 Bytes
|- Identification  : 4660
|- Flags / Frag Off : DF=1, MF=0, Offset=0 Bytes
|- TTL             : 64
|- Protocol        : 6 (TCP (Transmission Control Protocol))
|- Checksum        : 0x5C62 (VALID)
|- Source IP       : 192.168.1.100
|- Destination IP  : 10.0.0.1
------------------- TCP -------------------
|- Source Port     : 443
|- Destination Port: 54321
|- Sequence Number : 1000
|- Ack Number      : 2000
|- Header Length   : 5 DWORDS (20 Bytes)
|- Flags           : [ ACK PSH ] (0x18)
|- Window Size     : 65535
|- Checksum        : 0x2CB2 (VALID)
|- Urgent Pointer  : 0
|- Payload Dump (45 Bytes):
  0000: 47 45 54 20 2F 69 6E 64  65 78 2E 68 74 6D 6C 20  |GET /index.html |
  0010: 48 54 54 50 2F 31 2E 31  0D 0A 48 6F 73 74 3A 20  |HTTP/1.1..Host: |
  0020: 63 69 73 63 6F 2E 63 6F  6D 0D 0A 0D 0A           |cisco.com....|
```

### Telemetry & Analytics Summary
```
=======================================================
              NETWORK TRAFFIC ANALYTICS SUMMARY         
=======================================================
|- Total Packets Processed: 3
|- Total Bytes Processed  : 285
|- Average Packet Size    : 95.00 Bytes

--- Protocol Distribution ---
|- IPv4 Packets           : 3 (100.0%)
|- IPv6 Packets           : 0 (0.0%)
|- Non-IP / Other Packets : 0
|- VLAN Tagged Frames     : 3
|- ARP Packets            : 0
|- TCP Packets            : 2 (66.7%)
|- UDP Packets            : 1 (33.3%)
|- ICMP / ICMPv6 Packets  : 0 (0.0%)
|- Other L4 Packets       : 0

--- Packet Validation & Anomalies ---
|- Malformed Packets      : 0
|- Truncated Packets      : 0
|- Kernel Dropped Packets : 0

--- Top 2 Source IP Addresses ---
  [1] 192.168.1.100             : 2 packets (206 bytes, 66.7%)
  [2] 172.16.0.5                : 1 packets (79 bytes, 33.3%)

--- Top 2 Destination IP Addresses ---
  [1] 10.0.0.1                  : 2 packets (206 bytes, 66.7%)
  [2] 172.16.0.1                : 1 packets (79 bytes, 33.3%)
=======================================================
```

---

## 9. Testing Methodology

The project includes an automated offline test suite (`tests/test_runner.c`) executing 12 deterministic test scenarios without requiring root privileges:
1. `test_ethernet_arp`: L2 frame parsing & ARP detection.
2. `test_8021q_vlan_ipv4_tcp`: VLAN tag peeling, IPv4 header, TCP flags, checksums.
3. `test_qinq_vlan_udp`: 802.1ad Service VLAN + 802.1Q Customer VLAN + UDP.
4. `test_ipv4_options_icmp`: Variable IPv4 options (IHL=6, 24 bytes), ICMP Echo.
5. `test_ipv6_tcp`: IPv6 40-byte header, Flow Label, RFC 8200 pseudo-header TCP checksum.
6. `test_ipv6_extension_headers`: Hop-by-Hop options traversal, UDP.
7. `test_ipv4_fragmentation`: Frag flags (`MF=1`), fragment offset.
8. `test_malformed_packets`: Fault injection (illegal IHL < 5, total length < header length).
9. `test_truncated_packets`: Buffer boundary truncation handling.
10. `test_checksum_validation`: Checksum corruption detection.
11. `test_packet_filtering`: Multi-field filter validation (protocol, CIDR, ports).
12. `test_analytics_and_pcap`: PCAP write, read, and analytics frequency aggregation.

Run tests:
```bash
make test
```

---

## 10. Performance Measurements

Empirical benchmarks run on Linux Ubuntu with GCC 15.2.0 (`-O3`), benchmarking 5,000,000 packets per scenario:

| Scenario | Packet Size | Rate (Mpps) | Throughput (Gbps) | Avg Latency / Packet |
|---|---|---|---|---|
| **802.1Q VLAN + IPv4 + TCP** | 71 B | **21.92 Mpps** | **12.45 Gbps** | **45.62 ns** |
| **QinQ + IPv4 + UDP** | 64 B | **28.76 Mpps** | **14.73 Gbps** | **34.77 ns** |
| **IPv6 + TCP Header** | 91 B | **29.67 Mpps** | **21.60 Gbps** | **33.70 ns** |
| **IPv4 Options + ICMP** | 60 B | **28.50 Mpps** | **13.68 Gbps** | **35.09 ns** |

*Complete performance breakdown available in [BENCHMARKS.md](BENCHMARKS.md).*

---

## 11. Security Considerations

- **Privilege Separation:** Raw socket creation (`AF_PACKET`) requires the `CAP_NET_RAW` capability. Rather than running as `root`, assign capabilities using `sudo setcap cap_net_raw+ep ./sniffer`.
- **Eavesdropping Risks:** Promiscuous mode (`PACKET_MR_PROMISC`) captures all broadcast, multicast, and unicast frames on the collision domain / VLAN, exposing unencrypted credentials (HTTP, FTP, Telnet). Restrict execution to authorized diagnostic network segments.
- **Buffer Safety:** All memory references in the parser enforce strict boundary limits (`offset + header_len <= caplen`), preventing memory corruption and buffer over-reads from malformed packets.
- **DoS Mitigation in Extension Headers:** IPv6 extension header processing is bounded to a maximum of 8 chained headers to prevent infinite loops from malicious circular extension headers.

---

## 12. Known Limitations

- **TCP Segmentation Offload (TSO / GRO):** On virtual interfaces or NICs with Generic Receive Offload (GRO) enabled, incoming frames coalesced by the Linux kernel may appear as large frames (up to 64 KB) exceeding standard MTU.
- **Kernel-to-Userspace Copy Overhead:** Standard `AF_PACKET` raw sockets copy packet buffers from kernel `sk_buff` to userspace memory via `recvfrom()`, which limits throughput beyond ~2-5 Gbps under live high-volume saturation without `PACKET_MMAP`.
- **IPv4 Fragment Reassembly:** The parser identifies fragmented packets and decodes the initial fragment, but does not implement a stateful reassembly buffer for out-of-order IP fragments.

---

## 13. Future Improvements

1. **Linux `PACKET_MMAP` (RX_RING):** Implement circular memory-mapped ring buffers (`PACKET_RX_RING`) between kernel and userspace to eliminate `recvfrom()` system call overhead.
2. **eBPF / XDP Offload:** Deploy an eBPF program at the driver/NIC layer to perform line-rate packet filtering before packets are allocated into kernel `sk_buff` structures.
3. **Hardware Accelerations (DPDK):** Port the capture engine to the Data Plane Development Kit (DPDK) with poll-mode drivers (PMD) for line-rate 100 Gbps packet processing.
4. **Stateful Flow Tracking:** Implement a 5-tuple flow table (Source IP, Destination IP, Source Port, Destination Port, Protocol) to track TCP stream states (3-way handshake, sequence tracking, retransmissions).
